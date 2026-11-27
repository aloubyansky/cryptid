package io.github.aloubyansky.cryptid.analysis;

import io.github.aloubyansky.cryptid.AnalysisOptions;
import io.github.aloubyansky.cryptid.ArtifactAnalysis;
import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.CryptoInventory;
import io.github.aloubyansky.cryptid.InputArtifact;
import io.github.aloubyansky.cryptid.bytecode.CallGraph;
import io.github.aloubyansky.cryptid.bytecode.CallIndex;
import io.github.aloubyansky.cryptid.bytecode.Hierarchy;
import io.github.aloubyansky.cryptid.bytecode.JarCache;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.detection.ArtifactPaths;
import io.github.aloubyansky.cryptid.scan.ArtifactScan;
import io.github.aloubyansky.cryptid.scan.BytecodeScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.jboss.logging.Logger;

/**
 * One analysis of a set of artifacts: phase A reads all JARs into one class table and call graph,
 * then indexes the calls between them and keeps each JAR's candidate methods, phase B detects per JAR in parallel, and the scans are merged into the
 * inventory in the order of the artifacts. Scans kept in the cache directory are reused, and
 * phase A is skipped when every artifact's scan is there.
 */
public final class AnalysisRun {

    private static final Logger log = Logger.getLogger(AnalysisRun.class);

    private final BytecodeScanner scanner;
    private final Path cacheDir;
    private final AnalysisOptions options;
    private final List<InputArtifact> artifacts;
    private final Map<ArtifactCoordinates, InputArtifact> byCoordinates = new HashMap<>();
    private final List<Path> allJars;
    private final Hierarchy hierarchy;

    /**
     * Prepares an analysis.
     *
     * @param scanner the scanner, with the specs loaded
     * @param cacheDir the directory to keep scans in, or {@code null} for none
     * @param options the options
     * @param artifacts the artifacts, with distinct coordinates
     * @throws IllegalArgumentException if two artifacts have the same coordinates
     */
    public AnalysisRun(BytecodeScanner scanner, Path cacheDir, AnalysisOptions options, List<InputArtifact> artifacts) {
        this.scanner = scanner;
        this.cacheDir = cacheDir;
        this.options = options;
        this.artifacts = List.copyOf(artifacts);
        for (InputArtifact a : this.artifacts) {
            if (byCoordinates.putIfAbsent(a.coordinates(), a) != null) {
                throw new IllegalArgumentException("Artifact given twice: " + a.coordinates());
            }
        }
        this.allJars = this.artifacts.stream().map(InputArtifact::jar).distinct().toList();
        this.hierarchy = new Hierarchy(this.artifacts.stream().map(a -> ArtifactPaths.of(a.coordinates())).toList());
    }

    /**
     * Runs the analysis.
     *
     * @return the inventory, with an analysis for every artifact
     * @throws IOException if the cache directory can't be prepared
     */
    public CryptoInventory run() throws IOException {
        final Path resultsDir = cacheDir == null ? null : resultsDir();
        if (resultsDir != null) {
            log.infof("Results kept in %s", resultsDir);
        }
        final Map<ArtifactCoordinates, ArtifactScan> cached = new ConcurrentHashMap<>();
        if (resultsDir != null && !options.rescan()) {
            parallel(artifacts, a -> {
                final Path file = resultFile(resultsDir, a);
                if (Files.exists(file)) {
                    try {
                        cached.put(a.coordinates(), InventoryJson.read(file));
                    } catch (IOException e) {
                        log.warnf(e, "Analyzing %s again: its result can't be read", a.coordinates());
                    }
                }
                return null;
            }, "Read");
        }

        final List<ArtifactScan> scans;
        try (JarCache jarCache = new JarCache()) {
            // phase A: index the calls between all artifacts, for resolving values passed in
            // from callers; skipped when every artifact's scan is cached
            final CallIndex callIndex;
            final Map<ArtifactCoordinates, BytecodeScanner.CandidateMethods> candidates = new ConcurrentHashMap<>();
            if (cached.size() < artifacts.size()) {
                callIndex = index(jarCache, cached, candidates);
            } else {
                callIndex = null;
            }

            // phase B: detect, on the methods phase A kept
            scans = parallel(artifacts, a -> {
                final ArtifactScan reused = cached.get(a.coordinates());
                if (reused != null) {
                    return new ArtifactScan(reused.analysis().withOutcome(ArtifactAnalysis.Outcome.CACHED), reused.assets());
                }
                try {
                    // released once scanned; an artifact that failed to index is analyzed here
                    final BytecodeScanner.CandidateMethods f = candidates.remove(a.coordinates());
                    final ArtifactScan scan = scanner.scan(a.jar(), a.coordinates(), types(a), jarCache, callIndex, f);
                    if (resultsDir != null) {
                        InventoryJson.write(scan, resultFile(resultsDir, a));
                    }
                    if (scan.analysis().failedMethods() > 0) {
                        log.debugf("%s: %d methods couldn't be analyzed", a.coordinates(), scan.analysis().failedMethods());
                    }
                    return scan;
                } catch (Exception | LinkageError e) {
                    log.warnf(e, "Failed to analyze %s", a.coordinates());
                    return new ArtifactScan(ArtifactAnalysis.failed(a.coordinates(), String.valueOf(e)), List.of());
                }
            }, "Analyzed");
        }

        // merge, in the order of the artifacts, so that the inventory is the same in every run
        final CryptoInventory.Builder inventory = CryptoInventory.builder();
        for (ArtifactScan s : scans) {
            inventory.artifact(s.analysis());
            inventory.addAssets(s.assets());
        }
        return inventory.build();
    }

    /**
     * Phase A: reads every JAR's classes into the class table and the call graph, then indexes
     * the calls between all JARs and keeps the candidate methods of the JARs to scan, matching
     * specs with each JAR's view of the class table.
     */
    private CallIndex index(JarCache jarCache, Map<ArtifactCoordinates, ArtifactScan> cached,
            Map<ArtifactCoordinates, BytecodeScanner.CandidateMethods> candidates) throws IOException {
        final long t0 = System.currentTimeMillis();
        final Set<String> allClasses = new HashSet<>();
        for (Path j : allJars) {
            // an unreadable JAR fails its own analysis in phase B, not the whole analysis
            try {
                allClasses.addAll(jarCache.classNames(j));
            } catch (RuntimeException e) {
                log.warnf("Can't read %s: %s", j, e.getMessage());
            }
        }
        final CallGraph callGraph = new CallGraph(allClasses, hierarchy);
        parallel(artifacts, a -> {
            try {
                scanner.read(a.jar(), a.coordinates(), jarCache, hierarchy, callGraph);
            } catch (Exception | LinkageError e) {
                log.warnf(e, "Failed to read %s", a.coordinates());
            }
            return null;
        }, "Read");
        // nothing uses the call graph yet: see docs/reachability-design.md
        callGraph.finish();
        log.infof("Read %d classes in %d ms, %d of them in several artifacts with different contents; call graph: %d methods,"
                        + " %d calls (%d through method handles), %d instantiations",
                allClasses.size(), System.currentTimeMillis() - t0, hierarchy.ambiguousClasses(), callGraph.methodCount(),
                callGraph.edgeCount(), callGraph.handleEdgeCount(), callGraph.instantiationCount());

        final long t1 = System.currentTimeMillis();
        final CallIndex callIndex = new CallIndex(allClasses, hierarchy);
        parallel(artifacts, a -> {
            try {
                // artifacts to be scanned keep what detection needs, so they aren't analyzed twice
                final BytecodeScanner.CandidateMethods f = scanner.index(a.jar(), a.coordinates(), types(a), jarCache,
                        callIndex, !cached.containsKey(a.coordinates()));
                if (f != null) {
                    candidates.put(a.coordinates(), f);
                }
            } catch (Exception | LinkageError e) {
                log.warnf(e, "Failed to index %s", a.coordinates());
            }
            return null;
        }, "Indexed");
        callIndex.finish();
        log.infof("Indexed %d calls in %d ms; %d methods may contain crypto events",
                callIndex.size(), System.currentTimeMillis() - t1,
                candidates.values().stream().mapToInt(f -> f.methods().size()).sum());
        return callIndex;
    }

    /** The class table as an artifact sees it, for matching specs. */
    private Types types(InputArtifact a) {
        return Types.of(hierarchy.view(preference(a)));
    }

    /**
     * The artifacts whose copy of a class an artifact prefers, where copies differ: its own,
     * then its dependencies, transitively and breadth first in the order they are listed. Classes
     * in no preferred artifact resolve to the first artifact's copy in the order of the
     * analysis, and then to the JDK.
     *
     * @param a the artifact
     * @return artifact paths, the artifact's own first
     */
    List<String> preference(InputArtifact a) {
        final Set<ArtifactCoordinates> visited = new LinkedHashSet<>();
        visited.add(a.coordinates());
        if (a.dependencies() != null) {
            final Deque<ArtifactCoordinates> todo = new ArrayDeque<>(a.dependencies());
            while (!todo.isEmpty()) {
                final ArtifactCoordinates next = todo.pop();
                if (visited.add(next)) {
                    final InputArtifact dep = byCoordinates.get(next);
                    if (dep != null && dep.dependencies() != null) {
                        todo.addAll(dep.dependencies());
                    }
                }
            }
        }
        return visited.stream().filter(byCoordinates::containsKey).map(ArtifactPaths::of).toList();
    }

    /**
     * The directory of this analysis's scans in the cache. Scans are reused only by an analysis
     * with the same build of the tool, and the same artifacts, JARs and dependencies, see {@link
     * CacheKey}.
     */
    private Path resultsDir() throws IOException {
        final List<String> ids = new ArrayList<>(artifacts.size());
        for (InputArtifact a : artifacts) {
            ids.add(a.coordinates() + " " + a.jar() + " " + Files.size(a.jar()) + " " + Files.getLastModifiedTime(a.jar()).toMillis()
                    + " " + (a.dependencies() == null ? "?" : a.dependencies()));
        }
        return Files.createDirectories(cacheDir).toRealPath().resolve(CacheKey.of(CacheKey.build(), ids));
    }

    private static Path resultFile(Path resultsDir, InputArtifact a) {
        return resultsDir.resolve(ArtifactPaths.of(a.coordinates()) + ".json");
    }

    /** A task applied to each input element. */
    @FunctionalInterface
    private interface Task<I, O> {
        O apply(I input) throws Exception;
    }

    /**
     * Applies a task to all inputs in parallel, logging progress every 100 inputs.
     *
     * @return the results, in the order of the inputs
     */
    private <I, O> List<O> parallel(List<I> inputs, Task<I, O> task, String verb) throws IOException {
        final AtomicInteger progress = new AtomicInteger();
        final ExecutorService pool = Executors.newFixedThreadPool(options.threads());
        try {
            final List<Future<O>> futures = new ArrayList<>(inputs.size());
            for (I input : inputs) {
                futures.add(pool.submit(() -> {
                    final O out = task.apply(input);
                    final int n = progress.incrementAndGet();
                    if (n % 100 == 0) {
                        log.infof("%s %d/%d", verb, n, inputs.size());
                    }
                    return out;
                }));
            }
            final List<O> results = new ArrayList<>(inputs.size());
            for (Future<O> f : futures) {
                results.add(f.get());
            }
            return results;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted", e);
        } catch (ExecutionException e) {
            throw new IOException(e.getCause());
        } finally {
            pool.shutdownNow();
        }
    }
}
