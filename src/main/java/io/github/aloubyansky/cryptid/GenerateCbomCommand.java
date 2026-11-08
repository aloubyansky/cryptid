package io.github.aloubyansky.cryptid;

import io.github.aloubyansky.cryptid.bytecode.CallIndex;
import io.github.aloubyansky.cryptid.bytecode.JarCache;
import io.github.aloubyansky.cryptid.scan.BytecodeScanner;
import io.quarkus.picocli.runtime.annotations.TopCommand;
import jakarta.inject.Inject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.cyclonedx.model.Bom;
import org.jboss.logging.Logger;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@TopCommand
@Command(
        name = "cryptid",
        mixinStandardHelpOptions = true,
        description =
                "Generates a CBOM for the Maven components of a CycloneDX SBOM by analyzing the"
                        + " bytecode of their JARs with crypto API specifications derived from sonar-cryptography's Java rules")
public class GenerateCbomCommand implements Callable<Integer> {

    private static final Logger log = Logger.getLogger(GenerateCbomCommand.class);

    enum ClasspathMode {
        /** the component's JAR and its transitive dependencies from the SBOM graph */
        deps,
        /** all JARs of the SBOM */
        all,
        /** the component's JAR only */
        none
    }

    @Parameters(index = "0", paramLabel = "SBOM", description = "Input CycloneDX SBOM (JSON or XML)")
    Path sbomFile;

    @Option(
            names = {"-o", "--output"},
            defaultValue = "cbom.json",
            description = "Output CBOM file (default: ${DEFAULT-VALUE})")
    Path output;

    @Option(
            names = "--work-dir",
            description =
                    "Directory for the per-artifact CBOMs. Reusing it skips artifacts analyzed"
                            + " before (default: a temporary directory)")
    Path workDir;

    @Option(
            names = "--classpath",
            defaultValue = "deps",
            description =
                    "JARs to resolve supertypes from when matching crypto APIs: ${COMPLETION-CANDIDATES}"
                            + " (default: ${DEFAULT-VALUE}). 'deps' falls back to 'all' for"
                            + " components missing from the SBOM dependency graph")
    ClasspathMode classpathMode;

    @Option(
            names = "--threads",
            description = "Threads resolving and analyzing artifacts (default: the available CPUs)")
    Integer threads;

    @Option(names = "--rescan", description = "Re-analyze artifacts already analyzed in --work-dir")
    boolean rescan;

    @Inject SbomReader sbomReader;
    @Inject ArtifactResolver resolver;
    @Inject CbomAssembler assembler;

    /**
     * Components sharing one binary artifact, i.e. with equal coordinates.
     *
     * @param members the components, all with the same {@link MavenComponent#artifactKey()}
     * @param jar the resolved artifact, or {@code null} if it couldn't be resolved
     */
    private record ArtifactGroup(List<MavenComponent> members, Path jar) {
        /**
         * Returns a representative member, whose artifact-related values are the same for all.
         *
         * @return the first member
         */
        MavenComponent first() {
            return members.get(0);
        }
    }

    /**
     * Generates the CBOM: reads the SBOM, resolves the binary artifacts of its Maven components,
     * analyzes their bytecode and merges the results into the output file. Artifacts analyzed in an
     * earlier run in the same work directory are reused, unless {@code --rescan} is given.
     *
     * @return {@code 0}; artifacts that can't be resolved or analyzed are logged and skipped
     * @throws Exception if the SBOM can't be read, or the work directory or CBOM can't be written
     */
    @Override
    public Integer call() throws Exception {
        final long start = System.currentTimeMillis();
        final Bom sbom = sbomReader.read(sbomFile);
        final List<MavenComponent> mavenComponents = sbomReader.mavenComponents(sbom);
        log.infof("Found %d Maven components in %s", mavenComponents.size(), sbomFile);

        final Path baseDir = (workDir != null
                        ? Files.createDirectories(workDir)
                        : Files.createTempDirectory("cryptid"))
                .toRealPath();
        log.infof("Work directory: %s", baseDir);
        final int threadCount = threads != null ? Math.max(1, threads) : Runtime.getRuntime().availableProcessors();

        // components with equal coordinates share their binary artifact
        final Map<String, List<MavenComponent>> byArtifact = new LinkedHashMap<>();
        int notJars = 0;
        for (MavenComponent c : mavenComponents) {
            if (!"jar".equals(c.extension())) {
                notJars++;
                continue;
            }
            byArtifact.computeIfAbsent(c.artifactKey(), k -> new ArrayList<>()).add(c);
        }
        if (notJars > 0) {
            log.infof("Skipping %d components that aren't JARs", notJars);
        }

        // 1. resolve the binary artifacts
        final List<ArtifactGroup> groups = parallel(
                threadCount,
                new ArrayList<>(byArtifact.values()),
                members -> new ArtifactGroup(members, resolver.resolve(members.get(0).binaryArtifact()).orElse(null)),
                "Resolved");
        final List<ArtifactGroup> resolved = groups.stream().filter(g -> g.jar() != null).toList();
        log.infof("Resolved %d of %d artifacts", resolved.size(), groups.size());

        // 2. analyze their bytecode
        final Map<String, Path> jarsByRef = new HashMap<>();
        resolved.forEach(g -> g.members().forEach(c -> {
            if (c.bomRef() != null) {
                jarsByRef.put(c.bomRef(), g.jar());
            }
        }));
        final List<Path> allJars = resolved.stream().map(ArtifactGroup::jar).distinct().toList();
        final Map<String, Set<String>> closure =
                classpathMode == ClasspathMode.deps ? sbomReader.dependencyClosure(sbom) : Map.of();

        final BytecodeScanner scanner = new BytecodeScanner();
        log.infof("Loaded %s", scanner.detection());
        final AtomicInteger cached = new AtomicInteger();
        final AtomicInteger failed = new AtomicInteger();
        final AtomicInteger classes = new AtomicInteger();
        try (JarCache jarCache = new JarCache()) {
            // phase A: index the calls between all artifacts, for resolving values passed in
            // from callers; skipped when every artifact was analyzed before
            final boolean needed = rescan || resolved.stream().anyMatch(g -> !Files.exists(g.first().cbomFile(baseDir)));
            final CallIndex callIndex;
            final Map<String, BytecodeScanner.CandidateMethods> candidates = new ConcurrentHashMap<>();
            if (needed) {
                final long t0 = System.currentTimeMillis();
                final Set<String> allClasses = new HashSet<>();
                allJars.forEach(j -> allClasses.addAll(jarCache.classNames(j)));
                callIndex = new CallIndex(allClasses);
                parallel(threadCount, resolved, g -> {
                    try {
                        // artifacts to be scanned keep what detection needs, so they aren't analyzed twice
                        final boolean scanned = rescan || !Files.exists(g.first().cbomFile(baseDir));
                        final BytecodeScanner.CandidateMethods f = scanner.index(g.jar(), g.first().artifactPath(),
                                classpath(g, jarsByRef, allJars, closure), jarCache, callIndex, scanned);
                        if (f != null) {
                            candidates.put(g.first().artifactPath(), f);
                        }
                    } catch (Exception | LinkageError e) {
                        log.warnf(e, "Failed to index %s", g.first().artifactPath());
                    }
                    return null;
                }, "Indexed");
                callIndex.finish();
                log.infof("Indexed %d calls between %d classes in %d ms; %d methods may contain crypto events",
                        callIndex.size(), allClasses.size(), System.currentTimeMillis() - t0,
                        candidates.values().stream().mapToInt(f -> f.methods().size()).sum());
            } else {
                callIndex = null;
            }

            // phase B: detect, on the methods phase A kept
            parallel(threadCount, resolved, g -> {
                final MavenComponent c = g.first();
                final Path cbomFile = c.cbomFile(baseDir);
                if (!rescan && Files.exists(cbomFile)) {
                    cached.incrementAndGet();
                    return null;
                }
                try {
                    final List<Path> cp = classpath(g, jarsByRef, allJars, closure);
                    // released once scanned; an artifact that failed to index is analyzed here
                    final BytecodeScanner.CandidateMethods f = candidates.remove(c.artifactPath());
                    final BytecodeScanner.Result r = f != null
                            ? scanner.scan(g.jar(), c.artifactPath(), cp, jarCache, callIndex, f)
                            : scanner.scan(g.jar(), c.artifactPath(), cp, jarCache, callIndex);
                    CbomAssembler.write(r.bom(), cbomFile);
                    classes.addAndGet(r.classes());
                    if (r.failedMethods() > 0) {
                        log.debugf("%s: %d methods couldn't be analyzed", c.artifactPath(), r.failedMethods());
                    }
                } catch (Exception | LinkageError e) {
                    failed.incrementAndGet();
                    log.warnf(e, "Failed to analyze %s", c.artifactPath());
                }
                return null;
            }, "Analyzed");
        }
        log.infof(
                "Analyzed %d artifacts (%d classes), %d reused from the work directory, %d failed",
                resolved.size() - cached.get() - failed.get(),
                classes.get(),
                cached.get(),
                failed.get());

        // 3. merge
        final CbomAssembler.Result result =
                assembler.assemble(sbom, resolved.stream().map(ArtifactGroup::members).toList(), baseDir);
        CbomAssembler.write(result.bom(), output);
        log.infof(
                "Wrote CBOM to %s: %d findings in %d components, total time %ds",
                output,
                result.findings(),
                result.componentsWithAssets(),
                (System.currentTimeMillis() - start) / 1000);
        return 0;
    }

    /**
     * Returns the JARs to resolve an artifact's supertypes from, as selected by {@code
     * --classpath}. The scanner always searches the artifact's own JAR first.
     *
     * @param g the artifact group
     * @param jarsByRef resolved JARs by component bom-ref
     * @param allJars all resolved JARs
     * @param closure the SBOM's dependency closure by bom-ref
     * @return the JARs, in lookup order
     */
    private List<Path> classpath(
            ArtifactGroup g, Map<String, Path> jarsByRef, List<Path> allJars, Map<String, Set<String>> closure) {
        switch (classpathMode) {
            case none:
                return List.of();
            case all:
                return allJars;
            default:
                final Set<Path> jars = new LinkedHashSet<>();
                for (MavenComponent c : g.members()) {
                    final Set<String> refs = closure.get(c.bomRef());
                    if (refs == null) {
                        return allJars;
                    }
                    refs.stream().map(jarsByRef::get).filter(Objects::nonNull).forEach(jars::add);
                }
                jars.remove(g.jar());
                return List.copyOf(jars);
        }
    }

    /** A task applied to each input element. */
    @FunctionalInterface
    private interface Task<I, O> {
        O apply(I input) throws Exception;
    }

    /**
     * Applies a task to all inputs in parallel, logging progress every 100 inputs.
     *
     * @param threads the number of threads
     * @param inputs the inputs
     * @param task the task
     * @param verb describes the task in progress messages
     * @return the results, in the order of the inputs
     * @throws Exception if a task fails
     */
    private static <I, O> List<O> parallel(int threads, List<I> inputs, Task<I, O> task, String verb) throws Exception {
        final AtomicInteger progress = new AtomicInteger();
        final ExecutorService pool = Executors.newFixedThreadPool(threads);
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
        } finally {
            pool.shutdownNow();
        }
    }
}
