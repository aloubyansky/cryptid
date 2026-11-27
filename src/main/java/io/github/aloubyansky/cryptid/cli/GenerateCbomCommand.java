package io.github.aloubyansky.cryptid.cli;

import io.github.aloubyansky.cryptid.AnalysisInput;
import io.github.aloubyansky.cryptid.AnalysisOptions;
import io.github.aloubyansky.cryptid.ArtifactAnalysis;
import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.Cryptid;
import io.github.aloubyansky.cryptid.CryptoInventory;
import io.github.aloubyansky.cryptid.InputArtifact;
import io.github.aloubyansky.cryptid.cyclonedx.CbomWriter;
import io.quarkus.picocli.runtime.annotations.TopCommand;
import jakarta.inject.Inject;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.cyclonedx.model.Bom;
import org.jboss.logging.Logger;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * The {@code cryptid} command: reads a CycloneDX SBOM, resolves the JARs of its Maven components,
 * analyzes their bytecode in two phases (an index of calls across all JARs, then detection per
 * JAR, both in parallel), and writes one CBOM with the crypto assets found, linked to the
 * components whose JARs they occur in. Per-artifact results are kept in the work directory and
 * reused by later runs unless {@code --rescan} is given.
 */
@TopCommand
@Command(
        name = "cryptid",
        mixinStandardHelpOptions = true,
        description =
                "Generates a CBOM for the Maven components of a CycloneDX SBOM by analyzing the"
                        + " bytecode of their JARs with crypto API specifications derived from sonar-cryptography's Java rules")
public class GenerateCbomCommand implements Callable<Integer> {

    private static final Logger log = Logger.getLogger(GenerateCbomCommand.class);

    /** The input SBOM. */
    @Parameters(index = "0", paramLabel = "SBOM", description = "Input CycloneDX SBOM (JSON or XML)")
    Path sbomFile;

    /** Where the CBOM is written. */
    @Option(
            names = {"-o", "--output"},
            defaultValue = "cbom.json",
            description = "Output CBOM file (default: ${DEFAULT-VALUE})")
    Path output;

    /** The directory to keep each artifact's result in, or {@code null} for none. */
    @Option(
            names = "--work-dir",
            description =
                    "Directory to keep each artifact's result in. Reusing it skips artifacts analyzed"
                            + " before by the same build, with the same JARs (default: none)")
    Path workDir;

    /** The number of threads, or {@code null} for one per available CPU. */
    @Option(
            names = "--threads",
            description = "Threads resolving and analyzing artifacts (default: the available CPUs)")
    Integer threads;

    /** Whether artifacts already analyzed in the work directory are analyzed again. */
    @Option(names = "--rescan", description = "Re-analyze artifacts already analyzed in --work-dir")
    boolean rescan;

    /** Reads the input SBOM. */
    @Inject SbomReader sbomReader;
    /** Resolves the components' JARs. */
    @Inject ArtifactResolver resolver;
    /** Merges the per-artifact CBOMs. */
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
     * analyzes them with {@link Cryptid} and writes the CBOM. Results kept in the work directory
     * by an earlier run are reused, unless {@code --rescan} is given.
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
        final int threadCount = threads != null ? Math.max(1, threads) : Runtime.getRuntime().availableProcessors();

        // components with equal coordinates share their binary artifact
        final Map<String, List<MavenComponent>> byArtifact = new LinkedHashMap<>();
        int notJars = 0;
        for (MavenComponent c : mavenComponents) {
            if (!"jar".equals(c.extension())) {
                notJars++;
                continue;
            }
            byArtifact.computeIfAbsent(c.artifactKey(), k -> new ArrayList<>(1)).add(c);
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

        // 2. analyze them
        final Cryptid.Builder cryptid = Cryptid.builder();
        if (workDir != null) {
            log.infof("Work directory: %s", workDir);
            cryptid.cacheDirectory(workDir);
        }
        final CryptoInventory inventory = cryptid.build().analyze(AnalysisInput.builder().artifacts(inputs(sbom, resolved)).build(), AnalysisOptions.builder()
                .threads(threadCount)
                .rescan(rescan)
                .build());
        int analyzed = 0;
        int cached = 0;
        int failed = 0;
        long classes = 0;
        for (ArtifactAnalysis a : inventory.artifacts()) {
            switch (a.outcome()) {
                case ANALYZED -> {
                    analyzed++;
                    classes += a.classes();
                }
                case CACHED -> cached++;
                case FAILED -> failed++;
            }
        }
        log.infof("Analyzed %d artifacts (%d classes), %d reused from the work directory, %d failed",
                analyzed, classes, cached, failed);

        // 3. write the CBOM
        final CbomAssembler.Result result =
                assembler.assemble(sbom, resolved.stream().map(ArtifactGroup::members).toList(), inventory);
        CbomWriter.write(result.bom(), output);
        log.infof(
                "Wrote CBOM to %s: %d findings in %d components, total time %ds",
                output,
                result.findings(),
                result.componentsWithAssets(),
                (System.currentTimeMillis() - start) / 1000);
        return 0;
    }

    /**
     * Turns the resolved artifacts into the analysis's input, with their dependencies from the
     * SBOM's graph. A dependency that isn't analyzed, e.g. a POM, is looked through to the
     * analyzed artifacts it depends on; an artifact one of whose components is missing from the
     * graph has unknown dependencies.
     *
     * @param sbom the SBOM
     * @param resolved the resolved artifacts
     * @return one input per artifact, in the same order
     */
    private static List<InputArtifact> inputs(Bom sbom, List<ArtifactGroup> resolved) {
        final Map<String, List<String>> direct = new SbomReader().directDependencies(sbom);
        final Map<String, ArtifactCoordinates> analyzed = new HashMap<>();
        resolved.forEach(g -> g.members().forEach(c -> {
            if (c.bomRef() != null) {
                analyzed.put(c.bomRef(), g.first().coordinates());
            }
        }));
        final List<InputArtifact> inputs = new ArrayList<>(resolved.size());
        for (ArtifactGroup g : resolved) {
            Set<ArtifactCoordinates> deps = new LinkedHashSet<>();
            for (MavenComponent c : g.members()) {
                if (!direct.containsKey(c.bomRef())) {
                    deps = null;
                    break;
                }
                final Set<String> visited = new HashSet<>();
                final Deque<String> todo = new ArrayDeque<>(direct.get(c.bomRef()));
                while (!todo.isEmpty()) {
                    final String ref = todo.pop();
                    if (!visited.add(ref)) {
                        continue;
                    }
                    final ArtifactCoordinates dep = analyzed.get(ref);
                    if (dep != null) {
                        deps.add(dep);
                    } else {
                        todo.addAll(direct.getOrDefault(ref, List.of()));
                    }
                }
            }
            inputs.add(InputArtifact.builder(g.first().coordinates(), g.jar())
                    .dependencies(deps == null ? null : List.copyOf(deps))
                    .build());
        }
        return inputs;
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
