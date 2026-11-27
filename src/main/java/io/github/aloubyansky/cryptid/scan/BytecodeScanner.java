package io.github.aloubyansky.cryptid.scan;

import com.ibm.mapper.model.INode;
import io.github.aloubyansky.cryptid.ArtifactAnalysis;
import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.CodeLocation;
import io.github.aloubyansky.cryptid.CryptoInventory;
import io.github.aloubyansky.cryptid.bytecode.Analyzer;
import io.github.aloubyansky.cryptid.bytecode.CallGraph;
import io.github.aloubyansky.cryptid.bytecode.CallResolver;
import io.github.aloubyansky.cryptid.bytecode.Hierarchy;
import io.github.aloubyansky.cryptid.bytecode.JarCache;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.detection.ArtifactPaths;
import io.github.aloubyansky.cryptid.detection.CryptoEventDetector;
import io.github.aloubyansky.cryptid.detection.Finding;
import io.github.aloubyansky.cryptid.model.CryptoAssetModeler;
import io.github.aloubyansky.cryptid.spec.CryptoApiMatcher;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Detects cryptographic assets in a binary JAR by analyzing its bytecode with the crypto API
 * specs, models them with sonar-cryptography's translation, and returns them as an {@link
 * ArtifactScan}. No source code and no SonarSource analyzer is involved.
 *
 * <p>When values passed between artifacts are to be resolved, first {@link #read} every JAR into a
 * shared class table and call graph, then {@link #scan} each JAR with a {@link CallResolver} over
 * them, such as {@code DemandCallIndex}.
 *
 * <p>Thread-safe: specs are immutable and shared, and each thread uses its own translation
 * pipeline, so several JARs can be read or scanned concurrently.
 */
public final class BytecodeScanner {

    private final CryptoApiMatcher matcher;
    private final int apiCount;
    private final ThreadLocal<CryptoAssetModeler> modelers = ThreadLocal.withInitial(() -> {
        try {
            return new CryptoAssetModeler();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to load sonar-cryptography's Java translators", e);
        }
    });

    /**
     * Loads the crypto API specs.
     *
     * @throws IllegalStateException if they can't be loaded
     */
    public BytecodeScanner() {
        try {
            final CryptoApiSpecs specs = CryptoApiSpecs.load();
            this.matcher = new CryptoApiMatcher(specs);
            this.apiCount = specs.apis().size();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load the crypto API specs", e);
        }
    }

    /**
     * Describes what detection uses, for logging.
     *
     * @return e.g. {@code 515 crypto API specs}
     */
    public String detection() {
        return apiCount + " crypto API specs";
    }


    /**
     * The methods of a JAR that may contain crypto events: those calling a specified API, with
     * their call sites from the final round of the field fixpoint. Detecting on them gives the same
     * findings as analyzing the whole JAR.
     *
     * @param methods the methods that {@link CryptoEventDetector#mayDetect may contain events}, in
     *     analysis order
     * @param failedMethods the number of methods whose bytecode couldn't be interpreted
     */
    public record CandidateMethods(List<Analyzer.MethodResult> methods, int failedMethods) {}

    /**
     * Records a JAR's classes in the class table and, optionally, its methods' calls in the call
     * graph, read from the class files without interpreting them. The class table must hold every
     * JAR's classes before any JAR is {@linkplain #prepare prepared}, since spec matching
     * resolves supertypes through it.
     *
     * @param jar the JAR
     * @param artifact the JAR's artifact
     * @param jarCache the shared JAR cache
     * @param hierarchy the class table to fill
     * @param callGraph the call graph to fill, or {@code null}
     */
    public void read(Path jar, ArtifactCoordinates artifact, JarCache jarCache, Hierarchy hierarchy, CallGraph callGraph) {
        final String locationPrefix = ArtifactPaths.of(artifact);
        final Analyzer analyzer = new Analyzer();
        analyzer.addJar(jar, jarCache);
        hierarchy.add(locationPrefix, analyzer.classInfos());
        if (callGraph != null) {
            callGraph.addMethods(locationPrefix, analyzer.graphFacts());
        }
    }

    /**
     * Finds a JAR's candidate methods, those calling a specified API, and interprets them with the
     * methods their values depend on ({@link Analyzer#closure}), for {@linkplain #scan(Path,
     * ArtifactCoordinates, Types, JarCache, CallResolver, CandidateMethods) scanning} the JAR
     * without interpreting the rest of it. The candidates are found from the instructions and
     * kept if their interpretation confirms them, so they are those interpreting the whole JAR
     * would give.
     *
     * @param jar the JAR
     * @param types the class hierarchy as the JAR sees it, for matching specs
     * @param jarCache the shared JAR cache
     * @return the candidate methods, interpreted
     */
    public CandidateMethods prepare(Path jar, Types types, JarCache jarCache) {
        final Analyzer analyzer = new Analyzer();
        analyzer.addJar(jar, jarCache);
        final CryptoEventDetector screen = new CryptoEventDetector(matcher, types, null, null);
        final Set<String> found = analyzer.methodsCalling(screen::mayDetect);
        final List<Analyzer.MethodResult> methods = analyzer.analyze(analyzer.closure(found)).stream()
                .filter(m -> found.contains(m.method()) && screen.mayDetect(m))
                .toList();
        return new CandidateMethods(methods, analyzer.failedMethods);
    }

    /**
     * Scans a JAR, analyzing its bytecode.
     *
     * @param jar the JAR to scan
     * @param artifact the JAR's artifact, which the occurrences in it are located in
     * @param classpath JARs to resolve the scanned classes' supertypes from, for matching rules
     *     against subtypes; JDK classes are always resolved
     * @param jarCache the shared JAR cache
     * @param callIndex resolves values passed in from callers, possibly in other JARs; {@code
     *     null} to resolve values within methods only. Values resolved at a caller are located at
     *     the caller's call site, so the inventory may hold occurrences in other artifacts.
     * @return what scanning the JAR amounted to, and the assets found
     */
    public ArtifactScan scan(Path jar, ArtifactCoordinates artifact, List<Path> classpath, JarCache jarCache,
            CallResolver callIndex) {
        final Analyzer analyzer = new Analyzer();
        analyzer.addJar(jar, jarCache);
        final List<Analyzer.MethodResult> methods = analyzer.analyze();
        return detect(jar, artifact, types(jar, classpath, jarCache), jarCache, callIndex, methods, analyzer.failedMethods);
    }

    /**
     * Scans a JAR from its candidate methods, without analyzing it again.
     *
     * @param jar the JAR to scan
     * @param artifact the JAR's artifact
     * @param classpath JARs to resolve the scanned classes' supertypes from
     * @param jarCache the shared JAR cache
     * @param callIndex resolves values passed in from callers, or {@code null}
     * @param candidates the JAR's candidate methods, e.g. from {@link #prepare}
     * @return what scanning the JAR amounted to, and the assets found
     * @see #scan(Path, ArtifactCoordinates, List, JarCache, CallResolver)
     */
    public ArtifactScan scan(Path jar, ArtifactCoordinates artifact, List<Path> classpath, JarCache jarCache,
            CallResolver callIndex, CandidateMethods candidates) {
        return detect(jar, artifact, types(jar, classpath, jarCache), jarCache, callIndex, candidates.methods(),
                candidates.failedMethods());
    }

    /**
     * Scans a JAR, with supertypes from the class table.
     *
     * @param jar the JAR to scan
     * @param artifact the JAR's artifact
     * @param types the class hierarchy as the JAR sees it
     * @param jarCache the shared JAR cache
     * @param callIndex resolves values passed in from callers, or {@code null}
     * @param candidates the JAR's candidate methods from {@link #prepare}, or {@code null} to
     *     prepare them
     * @return what scanning the JAR amounted to, and the assets found
     */
    public ArtifactScan scan(Path jar, ArtifactCoordinates artifact, Types types, JarCache jarCache, CallResolver callIndex,
            CandidateMethods candidates) {
        final CandidateMethods c = candidates != null ? candidates : prepare(jar, types, jarCache);
        return detect(jar, artifact, types, jarCache, callIndex, c.methods(), c.failedMethods());
    }

    private ArtifactScan detect(Path jar, ArtifactCoordinates artifact, Types types, JarCache jarCache,
            CallResolver callIndex, List<Analyzer.MethodResult> methods, int failedMethods) {
        final CryptoEventDetector detector = new CryptoEventDetector(matcher, types, artifact, callIndex);
        final CryptoAssetModeler modeler = modelers.get();
        final CryptoInventory.Builder inventory = CryptoInventory.builder();
        final AssetCollector output = new AssetCollector(inventory);
        int findings = 0;
        // all methods at once, so that crypto objects are followed between them
        for (Finding f : detector.detect(methods)) {
            final Map<String, CodeLocation> locations = new HashMap<>();
            final List<INode> nodes = modeler.process(f.event(), locations);
            // a variant whose value the API wouldn't take, e.g. a MAC name for a signature
            if (!nodes.isEmpty() && (!f.variant() || CryptoAssetModeler.fitsApi(f.event(), nodes))) {
                output.add(nodes, locations);
                findings++;
            }
        }
        return new ArtifactScan(new ArtifactAnalysis(artifact, ArtifactAnalysis.Outcome.ANALYZED,
                jarCache.classNames(jar).size(), findings, failedMethods, null), inventory.build().assets());
    }

    /**
     * The class hierarchy for matching specs: the JAR, then its classpath, then the JDK, and
     * nothing of the tool's own classpath.
     */
    private static Types types(Path jar, List<Path> classpath, JarCache jarCache) {
        final List<Path> lookup = new ArrayList<>(classpath.size() + 1);
        lookup.add(jar);
        lookup.addAll(classpath);
        return Types.jdk(jarCache, lookup);
    }
}
