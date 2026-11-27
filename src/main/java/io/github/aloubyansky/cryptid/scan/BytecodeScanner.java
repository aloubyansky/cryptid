package io.github.aloubyansky.cryptid.scan;

import com.ibm.mapper.model.INode;
import io.github.aloubyansky.cryptid.ArtifactAnalysis;
import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.CodeLocation;
import io.github.aloubyansky.cryptid.CryptoInventory;
import io.github.aloubyansky.cryptid.bytecode.Analyzer;
import io.github.aloubyansky.cryptid.bytecode.CallGraph;
import io.github.aloubyansky.cryptid.bytecode.CallIndex;
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

/**
 * Detects cryptographic assets in a binary JAR by analyzing its bytecode with the crypto API
 * specs, models them with sonar-cryptography's translation, and returns them as the JAR's {@link
 * CryptoInventory}. No source code and no SonarSource analyzer is involved.
 *
 * <p>Scanning is two-phase when values passed between methods are to be resolved: first {@link
 * #index} every JAR into a shared {@link CallIndex}, then {@link #scan} each JAR with it.
 *
 * <p>Thread-safe: rules are immutable and shared, and each thread uses its own translation
 * pipeline, so several JARs can be indexed or scanned concurrently.
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
     * The methods of a JAR that may contain crypto events, kept by phase A for detection: those
     * calling a specified API, with their call sites from the final round of the
     * field fixpoint. Detecting on them gives the same findings as re-analyzing the JAR, without
     * interpreting it again.
     *
     * @param methods the methods that {@link CryptoEventDetector#mayDetect may contain events}, in
     *     analysis order
     * @param failedMethods the number of methods whose bytecode couldn't be interpreted
     */
    public record CandidateMethods(List<Analyzer.MethodResult> methods, int failedMethods) {}

    /**
     * Records a JAR's classes and its calls into analyzed classes in the call index, for
     * resolving values passed between methods during {@link #scan}, and optionally returns the
     * JAR's {@link CandidateMethods} for scanning it without analyzing it again.
     *
     * @param jar the JAR
     * @param artifact the JAR's artifact
     * @param classpath JARs to resolve supertypes from, as for {@link #scan}
     * @param jarCache the shared JAR cache
     * @param callIndex the index to fill
     * @param callGraph the call graph to fill, or {@code null} to index without building it
     * @param keepCandidates whether to return the JAR's candidate methods, for a JAR that will be
     *     scanned
     * @return the candidate methods, or {@code null} if not kept
     */
    public CandidateMethods index(Path jar, ArtifactCoordinates artifact, List<Path> classpath, JarCache jarCache,
            CallIndex callIndex, CallGraph callGraph, boolean keepCandidates) {
        final String locationPrefix = ArtifactPaths.of(artifact);
        final Analyzer analyzer = new Analyzer();
        analyzer.addJar(jar, jarCache);
        callIndex.addClasses(locationPrefix, analyzer.classInfos());
        if (callGraph != null) {
            callGraph.addMethods(locationPrefix, analyzer.graphFacts());
        }
        final List<Analyzer.MethodResult> methods = analyzer.analyze();
        callIndex.addCalls(methods, artifact, locationPrefix);
        if (!keepCandidates) {
            return null;
        }
        final CryptoEventDetector screen = new CryptoEventDetector(matcher, types(jar, classpath, jarCache), artifact, null);
        return new CandidateMethods(methods.stream().filter(screen::mayDetect).toList(), analyzer.failedMethods);
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
     * @return the JAR's inventory: its analysis and the assets found
     */
    public CryptoInventory scan(Path jar, ArtifactCoordinates artifact, List<Path> classpath, JarCache jarCache,
            CallIndex callIndex) {
        final Analyzer analyzer = new Analyzer();
        analyzer.addJar(jar, jarCache);
        final List<Analyzer.MethodResult> methods = analyzer.analyze();
        return detect(jar, artifact, classpath, jarCache, callIndex, methods, analyzer.failedMethods);
    }

    /**
     * Scans a JAR from the candidate methods {@link #index} kept for it, without analyzing it again.
     *
     * @param jar the JAR to scan
     * @param artifact the JAR's artifact
     * @param classpath JARs to resolve the scanned classes' supertypes from
     * @param jarCache the shared JAR cache
     * @param callIndex resolves values passed in from callers, or {@code null}
     * @param candidates the JAR's candidate methods from {@link #index}
     * @return the JAR's inventory: its analysis and the assets found
     * @see #scan(Path, ArtifactCoordinates, List, JarCache, CallIndex)
     */
    public CryptoInventory scan(Path jar, ArtifactCoordinates artifact, List<Path> classpath, JarCache jarCache,
            CallIndex callIndex, CandidateMethods candidates) {
        return detect(jar, artifact, classpath, jarCache, callIndex, candidates.methods(), candidates.failedMethods());
    }

    private CryptoInventory detect(Path jar, ArtifactCoordinates artifact, List<Path> classpath, JarCache jarCache,
            CallIndex callIndex, List<Analyzer.MethodResult> methods, int failedMethods) {
        final CryptoEventDetector detector = new CryptoEventDetector(matcher, types(jar, classpath, jarCache), artifact, callIndex);
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
        inventory.artifact(new ArtifactAnalysis(artifact, jarCache.classNames(jar).size(), findings, failedMethods));
        return inventory.build();
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
