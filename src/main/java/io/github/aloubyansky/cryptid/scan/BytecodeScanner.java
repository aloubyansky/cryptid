package io.github.aloubyansky.cryptid.scan;

import com.ibm.mapper.model.INode;
import com.ibm.output.cyclondx.CBOMOutputFile;
import io.github.aloubyansky.cryptid.bytecode.Analyzer;
import io.github.aloubyansky.cryptid.bytecode.CallIndex;
import io.github.aloubyansky.cryptid.bytecode.JarCache;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.detection.CryptoEventDetector;
import io.github.aloubyansky.cryptid.detection.Finding;
import io.github.aloubyansky.cryptid.model.CryptoAssetModeler;
import io.github.aloubyansky.cryptid.spec.CryptoApiMatcher;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.evidence.Occurrence;

/**
 * Detects cryptographic assets in a binary JAR by analyzing its bytecode with sonar-cryptography's
 * Java detection rules, and builds its CBOM with sonar-cryptography's translation and CycloneDX
 * output. No source code and no SonarSource analyzer is involved.
 *
 * <p>Scanning is two-phase when values passed between methods are to be resolved: first {@link
 * #index} every JAR into a shared {@link CallIndex}, then {@link #scan} each JAR with it.
 *
 * <p>Thread-safe: rules are immutable and shared, and each thread uses its own translation
 * pipeline, so several JARs can be indexed or scanned concurrently.
 */
public final class BytecodeScanner {

    /**
     * The result of scanning a JAR.
     *
     * @param bom the CBOM of the JAR
     * @param classes the number of classes analyzed
     * @param findings the number of rule matches that produced crypto assets
     * @param failedMethods the number of methods whose bytecode couldn't be interpreted
     */
    public record Result(Bom bom, int classes, int findings, int failedMethods) {}

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
     * Removes positions bytecode doesn't provide: the column offset always, and the line when the
     * class has no line number table (0), e.g. Bouncy Castle's release JARs. Both are optional in
     * CycloneDX, and a 0 would read as a real position.
     *
     * @param bom the CBOM to update in place
     */
    static void clearUnknownPositions(Bom bom) {
        if (bom.getComponents() == null) {
            return;
        }
        for (Component c : bom.getComponents()) {
            if (c.getEvidence() == null || c.getEvidence().getOccurrences() == null) {
                continue;
            }
            for (Occurrence o : c.getEvidence().getOccurrences()) {
                o.setOffset(null);
                if (o.getLine() != null && o.getLine() <= 0) {
                    o.setLine(null);
                }
            }
        }
    }

    /**
     * The methods of a JAR that may contain crypto events, kept by phase A for detection: those
     * calling an API that reports on its own, with their call sites from the final round of the
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
     * @param locationPrefix the artifact path, prepended to source files of call sites
     * @param classpath JARs to resolve supertypes from, as for {@link #scan}
     * @param jarCache the shared JAR cache
     * @param callIndex the index to fill
     * @param keepCandidates whether to return the JAR's candidate methods, for a JAR that will be
     *     scanned
     * @return the candidate methods, or {@code null} if not kept
     */
    public CandidateMethods index(Path jar, String locationPrefix, List<Path> classpath, JarCache jarCache, CallIndex callIndex,
            boolean keepCandidates) {
        final Analyzer analyzer = new Analyzer();
        analyzer.addJar(jar, jarCache);
        callIndex.addClasses(analyzer.classInfos());
        final List<Analyzer.MethodResult> methods = analyzer.analyze();
        callIndex.addCalls(methods, locationPrefix);
        if (!keepCandidates) {
            return null;
        }
        final CryptoEventDetector screen = new CryptoEventDetector(matcher, types(jar, classpath, jarCache), locationPrefix, null);
        return new CandidateMethods(methods.stream().filter(screen::mayDetect).toList(), analyzer.failedMethods);
    }

    /**
     * Scans a JAR, analyzing its bytecode.
     *
     * @param jar the JAR to scan
     * @param locationPrefix prepended to source file paths in occurrence locations, e.g. the
     *     artifact path {@code g/a/v}
     * @param classpath JARs to resolve the scanned classes' supertypes from, for matching rules
     *     against subtypes; JDK classes are always resolved
     * @param jarCache the shared JAR cache
     * @param callIndex resolves values passed in from callers, possibly in other JARs; {@code
     *     null} to resolve values within methods only. Values resolved at a caller are located at
     *     the caller's call site, so the CBOM may hold occurrences in other artifacts.
     * @return the CBOM of the JAR with statistics
     */
    public Result scan(Path jar, String locationPrefix, List<Path> classpath, JarCache jarCache, CallIndex callIndex) {
        final Analyzer analyzer = new Analyzer();
        analyzer.addJar(jar, jarCache);
        final List<Analyzer.MethodResult> methods = analyzer.analyze();
        return detect(jar, locationPrefix, classpath, jarCache, callIndex, methods, analyzer.failedMethods);
    }

    /**
     * Scans a JAR from the candidate methods {@link #index} kept for it, without analyzing it again.
     *
     * @param candidates the JAR's candidate methods from {@link #index}
     * @see #scan(Path, String, List, JarCache, CallIndex)
     */
    public Result scan(Path jar, String locationPrefix, List<Path> classpath, JarCache jarCache, CallIndex callIndex,
            CandidateMethods candidates) {
        return detect(jar, locationPrefix, classpath, jarCache, callIndex, candidates.methods(), candidates.failedMethods());
    }

    private Result detect(Path jar, String locationPrefix, List<Path> classpath, JarCache jarCache, CallIndex callIndex,
            List<Analyzer.MethodResult> methods, int failedMethods) {
        final CryptoEventDetector detector = new CryptoEventDetector(matcher, types(jar, classpath, jarCache), locationPrefix, callIndex);
        final CryptoAssetModeler modeler = modelers.get();
        final CBOMOutputFile output = new CBOMOutputFile();
        int findings = 0;
        for (Analyzer.MethodResult m : methods) {
            for (Finding f : detector.detect(m)) {
                final List<INode> nodes = modeler.process(f.event());
                if (!nodes.isEmpty()) {
                    output.add(nodes);
                    findings++;
                }
            }
        }
        final Bom bom = output.getBom();
        clearUnknownPositions(bom);
        return new Result(bom, jarCache.classNames(jar).size(), findings, failedMethods);
    }

    /** The class hierarchy for matching rules: the JAR, then its classpath, then the JDK. */
    private static Types types(Path jar, List<Path> classpath, JarCache jarCache) {
        final List<Path> lookup = new ArrayList<>(classpath.size() + 1);
        lookup.add(jar);
        lookup.addAll(classpath);
        return new Types(ClassLoader.getSystemClassLoader(), jarCache, lookup);
    }
}
