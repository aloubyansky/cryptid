package org.acme.cbom.bytecode;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import com.ibm.output.cyclondx.CBOMOutputFile;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.cyclonedx.model.Bom;

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

    private final List<IDetectionRule<Loc>> rules;
    private final ThreadLocal<Translation> translations = ThreadLocal.withInitial(() -> {
        try {
            return new Translation();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to load sonar-cryptography's Java translators", e);
        }
    });

    /**
     * Loads sonar-cryptography's Java detection rules.
     *
     * @throws IllegalStateException if the rules can't be loaded
     */
    public BytecodeScanner() {
        try {
            this.rules = Translation.javaRules();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to load sonar-cryptography's Java detection rules", e);
        }
    }

    /**
     * Returns the number of root detection rules.
     *
     * @return the number of rules
     */
    public int ruleCount() {
        return rules.size();
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
        for (org.cyclonedx.model.Component c : bom.getComponents()) {
            if (c.getEvidence() == null || c.getEvidence().getOccurrences() == null) {
                continue;
            }
            for (org.cyclonedx.model.component.evidence.Occurrence o : c.getEvidence().getOccurrences()) {
                o.setOffset(null);
                if (o.getLine() != null && o.getLine() <= 0) {
                    o.setLine(null);
                }
            }
        }
    }

    /**
     * Records a JAR's classes and its calls into analyzed classes in the call index, for
     * resolving values passed between methods during {@link #scan}.
     *
     * @param jar the JAR
     * @param locationPrefix the artifact path, prepended to source files of call sites
     * @param jarCache the shared JAR cache
     * @param callIndex the index to fill
     */
    public void index(Path jar, String locationPrefix, JarCache jarCache, CallIndex callIndex) {
        final Analyzer analyzer = new Analyzer();
        analyzer.addJar(jar, jarCache);
        callIndex.addClasses(analyzer.classInfos());
        callIndex.addCalls(analyzer.analyze(), locationPrefix);
    }

    /**
     * Scans a JAR.
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
        final List<Path> lookup = new ArrayList<>(classpath.size() + 1);
        lookup.add(jar);
        lookup.addAll(classpath);
        final Types types = new Types(ClassLoader.getSystemClassLoader(), jarCache, lookup);
        final Detector detector = new Detector(rules, types, locationPrefix, callIndex);
        final Translation translation = translations.get();

        final CBOMOutputFile output = new CBOMOutputFile();
        int findings = 0;
        for (Analyzer.MethodResult m : analyzer.analyze()) {
            for (Detector.Finding f : detector.detect(m)) {
                final List<INode> nodes = translation.process(f.store());
                if (!nodes.isEmpty()) {
                    output.add(nodes);
                    findings++;
                }
            }
        }
        final Bom bom = output.getBom();
        clearUnknownPositions(bom);
        return new Result(bom, jarCache.classNames(jar).size(), findings, analyzer.failedMethods);
    }
}
