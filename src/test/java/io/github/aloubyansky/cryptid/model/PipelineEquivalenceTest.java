package io.github.aloubyansky.cryptid.model;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import io.github.aloubyansky.cryptid.bytecode.Analyzer;
import io.github.aloubyansky.cryptid.bytecode.JarCache;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.detection.CryptoEventDetector;
import io.github.aloubyansky.cryptid.detection.Finding;
import io.github.aloubyansky.cryptid.detection.Loc;
import io.github.aloubyansky.cryptid.reference.RuleDetector;
import io.github.aloubyansky.cryptid.reference.SonarCryptographyRules;
import io.github.aloubyansky.cryptid.reference.SpecCorrections;
import io.github.aloubyansky.cryptid.scan.FixtureSupport;
import io.github.aloubyansky.cryptid.spec.CryptoApiMatcher;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.bouncycastle.crypto.engines.AESEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Checks that the spec-based pipeline produces every crypto asset the rule-based one did: for each
 * call site, each node of {@link RuleDetector}'s findings, translated by sonar-cryptography's {@code
 * ITranslator} ({@link RuleAssetModeler}), is among the nodes of {@link CryptoEventDetector}'s findings,
 * built by {@link AssetAssembler}, or refined there, with more below it. Refined and new
 * nodes come from objects the rule trees don't link, and are printed for review.
 *
 * <p>Corpus: sonar-cryptography's Java fixtures and Bouncy Castle's provider JAR.
 */
class PipelineEquivalenceTest {

    private static final Path FIXTURES = Path.of("src/test/resources/sonar-cryptography-fixtures");

    @TempDir
    Path work;

    @Test
    void specsTranslateToEverythingTheRulesDid() throws Exception {
        final List<IDetectionRule<Loc>> rules = SonarCryptographyRules.javaRules();
        final CryptoApiMatcher matcher = new CryptoApiMatcher(CryptoApiSpecs.load());
        final CryptoAssetModeler modeler = new CryptoAssetModeler();
        final Map<String, List<INode>> before = new TreeMap<>();
        final Map<String, List<INode>> after = new TreeMap<>();
        final Set<String> corrected = new TreeSet<>();

        int unit = 0;
        final String classpath = System.getProperty("java.class.path");
        try (Stream<Path> s = Files.walk(FIXTURES)) {
            for (Path src : s.filter(f -> f.toString().endsWith(".java")).sorted().toList()) {
                final Path classes = work.resolve("classes-" + unit);
                if (FixtureSupport.compile(List.of(src), work.resolve("src-" + unit++), classes, classpath) != null) {
                    continue;
                }
                final Analyzer analyzer = new Analyzer();
                analyzer.addClasses(classes);
                final Types types = new Types(getClass().getClassLoader());
                types.addClasses(classes);
                final List<Analyzer.MethodResult> methods = analyzer.analyze();
                SpecCorrections.collect(methods, matcher, types, corrected);
                compare(methods, rules, matcher, types, modeler, before, after);
            }
        }
        final Path bcprov = Path.of(AESEngine.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        try (JarCache jars = new JarCache()) {
            final Analyzer analyzer = new Analyzer();
            analyzer.addJar(bcprov, jars);
            final Types types = new Types(getClass().getClassLoader());
            final List<Analyzer.MethodResult> methods = analyzer.analyze();
            SpecCorrections.collect(methods, matcher, types, corrected);
            compare(methods, rules, matcher, types, modeler, before, after);
        }

        final List<String> lost = new ArrayList<>();
        int corrections = 0;
        int nodes = 0;
        int refined = 0;
        int gained = 0;
        final Set<String> keys = new TreeSet<>(before.keySet());
        keys.addAll(after.keySet());
        for (String key : keys) {
            final List<INode> remaining = new ArrayList<>(after.getOrDefault(key, List.of()));
            for (INode node : before.getOrDefault(key, List.of())) {
                nodes++;
                INode match = null;
                for (INode candidate : remaining) {
                    if (render(candidate).equals(render(node))) {
                        match = candidate;
                        break;
                    }
                }
                // or the same node with more below it
                for (int i = 0; match == null && i < remaining.size(); i++) {
                    if (subsumes(remaining.get(i), node)) {
                        match = remaining.get(i);
                        refined++;
                        System.out.println("  refined " + key + ": " + render(node) + "\n      -> " + render(match));
                    }
                }
                if (match == null && SpecCorrections.reflects(node, corrected)) {
                    // translated from a value of a corrected API: meant to differ from the rules'
                    corrections++;
                    System.out.println("  corrected " + key + ": " + render(node));
                } else if (match == null) {
                    lost.add(key + ": " + render(node));
                } else {
                    remaining.remove(match);
                }
            }
            for (INode node : remaining) {
                gained++;
                System.out.println("  gained " + key + ": " + render(node));
            }
        }
        System.out.printf("call sites: %d, translated nodes: %d, lost: %d, refined: %d, gained: %d, corrected: %d%n",
                keys.size(), nodes, lost.size(), refined, gained, corrections);
        assertTrue(lost.isEmpty(), lost.size() + " nodes lost, e.g.:\n  " + String.join("\n  ", lost.subList(0, Math.min(10, lost.size()))));
    }

    private static void compare(List<Analyzer.MethodResult> methods, List<IDetectionRule<Loc>> rules, CryptoApiMatcher matcher,
            Types types, CryptoAssetModeler modeler, Map<String, List<INode>> before, Map<String, List<INode>> after) {
        final RuleDetector rulesDetector = new RuleDetector(rules, types, "", null);
        final CryptoEventDetector specDetector = new CryptoEventDetector(matcher, types, "", null);
        final RuleAssetModeler ruleModeler = new RuleAssetModeler(modeler);
        for (Analyzer.MethodResult m : methods) {
            for (RuleDetector.RuleFinding f : rulesDetector.detect(m)) {
                before.computeIfAbsent(f.call().signature() + "@" + f.call().line(), k -> new ArrayList<>())
                        .addAll(ruleModeler.process(f.store()));
            }
            for (Finding f : specDetector.detect(m)) {
                after.computeIfAbsent(f.call().signature() + "@" + f.call().line(), k -> new ArrayList<>())
                        .addAll(modeler.process(f.event()));
            }
        }
    }

    /** Whether a node has the same kind and value as another, and children covering all of its. */
    static boolean subsumes(INode bigger, INode smaller) {
        if (bigger.getKind() != smaller.getKind() || !bigger.asString().equals(smaller.asString())) {
            return false;
        }
        for (INode child : smaller.getChildren().values()) {
            final INode other = bigger.getChildren().get(child.getKind());
            if (other == null || !subsumes(other, child)) {
                return false;
            }
        }
        return true;
    }

    /** A node and its children, children sorted by kind so the rendering doesn't depend on map order. */
    static String render(INode n) {
        final StringBuilder sb = new StringBuilder(n.getKind().getSimpleName()).append('=').append(n.asString());
        if (n.hasChildren()) {
            sb.append('{');
            n.getChildren().values().stream()
                    .sorted(Comparator.comparing((INode c) -> c.getKind().getSimpleName()).thenComparing(INode::asString))
                    .forEach(c -> sb.append(render(c)).append(' '));
            sb.append('}');
        }
        return sb.toString();
    }
}
