package org.acme.cbom.bytecode;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
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
import org.acme.cbom.spec.ApiSpecs;
import org.bouncycastle.crypto.engines.AESEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Checks that detection from the specs translates into every crypto asset the rule-based
 * detection did: for each call site, each node translated from {@link Detector}'s findings is
 * among those of {@link SpecDetector}'s, or refined there, with more below it. Refined and new
 * nodes come from objects the rule trees don't link, and are printed for review.
 *
 * <p>Corpus: sonar-cryptography's Java fixtures and Bouncy Castle's provider JAR.
 */
class DetectorEquivalenceTest {

    private static final Path FIXTURES = Path.of("src/test/resources/sonar-cryptography-fixtures");

    @TempDir
    Path work;

    @Test
    void specsTranslateToEverythingTheRulesDid() throws Exception {
        final List<IDetectionRule<Loc>> rules = Rules.javaRules();
        final ApiIndex apis = new ApiIndex(ApiSpecs.load());
        final Translation translation = new Translation();
        final Map<String, List<INode>> before = new TreeMap<>();
        final Map<String, List<INode>> after = new TreeMap<>();

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
                compare(analyzer.analyze(), rules, apis, types, translation, before, after);
            }
        }
        final Path bcprov = Path.of(AESEngine.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        try (JarCache jars = new JarCache()) {
            final Analyzer analyzer = new Analyzer();
            analyzer.addJar(bcprov, jars);
            compare(analyzer.analyze(), rules, apis, new Types(getClass().getClassLoader()), translation, before, after);
        }

        final List<String> lost = new ArrayList<>();
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
                if (match == null) {
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
        System.out.printf("call sites: %d, translated nodes: %d, lost: %d, refined: %d, gained: %d%n",
                keys.size(), nodes, lost.size(), refined, gained);
        assertTrue(lost.isEmpty(), lost.size() + " nodes lost, e.g.:\n  " + String.join("\n  ", lost.subList(0, Math.min(10, lost.size()))));
    }

    private static void compare(List<Analyzer.MethodResult> methods, List<IDetectionRule<Loc>> rules, ApiIndex apis,
            Types types, Translation translation, Map<String, List<INode>> before, Map<String, List<INode>> after) {
        final Detector rulesDetector = new Detector(rules, types, "", null);
        final SpecDetector specDetector = new SpecDetector(apis, types, "", null);
        for (Analyzer.MethodResult m : methods) {
            for (Finding f : rulesDetector.detect(m)) {
                translate(f, translation, before);
            }
            for (Finding f : specDetector.detect(m)) {
                translate(f, translation, after);
            }
        }
    }

    private static void translate(Finding f, Translation translation, Map<String, List<INode>> out) {
        out.computeIfAbsent(f.call().signature() + "@" + f.call().line, k -> new ArrayList<>())
                .addAll(translation.process(f.store()));
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
