package io.github.aloubyansky.cryptid.detection;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.model.factory.IValueFactory;
import io.github.aloubyansky.cryptid.bytecode.AVal;
import io.github.aloubyansky.cryptid.bytecode.Analyzer;
import io.github.aloubyansky.cryptid.bytecode.CallSite;
import io.github.aloubyansky.cryptid.bytecode.JarCache;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.detection.CryptoObjectGraph.CryptoApiCall;
import io.github.aloubyansky.cryptid.reference.RuleDetector;
import io.github.aloubyansky.cryptid.reference.RuleSpecExporter;
import io.github.aloubyansky.cryptid.reference.SonarCryptographyRules;
import io.github.aloubyansky.cryptid.scan.FixtureConformanceTest;
import io.github.aloubyansky.cryptid.scan.FixtureSupport;
import io.github.aloubyansky.cryptid.spec.CryptoApiMatcher;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.ApiSpec;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Arg;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Context;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Role;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
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
 * Checks that the object graph built from the specs carries what the current detection trees
 * carry. For every finding, both are read into the same lines: each value and action with the
 * path of argument indices, contexts and libraries from the finding's root, and its call site. If
 * the graph has every line of the trees, translation gets at least the same input. Lines only the
 * graph has are printed for review: objects the rule trees don't link.
 *
 * <p>Corpus: sonar-cryptography's Java fixtures (compiled as {@link FixtureConformanceTest}
 * does) and Bouncy Castle's provider JAR. Values resolved from callers aren't compared: they're
 * findings of their own, built the same way in both designs.
 */
class ObjectGraphEquivalenceTest {

    private static final Path FIXTURES = Path.of("src/test/resources/sonar-cryptography-fixtures");
    private static final int MAX_DEPTH = 8;

    @TempDir
    Path work;

    @Test
    void graphCarriesWhatTheDetectionTreesCarry() throws Exception {
        final CryptoApiMatcher matcher = new CryptoApiMatcher(CryptoApiSpecs.load());
        final List<com.ibm.engine.rule.IDetectionRule<Loc>> rules = SonarCryptographyRules.javaRules();
        final Map<String, Set<String>> before = new TreeMap<>();
        final Map<String, Set<String>> after = new TreeMap<>();

        // the fixtures
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
                compare(analyzer.analyze(), rules, matcher, types, before, after);
            }
        }
        // Bouncy Castle's own use of its APIs
        final Path bcprov = Path.of(AESEngine.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        try (JarCache jars = new JarCache()) {
            final Analyzer analyzer = new Analyzer();
            analyzer.addJar(bcprov, jars);
            compare(analyzer.analyze(), rules, matcher, new Types(getClass().getClassLoader()), before, after);
        }

        final List<String> missing = new ArrayList<>();
        final List<String> extra = new ArrayList<>();
        final Set<String> keys = new TreeSet<>(before.keySet());
        keys.addAll(after.keySet());
        int lines = 0;
        for (String key : keys) {
            final Set<String> b = before.getOrDefault(key, Set.of());
            final Set<String> a = after.getOrDefault(key, Set.of());
            lines += b.size();
            final Set<String> lost = new TreeSet<>(b);
            lost.removeAll(a);
            final Set<String> gained = new TreeSet<>(a);
            gained.removeAll(b);
            if (!lost.isEmpty()) {
                missing.add(key + "\n      " + String.join("\n      ", lost));
            }
            if (!gained.isEmpty()) {
                extra.add(key + "\n      " + String.join("\n      ", gained));
            }
        }
        System.out.printf("findings compared: %d, lines: %d, findings losing lines: %d, findings gaining lines: %d%n",
                keys.size(), lines, missing.size(), extra.size());
        // gained lines are objects the rule trees don't link, e.g. GMac over a GCM cipher from
        // GCMBlockCipher.newInstance: listed for review, since they change the CBOM
        extra.forEach(e -> System.out.println("  gained: " + e));
        assertTrue(missing.isEmpty(), missing.size() + " findings lose lines, e.g.:\n  "
                + String.join("\n  ", missing.subList(0, Math.min(10, missing.size()))));
    }

    /**
     * Compares over a list of JARs, one per line, each with all of them as the classpath; for a
     * one-off run on a large corpus, e.g. an SBOM's JARs. Not part of the build.
     */
    static String compareJars(List<Path> jars) throws Exception {
        final CryptoApiMatcher matcher = new CryptoApiMatcher(CryptoApiSpecs.load());
        final List<com.ibm.engine.rule.IDetectionRule<Loc>> rules = SonarCryptographyRules.javaRules();
        final Map<String, Set<String>> before = new TreeMap<>();
        final Map<String, Set<String>> after = new TreeMap<>();
        try (JarCache cache = new JarCache()) {
            for (Path jar : jars) {
                final Analyzer analyzer = new Analyzer();
                analyzer.addJar(jar, cache);
                final List<Path> lookup = new ArrayList<>(List.of(jar));
                lookup.addAll(jars);
                compare(analyzer.analyze(), rules, matcher, new Types(ClassLoader.getSystemClassLoader(), cache, lookup), before, after);
            }
        }
        final StringBuilder sb = new StringBuilder();
        int lost = 0, gained = 0, lines = 0;
        final Set<String> keys = new TreeSet<>(before.keySet());
        keys.addAll(after.keySet());
        for (String key : keys) {
            final Set<String> b = before.getOrDefault(key, Set.of());
            final Set<String> a = after.getOrDefault(key, Set.of());
            lines += b.size();
            final Set<String> l = new TreeSet<>(b);
            l.removeAll(a);
            final Set<String> g = new TreeSet<>(a);
            g.removeAll(b);
            if (!l.isEmpty()) {
                lost++;
                sb.append("LOST ").append(key).append("\n      ").append(String.join("\n      ", l)).append('\n');
            }
            if (!g.isEmpty()) {
                gained++;
                sb.append("GAINED ").append(key).append("\n      ").append(String.join("\n      ", g)).append('\n');
            }
        }
        return String.format("findings %d, lines %d, losing lines %d, gaining lines %d%n", keys.size(), lines, lost, gained) + sb;
    }

    private static void compare(List<Analyzer.MethodResult> methods, List<com.ibm.engine.rule.IDetectionRule<Loc>> rules,
            CryptoApiMatcher matcher, Types types, Map<String, Set<String>> before, Map<String, Set<String>> after) {
        final RuleDetector detector = new RuleDetector(rules, types, "", null);
        for (Analyzer.MethodResult m : methods) {
            for (RuleDetector.RuleFinding f : detector.detect(m)) {
                final Context ctx = RuleSpecExporter.context(f.store().getDetectionValueContext());
                final String key = key(f.call(), ctx, f.store().getDetectionRule().bundle().getIdentifier());
                lines(f.store(), "", before.computeIfAbsent(key, k -> new TreeSet<>()),
                        Collections.newSetFromMap(new IdentityHashMap<>()));
            }
            final CryptoObjectGraph graph = CryptoObjectGraph.of(m, matcher, types);
            for (CryptoApiCall root : graph.roots()) {
                final String key = key(root.site(), root.spec().context(), root.spec().library());
                lines(graph, root, root.spec().context(), "", 0, after.computeIfAbsent(key, k -> new TreeSet<>()));
            }
        }
    }

    private static String key(CallSite cs, Context ctx, String library) {
        return cs.signature() + "@" + cs.line() + " " + ctx + "/" + library;
    }

    // the current detection tree

    private static void lines(DetectionStore<Object, Loc, Object, Object> store, String path, Set<String> out,
            Set<DetectionStore<Object, Loc, Object, Object>> seen) {
        if (!seen.add(store)) {
            return;
        }
        store.getActionValue().ifPresent(a -> out.add(path + " | action " + describe(a)));
        store.detectionValuesForEachParameter((index, values) -> values.forEach(v -> out.add(path + " | v" + index + " " + describe(v))));
        store.childrenForEachParameter((index, children) -> children.forEach(c -> lines(c, child(path, index, c), out, seen)));
        store.getChildrenForMethod().forEach(c -> lines(c, child(path, -1, c), out, seen));
    }

    private static String child(String path, int index, DetectionStore<Object, Loc, Object, Object> c) {
        return path + "/" + index + ":" + RuleSpecExporter.context(c.getDetectionValueContext()) + "/" + c.getDetectionRule().bundle().getIdentifier();
    }

    // the object graph, read the way the detection tree is built

    @SuppressWarnings("unchecked")
    private static void lines(CryptoObjectGraph graph, CryptoApiCall call, Context ctx, String path, int depth, Set<String> out) {
        final ApiSpec spec = call.spec();
        final CallSite cs = call.site();
        final Loc loc = Loc.of(cs);
        if (spec.action() != null) {
            final Object factory = ValueFactories.create(spec.action());
            if (factory == null) {
                out.add(path + " | action " + spec.action().result() + " @ " + where(loc));
            } else {
                ((IActionFactory<Loc>) factory).apply(loc).ifPresent(a -> out.add(path + " | action " + describe(a)));
            }
        }
        for (Arg arg : spec.args()) {
            if (arg.index() >= cs.args().length) {
                continue;
            }
            final AVal value = cs.args()[arg.index()];
            if (arg.value() != null) {
                final IValueFactory<Loc> factory = (IValueFactory<Loc>) ValueFactories.create(arg.value());
                for (Object c : value.consts()) {
                    factory.apply(new ResolvedValue<>(c, loc)).ifPresent(v -> {
                        if (arg.movedUnder() != null) {
                            out.add(path + "/" + arg.movedUnder() + ":" + ctx + "/" + spec.library() + " | v" + arg.movedUnder() + " " + describe(v));
                        } else {
                            out.add(path + " | v" + arg.index() + " " + describe(v));
                        }
                    });
                }
            }
            if (arg.link() && depth < MAX_DEPTH) {
                for (CryptoApiCall linked : calls(graph.related(cs, value, CryptoObjectGraph.Path.ROOT))) {
                    final Context c = role(arg.roles(), ctx, linked.spec());
                    lines(graph, linked, c, path + "/" + arg.index() + ":" + c + "/" + linked.spec().library(), depth + 1, out);
                }
            }
        }
        if (!spec.next().isEmpty() && cs.created() >= 0 && depth < MAX_DEPTH) {
            for (CryptoApiCall next : calls(graph.createdBy(cs, CryptoObjectGraph.Path.ROOT))) {
                if (spec.next().contains(next.spec().api())) {
                    final Context c = role(spec.nextRoles(), ctx, next.spec());
                    lines(graph, next, c, path + "/-1:" + c + "/" + next.spec().library(), depth + 1, out);
                }
            }
        }
    }

    private static List<CryptoApiCall> calls(List<CryptoObjectGraph.Reached> reached) {
        return reached.stream().map(CryptoObjectGraph.Reached::call).toList();
    }

    /** The linked object's context: a role of the link if one applies, else its API's context. */
    private static Context role(List<Role> roles, Context parent, ApiSpec linked) {
        for (Role r : roles) {
            if ((r.when() == null || r.when().equals(parent)) && (r.api() == null || r.api().equals(linked.api()))) {
                return r.context();
            }
        }
        return linked.context();
    }

    private static String describe(IValue<Loc> v) {
        return v.getClass().getSimpleName() + " " + v.asString() + " @ " + where(v.getLocation());
    }

    private static String describe(IAction<Loc> a) {
        return a.getClass().getSimpleName() + " " + a.asString() + " @ " + where(a.getLocation());
    }

    private static String where(Loc loc) {
        return loc.signature() + "@" + loc.line();
    }
}
