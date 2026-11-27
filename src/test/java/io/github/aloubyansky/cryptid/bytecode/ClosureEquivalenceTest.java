package io.github.aloubyansky.cryptid.bytecode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.aloubyansky.cryptid.spec.CryptoApiMatcher;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.engines.AESEngine;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Interpreting the closure of a JAR's candidate methods gives them the call sites interpreting
 * the whole JAR gives: the first step of detection-driven analysis (docs/foundation.md).
 */
class ClosureEquivalenceTest {

    /** Totals over the JARs compared. */
    private static final class Totals {
        long methods;
        long candidates;
        long closure;
        int notConverged;
        final List<String> mismatches = new ArrayList<>();
    }

    @Test
    void bouncyCastle() throws Exception {
        final Totals t = compare(List.of(jarOf(AESEngine.class), jarOf(X509CertificateHolder.class)));
        assertEquals(List.of(), t.mismatches);
        assertEquals(0, t.notConverged);
    }

    /** All JARs listed in the file named by {@code -Dclosure.jars}, e.g. Keycloak's. */
    @Test
    @Tag("e2e")
    void listedJars() throws Exception {
        final String list = System.getProperty("closure.jars");
        assumeTrue(list != null, "-Dclosure.jars not set");
        final Totals t = compare(Files.readAllLines(Path.of(list)).stream().map(Path::of).toList());
        System.out.printf("closure equivalence: %d methods, %d candidates, closure %d, %d JARs not converged, %d mismatches%n",
                t.methods, t.candidates, t.closure, t.notConverged, t.mismatches.size());
        assertEquals(List.of(), t.mismatches.subList(0, Math.min(20, t.mismatches.size())));
    }

    private static Path jarOf(Class<?> c) throws Exception {
        return Path.of(c.getProtectionDomain().getCodeSource().getLocation().toURI());
    }

    private static Totals compare(List<Path> jars) throws Exception {
        final CryptoApiMatcher matcher = new CryptoApiMatcher(CryptoApiSpecs.load());
        final Totals t = new Totals();
        try (JarCache cache = new JarCache()) {
            for (Path jar : jars) {
                final Analyzer whole = new Analyzer();
                try {
                    whole.addJar(jar, cache);
                } catch (RuntimeException e) {
                    continue;
                }
                final List<Analyzer.MethodResult> all = whole.analyze();
                if (!whole.converged()) {
                    // the closure may converge further than the capped whole: not comparable
                    t.notConverged++;
                    continue;
                }
                final Types types = Types.jdk(cache, List.of(jar));
                final Map<String, Analyzer.MethodResult> candidates = new HashMap<>();
                for (Analyzer.MethodResult m : all) {
                    if (m.calls().stream().anyMatch(cs -> !matcher.match(cs, types).isEmpty())) {
                        candidates.put(m.method(), m);
                    }
                }
                final Analyzer part = new Analyzer();
                part.addJar(jar, cache);
                final Set<String> closure = part.closure(candidates.keySet());
                final Map<String, Analyzer.MethodResult> byMethod = new HashMap<>();
                part.analyze(closure).forEach(m -> byMethod.put(m.method(), m));
                t.methods += all.size();
                t.candidates += candidates.size();
                t.closure += closure.size();
                final Map<Integer, String> wholeKeys = whole.siteKeys();
                final Map<Integer, String> partKeys = part.siteKeys();
                candidates.forEach((method, expected) -> {
                    final Analyzer.MethodResult actual = byMethod.get(method);
                    final String e = describe(expected, wholeKeys);
                    final String a = actual == null ? "missing" : describe(actual, partKeys);
                    if (!e.equals(a)) {
                        t.mismatches.add(jar.getFileName() + " " + method + "\n  expected " + e + "\n  actual   " + a);
                    }
                });
            }
        }
        return t;
    }

    /** A method's call sites and returned value, with site ids replaced by where they are. */
    private static String describe(Analyzer.MethodResult m, Map<Integer, String> keys) {
        final StringBuilder sb = new StringBuilder(describe(m.returned(), keys));
        for (CallSite cs : m.calls()) {
            sb.append(" | ").append(cs.signature()).append('@').append(cs.line())
                    .append(" created ").append(cs.created() < 0 ? "-" : keys.get(cs.created()))
                    .append(" recv ").append(describe(cs.receiver(), keys));
            for (AVal a : cs.args()) {
                sb.append(" arg ").append(describe(a, keys));
            }
        }
        return sb.toString();
    }

    private static String describe(AVal v, Map<Integer, String> keys) {
        final Set<String> origins = new TreeSet<>();
        v.origins().forEach(o -> origins.add(keys.get(o)));
        return v.consts() + (v.anyConst() ? "*" : "") + " p" + v.params() + " s" + new TreeSet<>(v.stored().stream()
                .map(sp -> sp.method() + "/" + sp.index()).toList()) + " o" + origins + (v.wide() ? " w" : "");
    }
}
