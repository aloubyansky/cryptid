package org.acme.cbom.bytecode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.Parameter;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.acme.cbom.spec.ApiSpecs;
import org.acme.cbom.spec.ApiSpecs.ApiSpec;
import org.bouncycastle.crypto.engines.AESEngine;
import org.junit.jupiter.api.Test;

/**
 * Checks that the specs match exactly the calls sonar-cryptography's rules match: on every call
 * site of Bouncy Castle's provider JAR (on the test classpath), the API methods matched through
 * {@link ApiIndex} equal those of all rules, roots and nested ones, whose {@link MethodMatcher}
 * accepts the call.
 */
class ApiIndexTest {

    @Test
    void loadsTheShippedSpecs() throws Exception {
        final ApiSpecs specs = ApiSpecs.load();
        assertEquals(515, specs.apis().size());
        assertEquals("sonar-cryptography", specs.source().name());
    }

    @Test
    void parameterTypesMatchSubtypes() throws Exception {
        final ApiIndex index = new ApiIndex(ApiSpecs.load());
        final Types types = new Types(ApiIndexTest.class.getClassLoader());
        // Bouncy Castle narrowed the parameter to ExtendedDigest; the spec says Digest
        final CallSite cs = new CallSite(0, "m", "X.java", "org/bouncycastle/crypto/digests/ShortenedDigest", "<init>",
                "(Lorg/bouncycastle/crypto/ExtendedDigest;I)V", false, 1, 2);
        assertEquals(List.of("org.bouncycastle.crypto.digests.ShortenedDigest#<init>(org.bouncycastle.crypto.Digest, int)"),
                index.match(cs, types).stream().map(ApiSpec::api).toList());
        // primitives must be equal
        final CallSite wide = new CallSite(0, "m", "X.java", "org/bouncycastle/crypto/digests/ShortenedDigest", "<init>",
                "(Lorg/bouncycastle/crypto/ExtendedDigest;J)V", false, 1, 2);
        assertEquals(List.of(), index.match(wide, types));
    }

    @Test
    void matchesWhatTheRulesMatch() throws Exception {
        final Path bcprov = Path.of(AESEngine.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        final ApiIndex index = new ApiIndex(ApiSpecs.load());
        final List<IDetectionRule<Loc>> rules = allRules(Rules.javaRules());
        final RuleTable ruleTable = new RuleTable(rules);
        final Types types = new Types(ApiIndexTest.class.getClassLoader());

        int calls = 0;
        int matched = 0;
        final List<String> differences = new ArrayList<>();
        try (JarCache jars = new JarCache()) {
            final Analyzer analyzer = new Analyzer();
            analyzer.addJar(bcprov, jars);
            for (Analyzer.MethodResult m : analyzer.analyze()) {
                for (CallSite cs : m.calls()) {
                    calls++;
                    final Set<String> bySpecs = new TreeSet<>();
                    index.match(cs, types).forEach(s -> bySpecs.add(s.api()));
                    final Set<String> byRules = byRules(cs, ruleTable, types);
                    if (!bySpecs.isEmpty()) {
                        matched++;
                    }
                    if (!bySpecs.equals(byRules) && differences.size() < 20) {
                        differences.add(cs + ": specs " + bySpecs + ", rules " + byRules);
                    }
                }
            }
        }
        assertTrue(differences.isEmpty(), "specs and rules match differently:\n  " + String.join("\n  ", differences));
        assertTrue(matched > 1000, "call sites matched: " + matched + " of " + calls);
    }

    /**
     * The API methods of all rules whose matcher accepts the call, labelled with the rule's owner
     * the call matched through.
     */
    private static Set<String> byRules(CallSite cs, RuleTable table, Types types) {
        final Set<String> result = new TreeSet<>();
        final String owner = cs.owner.replace('/', '.');
        final Set<String> supertypes = types.supertypeNames(cs.owner);
        for (IDetectionRule<Loc> rule : table.candidates(cs.name, owner, supertypes)) {
            final MethodMatcher<Loc> m = RuleTable.matcher(rule);
            if (!m.matchKeys(types.ofClass(cs.owner, rule.shouldMatchExactTypes()), cs.name, types.ofParameters(cs.descriptor))) {
                continue;
            }
            final String params = SpecExporter.anyParameters(m) ? "(" + ApiSpecs.ANY_PARAMETERS + ")"
                    : "(" + String.join(", ", m.getParameterTypesSerializable()) + ")";
            for (String o : m.getInvokedObjectTypeStringsSerializable()) {
                if (rule.shouldMatchExactTypes() ? o.equals(owner) : supertypes.contains(o)) {
                    result.add(o + "#" + cs.name + params);
                }
            }
        }
        return result;
    }

    /** All distinct rules reachable from the roots. */
    private static List<IDetectionRule<Loc>> allRules(List<IDetectionRule<Loc>> roots) {
        final Set<IDetectionRule<Loc>> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        final List<IDetectionRule<Loc>> result = new ArrayList<>();
        final Deque<IDetectionRule<Loc>> todo = new ArrayDeque<>(roots);
        while (!todo.isEmpty()) {
            final IDetectionRule<Loc> r = todo.poll();
            if (!seen.add(r)) {
                continue;
            }
            result.add(r);
            if (r instanceof DetectionRule<Loc> dr) {
                for (Parameter<Loc> p : dr.parameters()) {
                    todo.addAll(p.getDetectionRules());
                }
            }
            todo.addAll(r.nextDetectionRules());
        }
        return result;
    }
}
