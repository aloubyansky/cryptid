package io.github.aloubyansky.cryptid.reference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.rule.IDetectionRule;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.detection.Loc;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * Checks that {@link RuleTable} returns exactly the root rules the brute-force search returns:
 * every rule with the call's method name whose owner types include the call's owner, or for
 * non-exact rules one of its supertypes. Uses sonar-cryptography's real Java rules, for every rule
 * method name and owner type, and subtypes of rule owners (Bouncy Castle is on the test classpath).
 */
class RuleTableTest {

    /** Classes whose supertypes, not themselves, are rule owners, besides the rules' own owners. */
    private static final List<String> SUBTYPES = List.of(
            "org/bouncycastle/crypto/digests/SHA512tDigest",
            "org/bouncycastle/crypto/engines/AESLightEngine",
            "org/bouncycastle/crypto/macs/HMac",
            "java/lang/Object");

    @Test
    void candidatesEqualBruteForce() throws Exception {
        final List<IDetectionRule<Loc>> rules = SonarCryptographyRules.javaRules();
        final RuleTable table = new RuleTable(rules);
        final Types types = new Types(RuleTableTest.class.getClassLoader());
        final Set<String> names = new TreeSet<>();
        final Set<String> owners = new TreeSet<>();
        for (IDetectionRule<Loc> rule : rules) {
            final MethodMatcher<Loc> m = RuleTable.matcher(rule);
            names.addAll(m.getMethodNamesSerializable());
            m.getInvokedObjectTypeStringsSerializable().forEach(o -> owners.add(o.replace('.', '/')));
        }
        owners.addAll(SUBTYPES);
        int nonEmpty = 0;
        for (String owner : owners) {
            final Set<String> supertypes = types.supertypeNames(owner);
            final String dotted = owner.replace('/', '.');
            for (String name : names) {
                final List<IDetectionRule<Loc>> expected = new ArrayList<>();
                for (IDetectionRule<Loc> rule : rules) {
                    final MethodMatcher<Loc> m = RuleTable.matcher(rule);
                    final List<String> ruleOwners = m.getInvokedObjectTypeStringsSerializable();
                    final boolean nameMatches = m.getMethodNamesSerializable().contains(name)
                            || m.getMethodNamesSerializable().contains(MethodMatcher.ANY);
                    final boolean ownerMatches = ruleOwners.contains(MethodMatcher.ANY)
                            || (rule.shouldMatchExactTypes()
                                    ? ruleOwners.contains(dotted)
                                    : ruleOwners.stream().anyMatch(supertypes::contains));
                    if (nameMatches && ownerMatches) {
                        expected.add(rule);
                    }
                }
                final List<IDetectionRule<Loc>> actual = table.candidates(name, dotted, supertypes);
                assertEquals(expected, actual, name + " on " + owner);
                nonEmpty += actual.isEmpty() ? 0 : 1;
            }
        }
        // subclasses of rule owners find their supertypes' non-exact rules
        assertTrue(!table.candidates("<init>", "org.bouncycastle.crypto.digests.SHA512tDigest",
                types.supertypeNames("org/bouncycastle/crypto/digests/SHA512tDigest")).isEmpty());
        assertTrue(nonEmpty > 100, "combinations with candidates: " + nonEmpty);
    }
}
