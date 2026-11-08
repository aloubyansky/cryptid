package org.acme.cbom.bytecode;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.MethodDetectionRule;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * sonar-cryptography's root detection rules, indexed by method name and owner type, for finding
 * the rules that may match a call without testing every rule with the same method name.
 *
 * <p>Almost every root rule matches a constructor, so indexing by name alone leaves about 2,400
 * candidates for every {@code new}. Indexed by name and owner type as well, a call has candidates
 * only if its owner, or for non-exact rules one of its supertypes, is an owner type of the rule:
 * the same condition as {@link Detector}'s owner pre-check. The rule's {@link MethodMatcher} still
 * makes the final decision, so matching is unchanged.
 *
 * <p>Immutable and thread-safe once built.
 */
final class RuleTable {

    /** Rules by {@code methodName + '#' + ownerType}, as root rule indexes in ascending order. */
    private final Map<String, List<Integer>> byKey = new HashMap<>();
    private final List<IDetectionRule<Loc>> rules;

    /**
     * Indexes root rules.
     *
     * @param rules the root rules, in the order candidates are returned
     */
    RuleTable(List<IDetectionRule<Loc>> rules) {
        this.rules = List.copyOf(rules);
        for (int i = 0; i < this.rules.size(); i++) {
            final MethodMatcher<Loc> m = matcher(this.rules.get(i));
            if (m == null) {
                continue;
            }
            for (String name : m.getMethodNamesSerializable()) {
                for (String owner : m.getInvokedObjectTypeStringsSerializable()) {
                    byKey.computeIfAbsent(name + "#" + owner, k -> new ArrayList<>()).add(i);
                }
            }
        }
    }

    /**
     * Returns the rules whose method names and owner types may match a call: the call's name or
     * {@link MethodMatcher#ANY}, and an owner type that is the call's owner, one of its
     * supertypes for rules that don't match exact types only, or {@link MethodMatcher#ANY}.
     *
     * @param name the invoked method's name
     * @param owner the invoked method's owner, as a binary name with dots
     * @param supertypes the owner and its supertypes, as binary names with dots
     * @return the candidate rules, in root rule order
     */
    List<IDetectionRule<Loc>> candidates(String name, String owner, Set<String> supertypes) {
        final TreeMap<Integer, IDetectionRule<Loc>> found = new TreeMap<>();
        for (String n : name.equals(MethodMatcher.ANY) ? List.of(name) : List.of(name, MethodMatcher.ANY)) {
            collect(n, MethodMatcher.ANY, owner, true, found);
            for (String type : supertypes) {
                collect(n, type, owner, false, found);
            }
        }
        return found.isEmpty() ? List.of() : List.copyOf(found.values());
    }

    private void collect(String name, String type, String owner, boolean anyOwner,
            TreeMap<Integer, IDetectionRule<Loc>> found) {
        for (int i : byKey.getOrDefault(name + "#" + type, List.of())) {
            final IDetectionRule<Loc> rule = rules.get(i);
            if (anyOwner || !rule.shouldMatchExactTypes() || type.equals(owner)) {
                found.put(i, rule);
            }
        }
    }

    /** The rule's method matcher, or {@code null} for a rule kind without one. */
    static MethodMatcher<Loc> matcher(IDetectionRule<Loc> rule) {
        if (rule instanceof DetectionRule<Loc> dr) {
            return dr.matchers();
        }
        if (rule instanceof MethodDetectionRule<Loc> mr) {
            return mr.matchers();
        }
        return null;
    }
}
