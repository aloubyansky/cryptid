package org.acme.cbom.bytecode;

import com.ibm.engine.rule.IDetectionRule;
import java.util.List;

/**
 * sonar-cryptography's Java detection rules, for the tests that compare the spec-based detection
 * with them and for exporting the specs. The tool itself doesn't load them.
 */
final class Rules {

    private Rules() {}

    /**
     * Loads the root rules of an inventory scan.
     *
     * @return the rules
     * @throws ReflectiveOperationException if they can't be loaded
     */
    @SuppressWarnings("unchecked")
    static List<IDetectionRule<Loc>> javaRules() throws ReflectiveOperationException {
        return (List<IDetectionRule<Loc>>) Class.forName("com.ibm.plugin.rules.detection.JavaDetectionRules")
                .getMethod("rules").invoke(null);
    }
}
