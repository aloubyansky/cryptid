package io.github.aloubyansky.cryptid.reference;

import com.ibm.engine.rule.IDetectionRule;
import io.github.aloubyansky.cryptid.detection.Loc;
import java.util.List;

/**
 * sonar-cryptography's Java detection rules, for the tests that compare the spec-based detection
 * with them and for exporting the specs. The tool itself doesn't load them.
 */
public final class SonarCryptographyRules {

    private SonarCryptographyRules() {}

    /**
     * Loads the root rules of an inventory scan.
     *
     * @return the rules
     * @throws ReflectiveOperationException if they can't be loaded
     */
    @SuppressWarnings("unchecked")
    public static List<IDetectionRule<Loc>> javaRules() throws ReflectiveOperationException {
        return (List<IDetectionRule<Loc>>) Class.forName("com.ibm.plugin.rules.detection.JavaDetectionRules")
                .getMethod("rules").invoke(null);
    }
}
