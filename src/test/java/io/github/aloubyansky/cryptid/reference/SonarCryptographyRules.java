package io.github.aloubyansky.cryptid.reference;

import com.ibm.engine.rule.IDetectionRule;
import io.github.aloubyansky.cryptid.detection.Loc;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.ApiSpec;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

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

    /**
     * The API methods the rules cover, as spec keys. The hand-maintained specs cover these and
     * more, so a test comparing the two needs to know which entries came from the rules.
     *
     * @return the API methods, in {@code owner#name(parameter types)} form
     * @throws Exception if the rules can't be loaded or exported
     */
    public static Set<String> apiMethods() throws Exception {
        final Set<String> apis = new TreeSet<>();
        for (ApiSpec spec : new RuleSpecExporter().export(javaRules()).specs().apis()) {
            apis.add(spec.api());
        }
        return apis;
    }
}
