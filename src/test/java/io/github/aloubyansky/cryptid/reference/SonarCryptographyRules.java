package io.github.aloubyansky.cryptid.reference;

import com.ibm.engine.rule.IDetectionRule;
import io.github.aloubyansky.cryptid.detection.Loc;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * sonar-cryptography's Java detection rules, for the tests that compare the spec-based detection
 * with them and for exporting the specs. The tool itself doesn't load them.
 */
public final class SonarCryptographyRules {

    private static Set<String> apiMethods;

    private SonarCryptographyRules() {}

    /**
     * The API methods the rules match, as {@code api} keys of the specs they export to.
     *
     * @return the API methods, computed once
     * @throws ReflectiveOperationException if the rules can't be loaded
     */
    public static synchronized Set<String> apiMethods() throws ReflectiveOperationException {
        if (apiMethods == null) {
            final Set<String> apis = new TreeSet<>();
            new RuleSpecExporter().export(javaRules()).specs().apis().forEach(a -> apis.add(a.api()));
            apiMethods = Collections.unmodifiableSet(apis);
        }
        return apiMethods;
    }

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
