package org.acme.cbom.bytecode;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.enricher.Enricher;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.Reorganizer;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Translates detection store trees into CBOM nodes with sonar-cryptography's own pipeline:
 * {@link ITranslator} with the Java context translators, then the Java reorganizer rules, then the
 * enricher, as {@code JavaTranslationProcess} does.
 *
 * <p>The Java rules, reorganizer rules and context translators declare sonar-java's {@code Tree}
 * as a generic type argument only, so they work with {@link Loc} at runtime. They are accessed
 * reflectively here, because compiling against their signatures would need sonar-java's classes.
 * Every class name is a string constant at its {@code Class.forName} call, which Quarkus jar
 * tree-shaking follows.
 */
final class Translation extends ITranslator<Object, Loc, Object, Object> {

    private static final String CONTEXTS = "com.ibm.plugin.translation.translator.contexts.";

    private final Map<String, IContextTranslation<Loc>> translators = new HashMap<>();
    private final List<IReorganizerRule> reorganizerRules;

    @SuppressWarnings("unchecked")
    Translation() throws ReflectiveOperationException {
        // context type -> translator, in the order of JavaTranslator; class names are compile-time
        // constants so that jar tree-shaking traces them
        final Map<String, Class<?>> classes = Map.ofEntries(
                Map.entry("CipherContext", Class.forName(CONTEXTS + "JavaCipherContextTranslator")),
                Map.entry("SecretKeyContext", Class.forName(CONTEXTS + "JavaSecretKeyContextTranslator")),
                Map.entry("KeyContext", Class.forName(CONTEXTS + "JavaKeyContextTranslator")),
                Map.entry("PublicKeyContext", Class.forName(CONTEXTS + "JavaKeyContextTranslator")),
                Map.entry("PrivateKeyContext", Class.forName(CONTEXTS + "JavaKeyContextTranslator")),
                Map.entry("KeyAgreementContext", Class.forName(CONTEXTS + "JavaKeyAgreementContextTranslator")),
                Map.entry("PRNGContext", Class.forName(CONTEXTS + "JavaPRNGContextTranslator")),
                Map.entry("DigestContext", Class.forName(CONTEXTS + "JavaDigestContextTranslator")),
                Map.entry("SignatureContext", Class.forName(CONTEXTS + "JavaSignatureContextTranslator")),
                Map.entry("MacContext", Class.forName(CONTEXTS + "JavaMacContextTranslator")),
                Map.entry("AlgorithmParameterContext", Class.forName(CONTEXTS + "JavaAlgorithmParameterContextTranslator")),
                Map.entry("ProtocolContext", Class.forName(CONTEXTS + "JavaProtocolContextTranslator")));
        for (Map.Entry<String, Class<?>> e : classes.entrySet()) {
            translators.put(e.getKey(), (IContextTranslation<Loc>) e.getValue().getDeclaredConstructor().newInstance());
        }
        reorganizerRules = (List<IReorganizerRule>) Class.forName(
                "com.ibm.plugin.translation.reorganizer.JavaReorganizerRules").getMethod("rules").invoke(null);
    }

    /** sonar-cryptography's Java detection rules, the root rules of an inventory scan. */
    @SuppressWarnings("unchecked")
    static List<IDetectionRule<Loc>> javaRules() throws ReflectiveOperationException {
        return (List<IDetectionRule<Loc>>) Class.forName("com.ibm.plugin.rules.detection.JavaDetectionRules")
                .getMethod("rules").invoke(null);
    }

    /** Translates, reorganizes and enriches a root store tree. */
    List<INode> process(DetectionStore<Object, Loc, Object, Object> root) {
        final List<INode> translated = translate(root);
        final List<INode> reorganized = new Reorganizer(reorganizerRules).reorganize(translated);
        return List.copyOf(Enricher.enrich(reorganized));
    }

    @Override
    protected Optional<INode> translate(IBundle bundle, IValue<Loc> value, IDetectionContext context, String filePath) {
        final IContextTranslation<Loc> t = translators.get(context.type().getSimpleName());
        if (t == null) {
            return Optional.empty();
        }
        return t.translate(bundle, value, context, getDetectionContextFrom(value.getLocation(), bundle, filePath));
    }

    @Override
    protected DetectionLocation getDetectionContextFrom(Loc location, IBundle bundle, String filePath) {
        return new DetectionLocation(filePath, location.line(), 0,
                List.of(location.signature(), location.methodName()), bundle);
    }
}
