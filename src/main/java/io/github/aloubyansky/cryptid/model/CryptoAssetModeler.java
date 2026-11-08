package io.github.aloubyansky.cryptid.model;

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.enricher.Enricher;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.Reorganizer;
import com.ibm.mapper.utils.DetectionLocation;
import io.github.aloubyansky.cryptid.detection.CryptoEvent;
import io.github.aloubyansky.cryptid.detection.Loc;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Models a finding's {@link CryptoEvent} tree as crypto assets, with sonar-cryptography's Java
 * knowledge: the context translators turn actions and values into model nodes, {@link
 * AssetAssembler} assembles them into asset trees, the Java reorganizer rules normalize them, and
 * the enricher adds what follows from them (OIDs, default sizes, functions). The result is a
 * forest of asset trees, which {@code CBOMOutputFile} writes as CycloneDX components and the links
 * between them.
 *
 * <p>The context translators and reorganizer rules declare sonar-java's {@code Tree} as a generic
 * type argument only, so they work with {@link Loc} at runtime. They are accessed reflectively,
 * because compiling against their signatures would need sonar-java's classes. Every class name is
 * a string constant at its {@code Class.forName} call, which Quarkus jar tree-shaking follows.
 */
public final class CryptoAssetModeler {

    private static final String CONTEXTS = "com.ibm.plugin.translation.translator.contexts.";

    private final Map<String, IContextTranslation<Loc>> translators = new HashMap<>();
    private final List<IReorganizerRule> reorganizerRules;

    @SuppressWarnings("unchecked")
    public CryptoAssetModeler() throws ReflectiveOperationException {
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

    /**
     * Models an event tree: assembles, reorganizes and enriches its nodes.
     *
     * @param root the root event
     * @return its crypto model nodes
     */
    public List<INode> process(CryptoEvent root) {
        return finish(new AssetAssembler(this::translate).build(root));
    }

    /** Reorganizes and enriches assembled nodes. */
    List<INode> finish(List<INode> nodes) {
        final List<INode> reorganized = new Reorganizer(reorganizerRules).reorganize(nodes);
        return List.copyOf(Enricher.enrich(reorganized));
    }

    /**
     * Translates one action or value with the translator of its context.
     *
     * @param library the event's library
     * @param value the action or value
     * @param context the event's context
     * @param file the source file, prefixed with the artifact path
     * @return the node, or empty if the value doesn't translate
     */
    Optional<INode> translate(IBundle library, IValue<Loc> value, IDetectionContext context, String file) {
        final IContextTranslation<Loc> t = translators.get(context.type().getSimpleName());
        if (t == null) {
            return Optional.empty();
        }
        final Loc loc = value.getLocation();
        return t.translate(library, value, context,
                new DetectionLocation(file, loc.line(), 0, List.of(loc.signature(), loc.methodName()), library));
    }
}
