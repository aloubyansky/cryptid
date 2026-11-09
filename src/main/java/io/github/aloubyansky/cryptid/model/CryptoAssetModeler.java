package io.github.aloubyansky.cryptid.model;

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.enricher.Enricher;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.Unknown;
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

    /**
     * Loads sonar-cryptography's Java context translators and reorganizer rules. A modeler isn't
     * thread-safe; use one per thread.
     *
     * @throws ReflectiveOperationException if a translator or the reorganizer rules can't be loaded
     */
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

    /**
     * Whether the model of an event is something its API can create: a {@code Signature}'s a
     * signature, a {@code Mac}'s a MAC, a {@code MessageDigest}'s a digest. A model with a
     * primitive of another kind and none of the API's comes from a value the API would reject at
     * runtime, e.g. {@code Signature.getInstance("HmacSHA256")}, which a mapping method returning
     * the names of a whole algorithm family can give. A secret key takes any name, but isn't for
     * an asymmetric algorithm: a {@code SecretKeySpec} modeled with a signature, public-key
     * encryption, key agreement or KEM doesn't fit. Events of other APIs, whose kinds vary, fit.
     *
     * @param root the event
     * @param nodes its model, from {@link #process}
     * @return {@code false} if the model is of a primitive the API doesn't create
     */
    public static boolean fitsApi(CryptoEvent root, List<INode> nodes) {
        final IDetectionContext context = root.detectionContext();
        final List<Class<? extends INode>> kinds;
        if (context instanceof SignatureContext) {
            kinds = List.of(Signature.class);
        } else if (context instanceof MacContext) {
            kinds = List.of(Mac.class);
        } else if (context instanceof DigestContext) {
            kinds = List.of(MessageDigest.class);
        } else if (context instanceof SecretKeyContext) {
            return nodes.stream().noneMatch(n -> hasKind(n, ASYMMETRIC));
        } else {
            return true;
        }
        boolean foreign = false;
        for (INode node : nodes) {
            final Class<? extends INode> kind = node.getKind();
            if (kinds.stream().anyMatch(k -> k.isAssignableFrom(kind))) {
                return true;
            }
            foreign |= IPrimitive.class.isAssignableFrom(kind) && !Unknown.class.isAssignableFrom(kind);
        }
        return !foreign;
    }

    private static final List<Class<? extends INode>> ASYMMETRIC =
            List.of(Signature.class, PublicKeyEncryption.class, KeyAgreement.class, KeyEncapsulationMechanism.class);

    /** Whether a node or one below it is of one of the kinds. */
    private static boolean hasKind(INode node, List<Class<? extends INode>> kinds) {
        final Class<? extends INode> kind = node.getKind();
        if (kinds.stream().anyMatch(k -> k.isAssignableFrom(kind))) {
            return true;
        }
        return node.getChildren().values().stream().anyMatch(c -> hasKind(c, kinds));
    }

    /**
     * Reorganizes and enriches assembled nodes, as sonar-cryptography does after translation.
     *
     * @param nodes the assembled nodes
     * @return the final nodes; unmodifiable
     */
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
        return t.translate(library, value, context, location(library, value.getLocation(), file));
    }

    /**
     * Where a value is, as sonar-cryptography's model takes it.
     *
     * @param library the event's library
     * @param loc the value's call site
     * @param file the source file the node is located in, with the artifact path
     * @return the location, with the called method as keywords and no column
     */
    static DetectionLocation location(IBundle library, Loc loc, String file) {
        return new DetectionLocation(file, loc.line(), 0, List.of(loc.signature(), loc.methodName()), library);
    }
}
