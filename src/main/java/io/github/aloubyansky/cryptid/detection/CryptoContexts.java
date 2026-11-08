package io.github.aloubyansky.cryptid.detection;

import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.rule.IBundle;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Context;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The contexts crypto events are translated in, created from their description in the specs:
 * sonar-cryptography's detection contexts (the kind of crypto object, and its role where a parent
 * gives it one, e.g. a digest used as MGF1), which select the translator, and libraries (its
 * bundles, e.g. {@code Jca}), which select the string mappers. Thread-safe; both are cached.
 */
final class CryptoContexts {

    /** A library, identified like sonar-cryptography's bundles, e.g. {@code Jca}. */
    private record Library(String getIdentifier) implements IBundle {}

    private static final Map<String, IBundle> LIBRARIES = new ConcurrentHashMap<>();
    private static final Map<Context, IDetectionContext> CONTEXTS = new ConcurrentHashMap<>();

    /** The context classes specs may name, referenced explicitly for jar tree-shaking. */
    private static final Map<String, Class<?>> CONTEXT_TYPES = KnownClasses.bySimpleName(
            AlgorithmParameterContext.class, CipherContext.class, DigestContext.class, KeyAgreementContext.class,
            KeyContext.class, KeyDerivationFunctionContext.class, MacContext.class, PRNGContext.class,
            PrivateKeyContext.class, ProtocolContext.class, PublicKeyContext.class, SecretKeyContext.class,
            SignatureContext.class);

    private CryptoContexts() {}

    /**
     * Returns the library of an identifier.
     *
     * @param id the identifier, e.g. {@code Jca}
     * @return the library
     */
    static IBundle library(String id) {
        return LIBRARIES.computeIfAbsent(id, Library::new);
    }

    /**
     * Returns the detection context a spec context describes.
     *
     * @param c the description
     * @return the context
     * @throws IllegalArgumentException if it can't be created
     */
    static IDetectionContext context(Context c) {
        return CONTEXTS.computeIfAbsent(c, CryptoContexts::create);
    }

    /**
     * Creates sonar-cryptography's detection context described by a spec context: with its
     * properties if it has any, else with its kind, else the default.
     *
     * @param c the description
     * @return the context
     * @throws IllegalArgumentException if it can't be created
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static IDetectionContext create(Context c) {
        try {
            final Class<?> type = KnownClasses.get(CONTEXT_TYPES, c.type());
            if (!c.properties().isEmpty()) {
                return (IDetectionContext) type.getConstructor(Map.class).newInstance(c.properties());
            }
            if (c.kind() != null) {
                for (var ctor : type.getConstructors()) {
                    if (ctor.getParameterCount() == 1 && ctor.getParameterTypes()[0].isEnum()) {
                        return (IDetectionContext) ctor.newInstance(Enum.valueOf((Class<? extends Enum>) ctor.getParameterTypes()[0], c.kind()));
                    }
                }
                throw new IllegalArgumentException("No constructor taking a kind: " + c);
            }
            return (IDetectionContext) type.getConstructor().newInstance();
        } catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException("Can't create context " + c, e);
        }
    }
}
