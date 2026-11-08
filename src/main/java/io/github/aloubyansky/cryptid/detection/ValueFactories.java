package io.github.aloubyansky.cryptid.detection;

import com.ibm.engine.model.Mode;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.AlgorithmParameterFactory;
import com.ibm.engine.model.factory.BlockSizeFactory;
import com.ibm.engine.model.factory.BooleanFactory;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.CipherSuiteFactory;
import com.ibm.engine.model.factory.CurveFactory;
import com.ibm.engine.model.factory.DigestSizeFactory;
import com.ibm.engine.model.factory.InitializationVectorSizeFactory;
import com.ibm.engine.model.factory.IterationCountFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.MacSizeFactory;
import com.ibm.engine.model.factory.ModeFactory;
import com.ibm.engine.model.factory.OperationModeFactory;
import com.ibm.engine.model.factory.PaddingFactory;
import com.ibm.engine.model.factory.ParameterIdentifierFactory;
import com.ibm.engine.model.factory.PasswordSizeFactory;
import com.ibm.engine.model.factory.ProtocolFactory;
import com.ibm.engine.model.factory.SaltSizeFactory;
import com.ibm.engine.model.factory.SeedSizeFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.TagSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Factory;
import java.lang.reflect.Constructor;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Creates sonar-cryptography's value and action factories from their description in the specs:
 * the class's simple name and at most one configuration value,
 * passed to the constructor taking it (a {@code String} or an enum constant).
 *
 * <p>Rule-specific functions ({@code factory: lambda}) can't be created this way; {@link #create}
 * returns {@code null} for them. Thread-safe; factories are cached.
 */
final class ValueFactories {

    /**
     * The factory classes specs may name, referenced explicitly so that jar tree-shaking keeps
     * them: they're only looked up by name.
     */
    private static final Map<String, Class<?>> FACTORIES = KnownClasses.bySimpleName(
            AlgorithmFactory.class, AlgorithmParameterFactory.class, BlockSizeFactory.class, BooleanFactory.class,
            CipherActionFactory.class, CipherSuiteFactory.class, CurveFactory.class, DigestSizeFactory.class,
            InitializationVectorSizeFactory.class, IterationCountFactory.class, KeyActionFactory.class,
            KeySizeFactory.class, MacSizeFactory.class, ModeFactory.class, OperationModeFactory.class,
            PaddingFactory.class, ParameterIdentifierFactory.class, PasswordSizeFactory.class, ProtocolFactory.class,
            SaltSizeFactory.class, SeedSizeFactory.class, SignatureActionFactory.class, TagSizeFactory.class,
            ValueActionFactory.class);

    /** The value classes rule-specific functions produce, by simple name. */
    private static final Map<String, Class<?>> VALUES = KnownClasses.bySimpleName(Mode.class);
    private static final Map<Factory, Object> CACHE = new ConcurrentHashMap<>();

    private ValueFactories() {}

    /**
     * Returns the factory a spec describes.
     *
     * @param spec the description
     * @return an {@code IValueFactory} or {@code IActionFactory}, or {@code null} for a
     *     rule-specific function
     * @throws IllegalArgumentException if the factory can't be created
     */
    static Object create(Factory spec) {
        if ("lambda".equals(spec.factory())) {
            return null;
        }
        return CACHE.computeIfAbsent(spec, ValueFactories::instantiate);
    }

    /**
     * Creates the action a rule-specific function produced when exported, from its recorded result
     * ({@code <value class> <value>}, e.g. {@code Mode GCM}): the value class in {@code
     * com.ibm.engine.model} constructed with the value and the location.
     *
     * @param spec the description, with {@code factory: lambda}
     * @param location the call's location
     * @return the action
     * @throws IllegalArgumentException if it can't be created
     */
    static Object lambdaAction(Factory spec, Loc location) {
        final String result = spec.result();
        final int space = result == null ? -1 : result.indexOf(' ');
        if (space < 0) {
            throw new IllegalArgumentException("No result recorded: " + spec);
        }
        try {
            return KnownClasses.get(VALUES, result.substring(0, space))
                    .getConstructor(String.class, Object.class)
                    .newInstance(result.substring(space + 1), location);
        } catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException("Can't create " + result, e);
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Object instantiate(Factory spec) {
        try {
            final Class<?> type = KnownClasses.get(FACTORIES, spec.factory());
            if (spec.config().isEmpty()) {
                return type.getConstructor().newInstance();
            }
            if (spec.config().size() > 1) {
                throw new IllegalArgumentException("More than one configuration value: " + spec);
            }
            final String value = spec.config().values().iterator().next();
            for (Constructor<?> c : type.getConstructors()) {
                if (c.getParameterCount() != 1) {
                    continue;
                }
                final Class<?> p = c.getParameterTypes()[0];
                if (p == String.class) {
                    return c.newInstance(value);
                }
                if (p.isEnum()) {
                    return c.newInstance(Enum.valueOf((Class<? extends Enum>) p, value));
                }
            }
            throw new IllegalArgumentException("No constructor taking the configuration: " + spec);
        } catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException("Can't create " + spec, e);
        }
    }
}
