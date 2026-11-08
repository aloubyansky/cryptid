package org.acme.cbom.bytecode;

import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.engine.rule.IDetectionRule;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.acme.cbom.spec.ApiSpecs.ApiSpec;
import org.acme.cbom.spec.ApiSpecs.Context;

/**
 * What sonar-cryptography's translation needs from a rule, from a spec: its library and the
 * context of the detection. It matches nothing; detection is done from the specs. Used for the
 * {@code DetectionStore}s built for translation while it still works on stores.
 *
 * @param spec the API's spec
 * @param context the context in this detection, the spec's or a role's, as in the specs
 * @param detectionValueContext the same context as sonar-cryptography's object
 * @param bundle the library
 */
record SpecRule(ApiSpec spec, Context context, IDetectionContext detectionValueContext, IBundle bundle)
        implements IDetectionRule<Loc> {

    /** A library, identified like sonar-cryptography's bundles, e.g. {@code Jca}. */
    private record Library(String getIdentifier) implements IBundle {}

    private static final Map<String, IBundle> LIBRARIES = new ConcurrentHashMap<>();
    private static final Map<Context, IDetectionContext> CONTEXTS = new ConcurrentHashMap<>();

    /**
     * Returns the rule for a spec in a context.
     *
     * @param spec the spec
     * @param context the context, the spec's own or a role's
     * @return the rule
     */
    static SpecRule of(ApiSpec spec, Context context) {
        return new SpecRule(spec, context, CONTEXTS.computeIfAbsent(context, SpecRule::context),
                LIBRARIES.computeIfAbsent(spec.library(), Library::new));
    }

    @Override
    public boolean is(Class<? extends IDetectionRule> kind) {
        return false;
    }

    @Override
    public boolean match(Loc expression, ILanguageTranslation<Loc> translation) {
        return false;
    }

    @Override
    public boolean shouldMatchExactTypes() {
        return !spec.subtypes();
    }

    @Override
    public List<IDetectionRule<Loc>> nextDetectionRules() {
        return List.of();
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
    static IDetectionContext context(Context c) {
        try {
            final Class<?> type = Class.forName("com.ibm.engine.model.context." + c.type());
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
