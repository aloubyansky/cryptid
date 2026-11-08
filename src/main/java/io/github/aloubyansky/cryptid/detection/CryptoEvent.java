package io.github.aloubyansky.cryptid.detection;

import com.ibm.engine.model.IAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.ApiSpec;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Context;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * An event on a crypto object, in the sense of CrySL's object and event model: the calls of one
 * specified API on an object, with what they contribute (an action, and values by argument
 * index), and the events they lead to: further events on the same object (children at {@code
 * -1}, e.g. {@code init} after {@code getInstance}) and events of the objects passed as arguments
 * (children at the argument's index, e.g. the creation of the key passed to {@code init}). A tree
 * of events rooted at an API that reports on its own is a finding. The input of {@link
 * AssetAssembler}.
 *
 * <p>Values and children are kept by ascending index, the order model building visits them in.
 * Mutable while {@link CryptoEventDetector} builds it.
 */
public final class CryptoEvent {

    private final ApiSpec spec;
    private final Context context;
    private final IDetectionContext detectionContext;
    private final IBundle library;
    private final String file;
    private IAction<Loc> action;
    private final Map<Integer, List<IValue<Loc>>> values = new TreeMap<>();
    private final Map<Integer, List<CryptoEvent>> children = new TreeMap<>();

    private CryptoEvent(ApiSpec spec, Context context, String file) {
        this.spec = spec;
        this.context = context;
        this.detectionContext = CryptoContexts.context(context);
        this.library = CryptoContexts.library(spec.library());
        this.file = file;
    }

    /**
     * Starts an event.
     *
     * @param spec the API's spec
     * @param context its context here: the spec's own or a role's
     * @param file the source file of the call, prefixed with the artifact path
     * @return the event
     */
    static CryptoEvent of(ApiSpec spec, Context context, String file) {
        return new CryptoEvent(spec, context, file);
    }

    ApiSpec spec() {
        return spec;
    }

    /** The context, as in the specs. */
    Context context() {
        return context;
    }

    /** The context, as sonar-cryptography's translation takes it. */
    public IDetectionContext detectionContext() {
        return detectionContext;
    }

    /** The library, as sonar-cryptography's translation takes it. */
    public IBundle library() {
        return library;
    }
    public String file() {
        return file;
    }

    public Optional<IAction<Loc>> action() {
        return Optional.ofNullable(action);
    }

    /** Sets the action; a later call's action replaces an earlier one's. */
    void action(IAction<Loc> a) {
        this.action = a;
    }

    void addValue(int index, IValue<Loc> value) {
        values.computeIfAbsent(index, k -> new ArrayList<>()).add(value);
    }

    void attach(int index, CryptoEvent child) {
        children.computeIfAbsent(index, k -> new ArrayList<>()).add(child);
    }

    /** Values by argument index, ascending. */
    public Map<Integer, List<IValue<Loc>>> values() {
        return Collections.unmodifiableMap(values);
    }

    /** Children by argument index, ascending, {@code -1} for calls made on the object. */
    public Map<Integer, List<CryptoEvent>> children() {
        return Collections.unmodifiableMap(children);
    }
}
