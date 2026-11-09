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
 * of events rooted at an API that reports on its own is a finding. The input of model building
 * ({@code AssetAssembler}).
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

    /**
     * The spec of the API whose calls this event holds.
     *
     * @return the spec
     */
    ApiSpec spec() {
        return spec;
    }

    /**
     * The context, as in the specs.
     *
     * @return the event's role: its spec's context, or the role the parent gives it
     */
    Context context() {
        return context;
    }

    /**
     * The context, as sonar-cryptography's translation takes it.
     *
     * @return the event's role: its spec's context, or the role the parent gives it
     */
    public IDetectionContext detectionContext() {
        return detectionContext;
    }

    /**
     * The library, as sonar-cryptography's translation takes it.
     *
     * @return the spec's API family, e.g. JCA or Bouncy Castle
     */
    public IBundle library() {
        return library;
    }

    /**
     * The source file the event's calls are in, which translated nodes are located in.
     *
     * @return the path, prefixed with the artifact path
     */
    public String file() {
        return file;
    }

    /**
     * What the event's calls state themselves, e.g. the algorithm a constructor implements or the
     * operation mode of {@code init}.
     *
     * @return the action of the last call stating one, or empty
     */
    public Optional<IAction<Loc>> action() {
        return Optional.ofNullable(action);
    }

    /**
     * The model node of cryptid's own the action is, from {@link ApiSpec#model()}.
     *
     * @return the node's name, or empty if sonar-cryptography's translators model the action
     */
    public Optional<String> model() {
        return Optional.ofNullable(spec.model());
    }

    /**
     * Sets the action; a later call's action replaces an earlier one's.
     *
     * @param a the action
     */
    void action(IAction<Loc> a) {
        this.action = a;
    }

    /**
     * Adds what an argument contributes.
     *
     * @param index the argument's position, or the child position it is moved under
     * @param value the value
     */
    void addValue(int index, IValue<Loc> value) {
        values.computeIfAbsent(index, k -> new ArrayList<>()).add(value);
    }

    /**
     * Adds an event this one leads to.
     *
     * @param index the linking argument's position, or {@code -1} for a further event on the
     *     same object
     * @param child the event
     */
    void attach(int index, CryptoEvent child) {
        children.computeIfAbsent(index, k -> new ArrayList<>()).add(child);
    }

    /**
     * What the event's calls' arguments contribute.
     *
     * @return values by argument index, ascending; unmodifiable
     */
    public Map<Integer, List<IValue<Loc>>> values() {
        return Collections.unmodifiableMap(values);
    }

    /**
     * The events this one leads to.
     *
     * @return children by argument index, ascending, {@code -1} for further events on the same
     *     object; unmodifiable
     */
    public Map<Integer, List<CryptoEvent>> children() {
        return Collections.unmodifiableMap(children);
    }
}
