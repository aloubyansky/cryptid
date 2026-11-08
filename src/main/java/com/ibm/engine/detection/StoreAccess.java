package com.ibm.engine.detection;

import com.ibm.engine.model.IAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.language.IScanContext;

/**
 * Builds {@link DetectionStore} trees without sonar-cryptography's language engine, so that its
 * translation ({@code ITranslator}) can be reused as is.
 *
 * <p>Lives in sonar-cryptography's package because {@code addValue} and {@code actionValue} are
 * package-private. A spike-only workaround; a proper solution would be a public builder upstream.
 */
public final class StoreAccess {

    private StoreAccess() {}

    /**
     * Creates a detection store. The handler and status reporting are only used by
     * sonar-cryptography's own detection engine, which isn't involved here.
     *
     * @param level the nesting level, 0 for root stores
     * @param rule the detection rule
     * @param scanContext provides the file path for translation
     * @param <T> the location type
     * @return a new store
     */
    public static <T> DetectionStore<Object, T, Object, Object> create(
            int level, IDetectionRule<T> rule, IScanContext<Object, T> scanContext) {
        return new DetectionStore<>(level, rule, scanContext, null, null);
    }

    /**
     * Adds a detected value for a parameter.
     *
     * @param store the store
     * @param index the parameter id
     * @param value the value
     * @param <T> the location type
     */
    public static <T> void addValue(DetectionStore<Object, T, Object, Object> store, int index, IValue<T> value) {
        store.addValue(index, value);
    }

    /**
     * Sets the action value of a store, e.g. the encrypt/decrypt operation of a method.
     *
     * @param store the store
     * @param action the action
     * @param <T> the location type
     */
    public static <T> void setAction(DetectionStore<Object, T, Object, Object> store, IAction<T> action) {
        store.actionValue = action;
    }
}
