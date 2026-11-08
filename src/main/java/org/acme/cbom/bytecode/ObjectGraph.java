package org.acme.cbom.bytecode;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.acme.cbom.spec.ApiSpecs.ApiSpec;

/**
 * The calls to specified crypto APIs in one method, with the objects they create and use: the
 * facts detection works from instead of rule trees.
 *
 * <p>An object is identified by the call site that created it, as in {@link AVal#origins()}: the
 * {@code new} for a constructor call, or the call for a method returning an object. Calls are
 * related to an object when they create it or are invoked on it. Objects are followed within the
 * method, like the current detection; across methods is a later step.
 */
final class ObjectGraph {

    /**
     * A call to a specified API.
     *
     * @param site the call site
     * @param spec the API's spec
     */
    record ApiCall(CallSite site, ApiSpec spec) {}

    private final List<ApiCall> calls;

    private ObjectGraph(List<ApiCall> calls) {
        this.calls = calls;
    }

    /**
     * Builds the graph of a method.
     *
     * @param method the method's call sites
     * @param apis the specs
     * @param types the class hierarchy, for specs matching subtypes
     * @return the graph
     */
    static ObjectGraph of(Analyzer.MethodResult method, ApiIndex apis, Types types) {
        final List<ApiCall> calls = new ArrayList<>();
        for (CallSite cs : method.calls()) {
            for (ApiSpec spec : apis.match(cs, types)) {
                calls.add(new ApiCall(cs, spec));
            }
        }
        return new ObjectGraph(List.copyOf(calls));
    }

    /** All calls to specified APIs, in bytecode order. */
    List<ApiCall> calls() {
        return calls;
    }

    /** The calls that report findings on their own, in bytecode order. */
    List<ApiCall> roots() {
        return calls.stream().filter(c -> c.spec().root()).toList();
    }

    /**
     * Returns the calls related to objects: those creating one of them, or invoked on one.
     *
     * @param origins the objects, by creating call site
     * @return the related calls, in bytecode order
     */
    List<ApiCall> related(Set<Integer> origins) {
        if (origins.isEmpty()) {
            return List.of();
        }
        final List<ApiCall> result = new ArrayList<>();
        for (ApiCall c : calls) {
            if (origins.contains(c.site().created) || c.site().receiver.origins().stream().anyMatch(origins::contains)) {
                result.add(c);
            }
        }
        return result;
    }
}
