package io.github.aloubyansky.cryptid.detection;

import io.github.aloubyansky.cryptid.bytecode.AVal;
import io.github.aloubyansky.cryptid.bytecode.Analyzer;
import io.github.aloubyansky.cryptid.bytecode.CallSite;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.spec.CryptoApiMatcher;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.ApiSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The crypto objects of one method and the calls to specified crypto APIs that create them or
 * are invoked on them: the facts detection works from.
 *
 * <p>An object is abstract: it stands for all instances created at one site, as in points-to
 * analysis. Its origin is the id of that site in {@link AVal#origins()}: the {@code new} for a
 * constructor call, or the call for a method returning an object, e.g. {@code
 * Cipher.getInstance}. A call creates the object of its own site, and is an event of every other
 * object its receiver may be; a constructor, which runs on the object its {@code new} allocated,
 * is that object's creation only. Arguments refer to objects through their origins too, which is how one
 * object uses another, e.g. the key passed to {@code Cipher.init}.
 *
 * <p>Objects are followed within the method. Objects coming from outside it (parameters, fields)
 * have no origin here, and an object returned by a method without a spec has no creating crypto
 * call; following objects across methods is a later step.
 */
final class CryptoObjectGraph {

    /**
     * A call to a specified crypto API.
     *
     * @param site the call site
     * @param spec the API's spec
     */
    record CryptoApiCall(CallSite site, ApiSpec spec) {}

    /**
     * An abstract crypto object.
     *
     * @param origin the id of the site creating it
     * @param creations the calls to specified APIs creating it, in bytecode order; empty if it's
     *     created by code without a spec, e.g. a helper method
     * @param events the calls to specified APIs invoked on it, in bytecode order
     */
    record CryptoObject(int origin, List<CryptoApiCall> creations, List<CryptoApiCall> events) {}

    private final List<CryptoApiCall> calls;
    private final Map<Integer, CryptoObject> objects;
    /** A call's position in {@link #calls}, for returning related calls in bytecode order. */
    private final Map<CryptoApiCall, Integer> positions = new IdentityHashMap<>();

    private CryptoObjectGraph(List<CryptoApiCall> calls) {
        this.calls = calls;
        final Map<Integer, List<CryptoApiCall>> creations = new LinkedHashMap<>();
        final Map<Integer, List<CryptoApiCall>> events = new LinkedHashMap<>();
        for (int i = 0; i < calls.size(); i++) {
            final CryptoApiCall c = calls.get(i);
            positions.put(c, i);
            if (c.site().created() >= 0) {
                creations.computeIfAbsent(c.site().created(), k -> new ArrayList<>()).add(c);
            }
            for (int origin : c.site().receiver().origins()) {
                // a constructor runs on the object its new allocated: that's its creation, not an event
                if (origin != c.site().created()) {
                    events.computeIfAbsent(origin, k -> new ArrayList<>()).add(c);
                }
            }
        }
        final Map<Integer, CryptoObject> result = new LinkedHashMap<>();
        creations.keySet().forEach(o -> result.put(o, null));
        events.keySet().forEach(o -> result.put(o, null));
        result.replaceAll((o, ignored) -> new CryptoObject(o,
                List.copyOf(creations.getOrDefault(o, List.of())), List.copyOf(events.getOrDefault(o, List.of()))));
        this.objects = Collections.unmodifiableMap(result);
    }

    /**
     * Builds the graph of a method.
     *
     * @param method the method's call sites
     * @param matcher the spec matcher
     * @param types the class hierarchy, for specs matching subtypes
     * @return the graph
     */
    static CryptoObjectGraph of(Analyzer.MethodResult method, CryptoApiMatcher matcher, Types types) {
        final List<CryptoApiCall> calls = new ArrayList<>();
        for (CallSite cs : method.calls()) {
            for (ApiSpec spec : matcher.match(cs, types)) {
                calls.add(new CryptoApiCall(cs, spec));
            }
        }
        return new CryptoObjectGraph(List.copyOf(calls));
    }

    /** All calls to specified APIs, in bytecode order. */
    List<CryptoApiCall> calls() {
        return calls;
    }

    /** The calls that report findings on their own, in bytecode order. */
    List<CryptoApiCall> roots() {
        return calls.stream().filter(c -> c.spec().root()).toList();
    }

    /** The objects created by, or acted on by, calls to specified APIs, in order of first call. */
    Collection<CryptoObject> objects() {
        return objects.values();
    }

    /**
     * Returns an object.
     *
     * @param origin the id of the site creating it
     * @return the object, or empty if no call to a specified API creates it or acts on it
     */
    Optional<CryptoObject> object(int origin) {
        return Optional.ofNullable(objects.get(origin));
    }

    /**
     * Returns the calls of objects: the calls creating them and their events.
     *
     * @param origins the objects
     * @return the calls, each once, in bytecode order
     */
    List<CryptoApiCall> related(Set<Integer> origins) {
        if (origins.isEmpty()) {
            return List.of();
        }
        final Set<CryptoApiCall> found = Collections.newSetFromMap(new IdentityHashMap<>());
        for (int origin : origins) {
            final CryptoObject o = objects.get(origin);
            if (o != null) {
                found.addAll(o.creations());
                found.addAll(o.events());
            }
        }
        final List<CryptoApiCall> result = new ArrayList<>(found);
        result.sort((a, b) -> Integer.compare(positions.get(a), positions.get(b)));
        return result;
    }
}
