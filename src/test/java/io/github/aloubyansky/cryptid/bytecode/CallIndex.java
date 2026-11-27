package io.github.aloubyansky.cryptid.bytecode;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.bytecode.Callers.Hit;
import io.github.aloubyansky.cryptid.bytecode.Callers.Site;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The reference for {@link DemandCallIndex}, in the tests only: the index of the calls into the
 * analyzed classes of all artifacts, filled by interpreting every method of every artifact, as
 * phase A did before detection-driven analysis (docs/foundation.md). Resolves values passed into
 * a method from its callers, within an artifact and across artifacts, through {@link Callers}.
 *
 * <p>It records, for every call to a method of an analyzed class, the constants and parameter
 * provenance of its {@code String} and {@code int} arguments, the types whose values the detection
 * rules turn into algorithm names and sizes. When a crypto API argument comes from a parameter of
 * the enclosing method, {@link #resolve} walks up the callers: a caller passing a constant yields
 * that constant, located at the caller's call site; a caller passing its own parameter is followed
 * further up. This is what sonar-cryptography's hooks did within one scan.
 *
 * <p>Calls are matched by the method they invoke, resolved to its declaring class along the
 * superclass chain, then the interfaces for default methods. Calls through a supertype reach its
 * overrides: resolving {@code C.m} also takes the calls to {@code T.m} for every supertype {@code
 * T} of {@code C} declaring {@code m}, interfaces included. This over-approximates, since such a
 * call may dispatch to another implementation.
 *
 * <p>Thread-safe while filling ({@link #addClasses}, {@link #addCalls}); call {@link #finish} once
 * before {@link #resolve}.
 */
public final class CallIndex implements CallResolver {


    private final Set<String> analyzedClasses;
    private final Hierarchy hierarchy;
    private final Map<String, List<Site>> byInvoked = new ConcurrentHashMap<>();
    private Map<String, List<Site>> byDeclaring;

    /**
     * Creates an empty index.
     *
     * @param analyzedClasses internal names of all classes of all artifacts; only calls to these
     *     are indexed
     */
    public CallIndex(Set<String> analyzedClasses) {
        this(analyzedClasses, new Hierarchy());
    }

    /**
     * Creates an empty index over a class table.
     *
     * @param analyzedClasses internal names of all classes of all artifacts; only calls to these
     *     are indexed
     * @param hierarchy the class table, shared with the call graph and complete before {@link
     *     #finish}
     */
    public CallIndex(Set<String> analyzedClasses, Hierarchy hierarchy) {
        this.analyzedClasses = analyzedClasses;
        this.hierarchy = hierarchy;
    }

    /**
     * Records the classes of an artifact.
     *
     * @param infos class infos by internal name
     */
    public void addClasses(Map<String, ClassInfo> infos) {
        hierarchy.add(infos);
    }

    /**
     * Records the classes of an artifact; of a class in several artifacts, the one of the
     * artifact whose path sorts first is kept.
     *
     * @param artifact the artifact path, e.g. {@code g/a/v}
     * @param infos class infos by internal name
     */
    public void addClasses(String artifact, Map<String, ClassInfo> infos) {
        hierarchy.add(artifact, infos);
    }

    /**
     * The classes recorded with {@link #addClasses}.
     *
     * @return the class hierarchy, shared with the call graph
     */
    public Hierarchy hierarchy() {
        return hierarchy;
    }

    /**
     * Records the calls of an artifact's methods into analyzed classes whose {@code String} or
     * {@code int} arguments carry constants or parameter provenance.
     *
     * @param methods the artifact's methods with their call sites
     * @param locationPrefix the artifact path, prepended to source files
     */
    public void addCalls(List<Analyzer.MethodResult> methods, String locationPrefix) {
        addCalls(methods, null, locationPrefix);
    }

    /**
     * Records the calls of an artifact's methods into analyzed classes whose {@code String} or
     * {@code int} arguments carry constants or parameter provenance.
     *
     * @param methods the artifact's methods with their call sites
     * @param artifact the artifact, or {@code null} if not known
     * @param locationPrefix the artifact path, prepended to source files
     */
    public void addCalls(List<Analyzer.MethodResult> methods, ArtifactCoordinates artifact, String locationPrefix) {
        final String prefix = locationPrefix.isEmpty() ? "" : locationPrefix + "/";
        final Map<String, List<Site>> local = new HashMap<>();
        for (Analyzer.MethodResult m : methods) {
            for (CallSite cs : m.calls()) {
                if (!analyzedClasses.contains(cs.owner)) {
                    continue;
                }
                final Site site = Callers.site(m, cs, artifact, prefix);
                if (site != null) {
                    local.computeIfAbsent(cs.owner + "." + cs.name + cs.descriptor, k -> new ArrayList<>()).add(site);
                }
            }
        }
        // ConcurrentHashMap.merge is atomic per key
        local.forEach((key, sites) -> byInvoked.merge(key, sites, (a, b) -> {
            final List<Site> all = new ArrayList<>(a);
            all.addAll(b);
            return all;
        }));
    }

    /**
     * Groups the recorded calls by the method they reach, resolving each invoked method to its
     * declaring class along the superclass chain.
     */
    public void finish() {
        final Map<String, List<Site>> result = new HashMap<>();
        byInvoked.forEach((key, sites) -> result.computeIfAbsent(hierarchy.declaring(key), k -> new ArrayList<>()).addAll(sites));
        // artifacts are indexed in parallel: order the sites, so values resolve in the same order in every run
        result.values().forEach(sites -> sites.sort(Callers.SITE_ORDER));
        byDeclaring = result;
    }

    @Override
    public List<Hit> resolve(String method, long params) {
        return Callers.resolve(hierarchy, source -> byDeclaring.getOrDefault(source, List.of()), method, params);
    }

    /**
     * Returns the number of indexed call sites, for logging.
     *
     * @return the number of call sites
     */
    public int size() {
        return byInvoked.values().stream().mapToInt(List::size).sum();
    }
}
