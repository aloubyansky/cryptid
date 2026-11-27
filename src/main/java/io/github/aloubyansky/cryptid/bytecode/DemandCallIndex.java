package io.github.aloubyansky.cryptid.bytecode;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Resolves the values of a method's parameters from its callers, finding the callers in the call
 * graph and interpreting them on demand: in each artifact containing a caller's class, the
 * closure of the callers asked about there ({@link Analyzer#closure}), which gives them the values
 * interpreting the whole artifact would. The call sites found are those {@link CallIndex} indexes,
 * and the resolution is the same, so the answers are too; but only the callers asked about are
 * interpreted.
 *
 * <p>Thread-safe. Interpretations are kept for the life of the index.
 */
public final class DemandCallIndex implements CallResolver {

    /**
     * An analyzed artifact.
     *
     * @param coordinates its coordinates
     * @param jar its JAR
     */
    public record Source(ArtifactCoordinates coordinates, Path jar) {}

    private final Set<String> analyzedClasses;
    private final Hierarchy hierarchy;
    private final CallGraph graph;
    private final Map<String, Source> artifacts;
    private final JarCache jarCache;

    /** declaring method key -> the call sites reaching it, in {@link CallIndex#SITE_ORDER} */
    private final Map<String, List<CallIndex.Site>> sites = new ConcurrentHashMap<>();
    /** artifact path -> method key -> its interpretation there */
    private final Map<String, Map<String, Analyzer.MethodResult>> interpreted = new ConcurrentHashMap<>();
    private final AtomicLong methodsInterpreted = new AtomicLong();
    private final AtomicLong artifactsRead = new AtomicLong();

    /**
     * Creates an index over a finished call graph.
     *
     * @param analyzedClasses internal names of all classes of all artifacts
     * @param hierarchy the class table, complete
     * @param graph the call graph, finished
     * @param artifacts the analyzed artifacts by path, e.g. {@code g/a/v}, as the class table
     *     and the call graph name them
     * @param jarCache the JAR cache
     */
    public DemandCallIndex(Set<String> analyzedClasses, Hierarchy hierarchy, CallGraph graph, Map<String, Source> artifacts,
            JarCache jarCache) {
        this.analyzedClasses = analyzedClasses;
        this.hierarchy = hierarchy;
        this.graph = graph;
        this.artifacts = Map.copyOf(artifacts);
        this.jarCache = jarCache;
    }

    @Override
    public List<CallIndex.Hit> resolve(String method, long params) {
        return CallIndex.resolve(hierarchy, this::sitesOf, method, params);
    }

    /**
     * The number of methods interpreted so far, for logging.
     *
     * @return the methods, counted once per artifact interpreting them
     */
    public long methodsInterpreted() {
        return methodsInterpreted.get();
    }

    /**
     * The number of times an artifact was read to interpret methods, for logging.
     *
     * @return the reads
     */
    public long artifactsRead() {
        return artifactsRead.get();
    }

    /** The call sites reaching a method, by its declaring key; computed once. */
    private List<CallIndex.Site> sitesOf(String source) {
        final List<CallIndex.Site> known = sites.get(source);
        if (known != null) {
            return known;
        }
        final List<CallIndex.Site> found = findSites(source);
        final List<CallIndex.Site> raced = sites.putIfAbsent(source, found);
        return raced == null ? found : raced;
    }

    private List<CallIndex.Site> findSites(String source) {
        final int id = graph.method(source);
        if (id < 0) {
            return List.of();
        }
        // the callers by the artifacts containing their class, in the class table's order
        final Map<String, List<String>> byArtifact = new LinkedHashMap<>();
        for (int caller : graph.callers(id)) {
            final String key = graph.methodKey(caller);
            for (String artifact : hierarchy.artifacts(key.substring(0, key.indexOf('.')))) {
                byArtifact.computeIfAbsent(artifact, k -> new ArrayList<>()).add(key);
            }
        }
        final List<CallIndex.Site> result = new ArrayList<>();
        byArtifact.forEach((artifact, callers) -> {
            final Source src = artifacts.get(artifact);
            final Map<String, Analyzer.MethodResult> results = interpret(artifact, callers);
            for (String key : callers) {
                final Analyzer.MethodResult m = results.get(key);
                if (m == null) {
                    continue;
                }
                for (CallSite cs : m.calls()) {
                    if (!analyzedClasses.contains(cs.owner)
                            || !hierarchy.declaring(cs.owner + "." + cs.name + cs.descriptor).equals(source)) {
                        continue;
                    }
                    final CallIndex.Site site = CallIndex.site(m, cs, src == null ? null : src.coordinates(),
                            artifact.isEmpty() ? "" : artifact + "/");
                    if (site != null) {
                        result.add(site);
                    }
                }
            }
        });
        result.sort(CallIndex.SITE_ORDER);
        return List.copyOf(result);
    }

    /** The interpretations of methods in an artifact, interpreting those not done yet as a closure. */
    private Map<String, Analyzer.MethodResult> interpret(String artifact, List<String> methods) {
        final Map<String, Analyzer.MethodResult> done = interpreted.computeIfAbsent(artifact, k -> new ConcurrentHashMap<>());
        final List<String> missing = methods.stream().filter(m -> !done.containsKey(m)).toList();
        if (missing.isEmpty()) {
            return done;
        }
        final Source src = artifacts.get(artifact);
        if (src == null) {
            return done;
        }
        synchronized (done) {
            final List<String> still = missing.stream().filter(m -> !done.containsKey(m)).toList();
            if (still.isEmpty()) {
                return done;
            }
            final Analyzer analyzer = new Analyzer();
            analyzer.addJar(src.jar(), jarCache);
            artifactsRead.incrementAndGet();
            final Map<String, Analyzer.MethodResult> results = new HashMap<>();
            for (Analyzer.MethodResult m : analyzer.analyze(analyzer.closure(still))) {
                results.put(m.method(), m);
            }
            methodsInterpreted.addAndGet(results.size());
            // a method the JAR doesn't have, e.g. of a copy the class table didn't keep, has no result
            for (String m : still) {
                done.put(m, results.getOrDefault(m, EMPTY));
            }
            results.forEach(done::putIfAbsent);
        }
        return done;
    }

    private static final Analyzer.MethodResult EMPTY = new Analyzer.MethodResult("", "", "", List.of(), AVal.UNKNOWN);
}
