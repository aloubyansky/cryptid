package org.acme.cbom.bytecode;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.StoreAccess;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.model.IAction;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.model.factory.IValueFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.acme.cbom.bytecode.ObjectGraph.ApiCall;
import org.acme.cbom.spec.ApiSpecs.ApiSpec;
import org.acme.cbom.spec.ApiSpecs.Arg;
import org.acme.cbom.spec.ApiSpecs.Context;
import org.acme.cbom.spec.ApiSpecs.Role;

/**
 * Detection from the crypto API specs: each call to an API that reports on its own is a finding,
 * with the objects it creates and uses from the method's {@link ObjectGraph}: the calls on the
 * created object the spec lists as next, and the objects passed through linking arguments, in the
 * roles the specs give them.
 *
 * <p>Findings are built as {@code DetectionStore} trees, the input of sonar-cryptography's
 * translation, the same way the rule-based detection built them: multi-valued arguments give
 * one finding per value combination (up to {@link #MAX_VARIANTS}), and arguments passed
 * in from callers are resolved through the {@link CallIndex} into findings located at the caller.
 * Unlike rule trees, a link accepts any object a specified API creates, not only those a rule
 * lists.
 */
final class SpecDetector {

    private static final int MAX_DEPTH = 8;

    /**
     * Most findings one match is split into, one per combination of the possible values of its
     * detectable arguments; beyond this, the values stay together in one finding.
     */
    static final int MAX_VARIANTS = 16;

    private final ApiIndex apis;
    private final Types types;
    private final String locationPrefix;
    private final CallIndex callIndex;

    /** A detectable argument of a call: the call site and the parameter position. */
    private record Point(CallSite call, int index) {}

    private List<Finding> resolved = new ArrayList<>();
    private Map<Point, List<Object>> multiValued;
    private Map<Point, Object> chosen = Map.of();

    /**
     * @param apis the specs
     * @param types the class hierarchy
     * @param locationPrefix prepended to source file paths, e.g. the artifact path {@code g/a/v};
     *     empty for none
     * @param callIndex resolves values passed in from callers; {@code null} for within methods only
     */
    SpecDetector(ApiIndex apis, Types types, String locationPrefix, CallIndex callIndex) {
        this.apis = apis;
        this.types = types;
        this.locationPrefix = locationPrefix.isEmpty() ? "" : locationPrefix + "/";
        this.callIndex = callIndex;
    }

    /**
     * Whether a method calls an API that reports findings on its own: {@link #detect} finds
     * nothing in any other method.
     *
     * @param method the method
     * @return {@code true} if {@link #detect} may find something in it
     */
    boolean mayDetect(Analyzer.MethodResult method) {
        for (CallSite cs : method.calls()) {
            for (ApiSpec spec : apis.match(cs, types)) {
                if (spec.root()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Detects the findings of a method.
     *
     * @param method the method
     * @return the findings, by call site and then API, followed after each by the findings of
     *     values its callers pass
     */
    List<Finding> detect(Analyzer.MethodResult method) {
        final ObjectGraph graph = ObjectGraph.of(method, apis, types);
        final IScanContext<Object, Loc> ctx = new ScanContext(locationPrefix + method.sourceFile());
        final List<Finding> findings = new ArrayList<>();
        for (ApiCall root : graph.roots()) {
            for (DetectionStore<Object, Loc, Object, Object> store : variants(root, graph, ctx)) {
                findings.add(new Finding(Loc.of(root.site()), root.site(), store));
            }
            findings.addAll(resolved);
            resolved = new ArrayList<>();
        }
        return findings;
    }

    private List<DetectionStore<Object, Loc, Object, Object>> variants(ApiCall root, ObjectGraph graph,
            IScanContext<Object, Loc> ctx) {
        final SpecRule rule = SpecRule.of(root.spec(), root.spec().context());
        multiValued = new LinkedHashMap<>();
        final DetectionStore<Object, Loc, Object, Object> merged = StoreAccess.create(0, rule, ctx);
        process(merged, rule, List.of(root.site()), graph, ctx, 0);
        final Map<Point, List<Object>> points = multiValued;
        multiValued = null;
        long count = 1;
        for (List<Object> values : points.values()) {
            count *= values.size();
        }
        if (points.isEmpty() || count > MAX_VARIANTS) {
            return List.of(merged);
        }
        List<Map<Point, Object>> combinations = List.of(Map.of());
        for (Map.Entry<Point, List<Object>> e : points.entrySet()) {
            final List<Map<Point, Object>> next = new ArrayList<>();
            for (Map<Point, Object> c : combinations) {
                for (Object v : e.getValue()) {
                    final Map<Point, Object> m = new LinkedHashMap<>(c);
                    m.put(e.getKey(), v);
                    next.add(m);
                }
            }
            combinations = next;
        }
        final List<Finding> fromCallers = resolved;
        resolved = new ArrayList<>();
        final List<DetectionStore<Object, Loc, Object, Object>> stores = new ArrayList<>();
        for (Map<Point, Object> c : combinations) {
            chosen = c;
            final DetectionStore<Object, Loc, Object, Object> store = StoreAccess.create(0, rule, ctx);
            process(store, rule, List.of(root.site()), graph, ctx, 0);
            stores.add(store);
        }
        chosen = Map.of();
        resolved = fromCallers;
        return stores;
    }

    private Collection<Object> values(CallSite cs, int index, AVal arg) {
        final Point point = new Point(cs, index);
        final Object v = chosen.get(point);
        if (v != null) {
            return List.of(v);
        }
        if (multiValued != null && arg.consts().size() > 1) {
            multiValued.putIfAbsent(point, List.copyOf(arg.consts()));
        }
        return arg.consts();
    }

    @SuppressWarnings("unchecked")
    private void process(DetectionStore<Object, Loc, Object, Object> store, SpecRule rule, List<CallSite> calls,
            ObjectGraph graph, IScanContext<Object, Loc> ctx, int depth) {
        final ApiSpec spec = rule.spec();
        final Context context = rule.context();
        for (CallSite cs : calls) {
            final Loc loc = Loc.of(cs);
            if (spec.action() != null) {
                final Object factory = SpecFactories.create(spec.action());
                if (factory == null) {
                    StoreAccess.setAction(store, (IAction<Loc>) SpecFactories.lambdaAction(spec.action(), loc));
                } else {
                    ((IActionFactory<Loc>) factory).apply(loc).ifPresent(a -> StoreAccess.setAction(store, a));
                }
            }
            for (Arg arg : spec.args()) {
                final int k = arg.index();
                if (k >= cs.args.length) {
                    continue;
                }
                final AVal value = cs.args[k];
                if (arg.value() != null) {
                    final IValueFactory<Loc> factory = (IValueFactory<Loc>) SpecFactories.create(arg.value());
                    for (Object c : values(cs, k, value)) {
                        factory.apply(new ResolvedValue<>(c, loc)).ifPresent(v -> {
                            if (arg.movedUnder() != null) {
                                final DetectionStore<Object, Loc, Object, Object> sub =
                                        StoreAccess.create(store.getLevel() + 1, rule, ctx);
                                StoreAccess.addValue(sub, arg.movedUnder(), v);
                                store.attach(arg.movedUnder(), sub);
                            } else {
                                StoreAccess.addValue(store, k, v);
                            }
                        });
                    }
                    if (value.params() != 0 && callIndex != null) {
                        resolveFromCallers(rule, arg, factory, cs, value.params());
                    }
                }
                if (arg.link()) {
                    follow(store, k, graph.related(value.origins()), arg.roles(), context, graph, ctx, depth);
                }
            }
            if (!spec.next().isEmpty() && cs.created >= 0) {
                // in the spec's order, then call order: translation attaches them in this order,
                // e.g. a signature's verify action before the parameters set on it
                final List<ApiCall> next = graph.related(Set.of(cs.created)).stream()
                        .filter(c -> spec.next().contains(c.spec().api()))
                        .sorted(Comparator.comparingInt(c -> spec.next().indexOf(c.spec().api())))
                        .toList();
                follow(store, -1, next, spec.nextRoles(), context, graph, ctx, depth);
            }
        }
    }

    /**
     * Attaches the related calls to the parent, one child store per API, holding all its calls,
     * as rule trees hold all calls of a rule.
     */
    private void follow(DetectionStore<Object, Loc, Object, Object> parent, int index, List<ApiCall> related,
            List<Role> roles, Context parentContext, ObjectGraph graph, IScanContext<Object, Loc> ctx, int depth) {
        if (related.isEmpty() || depth >= MAX_DEPTH) {
            return;
        }
        final Map<ApiSpec, List<CallSite>> byApi = new LinkedHashMap<>();
        for (ApiCall c : related) {
            byApi.computeIfAbsent(c.spec(), k -> new ArrayList<>()).add(c.site());
        }
        for (Map.Entry<ApiSpec, List<CallSite>> e : byApi.entrySet()) {
            final SpecRule rule = SpecRule.of(e.getKey(), role(roles, parentContext, e.getKey()));
            final DetectionStore<Object, Loc, Object, Object> child = StoreAccess.create(parent.getLevel() + 1, rule, ctx);
            parent.attach(index, child);
            process(child, rule, e.getValue(), graph, ctx, depth + 1);
        }
    }

    /** The linked object's context: the first role of the link that applies, else its API's. */
    static Context role(List<Role> roles, Context parent, ApiSpec linked) {
        for (Role r : roles) {
            if ((r.when() == null || r.when().equals(parent)) && (r.api() == null || r.api().equals(linked.api()))) {
                return r.context();
            }
        }
        return linked.context();
    }

    @SuppressWarnings("unchecked")
    private void resolveFromCallers(SpecRule rule, Arg arg, IValueFactory<Loc> factory, CallSite cs, long params) {
        final int index = arg.movedUnder() != null ? arg.movedUnder() : arg.index();
        for (CallIndex.Hit hit : callIndex.resolve(cs.method, params)) {
            final CallIndex.Site site = hit.site();
            final Loc at = new Loc(site.file(), site.line(), site.signature(), site.name());
            factory.apply(new ResolvedValue<>(hit.value(), at)).ifPresent(v -> {
                final DetectionStore<Object, Loc, Object, Object> store =
                        StoreAccess.create(0, rule, new ScanContext(site.file()));
                StoreAccess.addValue(store, index, v);
                resolved.add(new Finding(at, cs, store));
            });
        }
    }
}
