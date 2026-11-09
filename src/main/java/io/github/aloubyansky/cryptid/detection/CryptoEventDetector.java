package io.github.aloubyansky.cryptid.detection;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IAction;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.model.factory.IValueFactory;
import io.github.aloubyansky.cryptid.bytecode.AVal;
import io.github.aloubyansky.cryptid.bytecode.Analyzer;
import io.github.aloubyansky.cryptid.bytecode.CallIndex;
import io.github.aloubyansky.cryptid.bytecode.CallSite;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.detection.CryptoObjectGraph.CryptoApiCall;
import io.github.aloubyansky.cryptid.detection.CryptoObjectGraph.Path;
import io.github.aloubyansky.cryptid.detection.CryptoObjectGraph.Reached;
import io.github.aloubyansky.cryptid.spec.CryptoApiMatcher;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.ApiSpec;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Arg;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Context;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Role;
import java.lang.constant.MethodTypeDesc;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Detects crypto events from the crypto API specs: each call to an API that reports on its own is
 * a finding, a tree of {@link CryptoEvent}s built from the method's {@link CryptoObjectGraph}: the
 * events on the created object the spec lists as next, and the events of the objects passed
 * through linking arguments, in the roles the specs give them.
 *
 * <p>Event trees are built the way the rule-based detection built sonar-cryptography's detection
 * stores: multi-valued arguments give one finding per value combination (up to {@link
 * #MAX_VARIANTS}), and arguments passed in from callers are resolved through the {@link CallIndex}
 * into findings located at the caller. Unlike rule trees, a link accepts any object a specified
 * API creates, not only those a rule lists, and a link that may be one of several such objects is
 * a choice too, giving one finding per object.
 */
public final class CryptoEventDetector {

    private static final int MAX_DEPTH = 8;

    /**
     * Most findings one match is split into, one per combination of the possible values of its
     * detectable arguments; beyond this, the values stay together in one finding.
     */
    public static final int MAX_VARIANTS = 16;

    private final CryptoApiMatcher matcher;
    private final Types types;
    private final String locationPrefix;
    private final CallIndex callIndex;

    /**
     * A choice in a finding: the constant of a detectable argument, or the object of a linking
     * argument, of a call site's parameter.
     */
    private record Point(CallSite call, int index, boolean object) {}

    private List<Finding> resolved = new ArrayList<>();
    private Map<Point, List<Object>> multiValued;
    private Map<Point, Object> chosen = Map.of();

    /**
     * Creates a detector for one JAR.
     *
     * @param matcher the spec matcher
     * @param types the class hierarchy
     * @param locationPrefix prepended to source file paths, e.g. the artifact path {@code g/a/v};
     *     empty for none
     * @param callIndex resolves values passed in from callers; {@code null} for within methods only
     */
    public CryptoEventDetector(CryptoApiMatcher matcher, Types types, String locationPrefix, CallIndex callIndex) {
        this.matcher = matcher;
        this.types = types;
        this.locationPrefix = locationPrefix.isEmpty() ? "" : locationPrefix + "/";
        this.callIndex = callIndex;
    }

    /**
     * Whether a method calls a specified API: detection in a set of methods finds events only in
     * such methods. An event can be in a method without root APIs, e.g. {@code init} in a helper
     * the object is passed to, so these methods are kept too.
     *
     * @param method the method
     * @return {@code true} if the method may contain crypto events
     */
    public boolean mayDetect(Analyzer.MethodResult method) {
        for (CallSite cs : method.calls()) {
            if (!matcher.match(cs, types).isEmpty()) {
                return true;
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
    public List<Finding> detect(Analyzer.MethodResult method) {
        return detect(List.of(method));
    }

    /**
     * Detects the findings of methods, following crypto objects between them.
     *
     * @param methods the methods, e.g. a JAR's methods that may contain crypto events
     * @return the findings, by method, call site and then API, followed after each by the findings
     *     of values its callers pass
     */
    public List<Finding> detect(List<Analyzer.MethodResult> methods) {
        final CryptoObjectGraph graph = CryptoObjectGraph.of(methods, matcher, types);
        final List<Finding> findings = new ArrayList<>();
        for (CryptoApiCall root : graph.roots()) {
            final List<CryptoEvent> events = variants(root, graph);
            for (CryptoEvent d : events) {
                findings.add(new Finding(Loc.of(root.site()), root.site(), d, events.size() > 1));
            }
            findings.addAll(resolved);
            resolved = new ArrayList<>();
        }
        return findings;
    }

    private List<CryptoEvent> variants(CryptoApiCall root, CryptoObjectGraph graph) {
        final String file = file(root.site());
        final List<Reached> start = List.of(new Reached(root, Path.ROOT));
        multiValued = new LinkedHashMap<>();
        final CryptoEvent merged = CryptoEvent.of(root.spec(), root.spec().context(), file);
        process(merged, start, graph, 0);
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
        final List<CryptoEvent> events = new ArrayList<>();
        for (Map<Point, Object> c : combinations) {
            chosen = c;
            final CryptoEvent d = CryptoEvent.of(root.spec(), root.spec().context(), file);
            process(d, start, graph, 0);
            events.add(d);
        }
        chosen = Map.of();
        resolved = fromCallers;
        return events;
    }

    private Collection<Object> values(CallSite cs, int index, AVal arg) {
        final Point point = new Point(cs, index, false);
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
    private void process(CryptoEvent store, List<Reached> calls, CryptoObjectGraph graph, int depth) {
        final ApiSpec spec = store.spec();
        final Context context = store.context();
        final String file = store.file();
        for (Reached reached : calls) {
            final CallSite cs = reached.call().site();
            final Path path = reached.path();
            final Loc loc = Loc.of(cs);
            if (spec.action() != null) {
                final Object factory = ValueFactories.create(spec.action());
                if (factory == null) {
                    store.action((IAction<Loc>) ValueFactories.lambdaAction(spec.action(), loc));
                } else {
                    ((IActionFactory<Loc>) factory).apply(loc).ifPresent(store::action);
                }
            }
            for (Arg arg : spec.args()) {
                final int k = arg.index();
                if (k >= cs.args().length) {
                    continue;
                }
                final AVal value = cs.args()[k];
                if (arg.value() != null) {
                    final IValueFactory<Loc> factory = (IValueFactory<Loc>) ValueFactories.create(arg.value());
                    for (Object constant : values(cs, k, value)) {
                        final Object c = matcher.name(arg.value(), constant);
                        if (c == null) {
                            continue;
                        }
                        factory.apply(new ResolvedValue<>(c, loc)).ifPresent(v -> {
                            if (arg.movedUnder() != null) {
                                final CryptoEvent sub = CryptoEvent.of(spec, context, file);
                                sub.addValue(arg.movedUnder(), v);
                                store.attach(arg.movedUnder(), sub);
                            } else {
                                store.addValue(k, v);
                            }
                        });
                    }
                    if (value.params() != 0 && callIndex != null) {
                        resolveFromCallers(spec, context, arg, factory, cs, value.params());
                    }
                }
                if (arg.link()) {
                    follow(store, k, linked(cs, k, value, path, graph), arg.roles(), context, graph, depth);
                }
            }
            if (!spec.next().isEmpty() && cs.created() >= 0) {
                // in the spec's order, then call order: translation attaches them in this order,
                // e.g. a signature's verify action before the parameters set on it
                final List<Reached> next = graph.createdBy(cs, path).stream()
                        .filter(r -> spec.next().contains(r.call().spec().api()))
                        .sorted(Comparator.comparingInt(r -> spec.next().indexOf(r.call().spec().api())))
                        .toList();
                follow(store, -1, next, spec.nextRoles(), context, graph, depth);
            }
        }
    }

    /**
     * The calls of the objects a linking argument may be. When it may be one of several objects
     * with calls to specified APIs, e.g. a parameter spec chosen in a {@code switch}, each is a
     * choice, as each constant of a multi-valued argument is: one finding per object, instead of
     * one finding holding them all, where translation would keep one of them.
     */
    private List<Reached> linked(CallSite cs, int index, AVal value, Path path, CryptoObjectGraph graph) {
        if (value.origins().size() < 2) {
            return graph.related(cs, value, path);
        }
        final Point point = new Point(cs, index, true);
        final Object origin = chosen.get(point);
        if (origin != null) {
            return graph.related(cs, Set.of((Integer) origin), value.params(), path);
        }
        if (multiValued != null) {
            final List<Object> objects = new ArrayList<>();
            for (int o : value.origins()) {
                if (!graph.related(cs, Set.of(o), 0, path).isEmpty()) {
                    objects.add(o);
                }
            }
            if (objects.size() > 1) {
                multiValued.putIfAbsent(point, objects);
            }
        }
        return graph.related(cs, value, path);
    }

    /**
     * Attaches the related calls to the parent, one child event per API, holding all its
     * calls, as rule trees held all calls of a rule.
     */
    private void follow(CryptoEvent parent, int index, List<Reached> related, List<Role> roles, Context parentContext,
            CryptoObjectGraph graph, int depth) {
        if (related.isEmpty() || depth >= MAX_DEPTH) {
            return;
        }
        // one child event per API and source file, holding all its calls there, as rule trees
        // held all calls of a rule; calls in other files are events of their own file
        final Map<ApiSpec, Map<String, List<Reached>>> byApi = new LinkedHashMap<>();
        for (Reached r : related) {
            byApi.computeIfAbsent(r.call().spec(), k -> new LinkedHashMap<>())
                    .computeIfAbsent(file(r.call().site()), k -> new ArrayList<>()).add(r);
        }
        byApi.forEach((spec, byFile) -> byFile.forEach((file, calls) -> {
            final CryptoEvent child = CryptoEvent.of(spec, role(roles, parentContext, spec), file);
            parent.attach(index, child);
            process(child, calls, graph, depth + 1);
        }));
    }

    /** The source file of a call, prefixed with the artifact path. */
    private String file(CallSite cs) {
        return locationPrefix + cs.sourceFile();
    }

    /**
     * The context a linked object plays its role in.
     *
     * @param roles the roles of the link: the linking argument's or the next calls'
     * @param parent the context of the event linking it
     * @param linked the spec of the API that created the linked object
     * @return the first role that applies under the parent's context and to the linked API, else
     *     the linked API's own context
     */
    static Context role(List<Role> roles, Context parent, ApiSpec linked) {
        for (Role r : roles) {
            if ((r.when() == null || r.when().equals(parent)) && (r.api() == null || r.api().equals(linked.api()))) {
                return r.context();
            }
        }
        return linked.context();
    }

    /**
     * Whether the caller's call is a finding of its own: a call to a root API, e.g. a library
     * constructor delegating to another one passes on the value its caller gave it. The caller's
     * finding reports the value, with the events on the object, so resolving it here would report
     * it again with less.
     */
    private boolean reportedAtCaller(CallIndex.Site site) {
        final String signature = site.signature();
        final String owner = signature.substring(0, signature.indexOf('#')).replace('.', '/');
        final String descriptor = signature.substring(signature.indexOf('('));
        final CallSite call = new CallSite(-1, site.callerMethod(), site.file(), owner, site.name(), descriptor, false,
                site.line(), MethodTypeDesc.ofDescriptor(descriptor).parameterCount());
        return matcher.match(call, types).stream().anyMatch(ApiSpec::root);
    }

    @SuppressWarnings("unchecked")
    private void resolveFromCallers(ApiSpec spec, Context context, Arg arg, IValueFactory<Loc> factory, CallSite cs,
            long params) {
        final int index = arg.movedUnder() != null ? arg.movedUnder() : arg.index();
        for (CallIndex.Hit hit : callIndex.resolve(cs.method(), params)) {
            final CallIndex.Site site = hit.site();
            if (reportedAtCaller(site)) {
                continue;
            }
            final Loc at = new Loc(site.file(), site.line(), site.signature(), site.name());
            final Object c = matcher.name(arg.value(), hit.value());
            if (c == null) {
                continue;
            }
            factory.apply(new ResolvedValue<>(c, at)).ifPresent(v -> {
                final CryptoEvent d = CryptoEvent.of(spec, context, site.file());
                d.addValue(index, v);
                resolved.add(new Finding(at, cs, d, false));
            });
        }
    }
}
