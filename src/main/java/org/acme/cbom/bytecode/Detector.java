package org.acme.cbom.bytecode;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.StoreAccess;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.rule.DetectableParameter;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.MethodDetectionRule;
import com.ibm.engine.rule.Parameter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.Set;

/**
 * Evaluates sonar-cryptography's detection rules on the call sites of a method, building the same
 * {@link DetectionStore} trees its own engine builds from the AST:
 *
 * <ul>
 *   <li>a root rule matching a call site creates a root store;
 *   <li>detectable parameters turn the argument's possible constant values into values through the
 *       rule's value factory;
 *   <li>a parameter's depending rules are matched against the call sites that created the
 *       argument object, or are invoked on it;
 *   <li>the rule's next rules are matched against call sites invoked on the object the matched
 *       call created, e.g. {@code init} on the {@code Cipher} returned by {@code getInstance}.
 * </ul>
 *
 * <p>Objects are followed within the enclosing method, like sonar-cryptography follows the
 * variable a call is assigned to.
 */
final class Detector {

    private static final int MAX_DEPTH = 8;

    /**
     * A detection to translate and report on its own.
     *
     * @param loc where to report it: the matched call, or for a value resolved from a caller,
     *     the caller's call site
     * @param call the matched call
     * @param store its store tree
     */
    record Finding(Loc loc, CallSite call, DetectionStore<Object, Loc, Object, Object> store) {}

    /** Findings of values resolved from callers, collected while processing a method. */
    private List<Finding> resolved = new ArrayList<>();

    private final List<IDetectionRule<Loc>> rootRules;
    private final Types types;
    private final String locationPrefix;
    /** Resolves values passed in from callers; {@code null} to resolve within methods only. */
    private final CallIndex callIndex;
    /** Root rules by method name; {@link MethodMatcher#ANY} for rules matching any name. */
    private final Map<String, List<IDetectionRule<Loc>>> rulesByMethod = new HashMap<>();

    /**
     * @param rootRules the root detection rules
     * @param types the class hierarchy for matching rules against subtypes
     * @param locationPrefix prepended to source file paths in detection locations, e.g. the
     *     artifact path {@code g/a/v}; empty for none
     * @param callIndex resolves values passed in from callers, possibly in other artifacts;
     *     {@code null} to resolve values within methods only
     */
    Detector(List<IDetectionRule<Loc>> rootRules, Types types, String locationPrefix, CallIndex callIndex) {
        this.callIndex = callIndex;
        this.rootRules = rootRules;
        this.types = types;
        this.locationPrefix = locationPrefix.isEmpty() ? "" : locationPrefix + "/";
        for (IDetectionRule<Loc> rule : rootRules) {
            final MethodMatcher<Loc> m = matcher(rule);
            if (m != null) {
                for (String name : m.getMethodNamesSerializable()) {
                    rulesByMethod.computeIfAbsent(name, k -> new ArrayList<>()).add(rule);
                }
            }
        }
    }

    Detector(List<IDetectionRule<Loc>> rootRules, Types types) {
        this(rootRules, types, "", null);
    }

    List<Finding> detect(Analyzer.MethodResult method) {
        final IScanContext<Object, Loc> ctx = new ScanContext(locationPrefix + method.sourceFile());
        final List<Finding> findings = new ArrayList<>();
        for (CallSite cs : method.calls()) {
            for (IDetectionRule<Loc> rule : candidates(cs)) {
                if (matches(rule, cs)) {
                    final DetectionStore<Object, Loc, Object, Object> store = StoreAccess.create(0, rule, ctx);
                    process(store, rule, List.of(cs), method, ctx, 0);
                    findings.add(new Finding(Loc.of(cs), cs, store));
                    findings.addAll(resolved);
                    resolved = new ArrayList<>();
                }
            }
        }
        return findings;
    }

    /** The root rules that may match a call site, by its method name. */
    private List<IDetectionRule<Loc>> candidates(CallSite cs) {
        final List<IDetectionRule<Loc>> byName = rulesByMethod.getOrDefault(cs.name, List.of());
        final List<IDetectionRule<Loc>> any = rulesByMethod.getOrDefault(MethodMatcher.ANY, List.of());
        if (any.isEmpty()) {
            return byName;
        }
        final List<IDetectionRule<Loc>> all = new ArrayList<>(byName);
        all.addAll(any);
        return all;
    }

    private static MethodMatcher<Loc> matcher(IDetectionRule<Loc> rule) {
        if (rule instanceof DetectionRule<Loc> dr) {
            return dr.matchers();
        }
        if (rule instanceof MethodDetectionRule<Loc> mr) {
            return mr.matchers();
        }
        return null;
    }

    private boolean matches(IDetectionRule<Loc> rule, CallSite cs) {
        final MethodMatcher<Loc> matcher = matcher(rule);
        if (matcher == null) {
            return false;
        }
        // cheap pre-check on the owner type before the matcher's full predicate evaluation
        final List<String> owners = matcher.getInvokedObjectTypeStringsSerializable();
        if (!owners.contains(MethodMatcher.ANY)) {
            final java.util.Set<String> names = rule.shouldMatchExactTypes()
                    ? java.util.Set.of(cs.owner.replace('/', '.'))
                    : types.supertypeNames(cs.owner);
            if (owners.stream().noneMatch(names::contains)) {
                return false;
            }
        }
        return matcher.matchKeys(
                types.ofClass(cs.owner, rule.shouldMatchExactTypes()), cs.name, types.ofParameters(cs.descriptor));
    }

    private void process(DetectionStore<Object, Loc, Object, Object> store, IDetectionRule<Loc> rule,
            List<CallSite> calls, Analyzer.MethodResult method, IScanContext<Object, Loc> ctx, int depth) {
        for (CallSite cs : calls) {
            final Loc loc = Loc.of(cs);
            final Set<Integer> created = cs.created < 0 ? Set.of() : Set.of(cs.created);
            if (rule instanceof MethodDetectionRule<Loc> mr) {
                mr.actionFactory().apply(loc).ifPresent(a -> StoreAccess.setAction(store, a));
                follow(store, -1, mr.nextDetectionRules(), created, method, ctx, depth);
                continue;
            }
            final DetectionRule<Loc> dr = (DetectionRule<Loc>) rule;
            if (dr.actionFactory() != null) {
                dr.actionFactory().apply(loc).ifPresent(a -> StoreAccess.setAction(store, a));
            }
            final List<Parameter<Loc>> params = dr.parameters();
            for (int k = 0; k < params.size() && k < cs.args.length; k++) {
                final Parameter<Loc> p = params.get(k);
                final AVal arg = cs.args[k];
                if (p instanceof DetectableParameter<Loc> dp) {
                    for (Object value : arg.consts()) {
                        dp.getiValueFactory().apply(new ResolvedValue<>(value, loc)).ifPresent(v -> {
                            if (dp.getShouldBeMovedUnder().isPresent()) {
                                final int id = dp.getShouldBeMovedUnder().get();
                                final DetectionStore<Object, Loc, Object, Object> sub =
                                        StoreAccess.create(store.getLevel() + 1, rule, ctx);
                                StoreAccess.addValue(sub, id, v);
                                store.attach(id, sub);
                            } else {
                                StoreAccess.addValue(store, dp.getIndex(), v);
                            }
                        });
                    }
                    if (arg.params() != 0 && callIndex != null) {
                        resolveFromCallers(rule, dp, cs, arg.params());
                    }
                }
                follow(store, p.getIndex(), p.getDetectionRules(), arg.origins(), method, ctx, depth);
            }
            follow(store, -1, dr.nextDetectionRules(), created, method, ctx, depth);
        }
    }

    /**
     * Resolves a detectable argument that is passed in through parameters of the enclosing method,
     * from the constants its callers pass, possibly in other artifacts. Like sonar-cryptography's
     * hook stores, each resolved value becomes a finding of its own: a store of the same rule
     * holding that value, located at the caller's call site, so the asset is reported where the
     * value is chosen.
     *
     * @param rule the rule of the matched call
     * @param dp the detectable parameter
     * @param cs the matched call
     * @param params the enclosing method's parameters the argument may come from
     */
    private void resolveFromCallers(IDetectionRule<Loc> rule, DetectableParameter<Loc> dp, CallSite cs, long params) {
        final int index = dp.getShouldBeMovedUnder().orElse(dp.getIndex());
        for (CallIndex.Hit hit : callIndex.resolve(cs.method, params)) {
            final CallIndex.Site site = hit.site();
            final Loc at = new Loc(site.file(), site.line(), site.signature(), site.name());
            dp.getiValueFactory().apply(new ResolvedValue<>(hit.value(), at)).ifPresent(v -> {
                final DetectionStore<Object, Loc, Object, Object> store =
                        StoreAccess.create(0, rule, new ScanContext(site.file()));
                StoreAccess.addValue(store, index, v);
                resolved.add(new Finding(at, cs, store));
            });
        }
    }

    private void follow(DetectionStore<Object, Loc, Object, Object> parent, int index, List<IDetectionRule<Loc>> rules,
            Set<Integer> origins, Analyzer.MethodResult method, IScanContext<Object, Loc> ctx, int depth) {
        if (rules.isEmpty() || depth >= MAX_DEPTH) {
            return;
        }
        for (IDetectionRule<Loc> rule : rules) {
            final DetectionStore<Object, Loc, Object, Object> child = StoreAccess.create(parent.getLevel() + 1, rule, ctx);
            parent.attach(index, child);
            if (origins.isEmpty()) {
                continue;
            }
            final List<CallSite> matched = new ArrayList<>();
            for (CallSite cs : method.calls()) {
                final boolean related = origins.contains(cs.created)
                        || cs.receiver.origins().stream().anyMatch(origins::contains);
                if (related && matches(rule, cs)) {
                    matched.add(cs);
                }
            }
            process(child, rule, matched, method, ctx, depth + 1);
        }
    }

    /** Provides the file path to sonar-cryptography's translation. */
    private record ScanContext(String path) implements IScanContext<Object, Loc> {
        @Override
        public void reportIssue(Object rule, Loc tree, String message) {}

        @Override
        public org.sonar.api.batch.fs.InputFile getInputFile() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getFilePath() {
            return path;
        }

        @Override
        public String getRelativePath() {
            return path;
        }
    }
}
