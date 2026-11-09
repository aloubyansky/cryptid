package io.github.aloubyansky.cryptid.reference;

import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.model.IAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.ISupportKind;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.rule.DetectableParameter;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.MethodDetectionRule;
import com.ibm.engine.rule.Parameter;
import io.github.aloubyansky.cryptid.BuildInfo;
import io.github.aloubyansky.cryptid.detection.Loc;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.ApiSpec;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Arg;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Context;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Factory;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Role;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;

/**
 * Exports sonar-cryptography's Java detection rules as {@link CryptoApiSpecs}: one entry per API method,
 * instead of a rule tree per root API.
 *
 * <p>A rule matches one or more API methods (owner types × method names, with parameter types).
 * Everything a rule says about its method is the same in every tree the method appears in, except
 * the detection context, which a few parents override: such contexts become {@link Role}s on the
 * parent's argument or next calls. The objects an argument may be created by (a rule's depending
 * rules) aren't exported: in an object graph a link is the object actually passed. The {@link
 * Report} lists anything that doesn't fit.
 *
 * <p>Runs sonar-cryptography's rule definitions (Apache-2.0) in this JVM; no SonarSource analyzer.
 */
public final class RuleSpecExporter {

    /** A location for probing action factories, which only wrap it in the value they create. */
    private static final Loc PROBE = new Loc("Probe.java", 1, "probe", "probe");

    /** Comparison of everything a rule says about its API method, except context and next calls. */
    private record Base(boolean subtypes, String library, Factory action, List<Arg> args) {}

    /**
     * What the export couldn't express without choosing, for review.
     *
     * @param rules distinct rules walked
     * @param apis API methods exported
     * @param roots API methods matched by root rules
     * @param conflicts API methods whose rules disagree on more than the context
     * @param rootContexts API methods with several contexts as roots; the first sorted is used
     * @param pathDependent (parent link, parent context, child) cases where the child still has
     *     several contexts, i.e. its role depends on more than its parent link and the parent's role
     * @param roles roles exported
     */
    record Report(int rules, int apis, int roots, List<String> conflicts, List<String> rootContexts,
            List<String> pathDependent, int roles) {

        String summary() {
            final StringBuilder sb = new StringBuilder();
            sb.append(String.format("rules %d -> API methods %d (%d roots, %d nested only), roles %d%n",
                    rules, apis, roots, apis - roots, roles));
            sb.append("conflicts beyond context: ").append(conflicts.size()).append('\n');
            conflicts.forEach(c -> sb.append("  ").append(c).append('\n'));
            sb.append("several contexts as root: ").append(rootContexts.size()).append('\n');
            rootContexts.forEach(c -> sb.append("  ").append(c).append('\n'));
            sb.append("roles depending on more than the parent link and the parent's role: ").append(pathDependent.size()).append('\n');
            pathDependent.forEach(c -> sb.append("  ").append(c).append('\n'));
            return sb.toString();
        }
    }

    /** The specs and the report. */
    record Export(CryptoApiSpecs specs, Report report) {}

    private final Map<String, Base> bases = new TreeMap<>();
    private final Map<String, List<String>> conflicts = new TreeMap<>();
    private final Map<String, Set<Context>> rootContexts = new TreeMap<>();
    /** parent link ({@code api|argIndex} or {@code api|next}) -> parent's context -> child API -> contexts */
    private final Map<String, Map<Context, Map<String, Set<Context>>>> links = new TreeMap<>();
    /** child API -> context -> occurrences under links */
    private final Map<String, Map<Context, Integer>> linkedContexts = new TreeMap<>();
    private final Map<String, Set<String>> next = new TreeMap<>();

    /**
     * Exports the rules.
     *
     * @param roots sonar-cryptography's root rules
     * @return the specs with the report
     */
    Export export(List<IDetectionRule<Loc>> roots) {
        final Set<IDetectionRule<Loc>> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (IDetectionRule<Loc> r : roots) {
            for (String api : apis(r)) {
                rootContexts.computeIfAbsent(api, k -> new TreeSet<>(CONTEXT_ORDER)).add(context(r.detectionValueContext()));
            }
        }
        final Deque<IDetectionRule<Loc>> todo = new ArrayDeque<>(roots);
        while (!todo.isEmpty()) {
            final IDetectionRule<Loc> r = todo.poll();
            if (!seen.add(r)) {
                continue;
            }
            final List<String> apis = apis(r);
            final Base base = base(r);
            for (String api : apis) {
                final Base existing = bases.putIfAbsent(api, base);
                if (existing != null && !existing.equals(base)) {
                    conflicts.computeIfAbsent(api, k -> new ArrayList<>()).add(existing + " vs " + base);
                }
            }
            if (r instanceof DetectionRule<Loc> dr) {
                for (Parameter<Loc> p : dr.parameters()) {
                    for (IDetectionRule<Loc> child : p.getDetectionRules()) {
                        apis.forEach(api -> linked(api + "|" + p.getIndex(), r, child));
                        todo.add(child);
                    }
                }
            }
            for (IDetectionRule<Loc> n : r.nextDetectionRules()) {
                for (String api : apis) {
                    linked(api + "|next", r, n);
                    // in rule order: translation attaches next calls in this order
                    next.computeIfAbsent(api, k -> new LinkedHashSet<>()).addAll(apis(n));
                }
                todo.add(n);
            }
        }

        final Map<String, Context> defaults = new TreeMap<>();
        final List<String> severalAsRoot = new ArrayList<>();
        for (String api : bases.keySet()) {
            final Set<Context> asRoot = rootContexts.get(api);
            if (asRoot != null) {
                defaults.put(api, asRoot.iterator().next());
                if (asRoot.size() > 1) {
                    severalAsRoot.add(api + " " + asRoot);
                }
            } else {
                // the most frequent context under its parents' links
                defaults.put(api, linkedContexts.get(api).entrySet().stream()
                        .sorted(Map.Entry.<Context, Integer>comparingByValue().reversed()
                                .thenComparing(Map.Entry.comparingByKey(CONTEXT_ORDER)))
                        .findFirst().orElseThrow().getKey());
            }
        }

        final List<String> pathDependent = new ArrayList<>();
        final Map<String, List<Role>> rolesByLink = new TreeMap<>();
        int roleCount = 0;
        for (Map.Entry<String, Map<Context, Map<String, Set<Context>>>> link : links.entrySet()) {
            // child -> parent context -> its context there, where it isn't the child's default
            final Map<Context, Map<String, Context>> overrides = new TreeMap<>(CONTEXT_ORDER);
            final Set<String> children = new TreeSet<>();
            for (Map.Entry<Context, Map<String, Set<Context>>> byParent : link.getValue().entrySet()) {
                for (Map.Entry<String, Set<Context>> child : byParent.getValue().entrySet()) {
                    children.add(child.getKey());
                    if (child.getValue().size() > 1) {
                        pathDependent.add(link.getKey() + " when " + byParent.getKey() + " -> " + child.getKey() + " " + child.getValue());
                    }
                    for (Context c : child.getValue()) {
                        if (!c.equals(defaults.get(child.getKey()))) {
                            overrides.computeIfAbsent(byParent.getKey(), k -> new TreeMap<>()).put(child.getKey(), c);
                        }
                    }
                }
            }
            // a role needs its parent context only if the link has overrides under some parent
            // contexts and not others, or different ones
            final Set<String> distinct = new TreeSet<>();
            overrides.values().forEach(m -> distinct.add(m.toString()));
            final boolean conditional = overrides.size() < link.getValue().size() || distinct.size() > 1;
            final List<Role> roles = new ArrayList<>();
            for (Map.Entry<Context, Map<String, Context>> o : overrides.entrySet()) {
                final Context when = conditional ? o.getKey() : null;
                final Set<Context> contexts = new TreeSet<>(CONTEXT_ORDER);
                contexts.addAll(o.getValue().values());
                final Set<String> childrenUnderParent = link.getValue().get(o.getKey()).keySet();
                if (contexts.size() == 1 && o.getValue().keySet().equals(childrenUnderParent)) {
                    // the same context for every object linked here
                    roles.add(new Role(when, null, contexts.iterator().next()));
                } else {
                    o.getValue().forEach((api, c) -> roles.add(new Role(when, api, c)));
                }
                if (!conditional) {
                    break;
                }
            }
            if (!roles.isEmpty()) {
                rolesByLink.put(link.getKey(), roles);
                roleCount += roles.size();
            }
        }

        final List<ApiSpec> specs = new ArrayList<>();
        for (Map.Entry<String, Base> e : bases.entrySet()) {
            final String api = e.getKey();
            final Base b = e.getValue();
            final List<Arg> args = b.args().stream()
                    .map(a -> new Arg(a.index(), a.type(), a.value(), a.movedUnder(), a.link(),
                            rolesByLink.getOrDefault(api + "|" + a.index(), List.of())))
                    .toList();
            specs.add(new ApiSpec(api, b.subtypes(), b.library(), defaults.get(api), rootContexts.containsKey(api),
                    b.action(), args, List.copyOf(next.getOrDefault(api, Set.of())),
                    rolesByLink.getOrDefault(api + "|next", List.of())));
        }
        final List<String> conflictLines = new ArrayList<>();
        conflicts.forEach((api, list) -> conflictLines.add(api + ": " + list.size() + " differing rules, e.g. " + list.get(0)));
        final Report report = new Report(seen.size(), specs.size(), rootContexts.size(), conflictLines, severalAsRoot,
                pathDependent, roleCount);
        return new Export(new CryptoApiSpecs(CryptoApiSpecs.VERSION,
                new CryptoApiSpecs.Source("sonar-cryptography", BuildInfo.SONAR_CRYPTOGRAPHY_VERSION, "Apache-2.0"), specs), report);
    }

    private void linked(String link, IDetectionRule<Loc> parent, IDetectionRule<Loc> child) {
        final Context p = context(parent.detectionValueContext());
        final Context c = context(child.detectionValueContext());
        for (String api : apis(child)) {
            links.computeIfAbsent(link, k -> new TreeMap<>(CONTEXT_ORDER))
                    .computeIfAbsent(p, k -> new TreeMap<>())
                    .computeIfAbsent(api, k -> new TreeSet<>(CONTEXT_ORDER)).add(c);
            linkedContexts.computeIfAbsent(api, k -> new TreeMap<>(CONTEXT_ORDER)).merge(c, 1, Integer::sum);
        }
    }

    /**
     * Writes specs as YAML, with a header naming their origin.
     *
     * @param specs the specs
     * @return the YAML document
     */
    static String yaml(CryptoApiSpecs specs) throws Exception {
        final String header = """
                # Crypto API specifications, one entry per API method; see docs/detection-redesign.md.
                # Generated by RuleSpecExporter (src/test/java) from sonar-cryptography %s's Java detection rules,
                # https://github.com/cbomkit/sonar-cryptography, Copyright (C) 2024 PQCA, Apache License 2.0.
                # For comparison with the hand-maintained src/main/resources/crypto-api-specs.yaml
                # (written by RuleSpecDriftTest); never copied over it.
                """.formatted(specs.source().version());
        return header + mapper().writeValueAsString(specs);
    }

    static YAMLMapper mapper() {
        return new YAMLMapper(YAMLFactory.builder()
                .disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
                .enable(YAMLGenerator.Feature.MINIMIZE_QUOTES)
                .enable(YAMLGenerator.Feature.INDENT_ARRAYS_WITH_INDICATOR)
                .disable(YAMLGenerator.Feature.SPLIT_LINES)
                .build());
    }

    /**
     * The API methods a rule matches: {@code owner#name(parameter types)}, or {@code
     * owner#name(...)} for a matcher built without parameter types, which accepts any.
     */
    private static List<String> apis(IDetectionRule<Loc> rule) {
        final MethodMatcher<Loc> m = RuleTable.matcher(rule);
        final String params = anyParameters(m) ? "(" + CryptoApiSpecs.ANY_PARAMETERS + ")"
                : "(" + String.join(", ", m.getParameterTypesSerializable()) + ")";
        final List<String> result = new ArrayList<>();
        for (String owner : m.getInvokedObjectTypeStringsSerializable()) {
            for (String name : m.getMethodNamesSerializable()) {
                result.add(owner + "#" + name + params);
            }
        }
        return result;
    }

    /**
     * Whether a matcher accepts any parameters: built without parameter types, its parameter
     * predicate accepts any list, while one built with an empty list only accepts none. Both have
     * no serialized parameter types, so the predicate is tested.
     */
    @SuppressWarnings("unchecked")
    public static boolean anyParameters(MethodMatcher<Loc> m) {
        if (!m.getParameterTypesSerializable().isEmpty()) {
            return false;
        }
        try {
            final Field f = MethodMatcher.class.getDeclaredField("parameterTypes");
            f.setAccessible(true);
            final IType unknown = type -> false;
            return ((Predicate<List<IType>>) f.get(m)).test(List.of(unknown));
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Can't read MethodMatcher.parameterTypes", e);
        }
    }

    private static Base base(IDetectionRule<Loc> rule) {
        final IActionFactory<Loc> action;
        final List<Arg> args = new ArrayList<>();
        if (rule instanceof DetectionRule<Loc> dr) {
            action = dr.actionFactory();
            for (Parameter<Loc> p : dr.parameters()) {
                Factory value = null;
                Integer movedUnder = null;
                if (p instanceof DetectableParameter<Loc> dp) {
                    value = factory(dp.getiValueFactory(), null);
                    movedUnder = dp.getShouldBeMovedUnder().orElse(null);
                }
                args.add(new Arg(p.getIndex(), p.getParameterType(), value, movedUnder,
                        !p.getDetectionRules().isEmpty(), List.of()));
            }
        } else {
            action = ((MethodDetectionRule<Loc>) rule).actionFactory();
        }
        final Factory a = action == null ? null : factory(action, action.apply(PROBE).map(RuleSpecExporter::describe).orElse(null));
        return new Base(!rule.shouldMatchExactTypes(), rule.bundle().getIdentifier(), a, List.copyOf(args));
    }

    private static String describe(IAction<Loc> a) {
        return a.getClass().getSimpleName() + " " + a.asString();
    }

    /** A factory's class and configuration fields, read reflectively. */
    private static Factory factory(Object f, String probed) {
        String result = probed;
        final Class<?> type = f.getClass();
        if (type.isSynthetic() || type.getName().contains("$$Lambda")) {
            return new Factory("lambda", Map.of(), result);
        }
        // a factory class's result follows from its configuration
        result = null;
        final Map<String, String> config = new TreeMap<>();
        for (Class<?> c = type; c != null && c != Object.class; c = c.getSuperclass()) {
            for (Field field : c.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers()) || field.isSynthetic()) {
                    continue;
                }
                try {
                    field.setAccessible(true);
                    final Object v = field.get(f);
                    if (v != null) {
                        config.put(field.getName(), String.valueOf(v));
                    }
                } catch (ReflectiveOperationException | RuntimeException e) {
                    config.put(field.getName(), "?");
                }
            }
        }
        return new Factory(type.getSimpleName(), config, result);
    }

    public static Context context(IDetectionContext c) {
        String kind = null;
        if (c instanceof ISupportKind<?> sk && sk.kind() != null) {
            kind = String.valueOf(sk.kind());
        }
        final Map<String, String> properties = new TreeMap<>();
        if (c instanceof DetectionContext) {
            for (Class<?> t = c.getClass(); t != null && t != Object.class; t = t.getSuperclass()) {
                try {
                    final Field f = t.getDeclaredField("properties");
                    f.setAccessible(true);
                    @SuppressWarnings("unchecked")
                    final Map<String, String> p = (Map<String, String>) f.get(c);
                    if (p != null) {
                        properties.putAll(p);
                    }
                    break;
                } catch (NoSuchFieldException e) {
                    // look in the superclass
                } catch (ReflectiveOperationException e) {
                    break;
                }
            }
        }
        return new Context(c.type().getSimpleName(), kind, properties.isEmpty() ? null : properties);
    }

    private static final Comparator<Context> CONTEXT_ORDER = Comparator.comparing(Context::type)
            .thenComparing(c -> Optional.ofNullable(c.kind()).orElse(""))
            .thenComparing(c -> c.properties() == null ? "" : new LinkedHashMap<>(c.properties()).toString());
}
