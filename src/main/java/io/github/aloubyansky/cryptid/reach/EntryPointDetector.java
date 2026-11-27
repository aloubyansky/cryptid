package io.github.aloubyansky.cryptid.reach;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.EntryPoint;
import io.github.aloubyansky.cryptid.MethodId;
import io.github.aloubyansky.cryptid.bytecode.AnnotationInstance;
import io.github.aloubyansky.cryptid.bytecode.ArtifactDeclarations;
import io.github.aloubyansky.cryptid.bytecode.ClassDeclaration;
import io.github.aloubyansky.cryptid.bytecode.Hierarchy;
import io.github.aloubyansky.cryptid.bytecode.MethodDeclaration;
import io.github.aloubyansky.cryptid.spec.EntryPointSpecs.EntryPointSpec;
import io.github.aloubyansky.cryptid.spec.EntryPointSpecs;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Finds an application's entry points in its artifacts with the {@link EntryPointSpecs}, and the
 * classes instantiated without a {@code new} the analysis can see: beans, service providers and
 * the classes declaring entry points.
 *
 * <p>Entry points are searched for in the application's artifacts only. Annotations on supertypes'
 * methods, for specs that inherit them, and bean annotations are read from every artifact.
 */
public final class EntryPointDetector {

    /**
     * An artifact's declarations.
     *
     * @param artifact the artifact
     * @param application whether it is part of the application, and so searched for entry points
     * @param declarations what it declares
     */
    public record Artifact(ArtifactCoordinates artifact, boolean application, ArtifactDeclarations declarations) {}

    /**
     * The entry points and instantiated classes found.
     *
     * @param entryPoints the entry points, in the order of the artifacts, then of class and member
     * @param instantiated internal names of the classes instantiated without a visible {@code new}
     */
    public record Result(List<EntryPoint> entryPoints, Set<String> instantiated) {}

    /**
     * How a method matched a spec: the annotation it matched by, if any, and the method declaring
     * it, the method itself or the supertype method it inherits the annotation from.
     */
    private record Match(AnnotationInstance annotation, MethodDeclaration declaring) {}

    /** An {@code owner#name(parameters)} of the {@code overrides} form. */
    private record OverriddenMethod(String owner, String name, List<String> parameters) {}

    private final EntryPointSpecs specs;
    private final Hierarchy hierarchy;
    private final Map<EntryPointSpec, List<OverriddenMethod>> overrides = new HashMap<>();

    /**
     * Creates a detector.
     *
     * @param specs the specs
     * @param hierarchy the class table, for supertypes
     */
    public EntryPointDetector(EntryPointSpecs specs, Hierarchy hierarchy) {
        this.specs = specs;
        this.hierarchy = hierarchy;
        for (EntryPointSpec s : specs.entryPoints()) {
            final List<OverriddenMethod> list = new ArrayList<>();
            for (String o : s.overrides()) {
                final int hash = o.indexOf('#');
                final int paren = o.indexOf('(', hash);
                final String params = o.substring(paren + 1, o.lastIndexOf(')')).trim();
                list.add(new OverriddenMethod(o.substring(0, hash).replace('.', '/'), o.substring(hash + 1, paren),
                        params.equals("...") ? null : params.isEmpty() ? List.of() : List.of(params.split("\\s*,\\s*"))));
            }
            overrides.put(s, list);
        }
    }

    /**
     * Finds the entry points and instantiated classes.
     *
     * @param artifacts the artifacts' declarations, in the order of the analysis
     * @return what was found
     */
    public Result detect(List<Artifact> artifacts) {
        // every artifact's declarations by class, for supertypes' annotations
        final Map<String, List<ClassDeclaration>> byClass = new HashMap<>();
        for (Artifact a : artifacts) {
            for (ClassDeclaration c : a.declarations().classes()) {
                byClass.computeIfAbsent(c.className(), k -> new ArrayList<>()).add(c);
            }
        }
        final List<EntryPoint> entryPoints = new ArrayList<>();
        final Set<String> instantiated = new TreeSet<>();
        for (Artifact a : artifacts) {
            for (ClassDeclaration c : a.declarations().classes()) {
                if (c.annotations().stream().anyMatch(x -> specs.instantiated().beanAnnotations().contains(x.type()))) {
                    instantiated.add(c.className());
                }
            }
            if (specs.instantiated().services()) {
                a.declarations().services().values().forEach(providers -> providers.forEach(p -> instantiated.add(p.replace('.', '/'))));
            }
            if (!a.application()) {
                continue;
            }
            final List<ClassDeclaration> classes = new ArrayList<>(a.declarations().classes());
            classes.sort(Comparator.comparing(ClassDeclaration::className));
            for (ClassDeclaration c : classes) {
                final List<MethodDeclaration> methods = new ArrayList<>(c.methods());
                methods.sort(Comparator.comparing(MethodDeclaration::member));
                for (MethodDeclaration m : methods) {
                    if (!m.isRegular()) {
                        continue;
                    }
                    final EntryPoint e = entryPoint(a, c, m, byClass);
                    if (e != null) {
                        entryPoints.add(e);
                        if (specs.instantiated().entryPointClasses() && !m.isStatic()) {
                            instantiated.add(c.className());
                        }
                    }
                }
            }
        }
        return new Result(List.copyOf(entryPoints), Set.copyOf(instantiated));
    }

    /** The entry point a method is by the first spec it matches, or {@code null}. */
    private EntryPoint entryPoint(Artifact a, ClassDeclaration c, MethodDeclaration m, Map<String, List<ClassDeclaration>> byClass) {
        for (EntryPointSpec s : specs.entryPoints()) {
            final Match matched = matches(s, a, c, m, byClass);
            if (matched == null) {
                continue;
            }
            final String binary = c.className().replace('/', '.');
            return EntryPoint.builder(new MethodId(binary, m.name(), m.descriptor()), s.kind())
                    .artifact(a.artifact())
                    .exposure("internal".equalsIgnoreCase(s.exposure()) ? EntryPoint.Exposure.INTERNAL : EntryPoint.Exposure.EXTERNAL)
                    .address(address(s, c, matched, byClass))
                    .authenticated(authenticated(c, matched.declaring()))
                    .source(EntryPoint.Source.DETECTED)
                    .build();
        }
        return null;
    }

    /** Placeholder for a match without an annotation, e.g. by signature. */
    private static final AnnotationInstance NO_ANNOTATION = new AnnotationInstance("", Map.of());

    /** How a method matches a spec, or {@code null} if it doesn't. */
    private Match matches(EntryPointSpec s, Artifact a, ClassDeclaration c, MethodDeclaration m,
            Map<String, List<ClassDeclaration>> byClass) {
        if (!s.methodAnnotations().isEmpty()) {
            final AnnotationInstance own = first(m.annotations(), s.methodAnnotations());
            if (own != null) {
                return new Match(own, m);
            }
            if (s.inherited() && !m.isStatic()) {
                for (String t : hierarchy.supertypes(c.className())) {
                    for (ClassDeclaration sc : byClass.getOrDefault(t, List.of())) {
                        for (MethodDeclaration sm : sc.methods()) {
                            if (sm.member().equals(m.member())) {
                                final AnnotationInstance inherited = first(sm.annotations(), s.methodAnnotations());
                                if (inherited != null) {
                                    return new Match(inherited, sm);
                                }
                            }
                        }
                    }
                }
            }
        }
        if (!s.classAnnotations().isEmpty() && m.isPublic() && !m.isStatic() && !m.isAbstract()) {
            final AnnotationInstance onClass = first(c.annotations(), s.classAnnotations());
            if (onClass != null) {
                return new Match(onClass, m);
            }
        }
        if (!s.parameterAnnotations().isEmpty()) {
            for (List<AnnotationInstance> p : m.parameters()) {
                final AnnotationInstance onParameter = first(p, s.parameterAnnotations());
                if (onParameter != null) {
                    return new Match(onParameter, m);
                }
            }
        }
        if (!m.isAbstract() && !m.isStatic()) {
            for (OverriddenMethod o : overrides.get(s)) {
                if (o.name().equals(m.name()) && parametersMatch(o.parameters(), m.descriptor())
                        && hierarchy.supertypes(c.className()).contains(o.owner())) {
                    return new Match(NO_ANNOTATION, m);
                }
            }
        }
        final EntryPointSpecs.Signature sig = s.signature();
        if (sig != null && sig.name().equals(m.name()) && sig.descriptor().equals(m.descriptor())
                && (!sig.isStatic() || m.isStatic()) && (!sig.isPublic() || m.isPublic())) {
            final Optional<String> main = a.declarations().mainClass();
            if (!s.mainClass() || main.isEmpty() || main.get().equals(c.className().replace('/', '.'))) {
                return new Match(NO_ANNOTATION, m);
            }
        }
        return null;
    }

    private static boolean parametersMatch(List<String> expected, String descriptor) {
        if (expected == null) {
            return true;
        }
        final List<ClassDesc> actual = MethodTypeDesc.ofDescriptor(descriptor).parameterList();
        if (actual.size() != expected.size()) {
            return false;
        }
        for (int i = 0; i < actual.size(); i++) {
            if (!binaryName(actual.get(i)).equals(expected.get(i))) {
                return false;
            }
        }
        return true;
    }

    private static String binaryName(ClassDesc d) {
        if (d.isArray()) {
            return binaryName(d.componentType()) + "[]";
        }
        if (d.isPrimitive()) {
            return d.displayName();
        }
        final String s = d.descriptorString();
        return s.substring(1, s.length() - 1).replace('/', '.');
    }

    private static AnnotationInstance first(List<AnnotationInstance> annotations, List<String> types) {
        for (AnnotationInstance a : annotations) {
            if (types.contains(a.type())) {
                return a;
            }
        }
        return null;
    }

    /** The address from annotation values, e.g. {@code POST /realms/{realm}/token}, or {@code null}. */
    private String address(EntryPointSpec s, ClassDeclaration c, Match match, Map<String, List<ClassDeclaration>> byClass) {
        final MethodDeclaration m = match.declaring();
        final AnnotationInstance matched = match.annotation();
        final EntryPointSpecs.Address address = s.address();
        if (address == null) {
            return null;
        }
        if (address.value() != null) {
            final AnnotationInstance a = first(m.annotations(), List.of(address.value()));
            return a == null ? null : a.string("value").orElse(null);
        }
        final String verb = "annotation".equals(address.verb()) ? verb(matched) : null;
        String path = null;
        if (!address.path().isEmpty()) {
            final List<String> parts = new ArrayList<>();
            classPath(c, address.path(), byClass).ifPresent(parts::add);
            final AnnotationInstance onMethod = first(m.annotations(), address.path());
            final Optional<String> methodPath = onMethod != null ? pathOf(onMethod) : pathOf(matched);
            methodPath.ifPresent(parts::add);
            path = join(parts);
        }
        if (verb == null) {
            return path;
        }
        return path == null ? verb : verb + " " + path;
    }

    /** The class's path, from its own annotation, else from the nearest supertype's. */
    private Optional<String> classPath(ClassDeclaration c, List<String> types, Map<String, List<ClassDeclaration>> byClass) {
        final AnnotationInstance own = first(c.annotations(), types);
        if (own != null) {
            return pathOf(own);
        }
        for (String t : hierarchy.supertypes(c.className())) {
            for (ClassDeclaration sc : byClass.getOrDefault(t, List.of())) {
                final AnnotationInstance a = first(sc.annotations(), types);
                if (a != null) {
                    return pathOf(a);
                }
            }
        }
        return Optional.empty();
    }

    private static Optional<String> pathOf(AnnotationInstance a) {
        final Optional<String> value = a.string("value");
        return value.isPresent() ? value : a.string("path");
    }

    private static String join(List<String> parts) {
        final StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            final String trimmed = p.replaceAll("^/+|/+$", "");
            if (!trimmed.isEmpty()) {
                sb.append('/').append(trimmed);
            }
        }
        return sb.length() == 0 ? (parts.isEmpty() ? null : "/") : sb.toString();
    }

    /** The HTTP method an annotation stands for: its name, e.g. {@code GET}, or {@code GetMapping}'s prefix, or {@code RequestMapping}'s {@code method}. */
    private static String verb(AnnotationInstance a) {
        final String name = a.simpleName();
        if (name.equals("RequestMapping")) {
            final List<String> methods = a.strings("method");
            if (methods.isEmpty()) {
                return null;
            }
            final Set<String> verbs = new LinkedHashSet<>();
            methods.forEach(v -> verbs.add(v.substring(v.lastIndexOf('.') + 1)));
            return String.join("|", verbs);
        }
        if (name.endsWith("Mapping")) {
            return name.substring(0, name.length() - "Mapping".length()).toUpperCase(Locale.ROOT);
        }
        return name.isEmpty() ? null : name.toUpperCase(Locale.ROOT);
    }

    /** Whether the method's annotations, else its class's, say authentication is needed. */
    private Boolean authenticated(ClassDeclaration c, MethodDeclaration m) {
        final Boolean onMethod = authenticated(m.annotations());
        return onMethod != null ? onMethod : authenticated(c.annotations());
    }

    private Boolean authenticated(List<AnnotationInstance> annotations) {
        for (AnnotationInstance a : annotations) {
            if (specs.authentication().required().contains(a.type())) {
                return Boolean.TRUE;
            }
            if (specs.authentication().notRequired().contains(a.type())) {
                return Boolean.FALSE;
            }
        }
        return null;
    }

    /**
     * Counts entry points by kind and exposure, for logging.
     *
     * @param entryPoints the entry points
     * @return e.g. {@code http external -> 812}, in order of the counts, largest first
     */
    public static Map<String, Integer> summary(List<EntryPoint> entryPoints) {
        final Map<String, Integer> counts = new HashMap<>();
        for (EntryPoint e : entryPoints) {
            counts.merge(e.kind() + " " + e.exposure().name().toLowerCase(Locale.ROOT), 1, Integer::sum);
        }
        final Map<String, Integer> sorted = new LinkedHashMap<>();
        counts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
                .forEach(e -> sorted.put(e.getKey(), e.getValue()));
        return sorted;
    }
}
