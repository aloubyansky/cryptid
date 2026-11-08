package io.github.aloubyansky.cryptid.bytecode;

import io.smallrye.classfile.ClassFile;
import io.smallrye.classfile.ClassModel;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Class hierarchy for rule matching: analyzed classes, plus library and JDK classes read on demand
 * from the class path and the runtime image. Provides {@link IType}s with sonar-java's naming,
 * e.g. {@code javax.crypto.Cipher}, {@code byte[]}, {@code int}.
 */
public final class Types {

    private record Supers(String superclass, List<String> interfaces) {}

    private final Map<String, Optional<Supers>> supers = new HashMap<>();
    private final Map<String, byte[]> extra = new HashMap<>();
    private final ClassLoader loader;
    private final JarCache jarCache;
    private final List<Path> jars;

    /**
     * Creates a hierarchy over classes added with {@link #addClasses(Path)} and the JDK.
     *
     * @param loader the class loader to read JDK and other classes from
     */
    public Types(ClassLoader loader) {
        this(loader, null, List.of());
    }

    /**
     * Creates a hierarchy over the classes of the given JARs and the JDK.
     *
     * @param loader the class loader to read JDK classes from
     * @param jarCache the JAR cache
     * @param jars the JARs to look classes up in, in order
     */
    public Types(ClassLoader loader, JarCache jarCache, List<Path> jars) {
        this.loader = loader;
        this.jarCache = jarCache;
        this.jars = jars;
    }

    /** Makes the classes under a directory known to the hierarchy. */
    public void addClasses(Path dir) throws IOException {
        try (Stream<Path> s = Files.walk(dir)) {
            for (Path p : s.filter(f -> f.toString().endsWith(".class")).toList()) {
                final String rel = dir.relativize(p).toString().replace('\\', '/');
                extra.put(rel.substring(0, rel.length() - ".class".length()), Files.readAllBytes(p));
            }
        }
    }

    private final Map<String, Set<String>> supertypeNames = new HashMap<>();

    /**
     * Returns the fully qualified names of a class and all its supertypes, cached.
     *
     * @param internalName the class's internal name
     * @return names like {@code javax.crypto.Cipher}
     */
    public Set<String> supertypeNames(String internalName) {
        return supertypeNames.computeIfAbsent(internalName, n -> {
            final Set<String> names = new HashSet<>();
            for (String s : supertypes(n)) {
                names.add(s.replace('/', '.'));
            }
            return Set.copyOf(names);
        });
    }

    /** All supertypes of a class, including itself, as internal names. */
    Set<String> supertypes(String internalName) {
        final Set<String> result = new HashSet<>();
        final Deque<String> todo = new ArrayDeque<>(List.of(internalName));
        while (!todo.isEmpty()) {
            final String n = todo.pop();
            if (!result.add(n)) {
                continue;
            }
            supers(n).ifPresent(s -> {
                if (s.superclass() != null) {
                    todo.add(s.superclass());
                }
                todo.addAll(s.interfaces());
            });
        }
        return result;
    }

    private Optional<Supers> supers(String internalName) {
        return supers.computeIfAbsent(internalName, n -> {
            try {
                byte[] bytes = extra.get(n);
                for (int i = 0; bytes == null && i < jars.size(); i++) {
                    bytes = jarCache.read(jars.get(i), n);
                }
                if (bytes == null) {
                    try (InputStream in = loader.getResourceAsStream(n + ".class")) {
                        if (in == null) {
                            return Optional.empty();
                        }
                        bytes = in.readAllBytes();
                    }
                }
                final ClassModel cm = ClassFile.of().parse(bytes);
                return Optional.of(new Supers(
                        cm.superclass().map(c -> c.asInternalName()).orElse(null),
                        cm.interfaces().stream().map(c -> c.asInternalName()).toList()));
            } catch (IOException | RuntimeException e) {
                return Optional.empty();
            }
        });
    }
}
