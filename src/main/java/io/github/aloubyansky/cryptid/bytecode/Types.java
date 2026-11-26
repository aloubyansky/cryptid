package io.github.aloubyansky.cryptid.bytecode;

import io.smallrye.classfile.ClassFile;
import io.smallrye.classfile.ClassModel;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * Class hierarchy for rule matching: analyzed classes, plus library and JDK classes read on demand
 * from JARs and a fallback, for matching specs that accept subtypes. Names follow sonar-java's
 * naming, e.g. {@code javax.crypto.Cipher}, {@code byte[]}, {@code int}.
 *
 * <p>For scanning, the fallback is the JDK's runtime image ({@link #jdk(JarCache, List)}), so that
 * a scanned class's hierarchy doesn't depend on which of the tool's own dependencies are on its
 * classpath. Tests may fall back to a class loader instead.
 */
public final class Types {

    /** Reads the class file of a class not found in the JARs. */
    @FunctionalInterface
    interface ClassBytes {
        /**
         * Reads a class file.
         *
         * @param internalName the class's internal name
         * @return its bytes, or {@code null} if there is no such class
         * @throws IOException if it can't be read
         */
        byte[] read(String internalName) throws IOException;
    }

    private record Supers(String superclass, List<String> interfaces) {}

    private final Map<String, Optional<Supers>> supers = new HashMap<>();
    private final Map<String, byte[]> extra = new HashMap<>();
    private final ClassBytes fallback;
    private final JarCache jarCache;
    private final List<Path> jars;
    private final Map<String, Set<String>> supertypeNames = new HashMap<>();

    /**
     * Creates a hierarchy over classes added with {@link #addClasses(Path)} and those of a class
     * loader, including the JDK's.
     *
     * @param loader the class loader to read other classes from
     */
    public Types(ClassLoader loader) {
        this(loader, null, List.of());
    }

    /**
     * Creates a hierarchy over the classes of the given JARs and those of a class loader.
     *
     * @param loader the class loader to read classes not in the JARs from
     * @param jarCache the JAR cache
     * @param jars the JARs to look classes up in, in order
     */
    public Types(ClassLoader loader, JarCache jarCache, List<Path> jars) {
        this(n -> {
            try (InputStream in = loader.getResourceAsStream(n + ".class")) {
                return in == null ? null : in.readAllBytes();
            }
        }, jarCache, jars);
    }

    private Types(ClassBytes fallback, JarCache jarCache, List<Path> jars) {
        this.fallback = fallback;
        this.jarCache = jarCache;
        this.jars = jars;
    }

    /**
     * Creates a hierarchy over the classes of the given JARs and the JDK's runtime image, and
     * nothing else.
     *
     * @param jarCache the JAR cache, or {@code null} if there are no JARs
     * @param jars the JARs to look classes up in, in order
     * @return the hierarchy
     */
    public static Types jdk(JarCache jarCache, List<Path> jars) {
        return new Types(JdkClasses::read, jarCache, jars);
    }

    /**
     * Makes the classes under a directory known to the hierarchy, e.g. compiled test fixtures.
     *
     * @param dir the root of a class file tree
     * @throws IOException if the directory can't be read
     */
    public void addClasses(Path dir) throws IOException {
        try (Stream<Path> s = Files.walk(dir)) {
            for (Path p : s.filter(f -> f.toString().endsWith(".class")).toList()) {
                final String rel = dir.relativize(p).toString().replace('\\', '/');
                extra.put(rel.substring(0, rel.length() - ".class".length()), Files.readAllBytes(p));
            }
        }
    }

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

    /**
     * All supertypes of a class: superclasses and interfaces, transitively.
     *
     * @param internalName the class's internal name
     * @return the internal names of the class and its supertypes; a class that can't be read is
     *     included, without its supertypes
     */
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
                    bytes = fallback.read(n);
                    if (bytes == null) {
                        return Optional.empty();
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

    /** Classes of the JDK's runtime image, read through the {@code jrt:/} file system. */
    private static final class JdkClasses {

        private static final FileSystem JRT = FileSystems.getFileSystem(URI.create("jrt:/"));
        /** package name with dots -> the modules containing it */
        private static final Map<String, List<String>> MODULES = new ConcurrentHashMap<>();

        private JdkClasses() {}

        static byte[] read(String internalName) throws IOException {
            final int slash = internalName.lastIndexOf('/');
            if (slash < 0) {
                return null;
            }
            for (String module : modules(internalName.substring(0, slash).replace('/', '.'))) {
                final Path p = JRT.getPath("/modules", module, internalName + ".class");
                if (Files.exists(p)) {
                    return Files.readAllBytes(p);
                }
            }
            return null;
        }

        private static List<String> modules(String pkg) {
            return MODULES.computeIfAbsent(pkg, k -> {
                final List<String> modules = new ArrayList<>(1);
                try (DirectoryStream<Path> s = Files.newDirectoryStream(JRT.getPath("/packages", k))) {
                    s.forEach(m -> modules.add(m.getFileName().toString()));
                } catch (NoSuchFileException e) {
                    // not a JDK package
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
                modules.sort(null);
                return List.copyOf(modules);
            });
        }
    }
}
