package io.github.aloubyansky.cryptid.bytecode;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Open JARs and their class names, shared by all analyses. {@link ZipFile} supports concurrent
 * reads, so this class is thread-safe.
 */
public final class JarCache implements AutoCloseable {

    private static final String SERVICES = "META-INF/services/";

    private final Map<Path, ZipFile> zips = new ConcurrentHashMap<>();
    private final Map<Path, Set<String>> classNames = new ConcurrentHashMap<>();

    /**
     * Tells whether a JAR entry is a class of the base version, i.e. not a multi-release variant
     * and not a module or package descriptor.
     *
     * @param name the entry name
     * @return {@code true} for regular class entries
     */
    static boolean isBaseClassEntry(String name) {
        return name.endsWith(".class")
                && !name.startsWith("META-INF/")
                && !name.endsWith("module-info.class")
                && !name.endsWith("package-info.class");
    }

    private ZipFile zip(Path jar) {
        return zips.computeIfAbsent(jar, p -> {
            try {
                return new ZipFile(p.toFile());
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to open " + p, e);
            }
        });
    }

    /**
     * Returns the classes of a JAR.
     *
     * @param jar the JAR
     * @return internal names of its base-version classes
     */
    public Set<String> classNames(Path jar) {
        return classNames.computeIfAbsent(jar, p -> zip(p).stream()
                .map(ZipEntry::getName)
                .filter(JarCache::isBaseClassEntry)
                .map(n -> n.substring(0, n.length() - ".class".length()))
                .collect(Collectors.toUnmodifiableSet()));
    }

    /**
     * Reads a class file from a JAR.
     *
     * @param jar the JAR
     * @param internalName the class's internal name
     * @return the class file, or {@code null} if the JAR doesn't contain the class
     */
    public byte[] read(Path jar, String internalName) {
        if (!classNames(jar).contains(internalName)) {
            return null;
        }
        final ZipFile zip = zip(jar);
        final ZipEntry entry = zip.getEntry(internalName + ".class");
        try (InputStream in = zip.getInputStream(entry)) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read " + internalName + " from " + jar, e);
        }
    }

    /**
     * Reads all base-version class files of a JAR.
     *
     * @param jar the JAR
     * @return the class files, in name order
     */
    public List<byte[]> readAll(Path jar) {
        final List<byte[]> result = new ArrayList<>();
        classNames(jar).stream().sorted().forEach(n -> result.add(read(jar, n)));
        return result;
    }

    /**
     * Reads the service provider files of a JAR, {@code META-INF/services/<service type>}.
     *
     * @param jar the JAR
     * @return provider class names, binary, by service type, both in file order; empty if none
     */
    public Map<String, List<String>> services(Path jar) {
        final Map<String, List<String>> result = new TreeMap<>();
        final ZipFile zip = zip(jar);
        zip.stream()
                .filter(e -> !e.isDirectory() && e.getName().startsWith(SERVICES) && e.getName().length() > SERVICES.length())
                .forEach(e -> {
                    final List<String> providers = new ArrayList<>();
                    try (InputStream in = zip.getInputStream(e)) {
                        for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\\R")) {
                            final int hash = line.indexOf('#');
                            final String name = (hash < 0 ? line : line.substring(0, hash)).trim();
                            if (!name.isEmpty()) {
                                providers.add(name);
                            }
                        }
                    } catch (IOException ex) {
                        throw new UncheckedIOException("Failed to read " + e.getName() + " from " + jar, ex);
                    }
                    if (!providers.isEmpty()) {
                        result.put(e.getName().substring(SERVICES.length()), List.copyOf(providers));
                    }
                });
        return result;
    }

    /**
     * Reads the main class a JAR's manifest names.
     *
     * @param jar the JAR
     * @return the binary class name of {@code Main-Class}, or empty if the manifest names none
     */
    public Optional<String> mainClass(Path jar) {
        final ZipFile zip = zip(jar);
        final ZipEntry entry = zip.getEntry("META-INF/MANIFEST.MF");
        if (entry == null) {
            return Optional.empty();
        }
        try (InputStream in = zip.getInputStream(entry)) {
            final String main = new Manifest(in).getMainAttributes().getValue(Attributes.Name.MAIN_CLASS);
            return main == null || main.isBlank() ? Optional.empty() : Optional.of(main.trim());
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    @Override
    public void close() {
        for (ZipFile z : zips.values()) {
            try {
                z.close();
            } catch (IOException e) {
                // ignore
            }
        }
        zips.clear();
    }
}
