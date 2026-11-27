package io.github.aloubyansky.cryptid;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

/** Compiles test sources into JARs. */
public final class TestJars {

    private TestJars() {}

    /**
     * Compiles sources with debug information into a JAR.
     *
     * @param dir the directory to work in
     * @param name the JAR's name, without extension
     * @param sources the sources by path, e.g. {@code org/acme/Foo.java}
     * @param classpath the classpath to compile against, or {@code null}
     * @return the JAR
     * @throws IOException if a file can't be written
     */
    public static Path compile(Path dir, String name, Map<String, String> sources, Path classpath) throws IOException {
        return compile(dir, name, sources, classpath, Map.of());
    }

    /**
     * Compiles sources with debug information into a JAR, with other entries added.
     *
     * @param dir the directory to work in
     * @param name the JAR's name, without extension
     * @param sources the sources by path, e.g. {@code org/acme/Foo.java}
     * @param classpath the classpath to compile against, or {@code null}
     * @param resources other entries by path, e.g. {@code META-INF/MANIFEST.MF}
     * @return the JAR
     * @throws IOException if a file can't be written
     */
    public static Path compile(Path dir, String name, Map<String, String> sources, Path classpath, Map<String, String> resources)
            throws IOException {
        final Path src = dir.resolve(name + "-src");
        final Path classes = Files.createDirectories(dir.resolve(name + "-classes"));
        final List<String> args = new ArrayList<>(List.of("-g", "-proc:none", "-d", classes.toString()));
        if (classpath != null) {
            args.addAll(List.of("-cp", classpath.toString()));
        }
        for (Map.Entry<String, String> e : sources.entrySet()) {
            final Path file = src.resolve(e.getKey());
            Files.createDirectories(file.getParent());
            Files.writeString(file, e.getValue());
            args.add(file.toString());
        }
        final JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        assertEquals(0, javac.run(null, null, null, args.toArray(String[]::new)));
        final Path jar = dir.resolve(name + ".jar");
        try (OutputStream out = Files.newOutputStream(jar);
                JarOutputStream jos = new JarOutputStream(out);
                Stream<Path> files = Files.walk(classes)) {
            for (Path f : files.filter(Files::isRegularFile).sorted().toList()) {
                jos.putNextEntry(new JarEntry(classes.relativize(f).toString().replace('\\', '/')));
                jos.write(Files.readAllBytes(f));
                jos.closeEntry();
            }
            for (Map.Entry<String, String> r : resources.entrySet()) {
                jos.putNextEntry(new JarEntry(r.getKey()));
                jos.write(r.getValue().getBytes(StandardCharsets.UTF_8));
                jos.closeEntry();
            }
        }
        return jar;
    }
}
