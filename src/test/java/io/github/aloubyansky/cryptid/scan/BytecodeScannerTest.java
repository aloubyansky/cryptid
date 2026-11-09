package io.github.aloubyansky.cryptid.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.aloubyansky.cryptid.bytecode.Analyzer;
import io.github.aloubyansky.cryptid.bytecode.CallIndex;
import io.github.aloubyansky.cryptid.bytecode.JarCache;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BytecodeScannerTest {

    private static final String SOURCE = """
            package org.acme.sample;

            import javax.crypto.Cipher;
            import javax.crypto.KeyGenerator;
            import java.security.MessageDigest;

            public class Sample {
                private static final String DIGEST = "SHA-256";
                private String transformation = "AES/GCM/NoPadding";

                public void run() throws Exception {
                    Cipher c = Cipher.getInstance(transformation);
                    MessageDigest d = MessageDigest.getInstance(DIGEST);
                    KeyGenerator kg = KeyGenerator.getInstance("AES");
                    kg.init(256);
                }
            }
            """;

    @TempDir
    Path tmp;

    @Test
    void detectsCryptoAssetsInBytecode() throws Exception {
        final Path jar = compile("org/acme/sample/Sample.java", SOURCE);
        final BytecodeScanner.Result result;
        try (JarCache jars = new JarCache()) {
            result = new BytecodeScanner().scan(jar, "org.acme/sample/1.0", List.of(), jars, null);
        }
        final Bom bom = result.bom();
        final Map<String, Occurrence> byName = new TreeMap<>();
        for (Component c : bom.getComponents()) {
            for (Occurrence o : c.getEvidence().getOccurrences()) {
                byName.put(c.getName().replaceAll("@[0-9a-f-]{36}", ""), o);
            }
        }
        // the field value resolves through the constructor's assignment
        assertTrue(byName.containsKey("AES128-GCM") || byName.containsKey("AES-128-GCM"), byName.keySet().toString());
        assertTrue(byName.containsKey("SHA256") || byName.containsKey("SHA-256"), byName.keySet().toString());
        final Occurrence digest = byName.getOrDefault("SHA256", byName.get("SHA-256"));
        assertEquals("org.acme/sample/1.0/org/acme/sample/Sample.java", digest.getLocation());
        assertEquals(13, digest.getLine());
        assertTrue(digest.getAdditionalContext().startsWith("java.security.MessageDigest#getInstance"),
                digest.getAdditionalContext());
        assertEquals(1, result.classes());
    }

    private static final String WRAPPER = """
            package org.acme.wrap;

            import java.security.MessageDigest;

            public final class Digests {
                public static byte[] hash(String algorithm, byte[] data) throws Exception {
                    return digest(algorithm).digest(data);
                }

                private static MessageDigest digest(String name) throws Exception {
                    return MessageDigest.getInstance(name);
                }
            }
            """;

    private static final String CALLER = """
            package org.acme.app;

            import org.acme.wrap.Digests;

            public class App {
                public void run() throws Exception {
                    Digests.hash("SHA-512", new byte[0]);
                }
            }
            """;

    @Test
    void resolvesValuesPassedFromCallersInOtherJars() throws Exception {
        final Path wrapper = compile("wrapper", "org/acme/wrap/Digests.java", WRAPPER, null);
        final Path app = compile("app", "org/acme/app/App.java", CALLER, wrapper);
        final BytecodeScanner scanner = new BytecodeScanner();
        final Bom bom;
        try (JarCache jars = new JarCache()) {
            final Set<String> classes = new HashSet<>(jars.classNames(wrapper));
            classes.addAll(jars.classNames(app));
            final CallIndex index = new CallIndex(classes);
            final BytecodeScanner.CandidateMethods candidates = scanner.index(wrapper, "org.acme/wrap/1.0", List.of(), jars, index, true);
            assertNull(scanner.index(app, "org.acme/app/1.0", List.of(), jars, index, false));
            index.finish();
            // within the wrapper alone, the algorithm is unknown
            assertTrue(scanner.scan(wrapper, "org.acme/wrap/1.0", List.of(), jars, null).bom().getComponents() == null
                    || scanner.scan(wrapper, "org.acme/wrap/1.0", List.of(), jars, null).bom().getComponents().isEmpty());
            bom = scanner.scan(wrapper, "org.acme/wrap/1.0", List.of(), jars, index).bom();
            // the candidate methods kept by indexing: only the method calling MessageDigest, and the same CBOM
            assertEquals(List.of("org/acme/wrap/Digests.digest(Ljava/lang/String;)Ljava/security/MessageDigest;"),
                    candidates.methods().stream().map(Analyzer.MethodResult::method).toList());
            final Bom fromCandidates = scanner.scan(wrapper, "org.acme/wrap/1.0", List.of(), jars, index, candidates).bom();
            assertEquals(names(bom), names(fromCandidates));
        }
        final Component digest = bom.getComponents().stream()
                .filter(c -> c.getName().replace("-", "").equals("SHA512"))
                .findFirst()
                .orElseThrow(() -> new AssertionError(bom.getComponents().stream().map(Component::getName).toList()));
        // two hops (App.run -> Digests.hash -> Digests.digest), located where the value is chosen
        final Occurrence o = digest.getEvidence().getOccurrences().get(0);
        assertEquals("org.acme/app/1.0/org/acme/app/App.java", o.getLocation());
        assertEquals(7, o.getLine());
    }

    private static final String SERVICE = """
            package org.acme.spi;

            import javax.crypto.Cipher;

            public interface CryptoService {
                Cipher cipher(String transformation) throws Exception;

                static CryptoService get() {
                    return new DefaultCryptoService();
                }
            }

            class DefaultCryptoService implements CryptoService {
                @Override
                public Cipher cipher(String transformation) throws Exception {
                    return Cipher.getInstance(transformation);
                }
            }
            """;

    private static final String SPI_CALLER = """
            package org.acme.client;

            import org.acme.spi.CryptoService;

            public class Client {
                public void run(CryptoService injected) throws Exception {
                    CryptoService.get().cipher("ChaCha20-Poly1305");
                    injected.cipher("AES/CBC/PKCS5Padding");
                }
            }
            """;

    @Test
    void resolvesValuesPassedThroughInterfaces() throws Exception {
        final Path spi = compile("spi", "org/acme/spi/CryptoService.java", SERVICE, null);
        final Path client = compile("client", "org/acme/client/Client.java", SPI_CALLER, spi);
        final BytecodeScanner scanner = new BytecodeScanner();
        final Bom bom;
        try (JarCache jars = new JarCache()) {
            final Set<String> classes = new HashSet<>(jars.classNames(spi));
            classes.addAll(jars.classNames(client));
            final CallIndex index = new CallIndex(classes);
            scanner.index(spi, "org.acme/spi/1.0", List.of(), jars, index, false);
            scanner.index(client, "org.acme/client/1.0", List.of(), jars, index, false);
            index.finish();
            bom = scanner.scan(spi, "org.acme/spi/1.0", List.of(), jars, index).bom();
        }
        final Map<Integer, String> byLine = new TreeMap<>();
        for (Component c : bom.getComponents()) {
            for (Occurrence o : c.getEvidence().getOccurrences()) {
                if (o.getLocation().startsWith("org.acme/client/1.0/")) {
                    byLine.merge(o.getLine(), c.getName(), (a, b) -> a + ", " + b);
                }
            }
        }
        // both calls go through CryptoService.cipher and dispatch to DefaultCryptoService.cipher
        assertTrue(byLine.getOrDefault(7, "").contains("ChaCha20"), byLine.toString());
        assertTrue(byLine.getOrDefault(8, "").contains("AES"), byLine.toString());
    }

    private static final String ARGON2 = """
            package org.acme.hash;

            import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
            import org.bouncycastle.crypto.params.Argon2Parameters;

            public class Hasher {
                public byte[] hash(char[] password, byte[] salt) {
                    Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                            .withSalt(salt)
                            .withParallelism(4)
                            .withMemoryAsKB(65536)
                            .withIterations(3)
                            .build();
                    Argon2BytesGenerator generator = new Argon2BytesGenerator();
                    generator.init(parameters);
                    byte[] hash = new byte[32];
                    generator.generateBytes(password, hash);
                    return hash;
                }
            }
            """;

    /**
     * Argon2 is Keycloak's default password hashing, through Bouncy Castle's lightweight API.
     * sonar-cryptography 1.7.0 has no rule for it, so the bootstrapped specs had none either; see
     * {@code docs/coverage-gaps.md}.
     */
    @Test
    void detectsArgon2FromBouncyCastlesLightweightApi() throws Exception {
        final Path bc = bouncyCastleJar();
        final Path jar = compile("argon2", "org/acme/hash/Hasher.java", ARGON2, bc);
        final Bom bom;
        try (JarCache jars = new JarCache()) {
            bom = new BytecodeScanner().scan(jar, "org.acme/hash/1.0", List.of(bc), jars, null).bom();
        }
        // a password-based KDF, not the implementation class under a message digest, which is what
        // BcDerivationFunctionMapper's default branch would make of a name it doesn't know
        assertEquals(List.of("Argon2 | ALGORITHM | KDF | [KEYDERIVE]"), bom.getComponents().stream()
                .map(c -> c.getName() + " | " + c.getCryptoProperties().getAssetType()
                        + " | " + c.getCryptoProperties().getAlgorithmProperties().getPrimitive()
                        + " | " + c.getCryptoProperties().getAlgorithmProperties().getCryptoFunctions())
                .toList());
        final Occurrence where = bom.getComponents().get(0).getEvidence().getOccurrences().get(0);
        assertEquals("org.acme/hash/1.0/org/acme/hash/Hasher.java", where.getLocation());
    }

    /** The bcprov jar on the test class path, to compile and resolve the snippet against. */
    private static Path bouncyCastleJar() {
        for (String entry : System.getProperty("java.class.path").split(java.io.File.pathSeparator)) {
            if (entry.contains("bcprov")) {
                return Path.of(entry);
            }
        }
        throw new AssertionError("bcprov is not on the test class path");
    }

    /** Asset names with their occurrences, for comparing CBOMs. */
    private static List<String> names(Bom bom) {
        final List<String> result = new ArrayList<>();
        for (Component c : bom.getComponents()) {
            for (Occurrence o : c.getEvidence().getOccurrences()) {
                result.add(c.getName() + " @ " + o.getLocation() + ":" + o.getLine());
            }
        }
        result.sort(null);
        return result;
    }

    private Path compile(String path, String source) throws IOException {
        return compile("sample", path, source, null);
    }

    private Path compile(String name, String path, String source, Path classpath) throws IOException {
        final Path src = tmp.resolve(name + "-src").resolve(path);
        Files.createDirectories(src.getParent());
        Files.writeString(src, source);
        final Path classes = Files.createDirectories(tmp.resolve(name + "-classes"));
        final JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        final List<String> args = new ArrayList<>(List.of("-g", "-proc:none", "-d", classes.toString()));
        if (classpath != null) {
            args.addAll(List.of("-cp", classpath.toString()));
        }
        args.add(src.toString());
        assertEquals(0, javac.run(null, null, null, args.toArray(String[]::new)));
        final Path jar = tmp.resolve(name + ".jar");
        try (OutputStream out = Files.newOutputStream(jar);
                JarOutputStream jos = new JarOutputStream(out);
                Stream<Path> files = Files.walk(classes)) {
            for (Path f : files.filter(Files::isRegularFile).toList()) {
                jos.putNextEntry(new JarEntry(classes.relativize(f).toString().replace('\\', '/')));
                jos.write(Files.readAllBytes(f));
                jos.closeEntry();
            }
        }
        return jar;
    }
}
