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
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.crypto.enums.Primitive;
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

    private static final String MAPPING = """
            package org.acme.jose;

            import java.security.Signature;

            public class Signer {
                // maps every algorithm of a family, not only those a signature takes
                static String javaName(String alg) {
                    switch (alg) {
                        case "RS256": return "SHA256withRSA";
                        case "HS256": return "HmacSHA256";
                        case "A128": return "AES";
                        default: throw new IllegalArgumentException(alg);
                    }
                }

                public static Signature signature(String alg) throws Exception {
                    return Signature.getInstance(javaName(alg));
                }
            }
            """;

    /**
     * A value returned by a mapping method may be one the API rejects at runtime; such variants
     * are dropped: a {@code Signature} isn't a MAC or a block cipher.
     */
    @Test
    void dropsVariantsTheApiDoesNotTake() throws Exception {
        final Path jar = compile("org/acme/jose/Signer.java", MAPPING);
        final Bom bom;
        try (JarCache jars = new JarCache()) {
            bom = new BytecodeScanner().scan(jar, "org.acme/jose/1.0", List.of(), jars, null).bom();
        }
        final List<String> names = bom.getComponents().stream().map(Component::getName).toList();
        assertTrue(names.stream().anyMatch(n -> n.contains("RSA")), names.toString());
        assertTrue(names.stream().noneMatch(n -> n.startsWith("HMAC") || n.startsWith("AES")), names.toString());
    }

    private static final String SECRET = """
            package org.acme.jose;

            import javax.crypto.spec.SecretKeySpec;

            public class Secrets {
                static String javaName(String alg) {
                    switch (alg) {
                        case "RS256": return "SHA256withRSA";
                        case "HS256": return "HmacSHA256";
                        default: throw new IllegalArgumentException(alg);
                    }
                }

                public static SecretKeySpec key(byte[] secret, String alg) {
                    return new SecretKeySpec(secret, javaName(alg));
                }
            }
            """;

    /** A secret key isn't for an asymmetric algorithm, though {@code SecretKeySpec} takes any name. */
    @Test
    void dropsAsymmetricVariantsOfSecretKeys() throws Exception {
        final Path jar = compile("org/acme/jose/Secrets.java", SECRET);
        final Bom bom;
        try (JarCache jars = new JarCache()) {
            bom = new BytecodeScanner().scan(jar, "org.acme/jose/1.0", List.of(), jars, null).bom();
        }
        final List<String> names = bom.getComponents().stream().map(Component::getName).toList();
        assertTrue(names.stream().anyMatch(n -> n.startsWith("HMAC")), names.toString());
        assertTrue(names.stream().noneMatch(n -> n.contains("RSA")), names.toString());
    }

    /** The part of xmlsec's API the fixture uses; cryptid doesn't depend on xmlsec. */
    private static final String XMLCIPHER_STUB = """
            package org.apache.xml.security.encryption;

            import java.security.Key;

            public class XMLCipher {
                public static final String AES_128 = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
                public static final String AES_256 = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
                public static final String RSA_OAEP_11 = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
                public static final int ENCRYPT_MODE = 1;
                public static final int WRAP_MODE = 3;

                public static XMLCipher getInstance(String transformation) {
                    return new XMLCipher();
                }

                public static XMLCipher getInstance(String transformation, String canon, String digestMethod) {
                    return new XMLCipher();
                }

                public void init(int mode, Key key) {
                }
            }
            """;

    private static final String XML_ENCRYPTION = """
            package org.acme.saml;

            import java.security.Key;
            import org.apache.xml.security.encryption.XMLCipher;

            public class Encrypt {
                private static String url(int keySize) {
                    switch (keySize) {
                        case 256: return XMLCipher.AES_256;
                        default: return XMLCipher.AES_128;
                    }
                }

                public void encrypt(Key secret, Key publicKey, int keySize) {
                    XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_OAEP_11, null, null);
                    keyCipher.init(XMLCipher.WRAP_MODE, publicKey);
                    XMLCipher cipher = XMLCipher.getInstance(url(keySize));
                    cipher.init(XMLCipher.ENCRYPT_MODE, secret);
                }

                public void unknown() {
                    XMLCipher.getInstance("http://example.com/not-an-algorithm");
                }
            }
            """;

    /** xmlsec's algorithm URIs are translated to the JCA names xmlsec uses; other URIs are dropped. */
    @Test
    void detectsXmlEncryptionAlgorithms() throws Exception {
        final Path stub = compile("xmlsec", "org/apache/xml/security/encryption/XMLCipher.java", XMLCIPHER_STUB, null);
        final Path jar = compile("saml", "org/acme/saml/Encrypt.java", XML_ENCRYPTION, stub);
        final Bom bom;
        try (JarCache jars = new JarCache()) {
            bom = new BytecodeScanner().scan(jar, "org.acme/saml/1.0", List.of(stub), jars, null).bom();
        }
        final Map<String, Component> byName = new TreeMap<>();
        bom.getComponents().forEach(c -> byName.put(c.getName(), c));
        assertTrue(byName.keySet().containsAll(Set.of("AES-128-CBC-ISO 10126", "AES-256-CBC-ISO 10126", "RSA-OAEP")), byName.keySet().toString());
        assertTrue(byName.keySet().stream().noneMatch(n -> n.contains("example.com")), byName.keySet().toString());
        final Component aes = byName.get("AES-128-CBC-ISO 10126");
        assertEquals(List.of(CryptoFunction.ENCRYPT), aes.getCryptoProperties().getAlgorithmProperties().getCryptoFunctions());
    }

    private static final String CONTENT_SIGNER = """
            package org.acme.cert;

            import java.security.PrivateKey;
            import org.bouncycastle.operator.ContentSigner;
            import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

            public class Certs {
                public ContentSigner rsa(PrivateKey key) throws Exception {
                    JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
                    return builder.build(key);
                }

                public ContentSigner ec(PrivateKey key) throws Exception {
                    return new JcaContentSignerBuilder("SHA256WithECDSA").setProvider("BC").build(key);
                }

                public ContentSigner pss(PrivateKey key) throws Exception {
                    return new JcaContentSignerBuilder("SHA384WITHRSAANDMGF1").build(key);
                }
            }
            """;

    /** Bouncy Castle's names for signature algorithms are translated to the JCA names the translators read. */
    @Test
    void detectsBouncyCastleContentSigners() throws Exception {
        final Path jar = compile("cert", "org/acme/cert/Certs.java", CONTENT_SIGNER, Path.of(System.getProperty("java.class.path")));
        final Bom bom;
        try (JarCache jars = new JarCache()) {
            bom = new BytecodeScanner().scan(jar, "org.acme/cert/1.0", List.of(), jars, null).bom();
        }
        final Map<String, Component> byName = new TreeMap<>();
        bom.getComponents().forEach(c -> byName.put(c.getName(), c));
        assertTrue(byName.keySet().containsAll(Set.of("RSA-PKCS1-1.5-SHA-256", "ECDSA-SHA-256", "RSA-PSS", "SHA-384")), byName.keySet().toString());
        // build(key) signs, also through setProvider, which returns the builder
        assertEquals(List.of(CryptoFunction.SIGN),
                byName.get("RSA-PKCS1-1.5-SHA-256").getCryptoProperties().getAlgorithmProperties().getCryptoFunctions());
        assertEquals(List.of(CryptoFunction.SIGN),
                byName.get("ECDSA-SHA-256").getCryptoProperties().getAlgorithmProperties().getCryptoFunctions());
    }

    /** A library API whose constructor delegates to another specified one, as bcpkix's does. */
    private static final String DELEGATING_API = """
            package org.bouncycastle.operator.jcajce;

            import java.security.PrivateKey;
            import java.security.spec.AlgorithmParameterSpec;

            public class JcaContentSignerBuilder {
                public JcaContentSignerBuilder(String signatureAlgorithm) {
                    this(signatureAlgorithm, (AlgorithmParameterSpec) null);
                }

                public JcaContentSignerBuilder(String signatureAlgorithm, AlgorithmParameterSpec params) {
                }

                public Object build(PrivateKey key) {
                    return null;
                }
            }
            """;

    private static final String API_CALLER = """
            package org.acme.certs;

            import java.security.PrivateKey;
            import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

            public class Signer {
                public Object signer(PrivateKey key) {
                    return new JcaContentSignerBuilder("SHA256withRSA").build(key);
                }
            }
            """;

    /**
     * A value an API passes on inside its library isn't reported at the caller again when the
     * caller's call is itself a finding, with its own events.
     */
    @Test
    void doesNotReportCallersOfApisTwice() throws Exception {
        final Path lib = compile("signer-lib", "org/bouncycastle/operator/jcajce/JcaContentSignerBuilder.java", DELEGATING_API, null);
        final Path app = compile("signer-app", "org/acme/certs/Signer.java", API_CALLER, lib);
        final BytecodeScanner scanner = new BytecodeScanner();
        try (JarCache jars = new JarCache()) {
            final Set<String> classes = new HashSet<>(jars.classNames(lib));
            classes.addAll(jars.classNames(app));
            final CallIndex index = new CallIndex(classes);
            scanner.index(lib, "org.acme/lib/1.0", List.of(), jars, index, false);
            scanner.index(app, "org.acme/app/1.0", List.of(lib), jars, index, false);
            index.finish();
            final Bom libBom = scanner.scan(lib, "org.acme/lib/1.0", List.of(), jars, index).bom();
            final List<String> inApp = libBom.getComponents() == null ? List.of() : libBom.getComponents().stream()
                    .filter(c -> c.getEvidence().getOccurrences().stream().anyMatch(o -> o.getLocation().startsWith("org.acme/app/")))
                    .map(Component::getName).toList();
            assertEquals(List.of(), inApp);
            final Bom appBom = scanner.scan(app, "org.acme/app/1.0", List.of(lib), jars, index).bom();
            final Component rsa = appBom.getComponents().stream().filter(c -> c.getName().equals("RSA-PKCS1-1.5-SHA-256"))
                    .findFirst().orElseThrow(() -> new AssertionError(names(appBom)));
            assertEquals(List.of(CryptoFunction.SIGN), rsa.getCryptoProperties().getAlgorithmProperties().getCryptoFunctions());
        }
    }

    private static final String ARGON2 = """
            package org.acme.hash;

            import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
            import org.bouncycastle.crypto.params.Argon2Parameters;

            public class Hasher {
                public byte[] hash(char[] password, byte[] salt) {
                    Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                            .withSalt(salt).withIterations(3).withMemoryAsKB(65536).build();
                    Argon2BytesGenerator generator = new Argon2BytesGenerator();
                    generator.init(parameters);
                    byte[] result = new byte[32];
                    generator.generateBytes(password, result);
                    return result;
                }
            }
            """;

    /** Argon2 has no rule upstream and no model class; it is a password-based KDF of cryptid's own. */
    @Test
    void detectsArgon2() throws Exception {
        final Path jar = compile("argon2", "org/acme/hash/Hasher.java", ARGON2, Path.of(System.getProperty("java.class.path")));
        final Bom bom;
        try (JarCache jars = new JarCache()) {
            bom = new BytecodeScanner().scan(jar, "org.acme/hash/1.0", List.of(), jars, null).bom();
        }
        final Component argon2 = (bom.getComponents() == null ? List.<Component>of() : bom.getComponents()).stream()
                .filter(c -> c.getName().equals("Argon2")).findFirst()
                .orElseThrow(() -> new AssertionError(bom.getComponents() == null ? "no components" : names(bom).toString()));
        assertEquals(Primitive.KDF, argon2.getCryptoProperties().getAlgorithmProperties().getPrimitive());
        assertEquals(10, argon2.getEvidence().getOccurrences().get(0).getLine());
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
