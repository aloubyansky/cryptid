package io.github.aloubyansky.cryptid.detection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.aloubyansky.cryptid.bytecode.Analyzer;
import io.github.aloubyansky.cryptid.bytecode.CallSite;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.detection.CryptoObjectGraph.CryptoApiCall;
import io.github.aloubyansky.cryptid.detection.CryptoObjectGraph.CryptoObject;
import io.github.aloubyansky.cryptid.spec.CryptoApiMatcher;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Checks the crypto objects of a method: which calls create each object, which are its events,
 * and how an argument refers to the object passed.
 */
class CryptoObjectGraphTest {

    private static final String SOURCE = """
            package org.acme;

            import javax.crypto.Cipher;
            import javax.crypto.spec.GCMParameterSpec;
            import javax.crypto.spec.SecretKeySpec;

            public class Encrypt {
                public byte[] run(byte[] secret, byte[] data) throws Exception {
                    SecretKeySpec key = new SecretKeySpec(secret, "AES");
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
                    return cipher.doFinal(data);
                }
            }
            """;

    @TempDir
    Path tmp;

    @Test
    void objectsHaveTheirCreationsAndEvents() throws Exception {
        final Path src = tmp.resolve("src/org/acme/Encrypt.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, SOURCE);
        final Path classes = tmp.resolve("classes");
        Files.createDirectories(classes);
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null, "-g", "-d", classes.toString(), src.toString()));

        final Analyzer analyzer = new Analyzer();
        analyzer.addClasses(classes);
        final Analyzer.MethodResult run = analyzer.analyze().stream().filter(m -> m.method().contains(".run(")).findFirst().orElseThrow();
        final CryptoObjectGraph graph = CryptoObjectGraph.of(run, new CryptoApiMatcher(CryptoApiSpecs.load()), new Types(getClass().getClassLoader()));

        final CryptoApiCall getInstance = call(graph, "getInstance");
        final CryptoApiCall init = call(graph, "init");
        final CryptoApiCall keySpec = graph.calls().stream()
                .filter(c -> c.spec().api().startsWith("javax.crypto.spec.SecretKeySpec#<init>")).findFirst().orElseThrow();

        // the cipher: created by getInstance, init is an event on it
        final CryptoObject cipher = graph.object(run.method(), getInstance.site().created()).orElseThrow();
        assertEquals(List.of(getInstance), cipher.creations());
        assertTrue(cipher.events().contains(init), "events: " + cipher.events());

        // init's key argument refers to the object SecretKeySpec's constructor creates
        final List<CryptoApiCall> keyCalls = graph.related(init.site(), init.site().args()[1], CryptoObjectGraph.Path.ROOT)
                .stream().map(CryptoObjectGraph.Reached::call).toList();
        assertEquals(List.of(keySpec), keyCalls);
        final CryptoObject key = graph.object(run.method(), keySpec.site().created()).orElseThrow();
        assertEquals(List.of(keySpec), key.creations());
        assertEquals(List.of(), key.events());

        // getInstance reports a finding on its own; init and the specs only contribute
        assertTrue(graph.roots().contains(getInstance));
        assertTrue(!graph.roots().contains(init));
    }

    private static final String ACROSS_METHODS = """
            package org.acme;

            import java.security.Key;
            import javax.crypto.Cipher;
            import javax.crypto.spec.SecretKeySpec;

            public class Across {
                // a factory: the cipher it returns is initialized by its callers
                static Cipher create() throws Exception {
                    return Cipher.getInstance("AES/GCM/NoPadding");
                }

                public byte[] encrypt(byte[] secret, byte[] data) throws Exception {
                    Cipher cipher = create();
                    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secret, "AES"));
                    return cipher.doFinal(data);
                }

                // a helper: the cipher passed in is initialized here, with the caller's key
                static void configure(Cipher c, Key key) throws Exception {
                    c.init(Cipher.DECRYPT_MODE, key);
                }

                public byte[] decrypt(byte[] secret, byte[] data) throws Exception {
                    Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
                    configure(cipher, new SecretKeySpec(secret, "DES"));
                    return cipher.doFinal(data);
                }
            }
            """;

    @Test
    void objectsAreFollowedAcrossMethods() throws Exception {
        final List<Analyzer.MethodResult> methods = analyze("org/acme/Across.java", ACROSS_METHODS);
        final CryptoObjectGraph graph = CryptoObjectGraph.of(methods, new CryptoApiMatcher(CryptoApiSpecs.load()),
                new Types(getClass().getClassLoader()));

        final CryptoApiCall aes = graph.roots().stream().filter(c -> c.site().method().contains(".create(")).findFirst().orElseThrow();
        final CryptoApiCall des = graph.roots().stream()
                .filter(c -> c.site().method().contains(".decrypt(") && c.spec().api().startsWith("javax.crypto.Cipher#getInstance"))
                .findFirst().orElseThrow();

        // the factory's cipher: init in the caller, reached through the returned object
        final List<CryptoObjectGraph.Reached> aesCalls = graph.createdBy(aes.site(), CryptoObjectGraph.Path.ROOT);
        final CryptoObjectGraph.Reached aesInit = aesCalls.stream()
                .filter(r -> r.call().spec().api().startsWith("javax.crypto.Cipher#init")).findFirst()
                .orElseThrow(() -> new AssertionError("init after create() not reached: " + aesCalls));
        assertTrue(aesInit.call().site().method().contains(".encrypt("), aesInit.toString());

        // the helper's init on the cipher passed in, with the path through configure
        final List<CryptoObjectGraph.Reached> desCalls = graph.createdBy(des.site(), CryptoObjectGraph.Path.ROOT);
        final CryptoObjectGraph.Reached desInit = desCalls.stream()
                .filter(r -> r.call().spec().api().startsWith("javax.crypto.Cipher#init")).findFirst()
                .orElseThrow(() -> new AssertionError("init in configure() not reached: " + desCalls));
        assertTrue(desInit.call().site().method().contains(".configure("), desInit.toString());
        assertEquals(1, desInit.path().frames().size());

        // the helper's key parameter resolves to this caller's key, through the path
        final CallSite init = desInit.call().site();
        final List<CryptoApiCall> keys = graph.related(init, init.args()[1], desInit.path()).stream()
                .map(CryptoObjectGraph.Reached::call).toList();
        assertEquals(1, keys.size(), keys.toString());
        assertTrue(keys.get(0).site().method().contains(".decrypt("), keys.toString());
        assertTrue(keys.get(0).spec().api().startsWith("javax.crypto.spec.SecretKeySpec#<init>"), keys.toString());

        // the factory's own graph alone doesn't see the caller's init
        final Analyzer.MethodResult create = methods.stream().filter(m -> m.method().contains(".create(")).findFirst().orElseThrow();
        assertTrue(CryptoObjectGraph.of(create, new CryptoApiMatcher(CryptoApiSpecs.load()), new Types(getClass().getClassLoader()))
                .createdBy(aes.site(), CryptoObjectGraph.Path.ROOT).stream()
                .noneMatch(r -> r.call().spec().api().startsWith("javax.crypto.Cipher#init")));
    }

    private List<Analyzer.MethodResult> analyze(String path, String source) throws Exception {
        final Path src = tmp.resolve("src-" + path.hashCode()).resolve(path);
        Files.createDirectories(src.getParent());
        Files.writeString(src, source);
        final Path classes = tmp.resolve("classes-" + path.hashCode());
        Files.createDirectories(classes);
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null, "-g", "-d", classes.toString(), src.toString()));
        final Analyzer analyzer = new Analyzer();
        analyzer.addClasses(classes);
        return analyzer.analyze();
    }

    private static CryptoApiCall call(CryptoObjectGraph graph, String name) {
        return graph.calls().stream()
                .filter(c -> c.spec().api().startsWith("javax.crypto.Cipher#" + name + "("))
                .findFirst().orElseThrow(() -> new AssertionError("no call to Cipher." + name + " in " + graph.calls()));
    }
}
