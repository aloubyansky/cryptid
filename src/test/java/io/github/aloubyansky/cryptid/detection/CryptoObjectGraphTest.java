package io.github.aloubyansky.cryptid.detection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.aloubyansky.cryptid.bytecode.Analyzer;
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
        final CryptoObject cipher = graph.object(getInstance.site().created()).orElseThrow();
        assertEquals(List.of(getInstance), cipher.creations());
        assertTrue(cipher.events().contains(init), "events: " + cipher.events());

        // init's key argument refers to the object SecretKeySpec's constructor creates
        final List<CryptoApiCall> keyCalls = graph.related(init.site().args()[1].origins());
        assertEquals(List.of(keySpec), keyCalls);
        final CryptoObject key = graph.object(keySpec.site().created()).orElseThrow();
        assertEquals(List.of(keySpec), key.creations());
        assertEquals(List.of(), key.events());

        // getInstance reports a finding on its own; init and the specs only contribute
        assertTrue(graph.roots().contains(getInstance));
        assertTrue(!graph.roots().contains(init));
    }

    private static CryptoApiCall call(CryptoObjectGraph graph, String name) {
        return graph.calls().stream()
                .filter(c -> c.spec().api().startsWith("javax.crypto.Cipher#" + name + "("))
                .findFirst().orElseThrow(() -> new AssertionError("no call to Cipher." + name + " in " + graph.calls()));
    }
}
