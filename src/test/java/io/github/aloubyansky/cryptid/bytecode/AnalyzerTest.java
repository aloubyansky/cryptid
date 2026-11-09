package io.github.aloubyansky.cryptid.bytecode;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks values the interpreter resolves across methods. */
class AnalyzerTest {

    private static final String RETURNS = """
            package org.acme;

            import java.security.MessageDigest;
            import java.security.Signature;
            import javax.crypto.Cipher;

            public class Returns {
                enum Alg { RS256, RS384, PS256 }

                // a mapping method: each branch returns a constant
                public static String javaName(Alg alg) {
                    switch (alg) {
                        case RS256: return "SHA256withRSA";
                        case RS384: return "SHA384withRSA";
                        case PS256: return "SHA256withRSAandMGF1";
                        default: throw new IllegalArgumentException();
                    }
                }

                public static Signature signature(Alg alg) throws Exception {
                    return Signature.getInstance(javaName(alg));
                }

                // returns its parameter: the caller's argument is the result
                private static String same(String s) {
                    return s;
                }

                public static Cipher cipher() throws Exception {
                    return Cipher.getInstance(same("AES/GCM/NoPadding"));
                }

                // overridable: a subclass may return something else, so it isn't resolved
                protected String digestName() {
                    return "SHA-1";
                }

                public MessageDigest digest() throws Exception {
                    return MessageDigest.getInstance(digestName());
                }

                // final: can't be overridden
                protected final String finalDigestName() {
                    return "SHA-512";
                }

                public MessageDigest finalDigest() throws Exception {
                    return MessageDigest.getInstance(finalDigestName());
                }
            }
            """;

    @TempDir
    Path tmp;

    @Test
    void constantsReturnedByMethodsReachCallSites() throws Exception {
        final List<Analyzer.MethodResult> methods = analyze("org/acme/Returns.java", RETURNS);
        assertEquals(Set.of("SHA256withRSA", "SHA384withRSA", "SHA256withRSAandMGF1"), arg(methods, "signature", "getInstance"));
        assertEquals(Set.of("AES/GCM/NoPadding"), arg(methods, "cipher", "getInstance"));
        assertEquals(Set.of(), arg(methods, "digest", "getInstance"));
        assertEquals(Set.of("SHA-512"), arg(methods, "finalDigest", "getInstance"));
    }

    private static Set<Object> arg(List<Analyzer.MethodResult> methods, String caller, String callee) {
        final Analyzer.MethodResult m = methods.stream().filter(r -> r.method().contains("." + caller + "("))
                .findFirst().orElseThrow();
        final CallSite cs = m.calls().stream().filter(c -> c.name().equals(callee)).findFirst().orElseThrow();
        return cs.args()[0].consts();
    }

    private List<Analyzer.MethodResult> analyze(String path, String source) throws Exception {
        final Path src = tmp.resolve("src").resolve(path);
        Files.createDirectories(src.getParent());
        Files.writeString(src, source);
        final Path classes = tmp.resolve("classes");
        Files.createDirectories(classes);
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null, "-g", "-d", classes.toString(), src.toString()));
        final Analyzer analyzer = new Analyzer();
        analyzer.addClasses(classes);
        return analyzer.analyze();
    }
}
