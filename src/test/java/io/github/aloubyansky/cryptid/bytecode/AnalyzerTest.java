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

    private static final String FIELDS = """
            package org.acme;

            import java.security.MessageDigest;

            public class Holder {
                private final String alg;

                public Holder(String alg) {
                    this.alg = alg;
                }

                public byte[] hash(String text) throws Exception {
                    return MessageDigest.getInstance(alg).digest(text.getBytes());
                }

                public static byte[] run() throws Exception {
                    return new Holder("SHA-256").hash("MD5");
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

    /**
     * A field set from the constructor's parameter isn't the reading method's parameter: its value
     * mustn't resolve from the reading method's callers ({@code "MD5"} here), but from the
     * constructor's.
     */
    @Test
    void fieldsCarryTheStoringMethodsParameters() throws Exception {
        final List<Analyzer.MethodResult> methods = analyze("org/acme/Holder.java", FIELDS);
        final CallSite cs = call(methods, "hash", "getInstance");
        assertEquals(0, cs.args()[0].params(), cs.args()[0].toString());
        // but the constructor's parameter it was stored from
        assertEquals(Set.of(new AVal.StoredParam("org/acme/Holder.<init>(Ljava/lang/String;)V", 0)), cs.args()[0].stored());
    }

    private static Set<Object> arg(List<Analyzer.MethodResult> methods, String caller, String callee) {
        return call(methods, caller, callee).args()[0].consts();
    }

    private static CallSite call(List<Analyzer.MethodResult> methods, String caller, String callee) {
        final Analyzer.MethodResult m = methods.stream().filter(r -> r.method().contains("." + caller + "("))
                .findFirst().orElseThrow();
        return m.calls().stream().filter(c -> c.name().equals(callee)).findFirst().orElseThrow();
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
