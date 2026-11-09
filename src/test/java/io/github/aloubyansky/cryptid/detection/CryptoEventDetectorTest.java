package io.github.aloubyansky.cryptid.detection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ibm.mapper.model.INode;
import io.github.aloubyansky.cryptid.bytecode.Analyzer;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.model.CryptoAssetModeler;
import io.github.aloubyansky.cryptid.spec.CryptoApiMatcher;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks how findings are built from the object graph. */
class CryptoEventDetectorTest {

    private static final String ONE_OF_SEVERAL = """
            package org.acme;

            import java.security.Signature;
            import java.security.spec.MGF1ParameterSpec;
            import java.security.spec.PSSParameterSpec;

            public class Pss {
                public static Signature create(int bits) throws Exception {
                    Signature signature = Signature.getInstance("RSASSA-PSS");
                    PSSParameterSpec spec;
                    switch (bits) {
                        case 256:
                            spec = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
                            break;
                        case 384:
                            spec = new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
                            break;
                        default:
                            spec = new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
                    }
                    signature.setParameter(spec);
                    return signature;
                }
            }
            """;

    @TempDir
    Path tmp;

    /** An argument that is one of several objects gives one finding per object, as for values. */
    @Test
    void oneFindingPerPossibleObject() throws Exception {
        final List<Analyzer.MethodResult> methods = analyze("org/acme/Pss.java", ONE_OF_SEVERAL);
        final CryptoEventDetector detector = new CryptoEventDetector(new CryptoApiMatcher(CryptoApiSpecs.load()),
                new Types(getClass().getClassLoader()), "", null);
        final List<Finding> findings = detector.detect(methods).stream()
                .filter(f -> f.call().owner().equals("java/security/Signature")).toList();
        assertEquals(3, findings.size(), findings.toString());

        final CryptoAssetModeler modeler = new CryptoAssetModeler();
        final Set<String> digests = new TreeSet<>();
        for (Finding f : findings) {
            final List<String> names = new ArrayList<>();
            for (INode n : modeler.process(f.event())) {
                collect(n, names);
            }
            final List<String> sha = names.stream().filter(s -> s.startsWith("SHA")).distinct().toList();
            assertEquals(1, sha.size(), "one digest per finding: " + names);
            digests.addAll(sha);
        }
        assertEquals(Set.of("SHA-256", "SHA-384", "SHA-512"), digests);
    }

    private static void collect(INode node, List<String> names) {
        names.add(node.asString());
        node.getChildren().values().forEach(c -> collect(c, names));
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
        final List<Analyzer.MethodResult> methods = analyzer.analyze();
        assertTrue(!methods.isEmpty());
        return methods;
    }
}
