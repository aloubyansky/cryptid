package io.github.aloubyansky.cryptid.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.CryptoAsset;
import io.github.aloubyansky.cryptid.bytecode.CallGraph;
import io.github.aloubyansky.cryptid.bytecode.CallIndex;
import io.github.aloubyansky.cryptid.bytecode.CallResolver;
import io.github.aloubyansky.cryptid.bytecode.DemandCallIndex;
import io.github.aloubyansky.cryptid.bytecode.Hierarchy;
import io.github.aloubyansky.cryptid.bytecode.JarCache;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.detection.ArtifactPaths;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.engines.AESEngine;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * The call sites {@link DemandCallIndex} finds through the call graph, interpreting callers on
 * demand, answer every question detection asks as {@link CallIndex} does, and scans give the same
 * assets with either: the second step of detection-driven analysis (docs/foundation.md).
 */
class DemandCallIndexEquivalenceTest {

    @Test
    void bouncyCastle() throws Exception {
        final Map<ArtifactCoordinates, Path> jars = new LinkedHashMap<>();
        jars.put(ArtifactCoordinates.jar("org.bouncycastle", "bcprov-jdk18on", "1"), jarOf(AESEngine.class));
        jars.put(ArtifactCoordinates.jar("org.bouncycastle", "bcpkix-jdk18on", "1"), jarOf(X509CertificateHolder.class));
        jars.put(ArtifactCoordinates.jar("org.bouncycastle", "bcutil-jdk18on", "1"), jarOf(ContentInfo.class));
        final Result r = compare(jars);
        assertTrue(r.questions > 0, "no questions asked");
        assertEquals(List.of(), r.mismatches);
    }

    /** All JARs listed in the file named by {@code -Dclosure.jars}, e.g. Keycloak's. */
    @Test
    @Tag("e2e")
    void listedJars() throws Exception {
        final String list = System.getProperty("closure.jars");
        assumeTrue(list != null, "-Dclosure.jars not set");
        final Map<ArtifactCoordinates, Path> jars = new LinkedHashMap<>();
        for (String line : Files.readAllLines(Path.of(list))) {
            jars.put(ArtifactCoordinates.jar("listed", "a" + jars.size(), "1"), Path.of(line));
        }
        final Result r = compare(jars);
        System.out.printf("demand call index: %d questions, %d hits, %d methods interpreted in %d reads, %d mismatches%n",
                r.questions, r.hits, r.interpreted, r.reads, r.mismatches.size());
        assertEquals(List.of(), r.mismatches.subList(0, Math.min(20, r.mismatches.size())));
    }

    private record Result(int questions, long hits, long interpreted, long reads, List<String> mismatches) {}

    /** Records the questions detection asks. */
    private record Recording(CallResolver delegate, Set<String> questions) implements CallResolver {
        @Override
        public List<CallIndex.Hit> resolve(String method, long params) {
            questions.add(method + "#" + params);
            return delegate.resolve(method, params);
        }
    }

    private static Path jarOf(Class<?> c) throws Exception {
        return Path.of(c.getProtectionDomain().getCodeSource().getLocation().toURI());
    }

    private static Result compare(Map<ArtifactCoordinates, Path> jars) throws Exception {
        final BytecodeScanner scanner = new BytecodeScanner();
        final List<String> paths = jars.keySet().stream().map(ArtifactPaths::of).toList();
        final Hierarchy hierarchy = new Hierarchy(paths);
        final List<String> mismatches = new ArrayList<>();
        try (JarCache cache = new JarCache()) {
            final Set<String> classes = new HashSet<>();
            final Map<ArtifactCoordinates, Path> readable = new LinkedHashMap<>();
            jars.forEach((c, jar) -> {
                try {
                    classes.addAll(cache.classNames(jar));
                    readable.put(c, jar);
                } catch (RuntimeException e) {
                    // unreadable: not analyzed
                }
            });
            final CallGraph graph = new CallGraph(classes, hierarchy);
            readable.forEach((c, jar) -> scanner.read(jar, c, cache, hierarchy, graph));
            graph.finish();
            final CallIndex index = new CallIndex(classes, hierarchy);
            final Map<ArtifactCoordinates, BytecodeScanner.CandidateMethods> candidates = new HashMap<>();
            readable.forEach((c, jar) -> candidates.put(c,
                    scanner.index(jar, c, types(hierarchy, c), cache, index, true)));
            index.finish();
            final Map<String, DemandCallIndex.Source> sources = new HashMap<>();
            readable.forEach((c, jar) -> sources.put(ArtifactPaths.of(c), new DemandCallIndex.Source(c, jar)));
            final DemandCallIndex demand = new DemandCallIndex(classes, hierarchy, graph, sources, cache);

            final Set<String> questions = ConcurrentHashMap.newKeySet();
            long hits = 0;
            for (Map.Entry<ArtifactCoordinates, Path> e : readable.entrySet()) {
                final ArtifactCoordinates c = e.getKey();
                final ArtifactScan withIndex = scanner.scan(e.getValue(), c, types(hierarchy, c), cache,
                        new Recording(index, questions), candidates.get(c));
                final ArtifactScan withDemand = scanner.scan(e.getValue(), c, types(hierarchy, c), cache, demand, candidates.get(c));
                final String a = describe(withIndex.assets());
                final String b = describe(withDemand.assets());
                if (!a.equals(b)) {
                    mismatches.add("assets of " + c);
                    if (System.getProperty("dump.dir") != null) {
                        Files.writeString(Path.of(System.getProperty("dump.dir"), "index.txt"), a);
                        Files.writeString(Path.of(System.getProperty("dump.dir"), "demand.txt"), b);
                        Files.writeString(Path.of(System.getProperty("dump.dir"), "index2.txt"), describe(scanner.scan(e.getValue(), c,
                                types(hierarchy, c), cache, index, candidates.get(c)).assets()));
                    }
                }
            }
            for (String q : questions) {
                final int hash = q.lastIndexOf('#');
                final String method = q.substring(0, hash);
                final long params = Long.parseLong(q.substring(hash + 1));
                final List<CallIndex.Hit> expected = index.resolve(method, params);
                hits += expected.size();
                final String a = describeHits(expected);
                final String b = describeHits(demand.resolve(method, params));
                if (!a.equals(b)) {
                    mismatches.add(q + "\n  expected " + a + "\n  actual   " + b);
                }
            }
            return new Result(questions.size(), hits, demand.methodsInterpreted(), demand.artifactsRead(), mismatches);
        }
    }

    private static Types types(Hierarchy hierarchy, ArtifactCoordinates c) {
        return Types.of(hierarchy.view(List.of(ArtifactPaths.of(c))));
    }

    private static String describeHits(List<CallIndex.Hit> hits) {
        final StringBuilder sb = new StringBuilder();
        for (CallIndex.Hit h : hits) {
            final CallIndex.Site s = h.site();
            sb.append(h.value()).append(" @ ").append(s.file()).append(':').append(s.line()).append(' ').append(s.callerMethod())
                    .append(' ').append(s.signature()).append(' ').append(s.artifact()).append(' ')
                    .append(Arrays.toString(s.args())).append("; ");
        }
        return sb.toString();
    }

    private static String describe(List<CryptoAsset> assets) {
        final StringBuilder sb = new StringBuilder();
        for (CryptoAsset a : assets) {
            sb.append(a).append(' ').append(a.occurrences()).append(' ')
                    .append(a.dependsOn().stream().map(CryptoAsset::name).toList()).append('\n');
        }
        return sb.toString();
    }
}
