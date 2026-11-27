package io.github.aloubyansky.cryptid.reach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.aloubyansky.cryptid.AnalysisInput;
import io.github.aloubyansky.cryptid.AnalysisOptions;
import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.AssetOccurrence;
import io.github.aloubyansky.cryptid.AssetOccurrence.Reachability;
import io.github.aloubyansky.cryptid.CryptoInventory;
import io.github.aloubyansky.cryptid.Cryptid;
import io.github.aloubyansky.cryptid.EntryPoint;
import io.github.aloubyansky.cryptid.InputArtifact;
import io.github.aloubyansky.cryptid.MethodId;
import io.github.aloubyansky.cryptid.TestJars;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The walk from entry points, end to end through the analysis, on compiled stand-ins. */
class ReachabilityTest {

    private static final ArtifactCoordinates APP = ArtifactCoordinates.jar("org.acme", "app", "1");

    @TempDir
    static Path dir;
    static CryptoInventory inventory;

    @BeforeAll
    static void analyze() throws Exception {
        final Map<String, String> api = new LinkedHashMap<>();
        for (String a : List.of("GET", "POST")) {
            api.put("jakarta/ws/rs/" + a + ".java", "package jakarta.ws.rs; import java.lang.annotation.*;"
                    + " @Retention(RetentionPolicy.RUNTIME) public @interface " + a + " {}");
        }
        api.put("jakarta/ws/rs/Path.java", "package jakarta.ws.rs; import java.lang.annotation.*;"
                + " @Retention(RetentionPolicy.RUNTIME) public @interface Path { String value(); }");
        api.put("jakarta/enterprise/context/ApplicationScoped.java", "package jakarta.enterprise.context; import java.lang.annotation.*;"
                + " @Retention(RetentionPolicy.RUNTIME) public @interface ApplicationScoped {}");
        final Path apiJar = TestJars.compile(dir, "api", api, null);
        final Map<String, String> app = new LinkedHashMap<>();
        app.put("org/acme/Root.java", """
                package org.acme;
                import jakarta.ws.rs.*;
                @Path("/root")
                public class Root {
                    @Path("keys") public Keys keys() { return new Keys(new RsaSigner()); }
                    @GET public String hello() throws Exception { return Hashes.sha256(); }
                }
                """);
        app.put("org/acme/Keys.java", """
                package org.acme;
                import jakarta.ws.rs.*;
                public class Keys {
                    private final Signer signer;
                    public Keys(Signer signer) { this.signer = signer; }
                    @POST public Object sign() throws Exception { return signer.sign(); }
                }
                """);
        app.put("org/acme/Signer.java", "package org.acme; public interface Signer { Object sign() throws Exception; }");
        app.put("org/acme/RsaSigner.java", """
                package org.acme;
                public class RsaSigner implements Signer {
                    public Object sign() throws Exception { return java.security.Signature.getInstance("SHA256withRSA"); }
                }
                """);
        app.put("org/acme/DsaSigner.java", """
                package org.acme;
                public class DsaSigner implements Signer {
                    public Object sign() throws Exception { return java.security.Signature.getInstance("SHA256withDSA"); }
                }
                """);
        app.put("org/acme/Hashes.java", """
                package org.acme;
                public class Hashes {
                    static String sha256() throws Exception { java.security.MessageDigest.getInstance("SHA-256"); return ""; }
                    static void unused() throws Exception { java.security.MessageDigest.getInstance("MD5"); }
                    static void background() {
                        new Thread(new Task()).start();
                    }
                }
                """);
        app.put("org/acme/Task.java", """
                package org.acme;
                public class Task implements Runnable {
                    public void run() {
                        try { java.security.MessageDigest.getInstance("SHA-384"); } catch (Exception e) { }
                    }
                }
                """);
        app.put("org/acme/Bean.java", """
                package org.acme;
                @jakarta.enterprise.context.ApplicationScoped
                public class Bean {
                    public Bean() throws Exception { javax.crypto.Mac.getInstance("HmacSHA512"); }
                }
                """);
        final Path appJar = TestJars.compile(dir, "app", app, apiJar);
        inventory = Cryptid.builder().build().analyze(AnalysisInput.builder()
                        .artifact(InputArtifact.builder(APP, appJar).dependencies(List.of()).application(true).build())
                        .artifact(InputArtifact.builder(ArtifactCoordinates.jar("org.acme", "api", "1"), apiJar).build())
                        // Task is instantiated in background(), which nothing calls: supplied as instantiated by the caller
                        .instantiatedClass("org.acme.Task")
                        .build(),
                AnalysisOptions.defaults());
    }

    private static AssetOccurrence at(String className, String method) {
        return inventory.assets().stream().flatMap(a -> a.occurrences().stream())
                .filter(o -> o.location().method().className().equals(className) && o.location().method().name().equals(method))
                .findFirst().orElseThrow(() -> new AssertionError("no occurrence in " + className + "#" + method));
    }

    private static Optional<EntryPoint> entryPoint(String className, String method) {
        return inventory.entryPoints().stream()
                .filter(e -> e.method().className().equals(className) && e.method().name().equals(method))
                .findFirst();
    }

    @Test
    void aRootsCryptoIsReached() {
        final AssetOccurrence sha = at("org.acme.Hashes", "sha256");
        assertEquals(Reachability.REACHED, sha.reachability());
        assertEquals(List.of(entryPoint("org.acme.Root", "hello").orElseThrow()), sha.reachedBy());
        assertEquals(List.of(new MethodId("org.acme.Root", "hello", "()Ljava/lang/String;"),
                new MethodId("org.acme.Hashes", "sha256", "()Ljava/lang/String;")), sha.path());
    }

    @Test
    void aSubResourceReachedThroughItsLocatorBecomesAnEntryPoint() {
        final EntryPoint sign = entryPoint("org.acme.Keys", "sign").orElseThrow();
        assertEquals(EntryPoint.HTTP, sign.kind());
        final AssetOccurrence rsa = at("org.acme.RsaSigner", "sign");
        assertEquals(Reachability.REACHED, rsa.reachability());
        assertTrue(rsa.reachedBy().contains(sign), rsa.reachedBy().toString());
    }

    @Test
    void onlyInstantiatedImplementationsAreDispatchedTo() {
        assertEquals(Reachability.NOT_REACHED, at("org.acme.DsaSigner", "sign").reachability());
    }

    @Test
    void codeNothingCallsIsNotReached() {
        assertEquals(Reachability.NOT_REACHED, at("org.acme.Hashes", "unused").reachability());
    }

    @Test
    void jdkCallbacksOfInstantiatedClassesAreReached() {
        // Runnable.run, which the JDK calls, of a class the caller says is instantiated
        assertEquals(Reachability.REACHED, at("org.acme.Task", "run").reachability());
    }

    @Test
    void beansAreReachedByTheRuntime() {
        final AssetOccurrence mac = at("org.acme.Bean", "<init>");
        assertEquals(Reachability.REACHED, mac.reachability());
        assertEquals(List.of(), mac.reachedBy());
    }
}
