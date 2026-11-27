package io.github.aloubyansky.cryptid.reach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.EntryPoint;
import io.github.aloubyansky.cryptid.TestJars;
import io.github.aloubyansky.cryptid.bytecode.ArtifactDeclarations;
import io.github.aloubyansky.cryptid.bytecode.Hierarchy;
import io.github.aloubyansky.cryptid.bytecode.JarCache;
import io.github.aloubyansky.cryptid.detection.ArtifactPaths;
import io.github.aloubyansky.cryptid.scan.BytecodeScanner;
import io.github.aloubyansky.cryptid.spec.EntryPointSpecs;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EntryPointDetectorTest {

    /** Stand-ins for the annotations and types the specs name: matching is by name. */
    private static final Map<String, String> API = new LinkedHashMap<>();

    static {
        for (String verb : List.of("GET", "POST", "DELETE")) {
            API.put("jakarta/ws/rs/" + verb + ".java", "package jakarta.ws.rs; import java.lang.annotation.*;"
                    + " @Retention(RetentionPolicy.RUNTIME) public @interface " + verb + " {}");
        }
        API.put("jakarta/ws/rs/Path.java", "package jakarta.ws.rs; import java.lang.annotation.*;"
                + " @Retention(RetentionPolicy.RUNTIME) public @interface Path { String value(); }");
        API.put("jakarta/annotation/security/RolesAllowed.java", "package jakarta.annotation.security; import java.lang.annotation.*;"
                + " @Retention(RetentionPolicy.RUNTIME) public @interface RolesAllowed { String[] value(); }");
        API.put("jakarta/annotation/security/PermitAll.java", "package jakarta.annotation.security; import java.lang.annotation.*;"
                + " @Retention(RetentionPolicy.RUNTIME) public @interface PermitAll {}");
        API.put("jakarta/enterprise/event/Observes.java", "package jakarta.enterprise.event; import java.lang.annotation.*;"
                + " @Retention(RetentionPolicy.RUNTIME) public @interface Observes {}");
        API.put("jakarta/enterprise/context/ApplicationScoped.java", "package jakarta.enterprise.context; import java.lang.annotation.*;"
                + " @Retention(RetentionPolicy.RUNTIME) public @interface ApplicationScoped {}");
        API.put("jakarta/servlet/http/HttpServlet.java", "package jakarta.servlet.http;"
                + " public abstract class HttpServlet { protected void doGet(Object req, Object resp) {} }");
    }

    private static final ArtifactCoordinates APP = ArtifactCoordinates.jar("org.acme", "app", "1");
    private static final ArtifactCoordinates TOOL = ArtifactCoordinates.jar("org.acme", "tool", "1");
    private static final ArtifactCoordinates LIB = ArtifactCoordinates.jar("org.other", "lib", "1");

    @TempDir
    static Path dir;
    static EntryPointDetector.Result result;

    @BeforeAll
    static void detect() throws Exception {
        final Path api = TestJars.compile(dir, "api", API, null);
        final Map<String, String> app = new LinkedHashMap<>();
        app.put("org/acme/RealmsResource.java", """
                package org.acme;
                import jakarta.ws.rs.*;
                import jakarta.annotation.security.*;
                @Path("/realms")
                @RolesAllowed("admin")
                public class RealmsResource {
                    @GET @Path("{realm}") public String realm(String realm) { return realm; }
                    @POST @PermitAll public void create() {}
                    @Path("{realm}/users") public UsersResource users() { return new UsersResource(); }
                    public void notAnEndpoint() {}
                }
                """);
        app.put("org/acme/UsersResource.java", """
                package org.acme;
                import jakarta.ws.rs.*;
                public class UsersResource {
                    @DELETE @Path("/{id}/") public void delete(String id) {}
                }
                """);
        app.put("org/acme/ApiDefinition.java", """
                package org.acme;
                import jakarta.ws.rs.*;
                @Path("api") public interface ApiDefinition { @GET @Path("status") String status(); }
                """);
        app.put("org/acme/ApiImpl.java", """
                package org.acme;
                public class ApiImpl implements ApiDefinition { public String status() { return "ok"; } }
                """);
        app.put("org/acme/Lifecycle.java", """
                package org.acme;
                import jakarta.enterprise.event.Observes;
                import jakarta.enterprise.context.ApplicationScoped;
                @ApplicationScoped public class Lifecycle { void onStart(@Observes Object event) {} }
                """);
        app.put("org/acme/Servlet.java", """
                package org.acme;
                public class Servlet extends jakarta.servlet.http.HttpServlet {
                    @Override protected void doGet(Object req, Object resp) {}
                }
                """);
        app.put("org/acme/Main.java", "package org.acme; public class Main { public static void main(String[] args) {} }");
        app.put("org/acme/Other.java", "package org.acme; public class Other { public static void main(String[] args) {} }");
        app.put("org/acme/Provider.java", "package org.acme; public class Provider implements Runnable { public void run() {} }");
        final Path appJar = TestJars.compile(dir, "app", app, api, Map.of(
                "META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: org.acme.Main\n",
                "META-INF/services/java.lang.Runnable", "# a comment\norg.acme.Provider\n"));
        // an application artifact without a manifest: every main counts
        final Path toolJar = TestJars.compile(dir, "tool", Map.of("org/acme/tool/Tool.java",
                "package org.acme.tool; public class Tool { public static void main(String[] args) {} }"), null);
        // a library: not searched for entry points, but its beans are instantiated
        final Path libJar = TestJars.compile(dir, "lib", Map.of("org/other/LibResource.java", """
                package org.other;
                import jakarta.ws.rs.*;
                @jakarta.enterprise.context.ApplicationScoped
                @Path("lib") public class LibResource { @GET public String get() { return ""; } }
                """), api);

        final EntryPointSpecs specs = EntryPointSpecs.load();
        final Map<ArtifactCoordinates, Path> jars = new LinkedHashMap<>();
        jars.put(APP, appJar);
        jars.put(TOOL, toolJar);
        jars.put(LIB, libJar);
        jars.put(ArtifactCoordinates.jar("org.acme", "api", "1"), api);
        final Hierarchy hierarchy = new Hierarchy(jars.keySet().stream().map(ArtifactPaths::of).toList());
        final BytecodeScanner scanner = new BytecodeScanner();
        try (JarCache cache = new JarCache()) {
            final List<EntryPointDetector.Artifact> artifacts = new ArrayList<>();
            for (Map.Entry<ArtifactCoordinates, Path> e : jars.entrySet()) {
                final boolean application = e.getKey().groupId().equals("org.acme") && !e.getKey().artifactId().equals("api");
                final ArtifactDeclarations d = scanner.read(e.getValue(), e.getKey(), cache, hierarchy, null, specs.annotationTypes(),
                        application);
                artifacts.add(new EntryPointDetector.Artifact(e.getKey(), application, d));
            }
            result = new EntryPointDetector(specs, hierarchy).detect(artifacts);
        }
    }

    private static Optional<EntryPoint> at(String className, String name) {
        return result.entryPoints().stream()
                .filter(e -> e.method().className().equals(className) && e.method().name().equals(name))
                .findFirst();
    }

    @Test
    void jaxrsAddressesJoinTheClassAndMethodPaths() {
        final EntryPoint realm = at("org.acme.RealmsResource", "realm").orElseThrow();
        assertEquals(EntryPoint.HTTP, realm.kind());
        assertEquals(EntryPoint.Exposure.EXTERNAL, realm.exposure());
        assertEquals(Optional.of("GET /realms/{realm}"), realm.address());
        assertEquals(EntryPoint.Source.DETECTED, realm.source());
        assertEquals(Optional.of(APP), realm.artifact());
        assertEquals(Optional.of("POST /realms"), at("org.acme.RealmsResource", "create").orElseThrow().address());
        // a sub-resource has no path of its own class: its address is partial
        assertEquals(Optional.of("DELETE /{id}"), at("org.acme.UsersResource", "delete").orElseThrow().address());
        // a locator without an HTTP method isn't one, nor is a method without annotations
        assertTrue(at("org.acme.RealmsResource", "users").isEmpty());
        assertTrue(at("org.acme.RealmsResource", "notAnEndpoint").isEmpty());
    }

    @Test
    void annotationsOnAnInterfaceAreInherited() {
        assertEquals(Optional.of("GET /api/status"), at("org.acme.ApiImpl", "status").orElseThrow().address());
    }

    @Test
    void authenticationFromTheMethodElseTheClass() {
        assertEquals(Optional.of(true), at("org.acme.RealmsResource", "realm").orElseThrow().authenticated());
        assertEquals(Optional.of(false), at("org.acme.RealmsResource", "create").orElseThrow().authenticated());
        assertEquals(Optional.empty(), at("org.acme.UsersResource", "delete").orElseThrow().authenticated());
    }

    @Test
    void observersServletsAndMains() {
        final EntryPoint observer = at("org.acme.Lifecycle", "onStart").orElseThrow();
        assertEquals(EntryPoint.OBSERVER, observer.kind());
        assertEquals(EntryPoint.Exposure.INTERNAL, observer.exposure());
        assertEquals(EntryPoint.SERVLET, at("org.acme.Servlet", "doGet").orElseThrow().kind());
        // the manifest's Main-Class only, where there is one; every main where there isn't
        assertEquals(EntryPoint.MAIN, at("org.acme.Main", "main").orElseThrow().kind());
        assertTrue(at("org.acme.Other", "main").isEmpty());
        assertTrue(at("org.acme.tool.Tool", "main").isPresent());
    }

    @Test
    void librariesAreNotSearched() {
        assertTrue(at("org.other.LibResource", "get").isEmpty());
    }

    @Test
    void instantiatedClasses() {
        // beans in any artifact, service providers, and the classes declaring entry points
        assertTrue(result.instantiated().contains("org/acme/Lifecycle"), result.instantiated().toString());
        assertTrue(result.instantiated().contains("org/other/LibResource"));
        assertTrue(result.instantiated().contains("org/acme/Provider"));
        assertTrue(result.instantiated().contains("org/acme/RealmsResource"));
        // a class whose only entry point is static isn't
        assertFalse(result.instantiated().contains("org/acme/Main"));
    }

    @Test
    void entryPointsAreOrderedByArtifactThenClassThenMember() {
        final List<String> order = result.entryPoints().stream().map(e -> e.artifact().orElseThrow().artifactId() + " " + e.method())
                .collect(Collectors.toList());
        assertEquals(order.stream().sorted((a, b) -> {
            final int byArtifact = Integer.compare(a.startsWith("app") ? 0 : 1, b.startsWith("app") ? 0 : 1);
            return byArtifact != 0 ? byArtifact : a.compareTo(b);
        }).toList(), order);
    }
}
