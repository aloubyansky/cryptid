package io.github.aloubyansky.cryptid.spec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class EntryPointSpecsTest {

    private static EntryPointSpecs parse(String yaml) throws IOException {
        return EntryPointSpecs.parse(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)), "test");
    }

    @Test
    void theSpecsThatShipLoad() throws Exception {
        final EntryPointSpecs specs = EntryPointSpecs.load();
        final Set<String> ids = new HashSet<>();
        specs.entryPoints().forEach(e -> assertTrue(ids.add(e.id()), "duplicate id " + e.id()));
        specs.entryPoints().forEach(e -> assertTrue(e.kind() != null && e.exposure() != null, e.id()));
        assertTrue(specs.annotationTypes().containsAll(List.of("jakarta.ws.rs.GET", "jakarta.ws.rs.Path",
                "jakarta.annotation.security.RolesAllowed", "jakarta.enterprise.context.ApplicationScoped")));
        assertTrue(specs.instantiated().services());
    }

    @Test
    void aLaterSourceReplacesSpecsOfTheSameIdAndAddsAnnotations() throws Exception {
        final EntryPointSpecs base = parse("""
                specVersion: 1
                entryPoints:
                  - {id: a, kind: http, exposure: external, methodAnnotations: [x.A]}
                  - {id: b, kind: main, exposure: internal}
                authentication: {required: [x.R]}
                """);
        final EntryPointSpecs added = parse("""
                specVersion: 1
                entryPoints:
                  - {id: a, kind: messaging, exposure: internal, methodAnnotations: [x.B]}
                authentication: {required: [x.S], notRequired: [x.P]}
                instantiated: {beanAnnotations: [x.Bean]}
                """);
        final EntryPointSpecs combined = base.with(added);
        assertEquals(List.of("b", "a"), combined.entryPoints().stream().map(EntryPointSpecs.EntryPointSpec::id).toList());
        assertEquals("messaging", combined.entryPoints().get(1).kind());
        assertEquals(List.of("x.R", "x.S"), combined.authentication().required());
        assertEquals(Set.of("x.B", "x.R", "x.S", "x.P", "x.Bean"), combined.annotationTypes());
    }

    @Test
    void rejectsAnotherFormatVersionAndUnknownFields() {
        assertThrows(IOException.class, () -> parse("specVersion: 2\n"));
        assertThrows(IOException.class, () -> parse("specVersion: 1\nentryPoints: [{id: a, kind: http, color: red}]\n"));
    }
}
