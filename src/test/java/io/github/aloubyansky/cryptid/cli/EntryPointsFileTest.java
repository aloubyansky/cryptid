package io.github.aloubyansky.cryptid.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.EntryPoint;
import io.github.aloubyansky.cryptid.MethodId;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EntryPointsFileTest {

    @Test
    void readsSuppliedEntryPoints(@TempDir Path dir) throws Exception {
        final Path file = Files.writeString(dir.resolve("entry-points.yaml"), """
                - method: org.acme.Resource#hello(Ljava/lang/String;)Ljava/lang/String;
                  kind: http
                  address: GET /hello/{name}
                  authenticated: true
                  artifact: org.acme:app::jar:1.0
                - method: org.acme.Jobs#nightly()V
                  kind: scheduled
                  exposure: internal
                """);
        final List<EntryPoint> read = EntryPointsFile.read(file);
        assertEquals(2, read.size());
        final EntryPoint hello = read.get(0);
        assertEquals(new MethodId("org.acme.Resource", "hello", "(Ljava/lang/String;)Ljava/lang/String;"), hello.method());
        assertEquals(EntryPoint.Exposure.EXTERNAL, hello.exposure());
        assertEquals(Optional.of("GET /hello/{name}"), hello.address());
        assertEquals(Optional.of(true), hello.authenticated());
        assertEquals(Optional.of(ArtifactCoordinates.jar("org.acme", "app", "1.0")), hello.artifact());
        assertEquals(EntryPoint.Source.SUPPLIED, hello.source());
        assertEquals(EntryPoint.Exposure.INTERNAL, read.get(1).exposure());
    }

    @Test
    void rejectsMalformedEntries(@TempDir Path dir) throws Exception {
        assertThrows(IOException.class, () -> EntryPointsFile.read(Files.writeString(dir.resolve("a.yaml"), "- kind: http\n")));
        assertThrows(IOException.class, () -> EntryPointsFile.read(Files.writeString(dir.resolve("b.yaml"), "- {method: nope, kind: http}\n")));
    }
}
