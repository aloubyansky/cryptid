package io.github.aloubyansky.cryptid.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.aloubyansky.cryptid.AnalysisOptions;
import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.ClasspathScope;
import io.github.aloubyansky.cryptid.InputArtifact;
import io.github.aloubyansky.cryptid.scan.BytecodeScanner;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class AnalysisRunTest {

    private static final BytecodeScanner SCANNER = new BytecodeScanner();

    private static ArtifactCoordinates c(String a) {
        return ArtifactCoordinates.jar("org.acme", a, "1.0");
    }

    private static InputArtifact in(String a, List<ArtifactCoordinates> deps) {
        return new InputArtifact(c(a), Path.of(a + ".jar"), deps);
    }

    private static final List<InputArtifact> ARTIFACTS = List.of(
            in("app", List.of(c("b"), c("c"))),
            in("b", List.of(c("d"), c("missing"))),
            in("c", List.of(c("d"), c("app"))),
            in("d", List.of()),
            in("unknown", null));

    private static List<Path> classpath(ClasspathScope scope, String artifact) {
        final AnalysisRun run = new AnalysisRun(SCANNER, null, AnalysisOptions.builder().classpath(scope).build(), ARTIFACTS);
        return run.classpath(ARTIFACTS.stream().filter(a -> a.coordinates().equals(c(artifact))).findFirst().orElseThrow());
    }

    @Test
    void dependenciesAreTransitiveBreadthFirstWithoutTheArtifactItself() {
        assertEquals(List.of(Path.of("b.jar"), Path.of("c.jar"), Path.of("d.jar")), classpath(ClasspathScope.DEPENDENCIES, "app"));
        assertEquals(List.of(Path.of("d.jar"), Path.of("app.jar"), Path.of("b.jar")), classpath(ClasspathScope.DEPENDENCIES, "c"));
        assertEquals(List.of(), classpath(ClasspathScope.DEPENDENCIES, "d"));
    }

    @Test
    void unknownDependenciesMeanAllJars() {
        assertEquals(ARTIFACTS.stream().map(InputArtifact::jar).toList(), classpath(ClasspathScope.DEPENDENCIES, "unknown"));
    }

    @Test
    void allAndNone() {
        assertEquals(ARTIFACTS.stream().map(InputArtifact::jar).toList(), classpath(ClasspathScope.ALL, "app"));
        assertEquals(List.of(), classpath(ClasspathScope.NONE, "app"));
    }
}
