package io.github.aloubyansky.cryptid.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.aloubyansky.cryptid.AnalysisOptions;
import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.InputArtifact;
import io.github.aloubyansky.cryptid.scan.BytecodeScanner;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class AnalysisRunTest {

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

    private static final AnalysisRun RUN = new AnalysisRun(new BytecodeScanner(), null, AnalysisOptions.defaults(), ARTIFACTS);

    private static List<String> preference(String artifact) {
        return RUN.preference(ARTIFACTS.stream().filter(a -> a.coordinates().equals(c(artifact))).findFirst().orElseThrow());
    }

    @Test
    void ownCopyThenDependenciesBreadthFirst() {
        assertEquals(List.of("org.acme/app/1.0", "org.acme/b/1.0", "org.acme/c/1.0", "org.acme/d/1.0"), preference("app"));
        assertEquals(List.of("org.acme/c/1.0", "org.acme/d/1.0", "org.acme/app/1.0", "org.acme/b/1.0"), preference("c"));
        assertEquals(List.of("org.acme/d/1.0"), preference("d"));
    }

    @Test
    void unknownDependenciesPreferOnlyTheArtifactItself() {
        assertEquals(List.of("org.acme/unknown/1.0"), preference("unknown"));
    }
}
