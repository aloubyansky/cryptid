package io.github.aloubyansky.cryptid.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class CacheKeyTest {

    private static final List<String> ARTIFACTS = List.of("a:x:1 /m2/x-1.jar 10 100", "b:y:2 /m2/y-2.jar 20 200");

    @Test
    void isStableAndIndependentOfArtifactOrder() {
        final String key = CacheKey.of("build-1", ARTIFACTS);
        assertEquals(key, CacheKey.of("build-1", List.of(ARTIFACTS.get(1), ARTIFACTS.get(0))));
        assertTrue(key.matches("[0-9a-f]{16}"), key);
    }

    @Test
    void changesWithEachInput() {
        final String key = CacheKey.of("build-1", ARTIFACTS);
        assertNotEquals(key, CacheKey.of("build-2", ARTIFACTS), "build");
        assertNotEquals(key, CacheKey.of("build-1", ARTIFACTS.subList(0, 1)), "artifact removed");
        assertNotEquals(key, CacheKey.of("build-1", List.of(ARTIFACTS.get(0), "b:y:2 /m2/y-2.jar 21 200")),
                "artifact changed");
    }

    @Test
    void inputsDontRunTogether() {
        assertNotEquals(CacheKey.of("a", List.of("b")), CacheKey.of("ab", List.of()));
        assertNotEquals(CacheKey.of("b", List.of("x", "y")), CacheKey.of("b", List.of("x\ny")));
    }

    @Test
    void buildIdentifiesVersionTimeAndSpecs() {
        assertTrue(BuildInfo.BUILD_TIME.matches("\\d{4}-\\d\\d-\\d\\dT.*"), "unresolved: " + BuildInfo.BUILD_TIME);
        final String build = CacheKey.build();
        assertTrue(build.startsWith(BuildInfo.VERSION + " " + BuildInfo.BUILD_TIME + " "), build);
        assertEquals(build, CacheKey.build());
    }
}
