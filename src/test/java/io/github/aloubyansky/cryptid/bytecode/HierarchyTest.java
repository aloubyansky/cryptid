package io.github.aloubyansky.cryptid.bytecode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class HierarchyTest {

    private static final ClassInfo OLD = new ClassInfo("java/lang/Object", List.of(), Set.of("run()V"));
    private static final ClassInfo NEW = new ClassInfo("org/acme/Base", List.of(), Set.of("run()V"));

    @Test
    void resolvesToTheFirstArtifactsCopyWhateverTheOrderAdded() {
        final Hierarchy h = new Hierarchy(List.of("b", "a"));
        h.add("a", Map.of("org/acme/Foo", OLD));
        h.add("b", Map.of("org/acme/Foo", NEW));
        assertEquals(NEW, h.get("org/acme/Foo"));
        final Hierarchy reversed = new Hierarchy(List.of("b", "a"));
        reversed.add("b", Map.of("org/acme/Foo", NEW));
        reversed.add("a", Map.of("org/acme/Foo", OLD));
        assertEquals(NEW, reversed.get("org/acme/Foo"));
        assertEquals(1, h.ambiguousClasses());
    }

    @Test
    void viewsPreferTheirArtifactsCopies() {
        final Hierarchy h = new Hierarchy(List.of("a", "b", "c"));
        h.add("a", Map.of("org/acme/Foo", OLD));
        h.add("b", Map.of("org/acme/Foo", NEW));
        h.add("c", Map.of("org/acme/Bar", OLD));
        assertEquals(NEW, h.view(List.of("c", "b")).get("org/acme/Foo"));
        // no preferred artifact has it: the hierarchy's copy
        assertEquals(OLD, h.view(List.of("c")).get("org/acme/Foo"));
        // a class in one artifact is visible to every view
        assertEquals(OLD, h.view(List.of("a")).get("org/acme/Bar"));
        assertNull(h.view(List.of("a")).get("org/acme/Missing"));
    }

    @Test
    void identicalCopiesAreOne() {
        final Hierarchy h = new Hierarchy(List.of("a", "b"));
        h.add("a", Map.of("org/acme/Foo", OLD));
        h.add("b", Map.of("org/acme/Foo", new ClassInfo("java/lang/Object", List.of(), Set.of("run()V"))));
        assertEquals(0, h.ambiguousClasses());
        assertTrue(h.compare("a", "b") < 0 && h.compare("b", "z") < 0 && h.compare("y", "z") < 0);
    }
}
