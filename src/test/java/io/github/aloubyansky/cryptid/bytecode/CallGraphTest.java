package io.github.aloubyansky.cryptid.bytecode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks the call graph built from method facts and the class hierarchy. */
class CallGraphTest {

    private static final String SOURCE = """
            package org.acme;

            import java.util.ArrayList;

            public class G {
                interface Shape { double area(); default String label() { return "shape"; } }
                static class Square implements Shape { public double area() { return 4; } }
                static class Big extends Square { public double area() { return 9; } }
                static class Listy extends ArrayList<String> {}

                static double total(Shape s) { return s.area() + s.label().length(); }

                static double run() {
                    Listy l = new Listy();
                    return l.size() + total(new Big()) + new Square().area();
                }

                static Runnable later() { return G::run; }
            }
            """;

    private static final String RUN = "org/acme/G.run()D";
    private static final String TOTAL = "org/acme/G.total(Lorg/acme/G$Shape;)D";

    @TempDir
    Path tmp;

    @Test
    void exactAndVirtualCallees() throws Exception {
        final CallGraph g = graph(false, 1);
        assertEquals(ids(g, TOTAL, "org/acme/G$Big.<init>()V", "org/acme/G$Listy.<init>()V", "org/acme/G$Square.<init>()V"),
                set(g.exactCallees(g.method(RUN))));
        assertEquals(ids(g, "org/acme/G$Square.area()D"), set(g.virtualCallees(g.method(RUN))));
        assertEquals(ids(g, "org/acme/G$Shape.area()D", "org/acme/G$Shape.label()Ljava/lang/String;"),
                set(g.virtualCallees(g.method(TOTAL))));
        assertEquals(Set.of(g.type("org/acme/G$Big"), g.type("org/acme/G$Listy"), g.type("org/acme/G$Square")),
                set(g.instantiated(g.method(RUN))));
    }

    @Test
    void callsInheritedFromOutsideAreDropped() throws Exception {
        final CallGraph g = graph(false, 1);
        // Listy.size() is ArrayList's, and String.length() isn't analyzed
        assertEquals(-1, g.method("org/acme/G$Listy.size()I"));
        assertEquals(-1, g.method("java/lang/String.length()I"));
        assertEquals(-1, g.type("java/util/ArrayList"));
    }

    @Test
    void dispatch() throws Exception {
        final CallGraph g = graph(false, 1);
        final int area = g.method("org/acme/G$Shape.area()D");
        final int label = g.method("org/acme/G$Shape.label()Ljava/lang/String;");
        assertEquals(g.method("org/acme/G$Big.area()D"), g.dispatch(g.type("org/acme/G$Big"), area));
        assertEquals(g.method("org/acme/G$Square.area()D"), g.dispatch(g.type("org/acme/G$Square"), area));
        assertEquals(label, g.dispatch(g.type("org/acme/G$Big"), label), "a default method");
        assertEquals(-1, g.dispatch(g.type("org/acme/G$Listy"), area), "not a Shape");
    }

    @Test
    void methodHandleTargets() throws Exception {
        final CallGraph g = graph(false, 1);
        assertEquals(ids(g, RUN), set(g.exactCallees(g.method("org/acme/G.later()Ljava/lang/Runnable;"))));
        assertEquals(1, g.handleEdgeCount());
    }

    @Test
    void idsAreOrderedAndArraysSorted() throws Exception {
        final CallGraph g = graph(false, 1);
        for (int m = 0; m + 1 < g.methodCount(); m++) {
            assertTrue(g.methodKey(m).compareTo(g.methodKey(m + 1)) < 0);
        }
        final int[] callees = g.exactCallees(g.method(RUN));
        assertArrayEquals(Arrays.stream(callees).sorted().distinct().toArray(), callees);
    }

    @Test
    void sameWhateverTheOrderAndDuplicates() throws Exception {
        final CallGraph a = graph(false, 1);
        final CallGraph b = graph(true, 2); // the same classes from two artifacts, added in reverse
        assertEquals(a.methodCount(), b.methodCount());
        assertEquals(a.edgeCount(), b.edgeCount());
        assertEquals(a.instantiationCount(), b.instantiationCount());
        for (int m = 0; m < a.methodCount(); m++) {
            assertEquals(a.methodKey(m), b.methodKey(m));
            assertArrayEquals(a.exactCallees(m), b.exactCallees(m));
            assertArrayEquals(a.virtualCallees(m), b.virtualCallees(m));
            assertArrayEquals(a.instantiated(m), b.instantiated(m));
        }
    }

    private static Set<Integer> ids(CallGraph g, String... keys) {
        final Set<Integer> result = new HashSet<>();
        for (String key : keys) {
            final int id = g.method(key);
            assertTrue(id >= 0, "no method " + key);
            result.add(id);
        }
        return result;
    }

    private static Set<Integer> set(int[] ids) {
        final Set<Integer> result = new HashSet<>();
        Arrays.stream(ids).forEach(result::add);
        return result;
    }

    private CallGraph graph(boolean reversed, int times) throws Exception {
        final Path classes = tmp.resolve("classes");
        if (!Files.exists(classes)) {
            final Path src = tmp.resolve("src/org/acme/G.java");
            Files.createDirectories(src.getParent());
            Files.writeString(src, SOURCE);
            Files.createDirectories(classes);
            assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null, "-g", "-d", classes.toString(), src.toString()));
        }
        final Analyzer analyzer = new Analyzer();
        analyzer.addClasses(classes);
        final Map<String, CallIndex.ClassInfo> infos = analyzer.classInfos();
        final Hierarchy hierarchy = new Hierarchy();
        final CallGraph graph = new CallGraph(infos.keySet(), hierarchy);
        final List<MethodFacts> facts = new ArrayList<>(analyzer.graphFacts());
        if (reversed) {
            Collections.reverse(facts);
        }
        for (int i = 0; i < times; i++) {
            hierarchy.add(infos);
            graph.addMethods(facts);
        }
        graph.finish();
        return graph;
    }
}
