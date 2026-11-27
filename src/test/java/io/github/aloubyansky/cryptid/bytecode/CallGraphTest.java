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

                interface I { default String m() { return "I"; } }
                interface J extends I { default String m() { return "J"; } }
                static class B implements J {}
                static class C extends B implements I {}
                static class C2 implements I, J {}

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

    /** Of default methods overriding each other, the most specific interface's runs, wherever the class names it. */
    @Test
    void dispatchToTheMostSpecificDefaultMethod() throws Exception {
        final CallGraph g = graph(false, 1);
        final int im = g.method("org/acme/G$I.m()Ljava/lang/String;");
        final int jm = g.method("org/acme/G$J.m()Ljava/lang/String;");
        assertEquals(jm, g.dispatch(g.type("org/acme/G$C"), im));
        assertEquals(jm, g.dispatch(g.type("org/acme/G$C2"), im));
        assertEquals(jm, g.dispatch(g.type("org/acme/G$B"), im));
    }

    /**
     * Of a class in two artifacts with different code, each copy has its own methods with its own
     * calls, whichever is added first; the first artifact's copy is the default.
     */
    @Test
    void differingCopiesOfAClass() throws Exception {
        final String one = "package org.acme; public class V { static void one() {} static void two() {} static void v() { one(); } }";
        final String two = one.replace("{ one(); }", "{ two(); }");
        for (boolean reversed : new boolean[] {false, true}) {
            final Analyzer a = analyzer("a", one);
            final Analyzer b = analyzer("b", two);
            final Hierarchy hierarchy = new Hierarchy();
            final CallGraph g = new CallGraph(a.classInfos().keySet(), hierarchy);
            if (reversed) {
                hierarchy.add("g/b/1", b.classInfos());
                g.addMethods("g/b/1", b.graphFacts());
            }
            hierarchy.add("g/a/1", a.classInfos());
            g.addMethods("g/a/1", a.graphFacts());
            if (!reversed) {
                hierarchy.add("g/b/1", b.classInfos());
                g.addMethods("g/b/1", b.graphFacts());
            }
            g.finish();
            assertEquals(ids(g, "org/acme/V.one()V"), set(g.exactCallees(g.method("org/acme/V.v()V"))), "reversed: " + reversed);
            assertEquals(Set.of(g.method("g/b/1", "org/acme/V.two()V")), set(g.exactCallees(g.method("g/b/1", "org/acme/V.v()V"))),
                    "reversed: " + reversed);
            assertEquals(2, g.methods("org/acme/V.v()V").length);
            assertEquals("g/a/1", g.artifact(g.method("org/acme/V.v()V")));
        }
    }

    /** A copy shaded into another artifact calls its own copies, not the original's. */
    @Test
    void shadedCopiesCallTheirOwn() throws Exception {
        final String lib = "package org.acme; public class V { static void one() {} static void v() { one(); } }";
        final Analyzer original = analyzer("original", lib);
        final Analyzer shaded = analyzer("shaded", lib);
        final Hierarchy hierarchy = new Hierarchy(List.of("g/lib/1", "g/app/1"));
        final CallGraph g = new CallGraph(original.classInfos().keySet(), hierarchy);
        hierarchy.add("g/lib/1", original.classInfos());
        hierarchy.add("g/app/1", shaded.classInfos());
        g.addMethods("g/lib/1", original.graphFacts());
        g.addMethods("g/app/1", shaded.graphFacts());
        g.finish();
        final int libOne = g.method("g/lib/1", "org/acme/V.one()V");
        final int appOne = g.method("g/app/1", "org/acme/V.one()V");
        assertTrue(libOne >= 0 && appOne >= 0 && libOne != appOne);
        assertEquals(Set.of(appOne), set(g.exactCallees(g.method("g/app/1", "org/acme/V.v()V"))));
        assertEquals(Set.of(g.method("g/app/1", "org/acme/V.v()V")), set(g.callers(appOne)));
        assertEquals(Set.of(g.method("g/lib/1", "org/acme/V.v()V")), set(g.callers(libOne)));
    }

    private Analyzer analyzer(String name, String source) throws Exception {
        final Path src = tmp.resolve(name + "-src/org/acme/V.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, source);
        final Path classes = Files.createDirectories(tmp.resolve(name + "-classes"));
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null, "-g", "-d", classes.toString(), src.toString()));
        final Analyzer analyzer = new Analyzer();
        analyzer.addClasses(classes);
        return analyzer;
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
        // by class, then artifact, then member
        for (int m = 0; m + 1 < g.methodCount(); m++) {
            final String a = g.methodKey(m);
            final String b = g.methodKey(m + 1);
            final int byClass = a.substring(0, a.indexOf('.')).compareTo(b.substring(0, b.indexOf('.')));
            assertTrue(byClass < 0 || byClass == 0 && a.compareTo(b) < 0, a + " before " + b);
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
        final Map<String, ClassInfo> infos = analyzer.classInfos();
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
