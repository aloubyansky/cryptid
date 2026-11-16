package io.github.aloubyansky.cryptid.bytecode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.aloubyansky.cryptid.bytecode.MethodFacts.Call;
import io.github.aloubyansky.cryptid.bytecode.MethodFacts.Kind;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks the calls, instantiations and method handles read from a method's instructions. */
class GraphFactsTest {

    private static final String SOURCE = """
            package org.acme;

            import java.util.function.Function;
            import java.util.function.Supplier;

            public class Facts {
                interface Shape { double area(); }
                record Square(double side) implements Shape { public double area() { return side * side; } }
                abstract static class NoCode { abstract void m(); }

                static String name(Object o) { return String.valueOf(o); }

                Supplier<StringBuilder> refs() {
                    Function<Object, String> f = Facts::name;
                    Runnable r = () -> name(this);
                    r.run();
                    return StringBuilder::new;
                }

                double calls(Shape s) {
                    Square q = new Square(2);
                    return s.area() + q.area() + name(q).length() + name(s).length();
                }
            }
            """;

    private static final String NAME = "(Ljava/lang/Object;)Ljava/lang/String;";

    @TempDir
    Path tmp;

    @Test
    void callsAndInstantiations() throws Exception {
        final MethodFacts m = facts("org/acme/Facts.calls(Lorg/acme/Facts$Shape;)D");
        assertTrue(m.calls().containsAll(List.of(
                new Call(Kind.SPECIAL, "org/acme/Facts$Square", "<init>", "(D)V", false),
                new Call(Kind.INTERFACE, "org/acme/Facts$Shape", "area", "()D", false),
                new Call(Kind.VIRTUAL, "org/acme/Facts$Square", "area", "()D", false),
                new Call(Kind.STATIC, "org/acme/Facts", "name", NAME, false),
                new Call(Kind.VIRTUAL, "java/lang/String", "length", "()I", false))), m.toString());
        assertEquals(new HashSet<>(m.calls()).size(), m.calls().size(), "calls are distinct");
        assertEquals(List.of("org/acme/Facts$Square"), m.instantiated());
    }

    @Test
    void methodHandles() throws Exception {
        final MethodFacts m = facts("org/acme/Facts.refs()Ljava/util/function/Supplier;");
        assertTrue(m.calls().contains(new Call(Kind.STATIC, "org/acme/Facts", "name", NAME, true)), m.toString());
        assertTrue(m.calls().contains(new Call(Kind.SPECIAL, "java/lang/StringBuilder", "<init>", "()V", true)), m.toString());
        assertTrue(m.calls().stream().anyMatch(c -> c.handle() && c.owner().equals("org/acme/Facts") && c.name().startsWith("lambda$refs$")),
                m.toString());
        assertTrue(m.calls().contains(new Call(Kind.INTERFACE, "java/lang/Runnable", "run", "()V", false)), m.toString());
        // a constructor reference instantiates its class
        assertEquals(List.of("java/lang/StringBuilder"), m.instantiated());
    }

    @Test
    void fieldHandlesAndOtherBootstrapsAreNotCalls() throws Exception {
        // a record's toString is an invokedynamic of ObjectMethods, with a getter handle per component
        final MethodFacts m = facts("org/acme/Facts$Square.toString()Ljava/lang/String;");
        assertEquals(List.of(), m.calls());
        assertEquals(List.of(), m.instantiated());
    }

    @Test
    void methodsWithoutCodeHaveEmptyFacts() throws Exception {
        final MethodFacts m = facts("org/acme/Facts$NoCode.m()V");
        assertEquals(List.of(), m.calls());
        assertEquals(List.of(), m.instantiated());
    }

    private MethodFacts facts(String method) throws Exception {
        final Path src = tmp.resolve("src/org/acme/Facts.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, SOURCE);
        final Path classes = Files.createDirectories(tmp.resolve("classes"));
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null, "-g", "-d", classes.toString(), src.toString()));
        final Analyzer analyzer = new Analyzer();
        analyzer.addClasses(classes);
        return analyzer.graphFacts().stream().filter(f -> f.method().equals(method)).findFirst()
                .orElseThrow(() -> new AssertionError("no facts for " + method));
    }
}
