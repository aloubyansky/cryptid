package io.github.aloubyansky.cryptid.scan;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

/**
 * Compiles sonar-cryptography's test fixtures with javac and reads their expected detections.
 *
 * <p>The fixtures target sonar-java's error-tolerant parser, so copies are prepared for javac with
 * line-preserving edits only:
 *
 * <ul>
 *   <li>top-level classes lose {@code public}, since their names don't match the file names;
 *   <li>star imports of the JCA, JSSE and spec packages are added on the first line, since
 *       fixtures often omit imports, e.g. of exception classes;
 *   <li>methods with unreported checked exceptions get {@code throws Exception};
 *   <li>undeclared constants are declared as {@code static final String} before the file's last
 *       closing brace.
 * </ul>
 */
public final class FixtureSupport {

    private static final Pattern NONCOMPLIANT =
            Pattern.compile("//\\s*Noncompliant(?:@([+-]?\\d+))?((?:\\s*\\{\\{.*?}})*)");
    private static final Pattern MESSAGE = Pattern.compile("\\{\\{(.*?)}}");
    private static final Pattern METHOD_DECL = Pattern.compile(
            "^(\\s*(?:(?:public|protected|private|static|final|synchronized)\\s+)*(?:<[^>]+>\\s*)?(?:[\\w.<>\\[\\], ?]+\\s+)?\\w+\\s*\\([^)]*\\))(\\s*\\{.*)$");
    private static final Pattern MISSING_VARIABLE = Pattern.compile("symbol:\\s+variable\\s+(\\w+)");
    private static final String IMPORTS = "import java.security.*; import java.security.spec.*; import javax.crypto.*;"
            + " import javax.crypto.spec.*; import javax.net.ssl.*; import java.util.*;";

    private FixtureSupport() {}

    /**
     * Reads the expected messages from {@code // Noncompliant[@offset] {{message}}...} comments.
     *
     * @param lines the fixture's lines
     * @return expected messages by line number
     */
    static Map<Integer, List<String>> expected(List<String> lines) {
        final Map<Integer, List<String>> result = new TreeMap<>();
        for (int i = 0; i < lines.size(); i++) {
            final Matcher m = NONCOMPLIANT.matcher(lines.get(i));
            if (!m.find()) {
                continue;
            }
            int line = i + 1;
            if (m.group(1) != null) {
                line += Integer.parseInt(m.group(1).replace("+", ""));
            }
            final Matcher msg = MESSAGE.matcher(m.group(2));
            while (msg.find()) {
                result.computeIfAbsent(line, k -> new ArrayList<>()).add(msg.group(1));
            }
        }
        return result;
    }

    /**
     * Prepares fixtures for javac and compiles them together, fixing what the preparation steps
     * can fix over up to four rounds.
     *
     * @param sources the fixtures
     * @param preparedDir where to write the prepared copies
     * @param classes the output directory
     * @param classpath the class path for javac
     * @return {@code null} on success, otherwise the first remaining errors
     * @throws IOException if a file can't be read or written
     */
    public static String compile(List<Path> sources, Path preparedDir, Path classes, String classpath) throws IOException {
        final Map<Path, List<String>> files = new HashMap<>();
        final List<Path> prepared = new ArrayList<>();
        for (Path src : sources) {
            final Path p = preparedDir.resolve(src.getFileName().toString());
            files.put(p.toAbsolutePath().normalize(), prepare(Files.readAllLines(src)));
            prepared.add(p);
        }
        Files.createDirectories(preparedDir);
        String errors = null;
        for (int round = 0; round < 4; round++) {
            for (Map.Entry<Path, List<String>> e : files.entrySet()) {
                Files.write(e.getKey(), e.getValue());
            }
            final List<Diagnostic<? extends JavaFileObject>> diags = javac(prepared, classes, classpath);
            if (diags.isEmpty()) {
                return null;
            }
            boolean fixed = false;
            final List<String> msgs = new ArrayList<>();
            for (Diagnostic<? extends JavaFileObject> d : diags) {
                final String msg = d.getMessage(null);
                msgs.add(d.getLineNumber() + ": " + msg.lines().findFirst().orElse(""));
                final List<String> lines = d.getSource() == null
                        ? null
                        : files.get(Path.of(d.getSource().toUri()).toAbsolutePath().normalize());
                if (lines != null) {
                    fixed |= fix(lines, msg, (int) d.getLineNumber());
                }
            }
            errors = String.join("; ", msgs.subList(0, Math.min(3, msgs.size())));
            if (!fixed) {
                break;
            }
        }
        return errors;
    }

    private static List<String> prepare(List<String> original) {
        final List<String> lines = new ArrayList<>(original);
        for (int i = 0; i < lines.size(); i++) {
            lines.set(i, lines.get(i).replaceFirst(
                    "^public\\s+((?:final\\s+|abstract\\s+)?(?:class|interface|enum|record)\\s)", "$1"));
        }
        int pkg = -1;
        for (int i = 0; i < lines.size(); i++) {
            if (lines.get(i).matches("^\\s*package\\s+[\\w.]+\\s*;.*")) {
                pkg = i;
                break;
            }
        }
        if (pkg >= 0) {
            lines.set(pkg, lines.get(pkg).replaceFirst(";", "; " + IMPORTS));
        } else if (!lines.isEmpty()) {
            lines.set(0, IMPORTS + " " + lines.get(0));
        }
        return lines;
    }

    /** Applies the fix for one compilation error, if there is one. */
    private static boolean fix(List<String> lines, String msg, int line) {
        final Matcher mv = MISSING_VARIABLE.matcher(msg);
        if (msg.contains("cannot find symbol") && mv.find()) {
            final String decl = " static final String " + mv.group(1) + " = \"0123456789abcdef0123456789abcdef\"; ";
            for (int l = lines.size() - 1; l >= 0; l--) {
                final int brace = lines.get(l).lastIndexOf('}');
                if (brace >= 0) {
                    if (lines.get(l).contains(decl)) {
                        return false;
                    }
                    lines.set(l, lines.get(l).substring(0, brace) + decl + lines.get(l).substring(brace));
                    return true;
                }
            }
        }
        if (msg.contains("unreported exception")) {
            for (int l = line - 1; l >= 0; l--) {
                final Matcher m = METHOD_DECL.matcher(lines.get(l));
                if (m.matches() && !lines.get(l).contains(" throws ") && !lines.get(l).contains(" new ")
                        && !lines.get(l).trim().startsWith("return")) {
                    lines.set(l, m.group(1) + " throws Exception" + m.group(2));
                    return true;
                }
            }
        }
        return false;
    }

    private static List<Diagnostic<? extends JavaFileObject>> javac(List<Path> files, Path classes, String classpath)
            throws IOException {
        Files.createDirectories(classes);
        final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        final DiagnosticCollector<JavaFileObject> diags = new DiagnosticCollector<>();
        try (StandardJavaFileManager fm = compiler.getStandardFileManager(diags, null, null)) {
            final List<String> options = new ArrayList<>(List.of("-g", "-proc:none", "-nowarn", "-d", classes.toString()));
            if (!classpath.isEmpty()) {
                options.addAll(List.of("-cp", classpath));
            }
            compiler.getTask(null, fm, diags, options, null, fm.getJavaFileObjectsFromPaths(files)).call();
        }
        return diags.getDiagnostics().stream().filter(d -> d.getKind() == Diagnostic.Kind.ERROR).toList();
    }
}
