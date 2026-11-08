package org.acme.cbom.bytecode;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ibm.mapper.model.INode;
import com.ibm.rules.InventoryRule;
import com.ibm.rules.issue.Issue;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;
import org.acme.cbom.spec.ApiSpecs;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Checks the bytecode engine against sonar-cryptography's own Java test fixtures (see {@code
 * src/test/resources/sonar-cryptography-fixtures/NOTICE.md}): each fixture is compiled with javac,
 * analyzed with the call index, and the resulting inventory issues are compared with the fixture's
 * {@code // Noncompliant {{...}}} annotations.
 *
 * <p>Not every expected detection is reproduced yet, so the result of each fixture is compared with
 * a checked-in baseline, {@code src/test/resources/fixture-baseline.tsv}. The test fails when a
 * fixture regresses: fewer matched issues, more unexpected ones, or no longer compiling. It reports
 * improvements without failing. Run with {@code -Dfixtures.updateBaseline=true} to rewrite the
 * baseline from the current results, after a deliberate change.
 *
 * <p>An issue reported up to three lines earlier than expected counts as matched: javac records
 * no line entry for a constructor call continuing on the next lines of a statement.
 */
class FixtureConformanceTest {

    private static final Path FIXTURES = Path.of("src/test/resources/sonar-cryptography-fixtures");
    private static final Path BASELINE = Path.of("src/test/resources/fixture-baseline.tsv");
    /** Fixtures in these directories reference each other and are compiled together. */
    private static final List<String> COMPILED_TOGETHER = List.of("crossfile");

    /**
     * The result of one fixture.
     *
     * @param status {@code OK}, {@code DIFF} or {@code NOT_COMPILED}
     * @param matched expected issues found
     * @param expected expected issues
     * @param unexpected issues found that weren't expected
     * @param details missing and unexpected issues, or compilation errors
     */
    record Outcome(String status, int matched, int expected, int unexpected, List<String> details) {
        String toTsv(String fixture) {
            return fixture + "\t" + status + "\t" + matched + "\t" + expected + "\t" + unexpected;
        }
    }

    @Test
    void matchesBaseline(@TempDir Path work) throws Exception {
        final Translation translation = new Translation();
        final String classpath = System.getProperty("java.class.path");

        final Map<String, Outcome> outcomes = new TreeMap<>();
        int unit = 0;
        for (List<Path> sources : units()) {
            final Path classes = work.resolve("classes-" + unit);
            final String error = FixtureSupport.compile(sources, work.resolve("src-" + unit), classes, classpath);
            unit++;
            final Map<String, Map<Integer, List<String>>> actualByFile = new LinkedHashMap<>();
            if (error == null) {
                analyze(classes, translation, actualByFile);
            }
            for (Path src : sources) {
                final String fixture = FIXTURES.relativize(src).toString().replace('\\', '/');
                final Map<Integer, List<String>> expected = FixtureSupport.expected(Files.readAllLines(src));
                final int exp = expected.values().stream().mapToInt(List::size).sum();
                if (error != null) {
                    outcomes.put(fixture, new Outcome("NOT_COMPILED", 0, exp, 0, List.of(error)));
                } else {
                    outcomes.put(fixture, compare(expected, actual(actualByFile, src)));
                }
            }
        }

        final List<String> report = new ArrayList<>();
        int exp = 0, matched = 0, unexpected = 0, notCompiled = 0;
        for (Map.Entry<String, Outcome> e : outcomes.entrySet()) {
            final Outcome o = e.getValue();
            exp += o.expected();
            matched += o.matched();
            unexpected += o.unexpected();
            notCompiled += o.status().equals("NOT_COMPILED") ? 1 : 0;
        }
        report.add(String.format("Fixtures: %d (%d not compilable). Expected issues: %d, matched: %d, unexpected: %d",
                outcomes.size(), notCompiled, exp, matched, unexpected));

        if (Boolean.getBoolean("fixtures.updateBaseline")) {
            final List<String> lines = new ArrayList<>();
            lines.add("# fixture\tstatus\tmatched\texpected\tunexpected  (FixtureConformanceTest baseline)");
            outcomes.forEach((f, o) -> lines.add(o.toTsv(f)));
            Files.write(BASELINE, lines);
            System.out.println(String.join("\n", report) + "\nBaseline written to " + BASELINE);
            return;
        }

        final Map<String, String[]> baseline = new TreeMap<>();
        if (Files.exists(BASELINE)) {
            for (String line : Files.readAllLines(BASELINE)) {
                if (!line.startsWith("#") && !line.isBlank()) {
                    final String[] f = line.split("\t");
                    baseline.put(f[0], f);
                }
            }
        }
        final List<String> regressions = new ArrayList<>();
        final List<String> improvements = new ArrayList<>();
        outcomes.forEach((fixture, o) -> {
            final String[] b = baseline.get(fixture);
            if (b == null) {
                regressions.add(fixture + ": not in the baseline (" + o.toTsv(fixture) + ")");
                return;
            }
            final boolean wasCompiled = !b[1].equals("NOT_COMPILED");
            final int bMatched = Integer.parseInt(b[2]);
            final int bUnexpected = Integer.parseInt(b[4]);
            if (wasCompiled && o.status().equals("NOT_COMPILED")) {
                regressions.add(fixture + ": no longer compiles: " + o.details());
            } else if (o.matched() < bMatched || o.unexpected() > bUnexpected) {
                regressions.add(String.format("%s: matched %d (was %d), unexpected %d (was %d): %s",
                        fixture, o.matched(), bMatched, o.unexpected(), bUnexpected, o.details()));
            } else if (o.matched() > bMatched || o.unexpected() < bUnexpected || (!wasCompiled && !o.status().equals("NOT_COMPILED"))) {
                improvements.add(String.format("%s: matched %d (was %d), unexpected %d (was %d)",
                        fixture, o.matched(), bMatched, o.unexpected(), bUnexpected));
            }
        });
        baseline.keySet().stream().filter(f -> !outcomes.containsKey(f))
                .forEach(f -> regressions.add(f + ": in the baseline but no longer a fixture"));

        if (!improvements.isEmpty()) {
            report.add("Improvements over the baseline (rerun with -Dfixtures.updateBaseline=true to record them):");
            improvements.forEach(i -> report.add("  " + i));
        }
        System.out.println(String.join("\n", report));
        assertTrue(regressions.isEmpty(), "Regressions against " + BASELINE + ":\n  " + String.join("\n  ", regressions));
    }

    /** The compilation units: one per fixture, or one per directory compiled together. */
    private static List<List<Path>> units() throws IOException {
        final Map<String, List<Path>> together = new TreeMap<>();
        final List<List<Path>> units = new ArrayList<>();
        try (Stream<Path> s = Files.walk(FIXTURES)) {
            for (Path p : s.filter(f -> f.toString().endsWith(".java")).sorted().toList()) {
                final String dir = FIXTURES.relativize(p.getParent()).toString().replace('\\', '/');
                if (COMPILED_TOGETHER.contains(dir)) {
                    together.computeIfAbsent(dir, k -> new ArrayList<>()).add(p);
                } else {
                    units.add(List.of(p));
                }
            }
        }
        units.addAll(together.values());
        return units;
    }

    /** Analyzes compiled fixtures with the call index; collects issues by source file and line. */
    private static void analyze(Path classes, Translation translation,
            Map<String, Map<Integer, List<String>>> actualByFile) throws IOException {
        final Analyzer analyzer = new Analyzer();
        analyzer.addClasses(classes);
        final Types types = new Types(FixtureConformanceTest.class.getClassLoader());
        types.addClasses(classes);
        final Map<String, CallIndex.ClassInfo> infos = analyzer.classInfos();
        final CallIndex index = new CallIndex(infos.keySet());
        index.addClasses(infos);
        final List<Analyzer.MethodResult> methods = analyzer.analyze();
        index.addCalls(methods, "");
        index.finish();
        final SpecDetector detector = new SpecDetector(new ApiIndex(ApiSpecs.load()), types, "", index);
        for (Analyzer.MethodResult m : methods) {
            for (Finding f : detector.detect(m)) {
                final List<INode> nodes = translation.process(f.store());
                for (Issue<Loc> issue : new InventoryRule<Loc>().report(f.loc(), nodes)) {
                    actualByFile.computeIfAbsent(issue.tree().file(), k -> new TreeMap<>())
                            .computeIfAbsent(issue.tree().line(), k -> new ArrayList<>())
                            .add(issue.message());
                }
            }
        }
    }

    /** The issues located in a fixture, matched by its file name. */
    private static Map<Integer, List<String>> actual(Map<String, Map<Integer, List<String>>> byFile, Path src) {
        final String name = src.getFileName().toString();
        final Map<Integer, List<String>> result = new TreeMap<>();
        byFile.forEach((file, issues) -> {
            if (file.equals(name) || file.endsWith("/" + name)) {
                issues.forEach((line, msgs) -> result.computeIfAbsent(line, k -> new ArrayList<>()).addAll(msgs));
            }
        });
        return result;
    }

    /** Compares expected and actual issues, accepting matches up to three lines early. */
    private static Outcome compare(Map<Integer, List<String>> expected, Map<Integer, List<String>> actual) {
        final Map<Integer, List<String>> remaining = new TreeMap<>();
        actual.forEach((l, msgs) -> remaining.put(l, new ArrayList<>(msgs)));
        int matched = 0;
        final List<String[]> missing = new ArrayList<>();
        for (Map.Entry<Integer, List<String>> e : expected.entrySet()) {
            for (String msg : e.getValue()) {
                if (remaining.getOrDefault(e.getKey(), new ArrayList<>()).remove(msg)) {
                    matched++;
                } else {
                    missing.add(new String[] {String.valueOf(e.getKey()), msg});
                }
            }
        }
        for (Iterator<String[]> it = missing.iterator(); it.hasNext(); ) {
            final String[] m = it.next();
            final int line = Integer.parseInt(m[0]);
            for (int d = 1; d <= 3; d++) {
                final List<String> at = remaining.get(line - d);
                if (at != null && at.remove(m[1])) {
                    matched++;
                    it.remove();
                    break;
                }
            }
        }
        final List<String> details = new ArrayList<>();
        missing.forEach(m -> details.add("missing " + m[0] + ": " + m[1]));
        int unexpected = 0;
        for (Map.Entry<Integer, List<String>> e : remaining.entrySet()) {
            for (String msg : e.getValue()) {
                details.add("unexpected " + e.getKey() + ": " + msg);
                unexpected++;
            }
        }
        final int exp = expected.values().stream().mapToInt(List::size).sum();
        final String status = missing.isEmpty() && unexpected == 0 ? "OK" : "DIFF";
        return new Outcome(status, matched, exp, unexpected, details);
    }
}
