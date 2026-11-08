package org.acme.cbom;

import io.smallrye.classfile.Attributes;
import io.smallrye.classfile.ClassFile;
import io.smallrye.classfile.ClassModel;
import io.smallrye.classfile.CodeElement;
import io.smallrye.classfile.CodeModel;
import io.smallrye.classfile.Label;
import io.smallrye.classfile.MethodModel;
import io.smallrye.classfile.Opcode;
import io.smallrye.classfile.TypeKind;
import io.smallrye.classfile.extras.reflect.AccessFlag;
import io.smallrye.classfile.instruction.ArrayLoadInstruction;
import io.smallrye.classfile.instruction.ArrayStoreInstruction;
import io.smallrye.classfile.instruction.BranchInstruction;
import io.smallrye.classfile.instruction.ConstantInstruction;
import io.smallrye.classfile.instruction.ConvertInstruction;
import io.smallrye.classfile.instruction.ExceptionCatch;
import io.smallrye.classfile.instruction.FieldInstruction;
import io.smallrye.classfile.instruction.InvokeDynamicInstruction;
import io.smallrye.classfile.instruction.InvokeInstruction;
import io.smallrye.classfile.instruction.LabelTarget;
import io.smallrye.classfile.instruction.LoadInstruction;
import io.smallrye.classfile.instruction.LookupSwitchInstruction;
import io.smallrye.classfile.instruction.MonitorInstruction;
import io.smallrye.classfile.instruction.NewMultiArrayInstruction;
import io.smallrye.classfile.instruction.NewObjectInstruction;
import io.smallrye.classfile.instruction.NewPrimitiveArrayInstruction;
import io.smallrye.classfile.instruction.NewReferenceArrayInstruction;
import io.smallrye.classfile.instruction.OperatorInstruction;
import io.smallrye.classfile.instruction.ReturnInstruction;
import io.smallrye.classfile.instruction.StackInstruction;
import io.smallrye.classfile.instruction.StoreInstruction;
import io.smallrye.classfile.instruction.SwitchCase;
import io.smallrye.classfile.instruction.TableSwitchInstruction;
import io.smallrye.classfile.instruction.TypeCheckInstruction;
import java.io.IOException;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.jboss.logging.Logger;

/**
 * Finds the source files that must be scanned together for sonar-cryptography to resolve values
 * passed across sources JARs, by analyzing the bytecode of the binary JARs.
 *
 * <p>sonar-cryptography resolves a crypto API argument that comes from a method parameter, e.g.
 * {@code Cipher.getInstance(transformation)} in a wrapper method, through a hook on the enclosing
 * method that matches the method's call sites in the same scan. A scan of a single sources JAR
 * misses call sites in other JARs. This class computes which methods take part in such chains
 * across JARs:
 *
 * <ol>
 *   <li><b>Seeds</b>: methods passing one of their parameters, possibly transformed, as a {@code
 *       String} or {@code int} argument to a crypto API (JCA/JCE, JSSE, Bouncy Castle, Tink). A
 *       small abstract interpreter tracks, for every value, the parameters it may derive from and
 *       whether it may derive from a constant.
 *   <li><b>Propagation</b>: a call site passing a constant into a relevant parameter of a relevant
 *       method is a resolution site; a call site passing its own parameters makes its method
 *       relevant, which follows chains through intermediate methods.
 *   <li><b>Groups</b>: connected sets of relevant methods. Groups spanning several sources JARs
 *       need a joint scan of the source files of their methods.
 * </ol>
 *
 * <p>Calls are matched by their declared owner, resolved to the declaring class along the
 * superclass chain, but not through interface dispatch, which sonar-cryptography's hook matching
 * doesn't follow either. The analysis over-approximates otherwise; imprecision only costs scan
 * time.
 */
public final class CryptoCallGraph {

    private static final Logger log = Logger.getLogger(CryptoCallGraph.class);

    /** Bit marking values that may derive from a constant or a static field. */
    private static final long CONST = 1L << 62;

    /** Bit marking two-slot (long, double) stack entries; not part of the abstract value. */
    private static final long WIDE = 1L << 63;

    /** Parameters beyond this index aren't tracked. */
    private static final int MAX_PARAMS = 62;

    private static final Set<String> JAVA_SECURITY_APIS =
            Set.of(
                    "java/security/MessageDigest",
                    "java/security/Signature",
                    "java/security/KeyPairGenerator",
                    "java/security/KeyFactory",
                    "java/security/KeyStore",
                    "java/security/SecureRandom",
                    "java/security/AlgorithmParameters",
                    "java/security/AlgorithmParameterGenerator",
                    "java/security/cert/CertificateFactory");

    /**
     * A source file of a sources JAR.
     *
     * @param prefix the sources JAR's location prefix, see {@link MavenComponent#sourcesDirName()}
     * @param path the file path relative to the source root, e.g. {@code org/acme/Foo.java}
     */
    public record SourceFile(String prefix, String path) {}

    /**
     * A set of source files to scan together.
     *
     * @param files the files, grouped by sources JAR prefix
     * @param methods the number of relevant methods in the group
     * @param resolutionSites the number of call sites passing constants into the group's chains
     */
    public record Group(Map<String, Set<String>> files, int methods, int resolutionSites) {
        /**
         * Returns the number of source files in this group.
         *
         * @return the total number of files over all sources JARs
         */
        public int fileCount() {
            return files.values().stream().mapToInt(Set::size).sum();
        }
    }

    /**
     * The result of the analysis.
     *
     * @param groups the groups spanning several sources JARs, largest first
     * @param seeds the number of seed methods
     * @param relevantMethods the number of relevant methods, including seeds
     * @param resolutionSites the number of resolution sites
     */
    public record Result(List<Group> groups, int seeds, int relevantMethods, int resolutionSites) {}

    /** A call from a method to a method of an analyzed class, with its abstract argument values. */
    private record CallSite(int caller, long[] args) {}

    /** Per class: the sources JAR it belongs to, its superclass and its source file. */
    private record ClassInfo(String prefix, String superclass, String sourcePath, Set<String> methods) {}

    private final Map<String, Integer> methodIds = new HashMap<>();
    private final List<String> methodKeys = new ArrayList<>();
    private final Map<String, ClassInfo> classes = new HashMap<>();
    private final Map<Integer, List<CallSite>> callsTo = new HashMap<>();
    private final Map<Integer, Long> seeds = new HashMap<>();
    /** Seed calls by crypto API method, {@code owner.name}, for the debug summary. */
    private final Map<String, Integer> seedApis = new HashMap<>();
    private Set<String> analyzedClassNames = Set.of();

    /**
     * Analyzes the binary JARs of the sources JARs and computes the groups.
     *
     * @param binaries binary JARs by sources JAR prefix; several JARs per prefix are allowed, e.g.
     *     for classifiers sharing sources
     * @param sourceRoots the source root ({@code moduleDir/src/main/java}) of each sources JAR, by
     *     prefix; classes whose source file doesn't exist there are ignored as group members
     * @return the analysis result
     * @throws IOException if a JAR can't be read
     */
    public static Result analyze(Map<String, List<Path>> binaries, Map<String, Path> sourceRoots)
            throws IOException {
        final CryptoCallGraph g = new CryptoCallGraph();
        final long start = System.currentTimeMillis();
        g.analyzedClassNames = listClassNames(binaries);
        int methods = 0;
        for (Map.Entry<String, List<Path>> e : binaries.entrySet()) {
            for (Path jar : e.getValue()) {
                methods += g.readJar(e.getKey(), jar, sourceRoots.get(e.getKey()));
            }
        }
        final Result result = g.propagate();
        log.infof(
                "Call graph: %d classes, %d methods, %d seeds, %d relevant methods, %d resolution"
                        + " sites, %d groups spanning several sources JARs, in %d ms",
                g.classes.size(),
                methods,
                result.seeds(),
                result.relevantMethods(),
                result.resolutionSites(),
                result.groups().size(),
                System.currentTimeMillis() - start);
        if (log.isDebugEnabled()) {
            g.logSeedSummary(result);
        }
        return result;
    }

    /**
     * Logs, at debug level, where the seeds come from: per sources JAR, per crypto API method,
     * and the seeds that ended up in groups spanning several sources JARs.
     *
     * @param result the analysis result
     */
    private void logSeedSummary(Result result) {
        final Map<String, Integer> byPrefix = new HashMap<>();
        for (int m : seeds.keySet()) {
            byPrefix.merge(prefixOf(m), 1, Integer::sum);
        }
        log.debugf("Seeds by sources JAR (top 20 of %d):", byPrefix.size());
        top(byPrefix, 20).forEach(e -> log.debugf("  %6d  %s", e.getValue(), e.getKey()));
        log.debugf("Seed calls by crypto API method (top 25 of %d):", seedApis.size());
        top(seedApis, 25).forEach(e -> log.debugf("  %6d  %s", e.getValue(), e.getKey()));
        final Set<String> grouped = new HashSet<>();
        for (Group g : result.groups()) {
            g.files().forEach((prefix, files) -> files.forEach(f -> grouped.add(prefix + "/" + f)));
        }
        log.debug("Seeds in groups spanning several sources JARs:");
        seeds.keySet().stream()
                .map(methodKeys::get)
                .filter(k -> {
                    final ClassInfo ci = classes.get(k.substring(0, k.indexOf('.')));
                    return ci != null && ci.sourcePath() != null && grouped.contains(ci.prefix() + "/" + ci.sourcePath());
                })
                .sorted()
                .forEach(k -> log.debugf("  %s", k));
    }

    private String prefixOf(int method) {
        final String key = methodKeys.get(method);
        final ClassInfo ci = classes.get(key.substring(0, key.indexOf('.')));
        return ci == null ? "?" : ci.prefix();
    }

    private static List<Map.Entry<String, Integer>> top(Map<String, Integer> counts, int n) {
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(n)
                .toList();
    }

    /**
     * Lists the names of all classes in the JARs, to record only calls to analyzed classes.
     *
     * @param binaries binary JARs by sources JAR prefix
     * @return internal class names
     * @throws IOException if a JAR can't be read
     */
    private static Set<String> listClassNames(Map<String, List<Path>> binaries) throws IOException {
        final Set<String> names = new HashSet<>();
        for (List<Path> jars : binaries.values()) {
            for (Path jar : jars) {
                try (ZipFile zip = new ZipFile(jar.toFile())) {
                    zip.stream()
                            .map(ZipEntry::getName)
                            .filter(CryptoCallGraph::isBaseClassEntry)
                            .forEach(n -> names.add(n.substring(0, n.length() - ".class".length())));
                }
            }
        }
        return names;
    }

    /**
     * Tells whether a JAR entry is a class of the base version, i.e. not a multi-release variant
     * and not a module or package descriptor.
     *
     * @param name the entry name
     * @return {@code true} for regular class entries
     */
    private static boolean isBaseClassEntry(String name) {
        return name.endsWith(".class")
                && !name.startsWith("META-INF/")
                && !name.endsWith("module-info.class")
                && !name.endsWith("package-info.class");
    }

    /**
     * Reads the classes of a binary JAR, interpreting the code of every method.
     *
     * @param prefix the sources JAR prefix the JAR belongs to
     * @param jar the binary JAR
     * @param sourceRoot the source root of the sources JAR, or {@code null}
     * @return the number of methods read
     * @throws IOException if the JAR can't be read
     */
    private int readJar(String prefix, Path jar, Path sourceRoot) throws IOException {
        int methods = 0;
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            for (ZipEntry entry : zip.stream().filter(e -> isBaseClassEntry(e.getName())).toList()) {
                final ClassModel cm;
                try {
                    cm = ClassFile.of().parse(zip.getInputStream(entry).readAllBytes());
                } catch (RuntimeException e) {
                    log.debugf(e, "Skipping unparseable class %s in %s", entry.getName(), jar);
                    continue;
                }
                final String className = cm.thisClass().asInternalName();
                if (classes.containsKey(className)) {
                    continue;
                }
                final Set<String> declared = new HashSet<>();
                for (MethodModel mm : cm.methods()) {
                    declared.add(mm.methodName().stringValue() + mm.methodType().stringValue());
                }
                classes.put(
                        className,
                        new ClassInfo(
                                prefix,
                                cm.superclass().map(s -> s.asInternalName()).orElse(null),
                                sourcePath(cm, className, sourceRoot),
                                declared));
                for (MethodModel mm : cm.methods()) {
                    methods++;
                    mm.code().ifPresent(code -> interpret(className, mm, code));
                }
            }
        }
        return methods;
    }

    /**
     * Maps a class to its source file, using its package and {@code SourceFile} attribute, which
     * also maps nested and anonymous classes and lambdas to their enclosing source file.
     *
     * @param cm the class
     * @param className the internal class name
     * @param sourceRoot the source root of the sources JAR, or {@code null}
     * @return the source file path relative to the source root, or {@code null} if the class has
     *     no {@code SourceFile} attribute or the file doesn't exist
     */
    private static String sourcePath(ClassModel cm, String className, Path sourceRoot) {
        if (sourceRoot == null) {
            return null;
        }
        return cm.findAttribute(Attributes.sourceFile())
                .map(sf -> {
                    final int slash = className.lastIndexOf('/');
                    final String pkg = slash < 0 ? "" : className.substring(0, slash + 1);
                    return pkg + sf.sourceFile().stringValue();
                })
                .filter(p -> Files.isRegularFile(sourceRoot.resolve(p)))
                .orElse(null);
    }

    /**
     * Returns the id of a method, assigning one on first use.
     *
     * @param key {@code owner.name+descriptor}
     * @return the method id
     */
    private int methodId(String key) {
        return methodIds.computeIfAbsent(
                key,
                k -> {
                    methodKeys.add(k);
                    return methodKeys.size() - 1;
                });
    }

    /**
     * Tells whether a class is a crypto API whose calls sonar-cryptography detects.
     *
     * @param owner the internal class name
     * @return {@code true} for JCA/JCE, JSSE, Bouncy Castle and Tink classes
     */
    static boolean isCryptoApi(String owner) {
        return owner.startsWith("javax/crypto/")
                || owner.startsWith("javax/net/ssl/")
                || owner.startsWith("java/security/spec/")
                || JAVA_SECURITY_APIS.contains(owner)
                || owner.startsWith("org/bouncycastle/")
                || owner.startsWith("com/google/crypto/tink/");
    }

    // ---- abstract interpretation ----

    /** Abstract state at a program point: local variables and operand stack. */
    private static final class State {
        long[] locals;
        long[] stack;
        int sp;

        State(int locals, int stack) {
            this.locals = new long[locals];
            this.stack = new long[stack];
        }

        State copy() {
            final State s = new State(0, 0);
            s.locals = locals.clone();
            s.stack = stack.clone();
            s.sp = sp;
            return s;
        }

        /**
         * Merges another state into this one.
         *
         * @param o the other state
         * @return {@code true} if this state changed
         */
        boolean merge(State o) {
            boolean changed = false;
            if (o.locals.length > locals.length) {
                locals = Arrays.copyOf(locals, o.locals.length);
                changed = true;
            }
            for (int i = 0; i < o.locals.length; i++) {
                final long v = locals[i] | o.locals[i];
                changed |= v != locals[i];
                locals[i] = v;
            }
            for (int i = 0; i < Math.min(sp, o.sp); i++) {
                final long v = stack[i] | o.stack[i];
                changed |= v != stack[i];
                stack[i] = v;
            }
            return changed;
        }

        void push(long v, int size) {
            if (sp == stack.length) {
                stack = Arrays.copyOf(stack, Math.max(4, sp * 2));
            }
            stack[sp++] = size == 2 ? v | WIDE : v & ~WIDE;
        }

        void push(long entry) {
            if (sp == stack.length) {
                stack = Arrays.copyOf(stack, Math.max(4, sp * 2));
            }
            stack[sp++] = entry;
        }

        long pop() {
            return sp > 0 ? stack[--sp] : 0;
        }

        void store(int slot, long v) {
            if (slot >= locals.length) {
                locals = Arrays.copyOf(locals, slot + 1);
            }
            locals[slot] = v & ~WIDE;
        }

        long load(int slot) {
            return slot < locals.length ? locals[slot] : 0;
        }
    }

    private static boolean wide(long entry) {
        return (entry & WIDE) != 0;
    }

    private static long value(long entry) {
        return entry & ~WIDE;
    }

    /**
     * Interprets a method's code to find its crypto API calls and its calls to analyzed classes,
     * with the abstract values of their arguments. The interpretation is a forward data-flow
     * analysis over the control flow graph, merging states at branch targets and exception
     * handlers until a fixpoint is reached.
     *
     * @param className the internal name of the declaring class
     * @param mm the method
     * @param code its code
     */
    private void interpret(String className, MethodModel mm, CodeModel code) {
        final List<CodeElement> elements = code.elementList();
        final Map<Label, Integer> labels = new HashMap<>();
        final List<ExceptionCatch> handlers = new ArrayList<>();
        for (int i = 0; i < elements.size(); i++) {
            if (elements.get(i) instanceof LabelTarget lt) {
                labels.put(lt.label(), i);
            } else if (elements.get(i) instanceof ExceptionCatch ec) {
                handlers.add(ec);
            }
        }
        // exception handler ranges as element index intervals
        final int[][] ranges = new int[handlers.size()][];
        for (int h = 0; h < handlers.size(); h++) {
            final ExceptionCatch ec = handlers.get(h);
            ranges[h] =
                    new int[] {labels.get(ec.tryStart()), labels.get(ec.tryEnd()), labels.get(ec.handler())};
        }

        final int caller = methodId(className + "." + mm.methodName().stringValue() + mm.methodType().stringValue());
        final State entry = new State(8, 8);
        final MethodTypeDesc type = mm.methodTypeSymbol();
        int slot = mm.flags().has(AccessFlag.STATIC) ? 0 : 1;
        for (int p = 0; p < type.parameterCount(); p++) {
            entry.store(slot, p < MAX_PARAMS ? 1L << p : 0);
            slot += TypeKind.from(type.parameterType(p)).slotSize();
        }

        final State[] states = new State[elements.size()];
        states[0] = entry;
        final Deque<Integer> work = new ArrayDeque<>();
        work.add(0);
        // call sites by element index, recorded on every visit and merged at the end
        final Map<Integer, Object[]> sites = new HashMap<>();
        long seedMask = 0;

        while (!work.isEmpty()) {
            final int blockStart = work.poll();
            final State s = states[blockStart].copy();
            for (int i = blockStart; i < elements.size(); i++) {
                final CodeElement el = elements.get(i);
                if (i != blockStart && el instanceof LabelTarget) {
                    flow(states, work, i, s);
                    break;
                }
                for (int[] r : ranges) {
                    if (i >= r[0] && i < r[1]) {
                        final State h = new State(0, 0);
                        h.locals = s.locals.clone();
                        h.stack = new long[4];
                        h.push(0, 1);
                        flow(states, work, r[2], h);
                    }
                }
                switch (el) {
                    case LoadInstruction li -> s.push(s.load(li.slot()), li.typeKind().slotSize());
                    case StoreInstruction si -> s.store(si.slot(), s.pop());
                    case ConstantInstruction ci ->
                            s.push(ci.opcode() == Opcode.ACONST_NULL ? 0 : CONST, ci.typeKind().slotSize());
                    case OperatorInstruction oi -> operator(s, oi);
                    case ConvertInstruction ci -> s.push(value(s.pop()), ci.toType().slotSize());
                    case StackInstruction si -> stack(s, si.opcode());
                    case FieldInstruction fi -> field(s, fi);
                    case InvokeInstruction ii -> seedMask |= invoke(s, ii, caller, i, sites);
                    case InvokeDynamicInstruction id -> {
                        final MethodTypeDesc t = id.typeSymbol();
                        long v = 0;
                        for (int p = 0; p < t.parameterCount(); p++) {
                            v |= value(s.pop());
                        }
                        if (!t.returnType().descriptorString().equals("V")) {
                            s.push(v, TypeKind.from(t.returnType()).slotSize());
                        }
                    }
                    case NewObjectInstruction n -> s.push(0, 1);
                    case NewPrimitiveArrayInstruction n -> {
                        s.pop();
                        s.push(0, 1);
                    }
                    case NewReferenceArrayInstruction n -> {
                        s.pop();
                        s.push(0, 1);
                    }
                    case NewMultiArrayInstruction n -> {
                        for (int d = 0; d < n.dimensions(); d++) {
                            s.pop();
                        }
                        s.push(0, 1);
                    }
                    case ArrayLoadInstruction al -> {
                        s.pop();
                        s.push(value(s.pop()), al.typeKind().slotSize());
                    }
                    case ArrayStoreInstruction as -> {
                        final long v = value(s.pop());
                        s.pop();
                        s.pop();
                        // varargs idiom (new array, dup, index, value, store): taint the array
                        if (s.sp > 0) {
                            s.stack[s.sp - 1] |= v;
                        }
                    }
                    case TypeCheckInstruction tc -> {
                        final long v = value(s.pop());
                        s.push(tc.opcode() == Opcode.CHECKCAST ? v : 0, 1);
                    }
                    case MonitorInstruction m -> s.pop();
                    case BranchInstruction bi -> {
                        switch (bi.opcode()) {
                            case GOTO, GOTO_W -> {}
                            case IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE, IF_ACMPEQ, IF_ACMPNE -> {
                                s.pop();
                                s.pop();
                            }
                            default -> s.pop();
                        }
                        flow(states, work, labels.get(bi.target()), s);
                        if (bi.opcode() == Opcode.GOTO || bi.opcode() == Opcode.GOTO_W) {
                            i = elements.size();
                        }
                    }
                    case LookupSwitchInstruction ls -> {
                        s.pop();
                        flow(states, work, labels.get(ls.defaultTarget()), s);
                        for (SwitchCase c : ls.cases()) {
                            flow(states, work, labels.get(c.target()), s);
                        }
                        i = elements.size();
                    }
                    case TableSwitchInstruction ts -> {
                        s.pop();
                        flow(states, work, labels.get(ts.defaultTarget()), s);
                        for (SwitchCase c : ts.cases()) {
                            flow(states, work, labels.get(c.target()), s);
                        }
                        i = elements.size();
                    }
                    case ReturnInstruction r -> i = elements.size();
                    case io.smallrye.classfile.instruction.ThrowInstruction t -> i = elements.size();
                    case io.smallrye.classfile.instruction.DiscontinuedInstruction d -> i = elements.size();
                    default -> {} // nop, increment and pseudo-instructions
                }
            }
        }

        if (seedMask != 0) {
            seeds.merge(caller, seedMask, (a, b) -> a | b);
        }
        for (Object[] site : sites.values()) {
            callsTo.computeIfAbsent((Integer) site[0], k -> new ArrayList<>()).add(new CallSite(caller, (long[]) site[1]));
        }
    }

    /**
     * Propagates a state to a branch target, scheduling the target if its state changed.
     *
     * @param states states at block starts
     * @param work blocks to visit
     * @param target the target element index
     * @param s the state at the branch
     */
    private static void flow(State[] states, Deque<Integer> work, Integer target, State s) {
        if (target == null) {
            return;
        }
        if (states[target] == null) {
            states[target] = s.copy();
            work.add(target);
        } else if (states[target].merge(s)) {
            work.add(target);
        }
    }

    /**
     * Applies an operator instruction: unary operators and {@code arraylength} take one operand,
     * the others two; comparisons push an int.
     *
     * @param s the state
     * @param oi the instruction
     */
    private static void operator(State s, OperatorInstruction oi) {
        long v = value(s.pop());
        switch (oi.opcode()) {
            case INEG, LNEG, FNEG, DNEG, ARRAYLENGTH -> {}
            default -> v |= value(s.pop());
        }
        switch (oi.opcode()) {
            case LCMP, FCMPL, FCMPG, DCMPL, DCMPG, ARRAYLENGTH -> s.push(v, 1);
            default -> s.push(v, oi.typeKind().slotSize());
        }
    }

    /**
     * Applies a field instruction. Static fields count as constants: they often hold algorithm
     * names, and sonar-cryptography resolves them. Instance fields inherit the receiver's value.
     *
     * @param s the state
     * @param fi the instruction
     */
    private static void field(State s, FieldInstruction fi) {
        final int size = TypeKind.from(fi.typeSymbol()).slotSize();
        switch (fi.opcode()) {
            case GETSTATIC -> s.push(CONST, size);
            case GETFIELD -> s.push(value(s.pop()), size);
            case PUTSTATIC -> s.pop();
            default -> {
                s.pop();
                s.pop();
            }
        }
    }

    /**
     * Applies a method invocation: records crypto API calls with parameter-derived {@code String}
     * or {@code int} arguments as seeds and calls to analyzed classes as call sites.
     *
     * @param s the state
     * @param ii the instruction
     * @param caller the calling method's id
     * @param index the instruction's element index, identifying the call site
     * @param sites call sites recorded so far, by element index
     * @return the parameters of the calling method flowing into crypto API arguments
     */
    private long invoke(State s, InvokeInstruction ii, int caller, int index, Map<Integer, Object[]> sites) {
        final MethodTypeDesc t = ii.typeSymbol();
        final long[] args = new long[t.parameterCount()];
        for (int p = args.length - 1; p >= 0; p--) {
            args[p] = value(s.pop());
        }
        long result = 0;
        for (long a : args) {
            result |= a;
        }
        final boolean isStatic = ii.opcode() == Opcode.INVOKESTATIC;
        if (!isStatic) {
            result |= value(s.pop());
        }
        if (ii.opcode() == Opcode.INVOKESPECIAL && ii.name().equalsString("<init>") && s.sp > 0) {
            // constructor of a new object: the dup'ed reference left on the stack gets the args
            s.stack[s.sp - 1] |= result;
        }
        if (!t.returnType().descriptorString().equals("V")) {
            s.push(result, TypeKind.from(t.returnType()).slotSize());
        }

        final String owner = ii.owner().asInternalName();
        long seed = 0;
        if (isCryptoApi(owner)) {
            for (int p = 0; p < args.length; p++) {
                if (isResolvableType(t.parameterType(p))) {
                    seed |= args[p] & ~CONST;
                }
            }
            if (seed != 0) {
                seedApis.merge(owner + "." + ii.name().stringValue(), 1, Integer::sum);
            }
        }
        if (analyzedClassNames.contains(owner)) {
            final Object[] prev = sites.get(index);
            if (prev == null) {
                sites.put(index, new Object[] {methodId(owner + "." + ii.name().stringValue() + ii.type().stringValue()), args});
            } else {
                final long[] merged = (long[]) prev[1];
                for (int p = 0; p < merged.length; p++) {
                    merged[p] |= args[p];
                }
            }
        }
        return seed;
    }

    /**
     * Tells whether sonar-cryptography can resolve values of a parameter type into asset
     * properties, i.e. algorithm names and sizes.
     *
     * @param type the parameter type
     * @return {@code true} for {@code String} and {@code int}
     */
    private static boolean isResolvableType(ClassDesc type) {
        final String d = type.descriptorString();
        return d.equals("Ljava/lang/String;") || d.equals("I");
    }

    /**
     * Applies a stack manipulation instruction, honoring two-slot values.
     *
     * @param s the state
     * @param op the opcode
     */
    private static void stack(State s, Opcode op) {
        switch (op) {
            case POP -> s.pop();
            case POP2 -> {
                if (!wide(s.pop())) {
                    s.pop();
                }
            }
            case DUP -> {
                final long v = s.pop();
                s.push(v);
                s.push(v);
            }
            case DUP_X1 -> {
                final long v1 = s.pop(), v2 = s.pop();
                s.push(v1);
                s.push(v2);
                s.push(v1);
            }
            case DUP_X2 -> {
                final long v1 = s.pop(), v2 = s.pop();
                if (wide(v2)) {
                    s.push(v1);
                    s.push(v2);
                    s.push(v1);
                } else {
                    final long v3 = s.pop();
                    s.push(v1);
                    s.push(v3);
                    s.push(v2);
                    s.push(v1);
                }
            }
            case DUP2 -> {
                final long v1 = s.pop();
                if (wide(v1)) {
                    s.push(v1);
                    s.push(v1);
                } else {
                    final long v2 = s.pop();
                    s.push(v2);
                    s.push(v1);
                    s.push(v2);
                    s.push(v1);
                }
            }
            case DUP2_X1 -> {
                final long v1 = s.pop();
                if (wide(v1)) {
                    final long v2 = s.pop();
                    s.push(v1);
                    s.push(v2);
                    s.push(v1);
                } else {
                    final long v2 = s.pop(), v3 = s.pop();
                    s.push(v2);
                    s.push(v1);
                    s.push(v3);
                    s.push(v2);
                    s.push(v1);
                }
            }
            case DUP2_X2 -> {
                final long v1 = s.pop();
                if (wide(v1)) {
                    final long v2 = s.pop();
                    if (wide(v2)) {
                        s.push(v1);
                        s.push(v2);
                        s.push(v1);
                    } else {
                        final long v3 = s.pop();
                        s.push(v1);
                        s.push(v3);
                        s.push(v2);
                        s.push(v1);
                    }
                } else {
                    final long v2 = s.pop(), v3 = s.pop();
                    if (wide(v3)) {
                        s.push(v2);
                        s.push(v1);
                        s.push(v3);
                        s.push(v2);
                        s.push(v1);
                    } else {
                        final long v4 = s.pop();
                        s.push(v2);
                        s.push(v1);
                        s.push(v4);
                        s.push(v3);
                        s.push(v2);
                        s.push(v1);
                    }
                }
            }
            case SWAP -> {
                final long v1 = s.pop(), v2 = s.pop();
                s.push(v1);
                s.push(v2);
            }
            default -> {}
        }
    }

    // ---- propagation ----

    /**
     * Resolves a called method to the class declaring it, following the superclass chain of the
     * analyzed classes, the way javac and sonar-java resolve a method symbol.
     *
     * @param id the called method's id, keyed by the call's owner
     * @return the id keyed by the declaring class, or {@code id} if not found
     */
    private int declaring(int id) {
        final String key = methodKeys.get(id);
        final int dot = key.indexOf('.');
        String owner = key.substring(0, dot);
        final String member = key.substring(dot + 1);
        while (owner != null) {
            final ClassInfo ci = classes.get(owner);
            if (ci == null) {
                return id;
            }
            if (ci.methods().contains(member)) {
                final Integer declared = methodIds.get(owner + "." + member);
                return declared == null ? id : declared;
            }
            owner = ci.superclass();
        }
        return id;
    }

    /**
     * Propagates relevance from the seeds up the call graph and groups the relevant methods.
     *
     * @return the analysis result
     */
    private Result propagate() {
        // calls by declaring method
        final Map<Integer, List<CallSite>> calls = new HashMap<>();
        callsTo.forEach((callee, list) -> calls.computeIfAbsent(declaring(callee), k -> new ArrayList<>()).addAll(list));

        // relevant method -> its parameters flowing into crypto API arguments
        final Map<Integer, Long> relevant = new HashMap<>(seeds);
        final Deque<Integer> work = new ArrayDeque<>(seeds.keySet());
        // union-find over relevant methods
        final Map<Integer, Integer> parent = new HashMap<>();
        final Map<Integer, Integer> sitesPerMethod = new HashMap<>();
        while (!work.isEmpty()) {
            final int m = work.poll();
            final long mask = relevant.get(m);
            for (CallSite cs : calls.getOrDefault(m, List.of())) {
                long callerMask = 0;
                boolean resolves = false;
                for (int p = 0; p < cs.args().length && p < MAX_PARAMS; p++) {
                    if ((mask & (1L << p)) != 0) {
                        resolves |= (cs.args()[p] & CONST) != 0;
                        callerMask |= cs.args()[p] & ~CONST;
                    }
                }
                if (!resolves && callerMask == 0) {
                    continue;
                }
                union(parent, m, cs.caller());
                if (resolves) {
                    sitesPerMethod.merge(cs.caller(), 1, Integer::sum);
                }
                if (callerMask != 0) {
                    final long prev = relevant.getOrDefault(cs.caller(), 0L);
                    if ((prev | callerMask) != prev) {
                        relevant.put(cs.caller(), prev | callerMask);
                        work.add(cs.caller());
                    }
                }
            }
        }

        // groups: components spanning several sources JARs
        final Map<Integer, Map<String, Set<String>>> files = new LinkedHashMap<>();
        final Map<Integer, Integer> methodCount = new HashMap<>();
        final Map<Integer, Integer> siteCount = new HashMap<>();
        for (int m : parent.keySet()) {
            final int root = find(parent, m);
            methodCount.merge(root, 1, Integer::sum);
            siteCount.merge(root, sitesPerMethod.getOrDefault(m, 0), Integer::sum);
            final String key = methodKeys.get(m);
            final ClassInfo ci = classes.get(key.substring(0, key.indexOf('.')));
            if (ci != null && ci.sourcePath() != null) {
                files.computeIfAbsent(root, k -> new LinkedHashMap<>())
                        .computeIfAbsent(ci.prefix(), k -> new TreeSet<>())
                        .add(ci.sourcePath());
            }
        }
        final List<Group> groups = new ArrayList<>();
        files.forEach(
                (root, byPrefix) -> {
                    if (byPrefix.size() > 1) {
                        groups.add(new Group(byPrefix, methodCount.get(root), siteCount.get(root)));
                    }
                });
        groups.sort((a, b) -> Integer.compare(b.fileCount(), a.fileCount()));
        return new Result(
                groups,
                seeds.size(),
                relevant.size(),
                sitesPerMethod.values().stream().mapToInt(Integer::intValue).sum());
    }

    private static int find(Map<Integer, Integer> parent, int x) {
        parent.putIfAbsent(x, x);
        int root = x;
        while (parent.get(root) != root) {
            root = parent.get(root);
        }
        while (parent.get(x) != root) {
            final int next = parent.get(x);
            parent.put(x, root);
            x = next;
        }
        return root;
    }

    private static void union(Map<Integer, Integer> parent, int a, int b) {
        final int ra = find(parent, a), rb = find(parent, b);
        if (ra != rb) {
            parent.put(ra, rb);
        }
    }
}
