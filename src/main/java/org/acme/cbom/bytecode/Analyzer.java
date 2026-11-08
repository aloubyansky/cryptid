package org.acme.cbom.bytecode;

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
import io.smallrye.classfile.instruction.DiscontinuedInstruction;
import io.smallrye.classfile.instruction.ExceptionCatch;
import io.smallrye.classfile.instruction.FieldInstruction;
import io.smallrye.classfile.instruction.InvokeDynamicInstruction;
import io.smallrye.classfile.instruction.InvokeInstruction;
import io.smallrye.classfile.instruction.LabelTarget;
import io.smallrye.classfile.instruction.LineNumber;
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
import io.smallrye.classfile.instruction.ThrowInstruction;
import io.smallrye.classfile.instruction.TypeCheckInstruction;
import java.io.IOException;
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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Interprets the bytecode of all methods of a set of classes with {@link AVal}s, recording every
 * call site with the possible values of its receiver and arguments.
 *
 * <p>Field values are analyzed flow-insensitively: a field's value is the union of all values
 * stored into it anywhere, computed to a fixpoint over all classes. That resolves constants held
 * in fields, including assignment cycles between fields.
 */
public final class Analyzer {

    /** A method's call sites, in bytecode order. */
    record MethodResult(String className, String method, String sourceFile, List<CallSite> calls) {}

    private final List<ClassModel> classes = new ArrayList<>();
    private final Map<String, AVal> fields = new HashMap<>();
    private boolean fieldsChanged;
    private int nextId;
    /** Stable ids for allocation and call sites, by method and element index. */
    private final Map<String, Integer> siteIds = new HashMap<>();

    /**
     * Reads all class files under a directory.
     *
     * @param dir the directory
     * @throws IOException if a file can't be read
     */
    void addClasses(Path dir) throws IOException {
        try (Stream<Path> s = Files.walk(dir)) {
            for (Path p : s.filter(f -> f.toString().endsWith(".class")).sorted().toList()) {
                addClass(Files.readAllBytes(p));
            }
        }
    }

    /**
     * Reads the base-version classes of a JAR.
     *
     * @param jar the JAR
     * @param jars the JAR cache
     */
    void addJar(Path jar, JarCache jars) {
        for (byte[] bytes : jars.readAll(jar)) {
            addClass(bytes);
        }
    }

    /**
     * Returns the superclass, interfaces and declared methods of every class read, for resolving
     * called methods to their declaring class and calls through supertypes to their overrides.
     *
     * @return class infos by internal class name
     */
    Map<String, CallIndex.ClassInfo> classInfos() {
        final Map<String, CallIndex.ClassInfo> result = new HashMap<>();
        for (ClassModel cm : classes) {
            final Set<String> methods = new HashSet<>();
            for (MethodModel mm : cm.methods()) {
                methods.add(mm.methodName().stringValue() + mm.methodType().stringValue());
            }
            result.put(cm.thisClass().asInternalName(), new CallIndex.ClassInfo(
                    cm.superclass().map(c -> c.asInternalName()).orElse(null),
                    cm.interfaces().stream().map(c -> c.asInternalName()).toList(),
                    Set.copyOf(methods)));
        }
        return result;
    }

    private void addClass(byte[] bytes) {
        final ClassModel cm;
        try {
            cm = ClassFile.of().parse(bytes);
        } catch (RuntimeException e) {
            return; // not a parseable class file
        }
        classes.add(cm);
        analyzedClasses.add(cm.thisClass().asInternalName());
    }

    private final Set<String> analyzedClasses = new HashSet<>();

    /** Methods whose bytecode couldn't be interpreted, e.g. because of malformed code. */
    int failedMethods;

    /**
     * Interprets all methods until field values reach a fixpoint.
     *
     * @return the call sites of every method
     */
    List<MethodResult> analyze() {
        List<MethodResult> results = List.of();
        for (int round = 0; round < 10; round++) {
            fieldsChanged = false;
            results = new ArrayList<>();
            for (ClassModel cm : classes) {
                final String className = cm.thisClass().asInternalName();
                final String source = sourceFile(cm, className);
                for (MethodModel mm : cm.methods()) {
                    final String method = className + "." + mm.methodName().stringValue() + mm.methodType().stringValue();
                    final List<CallSite> calls = new ArrayList<>();
                    mm.code().ifPresent(code -> {
                        try {
                            calls.addAll(interpret(method, source, mm, code));
                        } catch (RuntimeException e) {
                            failedMethods++;
                        }
                    });
                    results.add(new MethodResult(className, method, source, calls));
                }
            }
            if (!fieldsChanged) {
                break;
            }
        }
        return results;
    }

    private static String sourceFile(ClassModel cm, String className) {
        final int slash = className.lastIndexOf('/');
        final String pkg = slash < 0 ? "" : className.substring(0, slash + 1);
        return cm.findAttribute(Attributes.sourceFile())
                .map(sf -> pkg + sf.sourceFile().stringValue())
                .orElse(className + ".java");
    }

    private int siteId(String method, int index) {
        return siteIds.computeIfAbsent(method + "#" + index, k -> nextId++);
    }

    // ---- interpretation ----

    private static final class State {
        AVal[] locals;
        final ArrayList<AVal> stack = new ArrayList<>();

        State(int locals) {
            this.locals = new AVal[Math.max(locals, 1)];
            Arrays.fill(this.locals, AVal.UNKNOWN);
        }

        State copy() {
            final State s = new State(0);
            s.locals = locals.clone();
            s.stack.addAll(stack);
            return s;
        }

        boolean merge(State o) {
            boolean changed = false;
            if (o.locals.length > locals.length) {
                final int old = locals.length;
                locals = Arrays.copyOf(locals, o.locals.length);
                Arrays.fill(locals, old, locals.length, AVal.UNKNOWN);
                changed = true;
            }
            for (int i = 0; i < o.locals.length; i++) {
                final AVal m = locals[i].merge(o.locals[i]);
                changed |= m != locals[i];
                locals[i] = m;
            }
            for (int i = 0; i < Math.min(stack.size(), o.stack.size()); i++) {
                final AVal m = stack.get(i).merge(o.stack.get(i));
                changed |= m != stack.get(i);
                stack.set(i, m);
            }
            return changed;
        }

        void push(AVal v) {
            stack.add(v);
        }

        AVal pop() {
            return stack.isEmpty() ? AVal.UNKNOWN : stack.remove(stack.size() - 1);
        }

        AVal load(int slot) {
            return slot < locals.length ? locals[slot] : AVal.UNKNOWN;
        }

        void store(int slot, AVal v) {
            if (slot >= locals.length) {
                final int old = locals.length;
                locals = Arrays.copyOf(locals, slot + 1);
                Arrays.fill(locals, old, locals.length, AVal.UNKNOWN);
            }
            locals[slot] = v.withSize(1);
        }
    }

    private List<CallSite> interpret(String method, String source, MethodModel mm, CodeModel code) {
        final List<CodeElement> elements = code.elementList();
        final Map<Label, Integer> labels = new HashMap<>();
        final List<int[]> handlers = new ArrayList<>();
        final int[] lines = new int[elements.size()];
        int line = 0;
        for (int i = 0; i < elements.size(); i++) {
            final CodeElement el = elements.get(i);
            if (el instanceof LabelTarget lt) {
                labels.put(lt.label(), i);
            } else if (el instanceof LineNumber ln) {
                line = ln.line();
            }
            lines[i] = line;
        }
        for (CodeElement el : elements) {
            if (el instanceof ExceptionCatch ec) {
                handlers.add(new int[] {labels.get(ec.tryStart()), labels.get(ec.tryEnd()), labels.get(ec.handler())});
            }
        }

        final State entry = new State(8);
        final MethodTypeDesc type = mm.methodTypeSymbol();
        int slot = mm.flags().has(AccessFlag.STATIC) ? 0 : 1;
        for (int p = 0; p < type.parameterCount(); p++) {
            final int size = TypeKind.from(type.parameterType(p)).slotSize();
            entry.store(slot, AVal.param(p, size));
            slot += size;
        }

        final State[] states = new State[elements.size()];
        states[0] = entry;
        final Deque<Integer> work = new ArrayDeque<>();
        work.add(0);
        final Map<Integer, CallSite> calls = new LinkedHashMap<>();
        final Map<Integer, Integer> newSites = new HashMap<>();

        while (!work.isEmpty()) {
            final int start = work.poll();
            final State s = states[start].copy();
            for (int i = start; i < elements.size(); i++) {
                final CodeElement el = elements.get(i);
                if (i != start && el instanceof LabelTarget) {
                    flow(states, work, i, s);
                    break;
                }
                for (int[] h : handlers) {
                    if (i >= h[0] && i < h[1]) {
                        final State hs = new State(0);
                        hs.locals = s.locals.clone();
                        hs.push(AVal.UNKNOWN);
                        flow(states, work, h[2], hs);
                    }
                }
                switch (el) {
                    case LoadInstruction li -> s.push(s.load(li.slot()).withSize(li.typeKind().slotSize()));
                    case StoreInstruction si -> s.store(si.slot(), s.pop());
                    case ConstantInstruction ci -> s.push(constant(ci));
                    case OperatorInstruction oi -> operator(s, oi);
                    case ConvertInstruction ci -> {
                        s.pop();
                        s.push(AVal.unknown(ci.toType().slotSize()));
                    }
                    case StackInstruction si -> stack(s, si.opcode());
                    case FieldInstruction fi -> field(s, fi);
                    case InvokeInstruction ii -> invoke(s, ii, method, source, i, lines[i], calls, newSites);
                    case InvokeDynamicInstruction id -> invokeDynamic(s, id);
                    case NewObjectInstruction n -> {
                        final int id = siteId(method, i);
                        newSites.put(id, i);
                        s.push(AVal.origin(id));
                    }
                    case NewPrimitiveArrayInstruction n -> {
                        s.pop();
                        s.push(AVal.UNKNOWN);
                    }
                    case NewReferenceArrayInstruction n -> {
                        s.pop();
                        s.push(AVal.UNKNOWN);
                    }
                    case NewMultiArrayInstruction n -> {
                        for (int d = 0; d < n.dimensions(); d++) {
                            s.pop();
                        }
                        s.push(AVal.UNKNOWN);
                    }
                    case ArrayLoadInstruction al -> {
                        s.pop();
                        s.pop();
                        s.push(AVal.unknown(al.typeKind().slotSize()));
                    }
                    case ArrayStoreInstruction as -> {
                        final AVal value = s.pop();
                        s.pop();
                        s.pop();
                        // array initializer idiom (new array, dup, index, value, store): the array
                        // left on the stack collects its elements' constants
                        if (!s.stack.isEmpty() && !value.consts().isEmpty() && !value.anyConst()) {
                            final int top = s.stack.size() - 1;
                            s.stack.set(top, s.stack.get(top).merge(AVal.constants(value.consts())));
                        }
                    }
                    case TypeCheckInstruction tc -> {
                        final AVal v = s.pop();
                        s.push(tc.opcode() == Opcode.CHECKCAST ? v : AVal.UNKNOWN);
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
                    case ThrowInstruction t -> i = elements.size();
                    case DiscontinuedInstruction d -> i = elements.size();
                    default -> {}
                }
            }
        }
        return new ArrayList<>(calls.values());
    }

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

    private static AVal constant(ConstantInstruction ci) {
        if (ci.opcode() == Opcode.ACONST_NULL) {
            return AVal.UNKNOWN;
        }
        final Object v = ci.constantValue();
        final int size = ci.typeKind().slotSize();
        if (v instanceof String || v instanceof Integer || v instanceof Long || v instanceof Float || v instanceof Double) {
            return AVal.constant(v, size);
        }
        return AVal.unknown(size);
    }

    private static void operator(State s, OperatorInstruction oi) {
        s.pop();
        switch (oi.opcode()) {
            case INEG, LNEG, FNEG, DNEG, ARRAYLENGTH -> {}
            default -> s.pop();
        }
        switch (oi.opcode()) {
            case LCMP, FCMPL, FCMPG, DCMPL, DCMPG, ARRAYLENGTH -> s.push(AVal.UNKNOWN);
            default -> s.push(AVal.unknown(oi.typeKind().slotSize()));
        }
    }

    private void field(State s, FieldInstruction fi) {
        final String key = fi.owner().asInternalName() + "." + fi.name().stringValue();
        final int size = TypeKind.from(fi.typeSymbol()).slotSize();
        switch (fi.opcode()) {
            case GETSTATIC -> {
                final AVal v = fields.get(key);
                if (v != null) {
                    s.push(v.withSize(size));
                } else if (!analyzedClasses.contains(fi.owner().asInternalName())) {
                    // a library constant without a known value, e.g. MLKEMParameters.ml_kem_1024:
                    // sonar-cryptography's mappers recognize such constants by their name
                    s.push(AVal.constant(fi.name().stringValue(), size));
                } else {
                    s.push(AVal.unknown(size));
                }
            }
            case GETFIELD -> {
                s.pop();
                s.push(fields.getOrDefault(key, AVal.UNKNOWN).withSize(size));
            }
            case PUTSTATIC -> putField(key, s.pop());
            default -> {
                putField(key, s.pop());
                s.pop();
            }
        }
    }

    private void putField(String key, AVal v) {
        final AVal prev = fields.get(key);
        final AVal merged = prev == null ? v.withSize(1) : prev.merge(v.withSize(1));
        if (prev == null || merged != prev) {
            fields.put(key, merged);
            fieldsChanged = true;
        }
    }

    private void invoke(State s, InvokeInstruction ii, String method, String source, int index, int line,
            Map<Integer, CallSite> calls, Map<Integer, Integer> newSites) {
        final MethodTypeDesc t = ii.typeSymbol();
        final AVal[] args = new AVal[t.parameterCount()];
        for (int p = args.length - 1; p >= 0; p--) {
            args[p] = s.pop().withSize(1);
        }
        final boolean isStatic = ii.opcode() == Opcode.INVOKESTATIC;
        final AVal receiver = isStatic ? AVal.UNKNOWN : s.pop();
        final String name = ii.name().stringValue();

        final int id = siteId(method, index);
        final CallSite cs = calls.computeIfAbsent(index, k -> new CallSite(id, method, source,
                ii.owner().asInternalName(), name, ii.type().stringValue(), isStatic, line, args.length));
        cs.receiver = cs.receiver.merge(receiver);
        for (int p = 0; p < args.length; p++) {
            cs.args[p] = cs.args[p].merge(args[p]);
        }

        AVal result = AVal.origin(id);
        if (name.equals("<init>")) {
            // the constructor creates the object allocated by the matching 'new'
            for (int o : receiver.origins()) {
                if (newSites.containsKey(o)) {
                    cs.created = o;
                }
            }
        } else if (!t.returnType().descriptorString().equals("V")) {
            cs.created = id;
            result = stringResult(cs, receiver, args);
        }
        if (!t.returnType().descriptorString().equals("V")) {
            s.push(result.withSize(TypeKind.from(t.returnType()).slotSize()));
        }
    }

    /**
     * Folds a few common {@code String} methods on constant receivers, e.g. {@code
     * "AES".toUpperCase()}; other calls return a new object.
     */
    private static AVal stringResult(CallSite cs, AVal receiver, AVal[] args) {
        if (cs.owner.equals("java/lang/String") && receiver.single() instanceof String str) {
            switch (cs.name) {
                case "toUpperCase", "toLowerCase", "trim", "intern", "toString" -> {
                    if (args.length == 0 || cs.name.startsWith("to") && args.length == 1) {
                        final String v = switch (cs.name) {
                            case "toUpperCase" -> str.toUpperCase(Locale.ROOT);
                            case "toLowerCase" -> str.toLowerCase(Locale.ROOT);
                            case "trim" -> str.trim();
                            default -> str;
                        };
                        return AVal.constant(v, 1);
                    }
                }
                default -> {}
            }
        }
        if (cs.owner.equals("java/lang/String") && cs.name.equals("valueOf") && args.length == 1 && args[0].single() != null) {
            return AVal.constant(String.valueOf(args[0].single()), 1);
        }
        return AVal.origin(cs.id);
    }

    /** String concatenation compiled to {@code makeConcatWithConstants}: folded when all arguments are constants. */
    private static void invokeDynamic(State s, InvokeDynamicInstruction id) {
        final MethodTypeDesc t = id.typeSymbol();
        final AVal[] args = new AVal[t.parameterCount()];
        for (int p = args.length - 1; p >= 0; p--) {
            args[p] = s.pop();
        }
        if (t.returnType().descriptorString().equals("V")) {
            return;
        }
        AVal result = AVal.unknown(TypeKind.from(t.returnType()).slotSize());
        if (id.bootstrapMethod().methodName().equals("makeConcatWithConstants")
                && !id.bootstrapArgs().isEmpty()
                && id.bootstrapArgs().get(0) instanceof String recipe) {
            final StringBuilder sb = new StringBuilder();
            int arg = 0;
            int constant = 1;
            boolean ok = true;
            for (char ch : recipe.toCharArray()) {
                if (ch == '\u0001') {
                    final Object v = arg < args.length ? args[arg++].single() : null;
                    if (v == null) {
                        ok = false;
                        break;
                    }
                    sb.append(v);
                } else if (ch == '\u0002') {
                    sb.append(id.bootstrapArgs().get(constant++));
                } else {
                    sb.append(ch);
                }
            }
            if (ok) {
                result = AVal.constant(sb.toString(), 1);
            }
        }
        s.push(result);
    }

    private static void stack(State s, Opcode op) {
        switch (op) {
            case POP -> s.pop();
            case POP2 -> {
                if (!s.pop().wide()) {
                    s.pop();
                }
            }
            case DUP -> {
                final AVal v = s.pop();
                s.push(v);
                s.push(v);
            }
            case DUP_X1 -> {
                final AVal v1 = s.pop(), v2 = s.pop();
                s.push(v1);
                s.push(v2);
                s.push(v1);
            }
            case DUP_X2 -> {
                final AVal v1 = s.pop(), v2 = s.pop();
                if (v2.wide()) {
                    s.push(v1);
                    s.push(v2);
                    s.push(v1);
                } else {
                    final AVal v3 = s.pop();
                    s.push(v1);
                    s.push(v3);
                    s.push(v2);
                    s.push(v1);
                }
            }
            case DUP2 -> {
                final AVal v1 = s.pop();
                if (v1.wide()) {
                    s.push(v1);
                    s.push(v1);
                } else {
                    final AVal v2 = s.pop();
                    s.push(v2);
                    s.push(v1);
                    s.push(v2);
                    s.push(v1);
                }
            }
            case DUP2_X1 -> {
                final AVal v1 = s.pop();
                if (v1.wide()) {
                    final AVal v2 = s.pop();
                    s.push(v1);
                    s.push(v2);
                    s.push(v1);
                } else {
                    final AVal v2 = s.pop(), v3 = s.pop();
                    s.push(v2);
                    s.push(v1);
                    s.push(v3);
                    s.push(v2);
                    s.push(v1);
                }
            }
            case DUP2_X2 -> {
                final AVal v1 = s.pop();
                if (v1.wide()) {
                    final AVal v2 = s.pop();
                    if (v2.wide()) {
                        s.push(v1);
                        s.push(v2);
                        s.push(v1);
                    } else {
                        final AVal v3 = s.pop();
                        s.push(v1);
                        s.push(v3);
                        s.push(v2);
                        s.push(v1);
                    }
                } else {
                    final AVal v2 = s.pop(), v3 = s.pop();
                    if (v3.wide()) {
                        s.push(v2);
                        s.push(v1);
                        s.push(v3);
                        s.push(v2);
                        s.push(v1);
                    } else {
                        final AVal v4 = s.pop();
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
                final AVal v1 = s.pop(), v2 = s.pop();
                s.push(v1);
                s.push(v2);
            }
            default -> {}
        }
    }
}
