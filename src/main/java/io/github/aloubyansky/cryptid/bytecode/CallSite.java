package io.github.aloubyansky.cryptid.bytecode;

import java.util.Arrays;

/**
 * A method or constructor invocation found in the bytecode, with the abstract values of its
 * receiver and arguments.
 */
public final class CallSite {
    final int id;
    final String method;
    final String sourceFile;
    final String owner;
    final String name;
    final String descriptor;
    final boolean isStatic;
    final int line;
    AVal receiver;
    AVal[] args;
    /** Id of the object this call creates: the {@code new} for constructors, the call itself for methods returning objects; -1 otherwise. */
    int created = -1;

    public CallSite(int id, String method, String sourceFile, String owner, String name, String descriptor, boolean isStatic, int line, int argCount) {
        this.id = id;
        this.method = method;
        this.sourceFile = sourceFile;
        this.owner = owner;
        this.name = name;
        this.descriptor = descriptor;
        this.isStatic = isStatic;
        this.line = line;
        this.args = new AVal[argCount];
        Arrays.fill(args, AVal.UNKNOWN);
        this.receiver = AVal.UNKNOWN;
    }

    /** sonar-java's method signature format, e.g. {@code javax.crypto.Cipher#getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;}. */
    /** The call site's id, unique within its {@code Analyzer}. */
    public int id() {
        return id;
    }

    /** The calling method, {@code owner.name+descriptor}. */
    public String method() {
        return method;
    }

    /** The calling class's source file, with its package path. */
    public String sourceFile() {
        return sourceFile;
    }

    /** The invoked method's owner, as an internal name. */
    public String owner() {
        return owner;
    }

    /** The invoked method's name. */
    public String name() {
        return name;
    }

    /** The invoked method's descriptor. */
    public String descriptor() {
        return descriptor;
    }

    /** Whether the call is static. */
    public boolean isStatic() {
        return isStatic;
    }

    /** The call's line, or {@code 0} without a line number table. */
    public int line() {
        return line;
    }

    /** The receiver's abstract value; unknown for static calls. */
    public AVal receiver() {
        return receiver;
    }

    /** The arguments' abstract values, by parameter position. */
    public AVal[] args() {
        return args;
    }

    /** The id of the object the call creates or returns, or {@code -1}. */
    public int created() {
        return created;
    }

    public String signature() {
        return owner.replace('/', '.') + "#" + name + descriptor;
    }

    @Override
    public String toString() {
        return signature() + "@" + line;
    }
}
