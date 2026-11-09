package io.github.aloubyansky.cryptid.bytecode;

import java.util.Arrays;

/**
 * A method or constructor invocation found in the bytecode, with the abstract values of its
 * receiver and arguments.
 */
public final class CallSite {
    /** See {@link #id()}. */
    final int id;
    /** See {@link #method()}. */
    final String method;
    /** See {@link #sourceFile()}. */
    final String sourceFile;
    /** See {@link #owner()}. */
    final String owner;
    /** See {@link #name()}. */
    final String name;
    /** See {@link #descriptor()}. */
    final String descriptor;
    /** See {@link #isStatic()}. */
    final boolean isStatic;
    /** See {@link #line()}. */
    final int line;
    /** The receiver, merged into by the interpreter on every path reaching the call. */
    AVal receiver;
    /** The arguments, merged into by the interpreter on every path reaching the call. */
    AVal[] args;
    /** Id of the object this call creates: the {@code new} for constructors, the call itself for methods returning objects; -1 otherwise. */
    int created = -1;

    /**
     * Creates a call site with unknown receiver and arguments, which the interpreter then merges
     * values into.
     *
     * @param id the call site's id, unique within its {@code Analyzer}
     * @param method the calling method, {@code owner.name+descriptor} with the internal class name
     * @param sourceFile the caller's source file, from the class's {@code SourceFile} attribute
     * @param owner the internal name of the class the call names
     * @param name the called method's name, {@code <init>} for a constructor
     * @param descriptor the called method's descriptor
     * @param isStatic whether the call is {@code invokestatic}
     * @param line the call's line, {@code 0} without a line number table
     * @param argCount the number of arguments, without the receiver
     */
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

    /**
     * The call site's id, unique within its {@code Analyzer}; also the origin of the object a
     * call returning one creates.
     *
     * @return the id
     */
    public int id() {
        return id;
    }

    /**
     * The calling method.
     *
     * @return {@code owner.name+descriptor}, with the internal class name
     */
    public String method() {
        return method;
    }

    /**
     * The caller's source file, without the artifact path.
     *
     * @return the path, e.g. {@code org/acme/App.java}
     */
    public String sourceFile() {
        return sourceFile;
    }

    /**
     * The class the call names, which may be a subtype of the class declaring the method.
     *
     * @return the internal name, e.g. {@code javax/crypto/Cipher}
     */
    public String owner() {
        return owner;
    }

    /**
     * The called method's name.
     *
     * @return the name, {@code <init>} for a constructor
     */
    public String name() {
        return name;
    }

    /**
     * The called method's descriptor.
     *
     * @return the descriptor, e.g. {@code (Ljava/lang/String;)Ljavax/crypto/Cipher;}
     */
    public String descriptor() {
        return descriptor;
    }

    /**
     * Whether the call is static, i.e. has no receiver.
     *
     * @return {@code true} for {@code invokestatic}
     */
    public boolean isStatic() {
        return isStatic;
    }

    /**
     * The call's line.
     *
     * @return the line, {@code 0} if the class has no line number table
     */
    public int line() {
        return line;
    }

    /**
     * The object the call is made on, merged over all paths reaching the call.
     *
     * @return the receiver, {@link AVal#UNKNOWN} for a static call
     */
    public AVal receiver() {
        return receiver;
    }

    /**
     * The arguments, merged over all paths reaching the call.
     *
     * @return the arguments by position, without the receiver; the array itself, not a copy
     */
    public AVal[] args() {
        return args;
    }

    /**
     * The object the call creates: the one its {@code new} allocated for a constructor, the
     * returned one, identified by the call's {@link #id()}, for a method returning an object.
     *
     * @return the object's origin, or {@code -1} for a call creating none
     */
    public int created() {
        return created;
    }

    /**
     * The called method in sonar-java's signature format.
     *
     * @return e.g. {@code javax.crypto.Cipher#getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;}
     */
    public String signature() {
        return owner.replace('/', '.') + "#" + name + descriptor;
    }

    @Override
    public String toString() {
        return signature() + "@" + line;
    }
}
