package org.acme.cbom.bytecode;

/**
 * A method or constructor invocation found in the bytecode, with the abstract values of its
 * receiver and arguments.
 */
final class CallSite {
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

    CallSite(int id, String method, String sourceFile, String owner, String name, String descriptor, boolean isStatic, int line, int argCount) {
        this.id = id;
        this.method = method;
        this.sourceFile = sourceFile;
        this.owner = owner;
        this.name = name;
        this.descriptor = descriptor;
        this.isStatic = isStatic;
        this.line = line;
        this.args = new AVal[argCount];
        java.util.Arrays.fill(args, AVal.UNKNOWN);
        this.receiver = AVal.UNKNOWN;
    }

    /** sonar-java's method signature format, e.g. {@code javax.crypto.Cipher#getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;}. */
    String signature() {
        return owner.replace('/', '.') + "#" + name + descriptor;
    }

    @Override
    public String toString() {
        return signature() + "@" + line;
    }
}
