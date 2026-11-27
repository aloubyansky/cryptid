package io.github.aloubyansky.cryptid;

import java.util.Objects;

/**
 * Identifies a method in bytecode by its class, name and descriptor.
 *
 * @param className the binary name of the class, e.g. {@code javax.crypto.Cipher}; for a called
 *     method, the class the call names, which may be a subtype of the declaring one
 * @param name the method's name, {@code <init>} for a constructor
 * @param descriptor the method's descriptor, e.g. {@code (Ljava/lang/String;)Ljavax/crypto/Cipher;}
 */
public record MethodId(String className, String name, String descriptor) {

    /** Checks that no part is {@code null}. */
    public MethodId {
        Objects.requireNonNull(className, "className");
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(descriptor, "descriptor");
    }

    /**
     * Returns the method as {@code className#name descriptor}, without a space.
     *
     * @return e.g. {@code javax.crypto.Cipher#getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;}
     */
    @Override
    public String toString() {
        return className + "#" + name + descriptor;
    }
}
