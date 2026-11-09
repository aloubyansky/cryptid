package io.github.aloubyansky.cryptid.model;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import java.util.Set;

/**
 * Model nodes of cryptid's own, for algorithms sonar-cryptography's model has no class for and its
 * mappers would turn into a node of the wrong kind: each mapper's default builds an algorithm of
 * that mapper's kind under the raw name, e.g. {@code Argon2BytesGenerator} as a message digest.
 * A spec names the node with {@code model}, so it is chosen by the API called, not by a name.
 */
public final class OwnModels {

    private OwnModels() {}

    /**
     * The names specs can give as {@code model}.
     *
     * @return the names
     */
    public static Set<String> names() {
        return Set.of(Argon2.NAME);
    }

    /**
     * Creates a node.
     *
     * @param name the node's name in the specs
     * @param location where it is detected
     * @return the node, or empty for an unknown name
     */
    static Optional<INode> create(String name, DetectionLocation location) {
        return Argon2.NAME.equals(name) ? Optional.of(new Argon2(location)) : Optional.empty();
    }

    /** Argon2, the password hashing function of RFC 9106. */
    static final class Argon2 extends Algorithm implements PasswordBasedKeyDerivationFunction {

        /** The node's name, in the specs and in the CBOM. */
        static final String NAME = "Argon2";

        /**
         * Creates the node.
         *
         * @param location where it is detected
         */
        Argon2(DetectionLocation location) {
            super(NAME, PasswordBasedKeyDerivationFunction.class, location);
        }
    }
}
