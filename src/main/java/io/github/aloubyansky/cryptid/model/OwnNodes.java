package io.github.aloubyansky.cryptid.model;

import com.ibm.engine.model.IValue;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.utils.DetectionLocation;
import io.github.aloubyansky.cryptid.detection.Loc;
import java.util.Optional;

/**
 * Model nodes for API values sonar-cryptography's mappers don't know.
 *
 * <p>The specs are ours and cover APIs its Java rules don't (see {@code docs/coverage-gaps.md}),
 * but translating a detected value into a model node goes through its mappers, which are {@code
 * switch}es over the names its own rules produce. An unknown name doesn't fail: each mapper's
 * {@code default} branch builds an algorithm of the kind that mapper is for, with the raw name. For
 * a Bouncy Castle key derivation function that is {@code
 * BcDerivationFunctionMapper}'s {@code new Algorithm(name, MessageDigest.class, …)}, so a spec we
 * add for a KDF it doesn't know is modeled as a message digest under its implementation class's
 * name.
 *
 * <p>So a spec for an API outside those rules needs its value mapped here. {@link #translate} is
 * consulted before the context translators and wins when it answers; everything else is unchanged.
 * Entries are expected to move here only until the mapping exists upstream.
 */
final class OwnNodes {

    private OwnNodes() {}

    /**
     * Returns the node for a value sonar-cryptography's mappers don't know.
     *
     * @param value the detected action or value
     * @param location where it was detected
     * @return the node, or empty to let the context translators handle the value
     */
    static Optional<INode> translate(IValue<Loc> value, DetectionLocation location) {
        return switch (value.asString()) {
            // org.bouncycastle.crypto.generators.Argon2BytesGenerator: RFC 9106, and Keycloak's
            // default password hashing. sonar-cryptography 1.7.0 has no rule and no model for it,
            // and no Argon2 variant class, so the variant stays in the parameters.
            case "Argon2BytesGenerator" -> {
                final Algorithm argon2 =
                        new Algorithm("Argon2", PasswordBasedKeyDerivationFunction.class, location);
                argon2.put(new KeyDerivation(location));
                yield Optional.of(argon2);
            }
            default -> Optional.empty();
        };
    }
}
