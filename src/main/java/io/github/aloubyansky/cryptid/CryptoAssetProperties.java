package io.github.aloubyansky.cryptid;

import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * What a crypto asset is: one record per CycloneDX asset type, with the properties detection
 * fills in. The values follow CycloneDX's vocabulary, so that they map to its CBOM one to one.
 */
public sealed interface CryptoAssetProperties {

    /**
     * The object identifier of the algorithm or material, if known.
     *
     * @return the OID, e.g. {@code 2.16.840.1.101.3.4.1}, or {@code null}
     */
    String oid();

    /**
     * An algorithm, e.g. AES-256-GCM or SHA-256.
     *
     * @param primitive the kind of algorithm
     * @param parameterSet the parameter set, e.g. a key or digest size, {@code null} if none
     * @param curve the elliptic curve, {@code null} if none
     * @param mode the block cipher mode, {@code null} if none
     * @param padding the padding scheme, {@code null} if none
     * @param functions what the algorithm is used for, in this asset's occurrences
     * @param oid the object identifier, {@code null} if unknown
     */
    record Algorithm(Primitive primitive, String parameterSet, String curve, Mode mode, Padding padding,
            Set<CryptoFunction> functions, String oid) implements CryptoAssetProperties {

        /** Copies the functions, treating {@code null} as none. */
        public Algorithm {
            functions = functions == null || functions.isEmpty()
                    ? Set.of() : Collections.unmodifiableSet(EnumSet.copyOf(functions));
        }
    }

    /**
     * Related crypto material, e.g. a key or an initialization vector.
     *
     * @param type the kind of material
     * @param size its size in bits, {@code null} if unknown
     * @param oid the object identifier, {@code null} if unknown
     */
    record RelatedMaterial(MaterialType type, Integer size, String oid) implements CryptoAssetProperties {}

    /**
     * A protocol, e.g. TLS 1.3.
     *
     * @param type the protocol
     * @param version its version, {@code null} if unknown
     * @param cipherSuites the cipher suites, empty if none are known
     * @param oid the object identifier, {@code null} if unknown
     */
    record Protocol(ProtocolType type, String version, List<CipherSuite> cipherSuites, String oid)
            implements CryptoAssetProperties {

        /** Copies the cipher suites, treating {@code null} as none. */
        public Protocol {
            cipherSuites = cipherSuites == null ? List.of() : List.copyOf(cipherSuites);
        }
    }

    /** The kind of an algorithm, as CycloneDX's {@code primitive}. */
    enum Primitive {
        DRBG, MAC, BLOCK_CIPHER, STREAM_CIPHER, SIGNATURE, HASH, PKE, XOF, KDF, KEY_AGREE, KEM, AE, COMBINER,
        KEY_WRAP, OTHER, UNKNOWN
    }

    /** What an algorithm is used for, as CycloneDX's {@code cryptoFunctions}. */
    enum CryptoFunction {
        GENERATE, KEYGEN, ENCRYPT, DECRYPT, DIGEST, TAG, KEYDERIVE, SIGN, VERIFY, ENCAPSULATE, DECAPSULATE, OTHER,
        UNKNOWN
    }

    /** A block cipher mode, as CycloneDX's {@code mode}. */
    enum Mode {
        CBC, ECB, CCM, GCM, CFB, OFB, CTR, OTHER, UNKNOWN
    }

    /** A padding scheme, as CycloneDX's {@code padding}. */
    enum Padding {
        PKCS5, PKCS7, PKCS1V15, OAEP, RAW, OTHER, UNKNOWN
    }

    /** A kind of related crypto material, as CycloneDX's {@code relatedCryptoMaterialProperties.type}. */
    enum MaterialType {
        PRIVATE_KEY, PUBLIC_KEY, SECRET_KEY, KEY, CIPHERTEXT, SIGNATURE, DIGEST, INITIALIZATION_VECTOR, NONCE,
        SEED, SALT, SHARED_SECRET, TAG, ADDITIONAL_DATA, PASSWORD, CREDENTIAL, TOKEN, OTHER, UNKNOWN
    }

    /** A protocol, as CycloneDX's {@code protocolProperties.type}. */
    enum ProtocolType {
        TLS, SSH, IPSEC, IKE, SSTP, WPA, DTLS, QUIC, EAP_AKA, EAP_AKA_PRIME, PRINS, FIVE_G_AKA, OTHER, UNKNOWN
    }
}
