package io.github.aloubyansky.cryptid.spec;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/**
 * The types cryptography is implemented through, as opposed to used: the JCA's service provider
 * interfaces, Bouncy Castle's primitive interfaces and provider registrations. A crypto asset
 * occurrence in a subtype of one is a provision. As data: {@code
 * src/main/resources/crypto-implementation-specs.yaml}.
 *
 * @param specVersion the format version
 * @param implementationTypes binary names of the types
 */
public record CryptoImplementationSpecs(int specVersion, List<String> implementationTypes) {

    /** The current format version. */
    public static final int VERSION = 1;

    /** The classpath resource holding the specs that ship. */
    public static final String RESOURCE = "/crypto-implementation-specs.yaml";

    /** Normalizes a missing list to an empty one. */
    public CryptoImplementationSpecs {
        implementationTypes = implementationTypes == null ? List.of() : List.copyOf(implementationTypes);
    }

    /**
     * Reads the specs that ship.
     *
     * @return the specs
     * @throws IOException if the resource is missing, can't be parsed, or is of another version
     */
    public static CryptoImplementationSpecs load() throws IOException {
        try (InputStream in = CryptoImplementationSpecs.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IOException("Missing resource " + RESOURCE);
            }
            final CryptoImplementationSpecs specs = new YAMLMapper()
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
                    .readValue(in, CryptoImplementationSpecs.class);
            if (specs.specVersion() != VERSION) {
                throw new IOException(RESOURCE + " has format version " + specs.specVersion() + ", expected " + VERSION);
            }
            return specs;
        }
    }
}
