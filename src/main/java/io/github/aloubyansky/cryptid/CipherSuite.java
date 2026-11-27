package io.github.aloubyansky.cryptid;

import java.util.List;

/**
 * A cipher suite of a protocol.
 *
 * @param name the suite's name, e.g. {@code TLS_AES_128_GCM_SHA256}
 * @param algorithms the algorithms it uses
 * @param identifiers its identifiers, e.g. {@code 0x13, 0x01}
 */
public record CipherSuite(String name, List<CryptoAsset> algorithms, List<String> identifiers) {

    /** Copies the lists, treating {@code null} as empty. */
    public CipherSuite {
        algorithms = algorithms == null ? List.of() : List.copyOf(algorithms);
        identifiers = identifiers == null ? List.of() : List.copyOf(identifiers);
    }
}
