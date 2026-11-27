package io.github.aloubyansky.cryptid.cli;

import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;

/**
 * Identifies the per-artifact results in the work directory that a run may reuse. A per-artifact
 * CBOM depends on more than its own JAR: on the tool and its specs, on the other artifacts of the
 * SBOM, whose callers pass values in and whose classes resolve supertypes, and on the classpath
 * mode. Results are kept under a directory named by the key of all of these, so that a run with
 * any of them changed doesn't reuse them.
 */
public final class CacheKey {

    private CacheKey() {}

    /**
     * Returns the key of the inputs.
     *
     * @param build identifies the tool's build, see {@link #build()}
     * @param classpathMode the {@code --classpath} mode
     * @param artifacts one entry per resolved artifact, identifying its coordinates and JAR; their
     *     order doesn't matter
     * @return 16 hexadecimal digits
     */
    public static String of(String build, String classpathMode, Collection<String> artifacts) {
        final MessageDigest sha = sha256();
        update(sha, build);
        update(sha, classpathMode);
        final List<String> sorted = new ArrayList<>(artifacts);
        sorted.sort(null);
        for (String a : sorted) {
            update(sha, a);
        }
        return HexFormat.of().formatHex(sha.digest(), 0, 8);
    }

    /**
     * Identifies this build of the tool: its version, build time and a digest of its specs, which
     * may differ from the build's when the tool runs from a development classpath.
     *
     * @return the version, build time and specs digest, separated by spaces
     */
    public static String build() {
        final MessageDigest sha = sha256();
        try (InputStream in = CryptoApiSpecs.class.getResourceAsStream(CryptoApiSpecs.RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Missing resource " + CryptoApiSpecs.RESOURCE);
            }
            sha.update(in.readAllBytes());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return BuildInfo.VERSION + " " + BuildInfo.BUILD_TIME + " " + HexFormat.of().formatHex(sha.digest(), 0, 8);
    }

    /** Adds a length-prefixed string, so that consecutive inputs can't run together. */
    private static void update(MessageDigest sha, String s) {
        final byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        sha.update((byte) (bytes.length >>> 24));
        sha.update((byte) (bytes.length >>> 16));
        sha.update((byte) (bytes.length >>> 8));
        sha.update((byte) bytes.length);
        sha.update(bytes);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
