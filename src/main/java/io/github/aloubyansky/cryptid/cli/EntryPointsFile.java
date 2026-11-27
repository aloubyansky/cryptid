package io.github.aloubyansky.cryptid.cli;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.EntryPoint;
import io.github.aloubyansky.cryptid.MethodId;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Reads the entry points {@code --entry-points} supplies: a YAML list of entries such as
 *
 * <pre>
 * - method: org.acme.Resource#hello(Ljava/lang/String;)Ljava/lang/String;
 *   kind: http
 *   exposure: external
 *   address: GET /hello/{name}
 *   authenticated: true
 *   artifact: org.acme:app::jar:1.0
 * </pre>
 *
 * with {@code method} and {@code kind} required, and {@code exposure} external by default.
 */
final class EntryPointsFile {

    private static final YAMLMapper YAML = (YAMLMapper) new YAMLMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

    /** One entry of the file. */
    record Entry(String method, String kind, String exposure, String address, Boolean authenticated, String artifact) {}

    private EntryPointsFile() {}

    /**
     * Reads a file of entry points.
     *
     * @param file the file
     * @return the entry points, supplied
     * @throws IOException if the file can't be read or an entry is malformed
     */
    static List<EntryPoint> read(Path file) throws IOException {
        final Entry[] entries = YAML.readValue(file.toFile(), Entry[].class);
        final List<EntryPoint> result = new ArrayList<>(entries == null ? 0 : entries.length);
        for (Entry e : entries == null ? new Entry[0] : entries) {
            if (e.method() == null || e.kind() == null) {
                throw new IOException(file + ": an entry point needs a method and a kind: " + e);
            }
            final int hash = e.method().indexOf('#');
            final int paren = e.method().indexOf('(', hash);
            if (hash <= 0 || paren < 0) {
                throw new IOException(file + ": not a method, class#name(descriptor): " + e.method());
            }
            final EntryPoint.Builder b = EntryPoint.builder(
                    new MethodId(e.method().substring(0, hash), e.method().substring(hash + 1, paren), e.method().substring(paren)),
                    e.kind());
            if (e.exposure() != null) {
                b.exposure(EntryPoint.Exposure.valueOf(e.exposure().toUpperCase(Locale.ROOT)));
            }
            b.address(e.address()).authenticated(e.authenticated());
            if (e.artifact() != null) {
                final String[] parts = e.artifact().split(":");
                if (parts.length != 5) {
                    throw new IOException(file + ": not groupId:artifactId:classifier:type:version: " + e.artifact());
                }
                b.artifact(new ArtifactCoordinates(parts[0], parts[1], parts[2], parts[3], parts[4]));
            }
            result.add(b.build());
        }
        return result;
    }
}
