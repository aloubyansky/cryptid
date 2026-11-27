package io.github.aloubyansky.cryptid.analysis;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.aloubyansky.cryptid.ArtifactAnalysis;
import io.github.aloubyansky.cryptid.AssetOccurrence;
import io.github.aloubyansky.cryptid.CipherSuite;
import io.github.aloubyansky.cryptid.CodeLocation;
import io.github.aloubyansky.cryptid.CryptoAsset;
import io.github.aloubyansky.cryptid.CryptoAssetProperties;
import io.github.aloubyansky.cryptid.CryptoInventory;
import io.github.aloubyansky.cryptid.scan.ArtifactScan;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads and writes an artifact's scan as JSON, the format of the results kept in the cache
 * directory. Assets refer to the assets they depend on, and cipher suites to their algorithms, by
 * their index in the file.
 */
final class InventoryJson {

    /** The format version; files of another version aren't read. */
    static final int FORMAT = 2;

    private static final ObjectMapper JSON = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

    /** The file's content. */
    record Doc(int format, ArtifactAnalysis analysis, List<Asset> assets) {}

    /** An asset, with references by index. */
    record Asset(String name, Properties properties, List<CodeLocation> occurrences, List<Integer> dependsOn) {}

    /** An asset's properties, of one of the three asset types. */
    record Properties(String assetType, String primitive, String parameterSet, String curve, String mode, String padding,
            List<String> functions, String materialType, Integer size, String protocolType, String version,
            List<Suite> cipherSuites, String oid) {}

    /** A cipher suite, with its algorithms by index. */
    record Suite(String name, List<Integer> algorithms, List<String> identifiers) {}

    private InventoryJson() {}

    /**
     * Writes a scan, atomically: to a temporary file first, then moved into place, so an existing
     * file always holds a complete scan.
     *
     * @param scan the scan
     * @param file the target file
     * @throws IOException if the file can't be written
     */
    static void write(ArtifactScan scan, Path file) throws IOException {
        final Map<CryptoAsset, Integer> index = new IdentityHashMap<>();
        for (CryptoAsset a : scan.assets()) {
            index.put(a, index.size());
        }
        final List<Asset> assets = new ArrayList<>(scan.assets().size());
        for (CryptoAsset a : scan.assets()) {
            assets.add(new Asset(a.name(), properties(a.properties(), index),
                    a.occurrences().stream().map(AssetOccurrence::location).toList(),
                    a.dependsOn().stream().map(index::get).toList()));
        }
        final Path dir = file.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        final Path tmp = Files.createTempFile(dir, file.getFileName().toString(), ".tmp");
        JSON.writeValue(tmp.toFile(), new Doc(FORMAT, scan.analysis(), assets));
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    /**
     * Reads a scan.
     *
     * @param file the file
     * @return the scan
     * @throws IOException if the file can't be read, or isn't of this format
     */
    static ArtifactScan read(Path file) throws IOException {
        final Doc doc = JSON.readValue(file.toFile(), Doc.class);
        if (doc.format() != FORMAT) {
            throw new IOException(file + " has format " + doc.format() + ", expected " + FORMAT);
        }
        final CryptoInventory.Builder builder = CryptoInventory.builder();
        final CryptoAsset[] assets = new CryptoAsset[doc.assets().size()];
        for (int i = 0; i < assets.length; i++) {
            asset(i, doc.assets(), assets, builder);
        }
        for (int i = 0; i < assets.length; i++) {
            final Asset a = doc.assets().get(i);
            for (CodeLocation l : a.occurrences()) {
                builder.occurrence(assets[i], l);
            }
            for (int d : a.dependsOn()) {
                builder.dependency(assets[i], assets[d]);
            }
        }
        return new ArtifactScan(doc.analysis(), builder.build().assets());
    }

    /** The asset at an index, created on first use, after the algorithms of its cipher suites. */
    private static CryptoAsset asset(int i, List<Asset> docs, CryptoAsset[] assets, CryptoInventory.Builder builder) {
        if (assets[i] == null) {
            final Asset a = docs.get(i);
            assets[i] = builder.asset(a.name(), properties(a.properties(), docs, assets, builder));
        }
        return assets[i];
    }

    private static Properties properties(CryptoAssetProperties p, Map<CryptoAsset, Integer> index) {
        if (p instanceof CryptoAssetProperties.Algorithm a) {
            return new Properties("algorithm", name(a.primitive()), a.parameterSet(), a.curve(), name(a.mode()),
                    name(a.padding()), a.functions().isEmpty() ? null : a.functions().stream().map(Enum::name).toList(),
                    null, null, null, null, null, a.oid());
        }
        if (p instanceof CryptoAssetProperties.RelatedMaterial m) {
            return new Properties("related-material", null, null, null, null, null, null, name(m.type()), m.size(), null,
                    null, null, m.oid());
        }
        final CryptoAssetProperties.Protocol pr = (CryptoAssetProperties.Protocol) p;
        return new Properties("protocol", null, null, null, null, null, null, null, null, name(pr.type()), pr.version(),
                pr.cipherSuites().isEmpty() ? null : pr.cipherSuites().stream()
                        .map(s -> new Suite(s.name(), s.algorithms().stream().map(index::get).toList(), s.identifiers()))
                        .toList(),
                pr.oid());
    }

    private static CryptoAssetProperties properties(Properties p, List<Asset> docs, CryptoAsset[] assets,
            CryptoInventory.Builder builder) {
        return switch (p.assetType()) {
            case "algorithm" -> {
                final Set<CryptoAssetProperties.CryptoFunction> functions = EnumSet.noneOf(CryptoAssetProperties.CryptoFunction.class);
                if (p.functions() != null) {
                    p.functions().forEach(f -> functions.add(CryptoAssetProperties.CryptoFunction.valueOf(f)));
                }
                yield new CryptoAssetProperties.Algorithm(
                        p.primitive() == null ? null : CryptoAssetProperties.Primitive.valueOf(p.primitive()),
                        p.parameterSet(), p.curve(),
                        p.mode() == null ? null : CryptoAssetProperties.Mode.valueOf(p.mode()),
                        p.padding() == null ? null : CryptoAssetProperties.Padding.valueOf(p.padding()),
                        functions, p.oid());
            }
            case "related-material" -> new CryptoAssetProperties.RelatedMaterial(
                    p.materialType() == null ? null : CryptoAssetProperties.MaterialType.valueOf(p.materialType()),
                    p.size(), p.oid());
            case "protocol" -> {
                final List<CipherSuite> suites = new ArrayList<>();
                if (p.cipherSuites() != null) {
                    for (Suite s : p.cipherSuites()) {
                        suites.add(new CipherSuite(s.name(),
                                s.algorithms().stream().map(i -> asset(i, docs, assets, builder)).toList(), s.identifiers()));
                    }
                }
                yield new CryptoAssetProperties.Protocol(
                        p.protocolType() == null ? null : CryptoAssetProperties.ProtocolType.valueOf(p.protocolType()),
                        p.version(), suites, p.oid());
            }
            default -> throw new IllegalArgumentException("Unknown asset type " + p.assetType());
        };
    }

    private static String name(Enum<?> e) {
        return e == null ? null : e.name();
    }
}
