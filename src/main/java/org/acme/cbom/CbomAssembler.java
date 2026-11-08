package org.acme.cbom;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.cyclonedx.model.metadata.ToolInformation;
import org.cyclonedx.parsers.JsonParser;
import org.jboss.logging.Logger;

/**
 * Merges the per-artifact CBOMs into one, adding the analyzed Maven components and linking each of
 * them to the crypto assets detected in its artifact using CycloneDX dependencies.
 */
@ApplicationScoped
public class CbomAssembler {

    private static final Logger log = Logger.getLogger(CbomAssembler.class);

    /** CycloneDX version of the produced CBOMs; cryptographic assets require 1.6. */
    static final Version CYCLONEDX_VERSION = Version.VERSION_16;

    /**
     * The merged CBOM and some statistics about it.
     *
     * @param bom the merged CBOM
     * @param componentsWithAssets the number of SBOM components linked to at least one crypto
     *     asset
     * @param findings the total number of crypto asset occurrences
     */
    public record Result(Bom bom, int componentsWithAssets, long findings) {}

    /**
     * Merges the per-artifact CBOMs into a single CBOM. The CBOM's metadata names this tool and
     * carries the SBOM's metadata component. The crypto assets of each artifact are added once.
     * Every SBOM component sharing that artifact is added as a component, unless it is the metadata
     * component, and gets a dependency entry pointing to the assets. Artifacts without a CBOM file,
     * i.e. that weren't analyzed successfully, and CBOMs without assets are skipped. Unreadable
     * CBOM files are skipped with a warning.
     *
     * @param inputSbom the input SBOM
     * @param groups the analyzed components, grouped by the binary artifact they share
     * @param workDir the work directory holding the per-artifact CBOMs
     * @return the merged CBOM with statistics
     */
    public Result assemble(Bom inputSbom, List<List<MavenComponent>> groups, Path workDir) {
        final Bom bom = new Bom();
        bom.setMetadata(metadata());
        String rootRef = null;
        if (inputSbom.getMetadata() != null && inputSbom.getMetadata().getComponent() != null) {
            final Component root = shallowCopy(inputSbom.getMetadata().getComponent());
            bom.getMetadata().setComponent(root);
            rootRef = root.getBomRef();
        }

        // component bom-ref -> its link to crypto assets; one entry per component
        final Map<String, Dependency> links = new LinkedHashMap<>();
        // artifact path -> components, for attributing assets by occurrence location
        final Map<String, List<MavenComponent>> byPath = new HashMap<>();
        groups.forEach(g -> byPath.put(g.get(0).artifactPath(), g));
        final JsonParser parser = new JsonParser();
        // occurrence key -> bom-ref of the asset kept for it
        final Map<String, String> seen = new HashMap<>();
        // asset -> asset dependencies, by bom-ref of the depending asset
        final Map<String, Dependency> assetLinks = new LinkedHashMap<>();
        long findings = 0;
        for (List<MavenComponent> group : groups) {
            final Optional<Bom> part = parse(parser, group.get(0).cbomFile(workDir));
            final List<Component> assets = new ArrayList<>(part.map(b -> b.getComponents() == null ? List.<Component>of() : b.getComponents())
                    .orElse(List.of()));
            // sonar-cryptography's output orders assets by a hash of random bom-refs: sort them, so
            // that which of two duplicates is kept is the same in every run
            assets.sort(Comparator.comparing(CbomAssembler::sortKey));
            if (assets.isEmpty()) {
                continue;
            }
            // bom-refs of this part's assets: kept ones map to themselves, duplicates to the kept asset
            final Map<String, String> refs = new HashMap<>();
            for (Component asset : assets) {
                // the same asset at the same occurrence can come from several artifacts, e.g. a
                // wrapper shaded into another JAR resolving the same callers: keep the first
                if (asset.getEvidence() != null && asset.getEvidence().getOccurrences() != null) {
                    final String content = contentKey(asset);
                    final List<Occurrence> fresh = new ArrayList<>();
                    String duplicateOf = null;
                    for (var o : asset.getEvidence().getOccurrences()) {
                        final String previous = seen.putIfAbsent(occurrenceKey(content, o), asset.getBomRef());
                        if (previous == null) {
                            fresh.add(o);
                        } else if (duplicateOf == null) {
                            duplicateOf = previous;
                        }
                    }
                    if (fresh.isEmpty()) {
                        refs.put(asset.getBomRef(), duplicateOf);
                        continue;
                    }
                    asset.getEvidence().setOccurrences(fresh);
                }
                refs.put(asset.getBomRef(), asset.getBomRef());
                bom.addComponent(asset);
                // an asset belongs to the artifacts its occurrences are located in: values
                // resolved at a caller are located in the caller's artifact
                final Set<List<MavenComponent>> owners = new LinkedHashSet<>();
                if (asset.getEvidence() != null && asset.getEvidence().getOccurrences() != null) {
                    for (var o : asset.getEvidence().getOccurrences()) {
                        findings++;
                        owners.add(owner(o.getLocation(), byPath, group));
                    }
                }
                if (owners.isEmpty()) {
                    owners.add(group);
                }
                for (List<MavenComponent> owner : owners) {
                    for (MavenComponent c : owner) {
                        link(links, bom, c, rootRef, asset);
                    }
                }
            }
            if (part.get().getDependencies() != null) {
                for (Dependency d : part.get().getDependencies()) {
                    linkAssets(assetLinks, refs, d);
                }
            }
        }
        assetLinks.values().forEach(bom::addDependency);
        links.values().forEach(bom::addDependency);
        log.infof(
                "%d of %d analyzed components contain cryptographic assets",
                links.size(),
                groups.stream().mapToInt(List::size).sum());
        return new Result(bom, links.size(), findings);
    }

    /**
     * Adds an asset's dependencies on other assets, redirecting duplicates to the asset kept for
     * them and dropping references to assets that aren't in the CBOM.
     *
     * @param assetLinks dependencies by bom-ref of the depending asset; updated
     * @param refs this part's asset bom-refs mapped to the kept asset's bom-ref
     * @param d a dependency entry of the part
     */
    private static void linkAssets(Map<String, Dependency> assetLinks, Map<String, String> refs, Dependency d) {
        final String from = refs.get(d.getRef());
        if (from == null || d.getDependencies() == null) {
            return;
        }
        for (Dependency to : d.getDependencies()) {
            final String target = refs.get(to.getRef());
            if (target == null || target.equals(from)) {
                continue;
            }
            final Dependency link = assetLinks.computeIfAbsent(from, Dependency::new);
            if (link.getDependencies() == null || link.getDependencies().stream().noneMatch(x -> x.getRef().equals(target))) {
                link.addDependency(new Dependency(target));
            }
        }
    }

    private static final ObjectMapper CONTENT_JSON = new ObjectMapper()
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    /**
     * Returns what identifies an asset apart from where it occurs: its name and crypto properties,
     * without the random UUIDs in names and references. Two assets at one location are duplicates
     * only if this is equal, e.g. not keys of different sizes.
     *
     * @param asset the crypto asset
     * @return the content key
     */
    static String contentKey(Component asset) {
        String props;
        try {
            props = asset.getCryptoProperties() == null ? "" : CONTENT_JSON.writeValueAsString(asset.getCryptoProperties());
        } catch (JsonProcessingException e) {
            props = String.valueOf(asset.getCryptoProperties());
        }
        final String name = asset.getName() == null ? "" : asset.getName();
        return NAME_UUID.matcher(name).replaceAll("") + "|" + ANY_UUID.matcher(props).replaceAll("");
    }

    /** A run-independent sort key for an asset: its content key and its occurrences. */
    private static String sortKey(Component asset) {
        final StringBuilder sb = new StringBuilder(contentKey(asset));
        if (asset.getEvidence() != null && asset.getEvidence().getOccurrences() != null) {
            for (var o : asset.getEvidence().getOccurrences()) {
                sb.append('|').append(o.getLocation()).append(':').append(o.getLine()).append(':').append(o.getAdditionalContext());
            }
        }
        return sb.toString();
    }

    private static final Pattern ANY_UUID =
            Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    /** Random UUIDs some asset names embed, e.g. {@code key@<uuid>}. */
    private static final Pattern NAME_UUID =
            Pattern.compile("@[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    /**
     * Returns the key identifying an occurrence of an asset across per-artifact CBOMs.
     *
     * @param contentKey the asset's {@link #contentKey}
     * @param o one of its occurrences
     * @return the content key with location, line and offset
     */
    static String occurrenceKey(String contentKey, Occurrence o) {
        return contentKey + "|" + o.getLocation() + "|" + o.getLine() + "|" + o.getOffset();
    }

    /**
     * Finds the components an occurrence location belongs to, by its artifact path prefix.
     *
     * @param location the occurrence location, e.g. {@code g/a/v/org/acme/Foo.java}
     * @param byPath components by artifact path
     * @param fallback the components to use when no artifact path matches
     * @return the components of the longest matching artifact path
     */
    static List<MavenComponent> owner(String location, Map<String, List<MavenComponent>> byPath, List<MavenComponent> fallback) {
        if (location == null) {
            return fallback;
        }
        // artifact paths are g/a/v or g/a/v/classifier: try the longer one first
        final String[] parts = location.split("/", 5);
        if (parts.length >= 4) {
            final List<MavenComponent> withClassifier = byPath.get(parts[0] + "/" + parts[1] + "/" + parts[2] + "/" + parts[3]);
            if (withClassifier != null) {
                return withClassifier;
            }
        }
        if (parts.length >= 3) {
            final List<MavenComponent> plain = byPath.get(parts[0] + "/" + parts[1] + "/" + parts[2]);
            if (plain != null) {
                return plain;
            }
        }
        return fallback;
    }

    /**
     * Links a component to a crypto asset. The first link of a component also adds the
     * component itself to the CBOM, unless it is the root.
     *
     * @param links the links created so far, by component bom-ref; updated
     * @param bom the CBOM being assembled
     * @param c the component
     * @param rootRef the bom-ref of the root (metadata) component, or {@code null}
     * @param asset the crypto asset; ignored if it has no bom-ref
     */
    private static void link(Map<String, Dependency> links, Bom bom, MavenComponent c, String rootRef, Component asset) {
        if (c.bomRef() == null || asset.getBomRef() == null) {
            return;
        }
        final Dependency link = links.computeIfAbsent(c.bomRef(), ref -> {
            if (!ref.equals(rootRef)) {
                bom.addComponent(shallowCopy(c.sbomComponent()));
            }
            return new Dependency(ref);
        });
        if (link.getDependencies() == null
                || link.getDependencies().stream().noneMatch(d -> d.getRef().equals(asset.getBomRef()))) {
            link.addDependency(new Dependency(asset.getBomRef()));
        }
    }

    /**
     * Writes a CBOM as CycloneDX JSON, atomically: to a temporary file first, then moved into
     * place, so an existing file always holds a complete CBOM.
     *
     * @param bom the CBOM
     * @param file the target file
     * @throws IOException if the file can't be written
     */
    public static void write(Bom bom, Path file) throws IOException {
        final String json;
        try {
            json = BomGeneratorFactory.createJson(CYCLONEDX_VERSION, bom).toJsonString();
        } catch (GeneratorException e) {
            throw new IOException("Failed to serialize CBOM " + file, e);
        }
        final Path dir = file.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        final Path tmp = Files.createTempFile(dir, file.getFileName().toString(), ".tmp");
        Files.writeString(tmp, json);
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    /**
     * Creates the CBOM metadata: a timestamp and this tool, with the sonar-cryptography version
     * whose Java rules the crypto API specs are derived from, and whose CBOM model it uses.
     *
     * @return the metadata
     */
    private static Metadata metadata() {
        final Metadata metadata = new Metadata();
        metadata.setTimestamp(new Date());
        final Component tool = new Component();
        tool.setType(Component.Type.APPLICATION);
        tool.setGroup("org.acme");
        tool.setName("cbom-generator");
        tool.setVersion(BuildInfo.VERSION);
        tool.setDescription("Bytecode analysis with crypto API specs derived from sonar-cryptography's Java rules");
        final Component rules = new Component();
        rules.setType(Component.Type.LIBRARY);
        rules.setGroup("com.ibm");
        rules.setName("sonar-cryptography");
        rules.setVersion(BuildInfo.SONAR_CRYPTOGRAPHY_VERSION);
        final ToolInformation tools = new ToolInformation();
        tools.setComponents(new ArrayList<>(List.of(tool, rules)));
        metadata.setToolChoice(tools);
        return metadata;
    }

    /**
     * Parses a CBOM file.
     *
     * @param parser the parser
     * @param file the CBOM file
     * @return the CBOM, or empty if the file doesn't exist or can't be parsed (logged as a warning)
     */
    private static Optional<Bom> parse(JsonParser parser, Path file) {
        if (!Files.exists(file)) {
            return Optional.empty();
        }
        try {
            return Optional.of(parser.parse(file.toFile()));
        } catch (Exception e) {
            log.warnf(e, "Ignoring unreadable CBOM %s", file);
            return Optional.empty();
        }
    }

    /**
     * Copies the identifying fields of an SBOM component, leaving out nested components,
     * licenses, hashes and other details the CBOM doesn't need.
     *
     * @param c the SBOM component
     * @return a copy with type, bom-ref (falling back to the purl), group, name, version and purl
     */
    private static Component shallowCopy(Component c) {
        final Component copy = new Component();
        copy.setType(c.getType());
        copy.setBomRef(c.getBomRef() != null ? c.getBomRef() : c.getPurl());
        copy.setGroup(c.getGroup());
        copy.setName(c.getName());
        copy.setVersion(c.getVersion());
        copy.setPurl(c.getPurl());
        return copy;
    }
}
