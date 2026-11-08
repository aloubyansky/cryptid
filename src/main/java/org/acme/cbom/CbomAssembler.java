package org.acme.cbom;

import jakarta.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
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
        final Map<String, List<MavenComponent>> byPath = new java.util.HashMap<>();
        groups.forEach(g -> byPath.put(g.get(0).artifactPath(), g));
        final JsonParser parser = new JsonParser();
        final java.util.Set<String> seen = new java.util.HashSet<>();
        long findings = 0;
        for (List<MavenComponent> group : groups) {
            final Optional<Bom> part = parse(parser, group.get(0).cbomFile(workDir));
            final List<Component> assets = part.map(b -> b.getComponents() == null ? List.<Component>of() : b.getComponents())
                    .orElse(List.of());
            if (assets.isEmpty()) {
                continue;
            }
            if (part.get().getDependencies() != null) {
                part.get().getDependencies().forEach(bom::addDependency);
            }
            for (Component asset : assets) {
                // the same occurrence can come from several artifacts, e.g. a wrapper shaded into
                // another JAR resolving the same callers: keep the first
                if (asset.getEvidence() != null && asset.getEvidence().getOccurrences() != null) {
                    final List<org.cyclonedx.model.component.evidence.Occurrence> fresh = new java.util.ArrayList<>();
                    for (var o : asset.getEvidence().getOccurrences()) {
                        if (seen.add(occurrenceKey(asset, o))) {
                            fresh.add(o);
                        }
                    }
                    if (fresh.isEmpty()) {
                        continue;
                    }
                    asset.getEvidence().setOccurrences(fresh);
                }
                bom.addComponent(asset);
                // an asset belongs to the artifacts its occurrences are located in: values
                // resolved at a caller are located in the caller's artifact
                final java.util.Set<List<MavenComponent>> owners = new java.util.LinkedHashSet<>();
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
        }
        links.values().forEach(bom::addDependency);
        log.infof(
                "%d of %d analyzed components contain cryptographic assets",
                links.size(),
                groups.stream().mapToInt(List::size).sum());
        return new Result(bom, links.size(), findings);
    }

    /** Random UUIDs some asset names embed, e.g. {@code key@<uuid>}. */
    private static final java.util.regex.Pattern NAME_UUID =
            java.util.regex.Pattern.compile("@[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    /**
     * Returns the key identifying an occurrence of an asset across per-artifact CBOMs.
     *
     * @param asset the crypto asset
     * @param o one of its occurrences
     * @return asset name without embedded UUIDs, location, line and offset
     */
    static String occurrenceKey(Component asset, org.cyclonedx.model.component.evidence.Occurrence o) {
        final String name = asset.getName() == null ? "" : NAME_UUID.matcher(asset.getName()).replaceAll("");
        return name + "|" + o.getLocation() + "|" + o.getLine() + "|" + o.getOffset();
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
     * whose detection rules and CBOM model it uses.
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
        tool.setDescription("Bytecode analysis with sonar-cryptography's Java detection rules");
        final Component rules = new Component();
        rules.setType(Component.Type.LIBRARY);
        rules.setGroup("com.ibm");
        rules.setName("sonar-cryptography");
        rules.setVersion(sonarCryptographyVersion());
        final ToolInformation tools = new ToolInformation();
        tools.setComponents(new ArrayList<>(List.of(tool, rules)));
        metadata.setToolChoice(tools);
        return metadata;
    }

    private static String sonarCryptographyVersion() {
        final Package p = com.ibm.engine.rule.IDetectionRule.class.getPackage();
        return p == null || p.getImplementationVersion() == null ? "1.7.0" : p.getImplementationVersion();
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
