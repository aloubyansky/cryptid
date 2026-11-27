package io.github.aloubyansky.cryptid.cli;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.AssetOccurrence;
import io.github.aloubyansky.cryptid.CryptoAsset;
import io.github.aloubyansky.cryptid.CryptoInventory;
import io.github.aloubyansky.cryptid.cyclonedx.CryptoAssetComponents;
import jakarta.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.metadata.ToolInformation;
import org.jboss.logging.Logger;

/**
 * Writes the crypto inventory of an SBOM's artifacts as a CBOM, adding the analyzed Maven
 * components and linking each of them to the crypto assets in its artifact using CycloneDX
 * dependencies.
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
     * Writes an inventory as a CBOM. The CBOM's metadata names this tool and carries the SBOM's
     * metadata component. Every crypto asset is a component, linked from each SBOM component
     * sharing an artifact its occurrences are in: values resolved at a caller are located in the
     * caller's artifact. SBOM components are added once linked, except the metadata component.
     *
     * @param inputSbom the input SBOM
     * @param groups the analyzed components, grouped by the binary artifact they share
     * @param inventory the assets found in the artifacts
     * @return the CBOM with statistics
     */
    public Result assemble(Bom inputSbom, List<List<MavenComponent>> groups, CryptoInventory inventory) {
        final Bom bom = new Bom();
        bom.setMetadata(metadata());
        String rootRef = null;
        if (inputSbom.getMetadata() != null && inputSbom.getMetadata().getComponent() != null) {
            final Component root = shallowCopy(inputSbom.getMetadata().getComponent());
            bom.getMetadata().setComponent(root);
            rootRef = root.getBomRef();
        }
        final Map<ArtifactCoordinates, List<MavenComponent>> byArtifact = new HashMap<>();
        groups.forEach(g -> byArtifact.put(g.get(0).coordinates(), g));

        final CryptoAssetComponents.Written written = CryptoAssetComponents.write(inventory.assets());
        // component bom-ref -> its link to crypto assets; one entry per component
        final Map<String, Dependency> links = new LinkedHashMap<>();
        long findings = 0;
        for (int i = 0; i < inventory.assets().size(); i++) {
            final CryptoAsset asset = inventory.assets().get(i);
            final Component component = written.components().get(i);
            bom.addComponent(component);
            final Set<ArtifactCoordinates> owners = new LinkedHashSet<>();
            for (AssetOccurrence o : asset.occurrences()) {
                findings++;
                owners.add(o.location().artifact());
            }
            for (ArtifactCoordinates owner : owners) {
                for (MavenComponent c : byArtifact.getOrDefault(owner, List.of())) {
                    link(links, bom, c, rootRef, component);
                }
            }
        }
        written.dependencies().forEach(bom::addDependency);
        links.values().forEach(bom::addDependency);
        log.infof(
                "%d of %d analyzed components contain cryptographic assets",
                links.size(),
                groups.stream().mapToInt(List::size).sum());
        return new Result(bom, links.size(), findings);
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
        tool.setGroup("io.github.aloubyansky");
        tool.setName("cryptid");
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
