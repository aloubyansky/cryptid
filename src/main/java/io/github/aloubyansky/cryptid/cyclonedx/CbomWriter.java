package io.github.aloubyansky.cryptid.cyclonedx;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.AssetOccurrence;
import io.github.aloubyansky.cryptid.CryptoAsset;
import io.github.aloubyansky.cryptid.CryptoInventory;
import io.github.aloubyansky.cryptid.analysis.BuildInfo;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.metadata.ToolInformation;

/**
 * Writes a crypto inventory as a CycloneDX CBOM.
 *
 * <p>Every crypto asset is a component. Its occurrences have the call's source file, prefixed
 * with the artifact's path, as {@code location}, its line, the method containing the call as
 * {@code symbol}, and the called method as {@code additionalContext}. Its bom-ref is derived from
 * its content, so it is the same in every run. Dependencies between assets are dependencies between
 * their components. The components the caller links to an artifact depend on the assets occurring
 * in it, so a value chosen by a caller in another artifact is linked to the caller's components.
 */
public final class CbomWriter {

    /** The CycloneDX version written; cryptographic assets need 1.6. */
    public static final Version CYCLONEDX_VERSION = Version.VERSION_16;

    private CbomWriter() {}

    /**
     * Writes an inventory as a CBOM.
     *
     * @param inventory the inventory
     * @param linkTo the components to link to an artifact's assets, e.g. those of an SBOM sharing
     *     the artifact; a component is added to the CBOM when first linked, unless it is the
     *     metadata component, and components without a bom-ref aren't linked
     * @param metadataComponent the CBOM's metadata component, e.g. an SBOM's, or {@code null}
     * @return the CBOM, with this tool and sonar-cryptography in its metadata
     */
    public static Bom toBom(CryptoInventory inventory, Function<ArtifactCoordinates, List<Component>> linkTo,
            Component metadataComponent) {
        final Bom bom = new Bom();
        bom.setMetadata(metadata());
        final String rootRef = metadataComponent == null ? null : metadataComponent.getBomRef();
        if (metadataComponent != null) {
            bom.getMetadata().setComponent(metadataComponent);
        }
        final CryptoAssetComponents.Written written = CryptoAssetComponents.write(inventory.assets());
        // component bom-ref -> its link to crypto assets; one entry per component
        final Map<String, Dependency> links = new LinkedHashMap<>();
        for (int i = 0; i < inventory.assets().size(); i++) {
            final CryptoAsset asset = inventory.assets().get(i);
            final Component component = written.components().get(i);
            bom.addComponent(component);
            final Set<ArtifactCoordinates> owners = new LinkedHashSet<>();
            for (AssetOccurrence o : asset.occurrences()) {
                owners.add(o.location().artifact());
            }
            for (ArtifactCoordinates owner : owners) {
                for (Component c : linkTo.apply(owner)) {
                    link(links, bom, c, rootRef, component);
                }
            }
        }
        written.dependencies().forEach(bom::addDependency);
        links.values().forEach(bom::addDependency);
        return bom;
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
     * Links a component to a crypto asset. The first link of a component also adds the component
     * itself to the CBOM, unless it is the metadata component.
     */
    private static void link(Map<String, Dependency> links, Bom bom, Component c, String rootRef, Component asset) {
        if (c.getBomRef() == null || asset.getBomRef() == null) {
            return;
        }
        final Dependency link = links.computeIfAbsent(c.getBomRef(), ref -> {
            if (!ref.equals(rootRef)) {
                bom.addComponent(c);
            }
            return new Dependency(ref);
        });
        if (link.getDependencies() == null
                || link.getDependencies().stream().noneMatch(d -> d.getRef().equals(asset.getBomRef()))) {
            link.addDependency(new Dependency(asset.getBomRef()));
        }
    }

    /**
     * The CBOM metadata: a timestamp and this tool, with the sonar-cryptography version whose
     * Java rules the crypto API specs are derived from, and whose CBOM model it uses.
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
}
