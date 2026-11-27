package io.github.aloubyansky.cryptid.cli;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.AssetOccurrence;
import io.github.aloubyansky.cryptid.CryptoAsset;
import io.github.aloubyansky.cryptid.CryptoInventory;
import io.github.aloubyansky.cryptid.cyclonedx.CbomWriter;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.jboss.logging.Logger;

/**
 * Writes the crypto inventory of an SBOM's artifacts as a CBOM with {@link CbomWriter}, linking
 * the SBOM's Maven components to the crypto assets in their artifacts and carrying the SBOM's
 * metadata component.
 */
@ApplicationScoped
public class CbomAssembler {

    private static final Logger log = Logger.getLogger(CbomAssembler.class);

    /**
     * The CBOM and some statistics about it.
     *
     * @param bom the CBOM
     * @param componentsWithAssets the number of SBOM components linked to at least one crypto
     *     asset
     * @param findings the total number of crypto asset occurrences
     */
    public record Result(Bom bom, int componentsWithAssets, long findings) {}

    /**
     * Writes an inventory as a CBOM. Every SBOM component sharing an artifact that a crypto asset
     * occurs in is linked to the asset, and added to the CBOM, except the metadata component.
     *
     * @param inputSbom the input SBOM
     * @param groups the analyzed components, grouped by the binary artifact they share
     * @param inventory the assets found in the artifacts
     * @return the CBOM with statistics
     */
    public Result assemble(Bom inputSbom, List<List<MavenComponent>> groups, CryptoInventory inventory) {
        final Component root = inputSbom.getMetadata() == null || inputSbom.getMetadata().getComponent() == null
                ? null : shallowCopy(inputSbom.getMetadata().getComponent());
        // the copies of the components sharing each artifact, made once
        final Map<ArtifactCoordinates, List<Component>> byArtifact = new HashMap<>();
        for (List<MavenComponent> g : groups) {
            final List<Component> copies = new ArrayList<>(g.size());
            for (MavenComponent c : g) {
                if (c.bomRef() != null) {
                    copies.add(shallowCopy(c.sbomComponent()));
                }
            }
            byArtifact.put(g.get(0).coordinates(), copies);
        }
        final Bom bom = CbomWriter.toBom(inventory, a -> byArtifact.getOrDefault(a, List.of()), root);

        long findings = 0;
        final Set<String> linked = new HashSet<>();
        for (CryptoAsset asset : inventory.assets()) {
            for (AssetOccurrence o : asset.occurrences()) {
                findings++;
                byArtifact.getOrDefault(o.location().artifact(), List.of()).forEach(c -> linked.add(c.getBomRef()));
            }
        }
        log.infof(
                "%d of %d analyzed components contain cryptographic assets",
                linked.size(),
                groups.stream().mapToInt(List::size).sum());
        return new Result(bom, linked.size(), findings);
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
