package io.github.aloubyansky.cryptid.scan;

import com.ibm.mapper.model.INode;
import com.ibm.output.cyclondx.CBOMOutputFile;
import io.github.aloubyansky.cryptid.AssetOccurrence;
import io.github.aloubyansky.cryptid.CipherSuite;
import io.github.aloubyansky.cryptid.CodeLocation;
import io.github.aloubyansky.cryptid.CryptoAsset;
import io.github.aloubyansky.cryptid.CryptoAssetProperties;
import io.github.aloubyansky.cryptid.CryptoInventory;
import io.github.aloubyansky.cryptid.model.CryptoAssetModeler;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.ProtocolProperties;
import org.cyclonedx.model.component.crypto.RelatedCryptoMaterialProperties;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.evidence.Occurrence;

/**
 * Collects the crypto assets of findings into an inventory: renders each finding's model nodes
 * with sonar-cryptography's {@link CBOMOutputFile}, and converts the components into {@link
 * CryptoAsset}s, with their occurrences mapped back to the code.
 *
 * <p>This is the only place that sees sonar-cryptography's output, and its random bom-refs and
 * the UUIDs it puts into names. Each finding goes through an output of its own, because {@link
 * CBOMOutputFile} identifies assets by name alone: a second asset of the same name would only add
 * its occurrences to the first and lose its properties.
 *
 * <p>The conversion is checked to be lossless: a component with a property the model doesn't
 * carry fails it, rather than lose the property.
 */
public final class AssetCollector {

    /** The random UUID sonar-cryptography's output appends to names of related material, e.g. {@code key@<uuid>}. */
    private static final Pattern NAME_UUID =
            Pattern.compile("@[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    private final CryptoInventory.Builder inventory;

    /**
     * Creates a collector adding to an inventory.
     *
     * @param inventory the inventory to add the assets to
     */
    public AssetCollector(CryptoInventory.Builder inventory) {
        this.inventory = inventory;
    }

    /**
     * Adds the assets of one finding.
     *
     * @param nodes the finding's model nodes
     * @param locations the code locations of the nodes' detection locations, by {@link
     *     CryptoAssetModeler#locationKey}
     * @throws IllegalStateException if the output has a property the model doesn't carry, or an
     *     occurrence without a code location
     */
    public void add(List<INode> nodes, Map<String, CodeLocation> locations) {
        add(nodes, locations, l -> AssetOccurrence.Role.USE);
    }

    /**
     * Adds the assets of one finding, with each occurrence's role.
     *
     * @param nodes the finding's model nodes
     * @param locations the code locations of the nodes' detection locations, by {@link
     *     CryptoAssetModeler#locationKey}
     * @param roles what the code at a location does with the asset
     * @throws IllegalStateException if the output has a property the model doesn't carry, or an
     *     occurrence without a code location
     */
    public void add(List<INode> nodes, Map<String, CodeLocation> locations, Function<CodeLocation, AssetOccurrence.Role> roles) {
        final CBOMOutputFile output = new CBOMOutputFile();
        output.add(nodes);
        final Bom part = output.getBom();
        final Map<String, Component> byRef = new HashMap<>();
        // sonar-cryptography's output orders components by a hash of their random bom-refs: order
        // them by name, unique within one output, so that assets are created in the same order in
        // every run
        final List<Component> components = new ArrayList<>(part.getComponents() == null ? List.of() : part.getComponents());
        components.sort(Comparator.comparing(c -> NAME_UUID.matcher(c.getName() == null ? "" : c.getName()).replaceAll("")));
        components.forEach(c -> byRef.put(c.getBomRef(), c));
        final Map<String, CryptoAsset> assets = new HashMap<>();
        for (Component c : components) {
            final CryptoAsset asset = asset(c, byRef, assets);
            if (c.getEvidence() != null && c.getEvidence().getOccurrences() != null) {
                for (Occurrence o : c.getEvidence().getOccurrences()) {
                    final String key = CryptoAssetModeler.locationKey(
                            o.getLocation(), o.getLine() == null ? 0 : o.getLine(), o.getAdditionalContext());
                    final CodeLocation location = locations.get(key);
                    if (location == null) {
                        throw new IllegalStateException("No code location for occurrence " + key + " of " + asset);
                    }
                    inventory.occurrence(asset, location, roles.apply(location));
                }
            }
        }
        // dependencies come in the order of the random bom-refs too: link them by name
        final Comparator<CryptoAsset> byName = Comparator.comparing(CryptoAsset::name);
        final Map<CryptoAsset, List<CryptoAsset>> links = new TreeMap<>(byName);
        for (Dependency d : part.getDependencies() == null ? List.<Dependency>of() : part.getDependencies()) {
            final CryptoAsset from = assets.get(d.getRef());
            if (from == null || d.getDependencies() == null) {
                continue;
            }
            for (Dependency to : d.getDependencies()) {
                final CryptoAsset target = assets.get(to.getRef());
                if (target != null) {
                    links.computeIfAbsent(from, k -> new ArrayList<>()).add(target);
                }
            }
        }
        links.forEach((from, targets) -> {
            targets.sort(byName);
            targets.forEach(target -> inventory.dependency(from, target));
        });
    }

    /** The asset of a component, converting it on first use. */
    private CryptoAsset asset(Component c, Map<String, Component> byRef, Map<String, CryptoAsset> assets) {
        final CryptoAsset done = assets.get(c.getBomRef());
        if (done != null) {
            return done;
        }
        final String name = NAME_UUID.matcher(c.getName() == null ? "" : c.getName()).replaceAll("");
        final CryptoAsset asset = inventory.asset(name, properties(c, byRef, assets));
        assets.put(c.getBomRef(), asset);
        return asset;
    }

    private CryptoAssetProperties properties(Component c, Map<String, Component> byRef, Map<String, CryptoAsset> assets) {
        final CryptoProperties p = c.getCryptoProperties();
        if (p == null || p.getAssetType() == null) {
            throw new IllegalStateException("No crypto properties: " + c.getName());
        }
        unsupported(c, "certificateProperties", p.getCertificateProperties());
        switch (p.getAssetType()) {
            case ALGORITHM -> {
                final AlgorithmProperties a = p.getAlgorithmProperties();
                if (a == null) {
                    return new CryptoAssetProperties.Algorithm(null, null, null, null, null, null, p.getOid());
                }
                unsupported(c, "executionEnvironment", a.getExecutionEnvironment());
                unsupported(c, "implementationPlatform", a.getImplementationPlatform());
                unsupported(c, "certificationLevel", a.getCertificationLevel());
                unsupported(c, "classicalSecurityLevel", a.getClassicalSecurityLevel());
                unsupported(c, "nistQuantumSecurityLevel", a.getNistQuantumSecurityLevel());
                final Set<CryptoAssetProperties.CryptoFunction> functions = new LinkedHashSet<>();
                if (a.getCryptoFunctions() != null) {
                    for (CryptoFunction f : a.getCryptoFunctions()) {
                        functions.add(CryptoAssetProperties.CryptoFunction.valueOf(f.name()));
                    }
                }
                return new CryptoAssetProperties.Algorithm(
                        a.getPrimitive() == null ? null : CryptoAssetProperties.Primitive.valueOf(a.getPrimitive().name()),
                        a.getParameterSetIdentifier(),
                        a.getCurve(),
                        a.getMode() == null ? null : CryptoAssetProperties.Mode.valueOf(a.getMode().name()),
                        a.getPadding() == null ? null : CryptoAssetProperties.Padding.valueOf(a.getPadding().name()),
                        functions,
                        p.getOid());
            }
            case RELATED_CRYPTO_MATERIAL -> {
                final RelatedCryptoMaterialProperties m = p.getRelatedCryptoMaterialProperties();
                if (m == null) {
                    return new CryptoAssetProperties.RelatedMaterial(null, null, p.getOid());
                }
                unsupported(c, "id", m.getId());
                unsupported(c, "state", m.getState());
                unsupported(c, "algorithmRef", m.getAlgorithmRef());
                unsupported(c, "creationDate", m.getCreationDate());
                unsupported(c, "activationDate", m.getActivationDate());
                unsupported(c, "updateDate", m.getUpdateDate());
                unsupported(c, "expirationDate", m.getExpirationDate());
                unsupported(c, "value", m.getValue());
                unsupported(c, "format", m.getFormat());
                unsupported(c, "securedBy", m.getSecuredBy());
                return new CryptoAssetProperties.RelatedMaterial(
                        m.getType() == null ? null : CryptoAssetProperties.MaterialType.valueOf(m.getType().name()),
                        m.getSize(),
                        p.getOid());
            }
            case PROTOCOL -> {
                final ProtocolProperties pr = p.getProtocolProperties();
                if (pr == null) {
                    return new CryptoAssetProperties.Protocol(null, null, null, p.getOid());
                }
                unsupported(c, "ikev2TransformTypes", pr.getIkev2TransformTypes());
                unsupported(c, "cryptoRefArray", pr.getCryptoRefArray());
                final List<CipherSuite> suites = new ArrayList<>();
                if (pr.getCipherSuites() != null) {
                    for (org.cyclonedx.model.component.crypto.CipherSuite s : pr.getCipherSuites()) {
                        final List<CryptoAsset> algorithms = new ArrayList<>();
                        for (String ref : s.getAlgorithms() == null ? List.<String>of() : s.getAlgorithms()) {
                            final Component algorithm = byRef.get(ref);
                            if (algorithm == null) {
                                throw new IllegalStateException("Cipher suite " + s.getName() + " refers to a missing asset " + ref);
                            }
                            algorithms.add(asset(algorithm, byRef, assets));
                        }
                        suites.add(new CipherSuite(s.getName(), algorithms, s.getIdentifiers()));
                    }
                }
                return new CryptoAssetProperties.Protocol(
                        pr.getType() == null ? null : CryptoAssetProperties.ProtocolType.valueOf(pr.getType().name()),
                        pr.getVersion(),
                        suites,
                        p.getOid());
            }
            default -> throw new IllegalStateException("Unsupported asset type " + p.getAssetType() + ": " + c.getName());
        }
    }

    /** Fails on a property the model doesn't carry. */
    private static void unsupported(Component c, String property, Object value) {
        if (value != null && !(value instanceof List<?> l && l.isEmpty())) {
            throw new IllegalStateException("Unsupported property " + property + " of " + c.getName() + ": " + value);
        }
    }
}
