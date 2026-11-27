package io.github.aloubyansky.cryptid.cyclonedx;

import io.github.aloubyansky.cryptid.AssetOccurrence;
import io.github.aloubyansky.cryptid.CipherSuite;
import io.github.aloubyansky.cryptid.CodeLocation;
import io.github.aloubyansky.cryptid.CryptoAsset;
import io.github.aloubyansky.cryptid.CryptoAssetProperties;
import io.github.aloubyansky.cryptid.detection.ArtifactPaths;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.ProtocolProperties;
import org.cyclonedx.model.component.crypto.RelatedCryptoMaterialProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.crypto.enums.Mode;
import org.cyclonedx.model.component.crypto.enums.Padding;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.cyclonedx.model.component.crypto.enums.ProtocolType;
import org.cyclonedx.model.component.crypto.enums.RelatedCryptoMaterialType;
import org.cyclonedx.model.component.evidence.Occurrence;

/**
 * Writes crypto assets as CycloneDX components and the dependencies between them.
 *
 * <p>An occurrence's {@code location} and {@code line} are the call's source file and line, its
 * {@code symbol} the method containing the call, and its {@code additionalContext} the called
 * method, both as {@code class#name(descriptor)}.
 *
 * <p>A component's bom-ref is derived from its asset's content, so it is the same in every run
 * and unique among assets of distinct content. Related material is named with the bom-ref
 * appended, e.g. {@code key@<bom-ref>}, as sonar-cryptography's output names it.
 */
final class CryptoAssetComponents {

    /**
     * Assets written as components.
     *
     * @param components one component per asset, in the order of the assets
     * @param dependencies the assets' dependencies on other assets, one entry per asset that has any
     * @param refs the bom-ref of each asset's component
     */
    record Written(List<Component> components, List<Dependency> dependencies, Map<CryptoAsset, String> refs) {}

    private CryptoAssetComponents() {}

    /**
     * Writes assets as components.
     *
     * @param assets the assets, of distinct content; assets they depend on or that their cipher
     *     suites name must be among them
     * @return the components, their dependencies and their bom-refs
     */
    static Written write(List<CryptoAsset> assets) {
        final Map<CryptoAsset, String> refs = new IdentityHashMap<>();
        for (CryptoAsset a : assets) {
            refs.put(a, bomRef(a));
        }
        final List<Component> components = new ArrayList<>(assets.size());
        final List<Dependency> dependencies = new ArrayList<>();
        for (CryptoAsset a : assets) {
            components.add(component(a, refs));
            if (!a.dependsOn().isEmpty()) {
                final Dependency d = new Dependency(refs.get(a));
                for (CryptoAsset target : a.dependsOn()) {
                    d.addDependency(new Dependency(ref(target, refs)));
                }
                dependencies.add(d);
            }
        }
        return new Written(components, dependencies, refs);
    }

    /**
     * Returns the occurrence location of a code location: its source file, prefixed with the
     * artifact's path.
     *
     * @param location the code location
     * @return e.g. {@code org.bouncycastle/bcprov-jdk18on/1.78.1/org/bouncycastle/crypto/engines/AESEngine.java}
     */
    static String location(CodeLocation location) {
        return location.artifact() == null ? location.sourceFile()
                : ArtifactPaths.of(location.artifact()) + "/" + location.sourceFile();
    }

    /** A bom-ref derived from the asset's content. */
    private static String bomRef(CryptoAsset asset) {
        return UUID.nameUUIDFromBytes(asset.toString().getBytes(StandardCharsets.UTF_8)).toString();
    }

    private static String ref(CryptoAsset asset, Map<CryptoAsset, String> refs) {
        final String ref = refs.get(asset);
        if (ref == null) {
            throw new IllegalArgumentException("Not among the assets written: " + asset);
        }
        return ref;
    }

    private static Component component(CryptoAsset a, Map<CryptoAsset, String> refs) {
        final Component c = new Component();
        c.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        final String ref = refs.get(a);
        c.setBomRef(ref);
        c.setName(a.properties() instanceof CryptoAssetProperties.RelatedMaterial ? a.name() + "@" + ref : a.name());
        if (!a.occurrences().isEmpty()) {
            final List<Occurrence> occurrences = new ArrayList<>(a.occurrences().size());
            for (AssetOccurrence o : a.occurrences()) {
                final Occurrence out = new Occurrence();
                out.setLocation(location(o.location()));
                if (o.location().line() > 0) {
                    out.setLine(o.location().line());
                }
                if (o.location().method() != null) {
                    out.setSymbol(o.location().method().toString());
                }
                out.setAdditionalContext(o.location().invokedMethod().toString());
                occurrences.add(out);
            }
            final Evidence evidence = new Evidence();
            evidence.setOccurrences(occurrences);
            c.setEvidence(evidence);
        }
        c.setCryptoProperties(properties(a.properties(), refs));
        return c;
    }

    private static CryptoProperties properties(CryptoAssetProperties properties, Map<CryptoAsset, String> refs) {
        final CryptoProperties p = new CryptoProperties();
        p.setOid(properties.oid());
        if (properties instanceof CryptoAssetProperties.Algorithm a) {
            p.setAssetType(AssetType.ALGORITHM);
            final AlgorithmProperties ap = new AlgorithmProperties();
            ap.setPrimitive(a.primitive() == null ? null : Primitive.valueOf(a.primitive().name()));
            ap.setParameterSetIdentifier(a.parameterSet());
            ap.setCurve(a.curve());
            ap.setMode(a.mode() == null ? null : Mode.valueOf(a.mode().name()));
            ap.setPadding(a.padding() == null ? null : Padding.valueOf(a.padding().name()));
            if (!a.functions().isEmpty()) {
                ap.setCryptoFunctions(a.functions().stream().map(f -> CryptoFunction.valueOf(f.name())).toList());
            }
            p.setAlgorithmProperties(ap);
        } else if (properties instanceof CryptoAssetProperties.RelatedMaterial m) {
            p.setAssetType(AssetType.RELATED_CRYPTO_MATERIAL);
            final RelatedCryptoMaterialProperties mp = new RelatedCryptoMaterialProperties();
            mp.setType(m.type() == null ? null : RelatedCryptoMaterialType.valueOf(m.type().name()));
            mp.setSize(m.size());
            p.setRelatedCryptoMaterialProperties(mp);
        } else if (properties instanceof CryptoAssetProperties.Protocol pr) {
            p.setAssetType(AssetType.PROTOCOL);
            final ProtocolProperties pp = new ProtocolProperties();
            pp.setType(pr.type() == null ? null : ProtocolType.valueOf(pr.type().name()));
            pp.setVersion(pr.version());
            if (!pr.cipherSuites().isEmpty()) {
                final List<org.cyclonedx.model.component.crypto.CipherSuite> suites = new ArrayList<>();
                for (CipherSuite s : pr.cipherSuites()) {
                    final org.cyclonedx.model.component.crypto.CipherSuite out = new org.cyclonedx.model.component.crypto.CipherSuite();
                    out.setName(s.name());
                    if (!s.algorithms().isEmpty()) {
                        out.setAlgorithms(s.algorithms().stream().map(x -> ref(x, refs)).toList());
                    }
                    if (!s.identifiers().isEmpty()) {
                        out.setIdentifiers(s.identifiers());
                    }
                    suites.add(out);
                }
                pp.setCipherSuites(suites);
            }
            p.setProtocolProperties(pp);
        }
        return p;
    }
}
