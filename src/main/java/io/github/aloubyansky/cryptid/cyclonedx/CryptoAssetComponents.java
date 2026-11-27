package io.github.aloubyansky.cryptid.cyclonedx;

import io.github.aloubyansky.cryptid.AssetOccurrence;
import io.github.aloubyansky.cryptid.CipherSuite;
import io.github.aloubyansky.cryptid.CodeLocation;
import io.github.aloubyansky.cryptid.CryptoAsset;
import io.github.aloubyansky.cryptid.CryptoAssetProperties;
import io.github.aloubyansky.cryptid.EntryPoint;
import io.github.aloubyansky.cryptid.MethodId;
import io.github.aloubyansky.cryptid.detection.ArtifactPaths;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.Property;
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
import org.cyclonedx.model.component.evidence.Callstack;
import org.cyclonedx.model.component.evidence.Frame;
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
            final List<Property> reached = new ArrayList<>();
            AssetOccurrence shortest = null;
            boolean anyKnown = false;
            for (int i = 0; i < a.occurrences().size(); i++) {
                final AssetOccurrence o = a.occurrences().get(i);
                final Occurrence out = new Occurrence();
                final String occurrenceRef = ref + "/occurrence/" + i;
                out.setBomRef(occurrenceRef);
                anyKnown |= o.reachability() != AssetOccurrence.Reachability.UNKNOWN;
                if (o.reachability() == AssetOccurrence.Reachability.REACHED) {
                    reached.add(new Property(REACHED, occurrenceRef + " " + o.reachedBy().size() + " " + firstEntryPoint(o)));
                    // the call stack of the shortest path from an entry point; one only the runtime
                    // reaches, e.g. a service provider's constructor, if there's no other
                    if (shortest == null || better(o, shortest)) {
                        shortest = o;
                    }
                }
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
            if (shortest != null) {
                evidence.setCallstack(callstack(shortest.path()));
            }
            c.setEvidence(evidence);
            c.addProperty(new Property(REACHABILITY, !anyKnown ? "unknown" : reached.isEmpty() ? "not-reached" : "reached"));
            reached.forEach(c::addProperty);
        }
        c.setCryptoProperties(properties(a.properties(), refs));
        return c;
    }

    /** The asset property saying whether any of its occurrences is reached: reached, not-reached or unknown. */
    static final String REACHABILITY = "cryptid:reachability";

    /**
     * The asset property of a reached occurrence: its bom-ref, the number of entry points reaching
     * it, and the kind and address, or method, of the one it was first reached from.
     */
    static final String REACHED = "cryptid:reached";

    /** The entry point an occurrence was first reached from, as {@code kind address-or-method}, or {@code runtime}. */
    private static String firstEntryPoint(AssetOccurrence o) {
        final MethodId start = o.path().isEmpty() ? null : o.path().get(0);
        EntryPoint first = null;
        for (EntryPoint e : o.reachedBy()) {
            if (e.method().equals(start)) {
                first = e;
                break;
            }
        }
        if (first == null && !o.reachedBy().isEmpty()) {
            first = o.reachedBy().get(0);
        }
        if (first == null) {
            return "runtime";
        }
        return first.kind() + " " + first.address().orElse(first.method().toString());
    }

    /** Whether an occurrence's path makes a better call stack than another's: from an entry point, then shorter. */
    private static boolean better(AssetOccurrence o, AssetOccurrence than) {
        final boolean fromEntry = !o.reachedBy().isEmpty();
        final boolean thanFromEntry = !than.reachedBy().isEmpty();
        if (fromEntry != thanFromEntry) {
            return fromEntry;
        }
        return o.path().size() < than.path().size();
    }

    /** A call stack of a path, innermost first, as a stack trace lists frames. */
    private static Callstack callstack(List<MethodId> path) {
        final List<Frame> frames = new ArrayList<>(path.size());
        for (int i = path.size() - 1; i >= 0; i--) {
            final MethodId m = path.get(i);
            final Frame f = new Frame();
            final int dot = m.className().lastIndexOf('.');
            if (dot > 0) {
                f.setPackageFrame(m.className().substring(0, dot));
            }
            f.setModule(m.className());
            f.setFunction(m.name());
            final List<String> parameters = MethodTypeDesc.ofDescriptor(m.descriptor()).parameterList().stream()
                    .map(ClassDesc::displayName).toList();
            if (!parameters.isEmpty()) {
                f.setParameters(parameters);
            }
            frames.add(f);
        }
        final Callstack callstack = new Callstack();
        callstack.setFrames(frames);
        return callstack;
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
