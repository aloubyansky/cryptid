package io.github.aloubyansky.cryptid.scan;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.ibm.mapper.model.INode;
import com.ibm.output.cyclondx.CBOMOutputFile;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.evidence.Occurrence;

/**
 * Collects the crypto assets of a JAR's findings into one CBOM, merging assets with the same
 * content: name and crypto properties.
 *
 * <p>sonar-cryptography's {@link CBOMOutputFile} identifies assets by name alone: a second asset
 * of the same name only adds its occurrences to the first, and its own properties are lost, e.g.
 * the {@code AES-128} key of a {@code SecretKeySpec} would take the functions of an {@code AES-128}
 * found in a signature elsewhere in the JAR. So each finding goes through an output of its own, and
 * the assets are merged here by {@link #contentKey}.
 */
public final class AssetCollector {

    private static final ObjectMapper CONTENT_JSON = new ObjectMapper()
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private static final Pattern ANY_UUID =
            Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    /** Random UUIDs some asset names embed, e.g. {@code key@<uuid>}. */
    private static final Pattern NAME_UUID =
            Pattern.compile("@[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    /** content key -> the asset kept for it, in the order first added */
    private final Map<String, Component> assets = new LinkedHashMap<>();
    /** occurrences already on the kept assets, by content key, location, line and offset */
    private final Set<String> occurrences = new HashSet<>();
    /** bom-ref of a depending asset -> its dependencies */
    private final Map<String, Dependency> dependencies = new LinkedHashMap<>();

    /**
     * Returns what identifies an asset apart from where it occurs: its name and crypto properties,
     * without the random UUIDs in names and references. Two assets are the same only if this is
     * equal, e.g. not keys of different sizes.
     *
     * @param asset the crypto asset
     * @return the content key
     */
    public static String contentKey(Component asset) {
        String props;
        try {
            props = asset.getCryptoProperties() == null ? "" : CONTENT_JSON.writeValueAsString(asset.getCryptoProperties());
        } catch (JsonProcessingException e) {
            props = String.valueOf(asset.getCryptoProperties());
        }
        final String name = asset.getName() == null ? "" : asset.getName();
        return NAME_UUID.matcher(name).replaceAll("") + "|" + ANY_UUID.matcher(props).replaceAll("");
    }

    /**
     * Returns the key identifying an occurrence of an asset.
     *
     * @param contentKey the asset's {@link #contentKey}
     * @param o one of its occurrences
     * @return the content key with location, line and offset
     */
    public static String occurrenceKey(String contentKey, Occurrence o) {
        return contentKey + "|" + o.getLocation() + "|" + o.getLine() + "|" + o.getOffset();
    }

    /**
     * Adds the assets of one finding.
     *
     * @param nodes the finding's model nodes
     */
    public void add(List<INode> nodes) {
        final CBOMOutputFile output = new CBOMOutputFile();
        output.add(nodes);
        final Bom part = output.getBom();
        // this part's bom-refs -> the bom-refs of the assets kept for them
        final Map<String, String> refs = new HashMap<>();
        for (Component asset : part.getComponents() == null ? List.<Component>of() : part.getComponents()) {
            final String key = contentKey(asset);
            final Component kept = assets.putIfAbsent(key, asset);
            final List<Occurrence> found = asset.getEvidence() == null || asset.getEvidence().getOccurrences() == null
                    ? List.of() : asset.getEvidence().getOccurrences();
            if (kept == null) {
                refs.put(asset.getBomRef(), asset.getBomRef());
                found.forEach(o -> occurrences.add(occurrenceKey(key, o)));
                continue;
            }
            refs.put(asset.getBomRef(), kept.getBomRef());
            for (Occurrence o : found) {
                if (occurrences.add(occurrenceKey(key, o))) {
                    if (kept.getEvidence() == null) {
                        kept.setEvidence(new Evidence());
                    }
                    final List<Occurrence> merged = kept.getEvidence().getOccurrences() == null
                            ? new ArrayList<>() : new ArrayList<>(kept.getEvidence().getOccurrences());
                    merged.add(o);
                    kept.getEvidence().setOccurrences(merged);
                }
            }
        }
        for (Dependency d : part.getDependencies() == null ? List.<Dependency>of() : part.getDependencies()) {
            final String from = refs.get(d.getRef());
            if (from == null || d.getDependencies() == null) {
                continue;
            }
            for (Dependency to : d.getDependencies()) {
                final String target = refs.get(to.getRef());
                if (target == null || target.equals(from)) {
                    continue;
                }
                final Dependency link = dependencies.computeIfAbsent(from, Dependency::new);
                if (link.getDependencies() == null || link.getDependencies().stream().noneMatch(x -> x.getRef().equals(target))) {
                    link.addDependency(new Dependency(target));
                }
            }
        }
    }

    /**
     * Returns the collected CBOM.
     *
     * @return the assets and their dependencies, with the metadata sonar-cryptography's output
     *     gives a CBOM
     */
    public Bom bom() {
        final Bom bom = new CBOMOutputFile().getBom();
        assets.values().forEach(bom::addComponent);
        dependencies.values().forEach(bom::addDependency);
        return bom;
    }
}
