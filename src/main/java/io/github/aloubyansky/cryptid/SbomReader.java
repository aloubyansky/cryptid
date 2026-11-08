package io.github.aloubyansky.cryptid;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import jakarta.enterprise.context.ApplicationScoped;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.parsers.BomParserFactory;
import org.jboss.logging.Logger;

/** Reads a CycloneDX SBOM (JSON or XML) and extracts Maven components from it. */
@ApplicationScoped
public class SbomReader {

    private static final Logger log = Logger.getLogger(SbomReader.class);

    /**
     * Parses a CycloneDX SBOM. The format, JSON or XML, is detected from the file content.
     *
     * @param sbomFile the SBOM file
     * @return the parsed SBOM
     * @throws IllegalArgumentException if the file can't be parsed as a CycloneDX SBOM
     */
    public Bom read(Path sbomFile) {
        try {
            return BomParserFactory.createParser(sbomFile.toFile()).parse(sbomFile.toFile());
        } catch (ParseException e) {
            throw new IllegalArgumentException("Failed to parse SBOM " + sbomFile, e);
        }
    }

    /**
     * Collects the Maven components of an SBOM: the metadata component, the top-level components
     * and their nested components. Components without a {@code pkg:maven} purl, and {@code pom}
     * type components, are ignored.
     *
     * <p>Components are de-duplicated by {@link MavenComponent#bomRef()}, not by coordinates: an
     * SBOM may list the same coordinates several times under different bom-refs, e.g. for copies
     * of an artifact at different locations of a distribution, and each of them must be linked to
     * its crypto assets. Components with equal coordinates share their sources JAR, so they are
     * still scanned only once.
     *
     * @param bom the SBOM
     * @return Maven components in encounter order, one per bom-ref
     */
    public List<MavenComponent> mavenComponents(Bom bom) {
        final Map<String, MavenComponent> result = new LinkedHashMap<>();
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            collect(bom.getMetadata().getComponent(), result);
        }
        if (bom.getComponents() != null) {
            for (Component c : bom.getComponents()) {
                collect(c, result);
            }
        }
        return new ArrayList<>(result.values());
    }

    /**
     * Computes the transitive dependency closure of every component in an SBOM's dependency
     * graph. Cycles in the graph are tolerated.
     *
     * @param bom the SBOM
     * @return for each bom-ref with an entry in the SBOM's {@code dependencies}, the bom-refs of
     *     all its direct and transitive dependencies, which may be empty; bom-refs missing from the
     *     graph have no key in the map, so callers can tell "no dependencies" from "unknown"
     */
    public Map<String, Set<String>> dependencyClosure(Bom bom) {
        final Map<String, Set<String>> direct = new HashMap<>();
        if (bom.getDependencies() != null) {
            for (Dependency d : bom.getDependencies()) {
                final Set<String> deps = direct.computeIfAbsent(d.getRef(), k -> new HashSet<>());
                if (d.getDependencies() != null) {
                    d.getDependencies().forEach(child -> deps.add(child.getRef()));
                }
            }
        }
        final Map<String, Set<String>> closure = new HashMap<>(direct.size());
        for (String ref : direct.keySet()) {
            final Set<String> visited = new LinkedHashSet<>();
            final Deque<String> todo = new ArrayDeque<>(direct.get(ref));
            while (!todo.isEmpty()) {
                final String next = todo.pop();
                if (visited.add(next)) {
                    todo.addAll(direct.getOrDefault(next, Set.of()));
                }
            }
            closure.put(ref, visited);
        }
        return closure;
    }

    /**
     * Adds a component, if it's a Maven component, and its nested components to the result,
     * keeping the first occurrence of each bom-ref.
     *
     * @param c the component to visit
     * @param result Maven components collected so far, by bom-ref
     */
    private static void collect(Component c, Map<String, MavenComponent> result) {
        final MavenComponent mc = toMavenComponent(c);
        if (mc != null) {
            result.putIfAbsent(mc.bomRef(), mc);
        }
        if (c.getComponents() != null) {
            for (Component child : c.getComponents()) {
                collect(child, result);
            }
        }
    }

    /**
     * Maps an SBOM component to Maven coordinates using its purl. The {@code classifier} and
     * {@code type} purl qualifiers are honored.
     *
     * @param c the SBOM component
     * @return the Maven component, or {@code null} if the component has no purl, a malformed purl
     *     (logged as a warning), a non-Maven purl, a purl without namespace or version, or the
     *     {@code pom} type, which has no Java sources
     */
    static MavenComponent toMavenComponent(Component c) {
        if (c.getPurl() == null) {
            return null;
        }
        final PackageURL purl;
        try {
            purl = new PackageURL(c.getPurl());
        } catch (MalformedPackageURLException e) {
            log.warnf("Skipping component with malformed purl %s", c.getPurl());
            return null;
        }
        if (!PackageURL.StandardTypes.MAVEN.equals(purl.getType())
                || purl.getNamespace() == null
                || purl.getVersion() == null) {
            return null;
        }
        final Map<String, String> qualifiers = purl.getQualifiers();
        final String type = qualifiers == null ? null : qualifiers.get("type");
        // pom/bom-only artifacts have no Java sources
        if ("pom".equals(type)) {
            return null;
        }
        return new MavenComponent(
                purl.getNamespace(),
                purl.getName(),
                qualifiers == null ? null : qualifiers.get("classifier"),
                type,
                purl.getVersion(),
                c);
    }
}
