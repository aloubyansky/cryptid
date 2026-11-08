package io.github.aloubyansky.cryptid;

import java.nio.file.Path;
import java.util.Set;
import org.cyclonedx.model.Component;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;

/**
 * A Maven component found in the input SBOM.
 *
 * <p>Components are identified by their bom-ref. Components with equal coordinates, e.g. copies of
 * an artifact at different locations of a distribution, share their binary artifact, which is
 * analyzed once; see {@link #artifactKey()}.
 *
 * @param groupId Maven groupId
 * @param artifactId Maven artifactId
 * @param classifier Maven classifier, empty if none
 * @param type Maven type (e.g. {@code jar}, {@code test-jar}, {@code bundle})
 * @param version Maven version
 * @param sbomComponent the original SBOM component
 */
public record MavenComponent(
        String groupId,
        String artifactId,
        String classifier,
        String type,
        String version,
        Component sbomComponent) {

    /** Types whose artifact file is a JAR although the type isn't {@code jar}. */
    private static final Set<String> JAR_TYPES =
            Set.of("jar", "test-jar", "bundle", "maven-plugin", "ejb", "ejb-client", "java-source", "javadoc");

    /**
     * Normalizes the coordinates: a {@code null} classifier becomes empty, and a {@code null} or
     * empty type becomes {@code jar}.
     */
    public MavenComponent {
        classifier = classifier == null ? "" : classifier;
        type = type == null || type.isEmpty() ? "jar" : type;
    }

    /**
     * Returns the complete coordinates of this component.
     *
     * @return {@code groupId:artifactId:classifier:type:version}, with an empty classifier if
     *     there is none, e.g. {@code io.netty:netty-transport-native-epoll:linux-x86_64:jar:4.1.115.Final}
     */
    public String key() {
        return groupId + ":" + artifactId + ":" + classifier + ":" + type + ":" + version;
    }

    /**
     * Returns the reference used to link this component to its crypto assets in the CBOM.
     *
     * @return the bom-ref of the original SBOM component, or its purl if it has no bom-ref
     */
    public String bomRef() {
        return sbomComponent.getBomRef() != null ? sbomComponent.getBomRef() : sbomComponent.getPurl();
    }

    /**
     * Returns the file extension of this component's artifact. Types such as {@code test-jar},
     * {@code bundle} or {@code maven-plugin} are packaged as JARs; other types are assumed to equal
     * their extension.
     *
     * @return the artifact file extension, e.g. {@code jar}
     */
    public String extension() {
        return JAR_TYPES.contains(type) ? "jar" : type;
    }

    /**
     * Returns the classifier of the binary artifact. A {@code test-jar} without a classifier gets
     * the {@code tests} classifier, following Maven's convention.
     *
     * @return the artifact classifier, empty if none
     */
    public String artifactClassifier() {
        return classifier.isEmpty() && "test-jar".equals(type) ? "tests" : classifier;
    }

    /**
     * Returns the binary artifact of this component, which is analyzed and used for type
     * resolution when analyzing the components depending on it.
     *
     * @return the binary artifact, including the classifier
     */
    public Artifact binaryArtifact() {
        return new DefaultArtifact(groupId, artifactId, artifactClassifier(), extension(), version);
    }

    /**
     * Returns the coordinates of the binary artifact. Components with equal artifact keys share
     * their binary, which is analyzed once.
     *
     * @return {@code groupId:artifactId:classifier:extension:version}
     */
    public String artifactKey() {
        return groupId + ":" + artifactId + ":" + artifactClassifier() + ":" + extension() + ":" + version;
    }

    /**
     * Returns the relative path identifying the binary artifact. It is the prefix of occurrence
     * locations in the CBOM, so that findings can be traced back to the artifact and its sources,
     * and names the artifact's CBOM in the work directory.
     *
     * @return {@code groupId/artifactId/version}, followed by {@code /classifier} if the artifact
     *     has one, e.g. {@code org.bouncycastle/bcprov-jdk18on/1.78.1}
     */
    public String artifactPath() {
        final String c = artifactClassifier();
        return groupId + "/" + artifactId + "/" + version + (c.isEmpty() ? "" : "/" + c);
    }

    /**
     * Returns the file holding the CBOM produced by analyzing this component's binary artifact.
     * Its existence means the artifact was analyzed successfully.
     *
     * @param workDir the work directory
     * @return {@code workDir/cbom/}{@link #artifactPath()}{@code .json}
     */
    public Path cbomFile(Path workDir) {
        return workDir.resolve("cbom").resolve(artifactPath() + ".json");
    }
}
