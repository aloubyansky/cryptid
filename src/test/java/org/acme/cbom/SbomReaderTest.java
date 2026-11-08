package org.acme.cbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.junit.jupiter.api.Test;

class SbomReaderTest {

    private final SbomReader reader = new SbomReader();

    @Test
    void collectsMavenComponentsOnly() {
        final Bom bom = reader.read(Path.of("src/test/resources/sample-sbom.json"));
        final List<String> keys = reader.mavenComponents(bom).stream().map(MavenComponent::key).toList();
        assertEquals(
                List.of(
                        "org.acme:sample-app::jar:1.0.0",
                        "org.bouncycastle:bcprov-jdk18on::jar:1.78.1",
                        "commons-codec:commons-codec::jar:1.17.1",
                        "io.netty:netty-transport-native-epoll::jar:4.1.115.Final",
                        "io.netty:netty-transport-native-epoll:linux-x86_64:jar:4.1.115.Final"),
                keys);
    }

    @Test
    void sameCoordinatesWithDifferentBomRefsAreKept() {
        final Bom bom = new Bom();
        final Component root = component("root", "pkg:maven/org.acme/app@1.0?type=jar");
        final org.cyclonedx.model.Metadata md = new org.cyclonedx.model.Metadata();
        md.setComponent(root);
        bom.setMetadata(md);
        bom.addComponent(component("pkg:maven/org.apache.httpcomponents/httpclient@4.5.14?type=jar", "pkg:maven/org.apache.httpcomponents/httpclient@4.5.14?type=jar"));
        bom.addComponent(component("pkg:maven/org.apache.httpcomponents/httpclient@4.5.14?type=jar#2", "pkg:maven/org.apache.httpcomponents/httpclient@4.5.14?type=jar"));
        // the root listed again among the components
        bom.addComponent(component("root", "pkg:maven/org.acme/app@1.0?type=jar"));
        final List<MavenComponent> mcs = reader.mavenComponents(bom);
        assertEquals(
                List.of(
                        "root",
                        "pkg:maven/org.apache.httpcomponents/httpclient@4.5.14?type=jar",
                        "pkg:maven/org.apache.httpcomponents/httpclient@4.5.14?type=jar#2"),
                mcs.stream().map(MavenComponent::bomRef).toList());
        assertEquals(mcs.get(1).artifactKey(), mcs.get(2).artifactKey());
    }

    private static Component component(String bomRef, String purl) {
        final Component c = new Component();
        c.setBomRef(bomRef);
        c.setPurl(purl);
        return c;
    }

    @Test
    void classifiersAreSeparateArtifacts() {
        final MavenComponent plain = component("pkg:maven/io.netty/netty-transport-native-epoll@4.1.115.Final?type=jar");
        final MavenComponent native64 =
                component("pkg:maven/io.netty/netty-transport-native-epoll@4.1.115.Final?classifier=linux-x86_64&type=jar");
        assertNotEquals(plain.artifactKey(), native64.artifactKey());
        assertEquals("io.netty:netty-transport-native-epoll::jar:4.1.115.Final", plain.artifactKey());
        assertEquals("io.netty/netty-transport-native-epoll/4.1.115.Final", plain.artifactPath());
        assertEquals("io.netty/netty-transport-native-epoll/4.1.115.Final/linux-x86_64", native64.artifactPath());
        assertEquals("linux-x86_64", native64.binaryArtifact().getClassifier());
    }

    @Test
    void testJar() {
        final MavenComponent c = component("pkg:maven/org.acme/lib@1.0?type=test-jar");
        assertEquals("org.acme:lib::test-jar:1.0", c.key());
        assertEquals("tests", c.binaryArtifact().getClassifier());
        assertEquals("jar", c.binaryArtifact().getExtension());
        assertEquals("org.acme:lib:tests:jar:1.0", c.artifactKey());
        assertEquals("org.acme/lib/1.0/tests", c.artifactPath());
    }

    @Test
    void bundleTypeUsesJarExtension() {
        final MavenComponent c = component("pkg:maven/org.acme/lib@1.0?type=bundle");
        assertEquals("jar", c.binaryArtifact().getExtension());
        assertEquals("org.acme:lib::jar:1.0", c.artifactKey());
    }

    @Test
    void pomTypeIsSkipped() {
        final Component c = new Component();
        c.setPurl("pkg:maven/org.acme/bom@1.0?type=pom");
        assertNull(SbomReader.toMavenComponent(c));
    }

    private static MavenComponent component(String purl) {
        final Component c = new Component();
        c.setPurl(purl);
        return SbomReader.toMavenComponent(c);
    }

    @Test
    void transitiveClosure() {
        final Bom bom = new Bom();
        bom.addDependency(dep("a", "b"));
        bom.addDependency(dep("b", "c"));
        bom.addDependency(dep("c", "a")); // cycle
        bom.addDependency(dep("d"));
        final Map<String, Set<String>> closure = reader.dependencyClosure(bom);
        assertEquals(Set.of("a", "b", "c"), closure.get("a"));
        assertEquals(Set.of(), closure.get("d"));
        assertEquals(null, closure.get("unknown"));
    }

    private static Dependency dep(String ref, String... deps) {
        final Dependency d = new Dependency(ref);
        for (String child : deps) {
            d.addDependency(new Dependency(child));
        }
        return d;
    }
}
