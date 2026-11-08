package org.acme.cbom;

import io.quarkus.bootstrap.resolver.maven.BootstrapMavenException;
import io.quarkus.bootstrap.resolver.maven.MavenArtifactResolver;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.nio.file.Path;
import java.util.Optional;
import org.eclipse.aether.artifact.Artifact;
import org.jboss.logging.Logger;

/** Resolves Maven artifacts using the resolver provided by the quarkus-maven-resolver extension. */
@ApplicationScoped
public class ArtifactResolver {

    private static final Logger log = Logger.getLogger(ArtifactResolver.class);

    @Inject MavenArtifactResolver resolver;

    /**
     * Resolves an artifact from the local repository, or downloads it from the remote
     * repositories configured in the Maven settings and {@code quarkus.maven-resolver.*}. This
     * method is safe to call from multiple threads.
     *
     * @param artifact the artifact to resolve
     * @return the path to the artifact file, or empty if it couldn't be resolved; the cause is
     *     logged at debug level
     */
    public Optional<Path> resolve(Artifact artifact) {
        try {
            return Optional.of(resolver.resolve(artifact).getArtifact().getFile().toPath());
        } catch (BootstrapMavenException e) {
            log.debugf(e, "Failed to resolve %s", artifact);
            return Optional.empty();
        }
    }
}
