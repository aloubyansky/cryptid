package io.github.aloubyansky.cryptid.detection;

import io.github.aloubyansky.cryptid.ArtifactCoordinates;
import io.github.aloubyansky.cryptid.CodeLocation;
import io.github.aloubyansky.cryptid.MethodId;
import io.github.aloubyansky.cryptid.bytecode.Callers;
import io.github.aloubyansky.cryptid.bytecode.CallSite;

/** Code locations of call sites, for the result model. */
public final class CodeLocations {

    private CodeLocations() {}

    /**
     * The code location of a call site.
     *
     * @param artifact the artifact containing it
     * @param cs the call site
     * @return its location
     */
    public static CodeLocation of(ArtifactCoordinates artifact, CallSite cs) {
        return new CodeLocation(artifact, cs.sourceFile(), method(cs.method()), cs.line(),
                new MethodId(cs.owner().replace('/', '.'), cs.name(), cs.descriptor()));
    }

    /**
     * The code location of a call into an analyzed class, or {@code null} if the index doesn't
     * know its artifact.
     *
     * @param site the call
     * @return its location, or {@code null}
     */
    public static CodeLocation of(Callers.Site site) {
        return site.artifact() == null ? null
                : new CodeLocation(site.artifact(), site.sourceFile(), method(site.callerMethod()), site.line(),
                        signature(site.signature()));
    }

    /**
     * Parses a method key of the analysis.
     *
     * @param key {@code owner.name+descriptor} with the internal class name
     * @return the method
     */
    public static MethodId method(String key) {
        final int paren = key.indexOf('(');
        final int dot = key.lastIndexOf('.', paren);
        return new MethodId(key.substring(0, dot).replace('/', '.'), key.substring(dot + 1, paren), key.substring(paren));
    }

    /**
     * Parses a method in sonar-java's signature format.
     *
     * @param signature {@code className#name+descriptor} with the binary class name
     * @return the method
     */
    public static MethodId signature(String signature) {
        final int hash = signature.indexOf('#');
        final int paren = signature.indexOf('(', hash);
        return new MethodId(signature.substring(0, hash), signature.substring(hash + 1, paren), signature.substring(paren));
    }
}
