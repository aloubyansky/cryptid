package io.github.aloubyansky.cryptid.reference;

import com.ibm.mapper.model.IAsset;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Property;
import com.ibm.mapper.utils.DetectionLocation;
import io.github.aloubyansky.cryptid.bytecode.Analyzer;
import io.github.aloubyansky.cryptid.bytecode.CallSite;
import io.github.aloubyansky.cryptid.bytecode.Types;
import io.github.aloubyansky.cryptid.spec.CryptoApiMatcher;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.ApiSpec;
import java.util.List;
import java.util.Set;

/**
 * Where the specs deliberately differ from sonar-cryptography's rules: the call sites of APIs
 * whose spec has a {@link ApiSpec#correction()}. The equivalence tests compare the spec-based
 * pipeline with the rules', and a difference located at such a call site is the correction's
 * effect, not a regression: it is reported, not failed on.
 */
public final class SpecCorrections {

    private SpecCorrections() {}

    /**
     * Adds the call sites of corrected APIs among methods' calls.
     *
     * @param methods the analyzed methods
     * @param matcher the spec matcher
     * @param types the class hierarchy
     * @param sites the call sites found so far, as {@code signature@line}; updated
     */
    public static void collect(List<Analyzer.MethodResult> methods, CryptoApiMatcher matcher, Types types, Set<String> sites) {
        for (Analyzer.MethodResult m : methods) {
            for (CallSite cs : m.calls()) {
                if (matcher.match(cs, types).stream().anyMatch(s -> s.correction() != null)) {
                    sites.add(site(cs.signature(), cs.line()));
                }
            }
        }
    }

    /**
     * A call site's key, as {@link #collect} records it.
     *
     * @param signature the called method in sonar-java's format
     * @param line the call's line
     * @return {@code signature@line}
     */
    public static String site(String signature, int line) {
        return signature + "@" + line;
    }

    /**
     * Whether a node, or a node below it, was translated from a value of a corrected API.
     *
     * @param node the node
     * @param sites the call sites of corrected APIs, from {@link #collect}
     * @return {@code true} if the node reflects a correction
     */
    public static boolean reflects(INode node, Set<String> sites) {
        final DetectionLocation location = node instanceof IAsset a ? a.getDetectionContext()
                : node instanceof Property p ? p.getDetectionContext() : null;
        if (location != null && location.lineNumber() != null && !location.keywords().isEmpty()
                && sites.contains(site(location.keywords().get(0), location.lineNumber()))) {
            return true;
        }
        return node.getChildren().values().stream().anyMatch(c -> reflects(c, sites));
    }
}
