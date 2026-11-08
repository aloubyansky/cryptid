package io.github.aloubyansky.cryptid.detection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import io.github.aloubyansky.cryptid.reference.RuleSpecExporter;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.ApiSpec;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Arg;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Context;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs.Role;
import io.github.aloubyansky.cryptid.spec.CryptoApiSpecs;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Checks that everything the specs name can be created at runtime: every value and action
 * factory, every rule-specific action, and every context, including roles, each of which converts
 * back to exactly its spec. Detection only looks these classes up by name, so this also guards
 * the explicit class lists jar tree-shaking relies on.
 */
class SpecResourcesTest {

    private static final Loc LOC = new Loc("X.java", 1, "sig", "m");

    @Test
    void everythingTheSpecsNameCanBeCreated() throws Exception {
        final List<Context> contexts = new ArrayList<>();
        for (ApiSpec spec : CryptoApiSpecs.load().apis()) {
            contexts.add(spec.context());
            if (spec.action() != null) {
                final Object action = ValueFactories.create(spec.action());
                assertNotNull(action != null ? action : ValueFactories.lambdaAction(spec.action(), LOC), spec.api());
            }
            for (Arg arg : spec.args()) {
                if (arg.value() != null) {
                    assertNotNull(ValueFactories.create(arg.value()), spec.api() + " arg " + arg.index());
                }
                roles(arg.roles(), contexts);
            }
            roles(spec.nextRoles(), contexts);
        }
        for (Context c : contexts) {
            assertEquals(c, RuleSpecExporter.context(CryptoContexts.context(c)));
        }
    }

    private static void roles(List<Role> roles, List<Context> contexts) {
        for (Role r : roles) {
            contexts.add(r.context());
            if (r.when() != null) {
                contexts.add(r.when());
            }
        }
    }
}
