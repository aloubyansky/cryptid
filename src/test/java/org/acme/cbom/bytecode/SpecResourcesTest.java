package org.acme.cbom.bytecode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.ArrayList;
import java.util.List;
import org.acme.cbom.spec.ApiSpecs;
import org.acme.cbom.spec.ApiSpecs.ApiSpec;
import org.acme.cbom.spec.ApiSpecs.Arg;
import org.acme.cbom.spec.ApiSpecs.Context;
import org.acme.cbom.spec.ApiSpecs.Role;
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
        for (ApiSpec spec : ApiSpecs.load().apis()) {
            contexts.add(spec.context());
            if (spec.action() != null) {
                final Object action = SpecFactories.create(spec.action());
                assertNotNull(action != null ? action : SpecFactories.lambdaAction(spec.action(), LOC), spec.api());
            }
            for (Arg arg : spec.args()) {
                if (arg.value() != null) {
                    assertNotNull(SpecFactories.create(arg.value()), spec.api() + " arg " + arg.index());
                }
                roles(arg.roles(), contexts);
            }
            roles(spec.nextRoles(), contexts);
        }
        for (Context c : contexts) {
            assertEquals(c, SpecExporter.context(SpecRule.context(c)));
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
