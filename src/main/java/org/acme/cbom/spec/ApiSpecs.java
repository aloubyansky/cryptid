package org.acme.cbom.spec;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Specifications of cryptographic APIs: for each API method, what a call contributes to the crypto
 * model. Detection records facts about calls to these APIs and the objects they create or
 * configure; model building applies the specs to those facts.
 *
 * <p>The initial specs are exported from sonar-cryptography's Java detection rules (see {@code
 * docs/detection-redesign.md}); the file is {@code src/main/resources/crypto-api-specs.yaml}.
 *
 * @param specVersion the format version
 * @param source where the specs come from
 * @param apis one entry per API method, sorted by {@link ApiSpec#api()}
 */
@JsonPropertyOrder({"specVersion", "source", "apis"})
public record ApiSpecs(int specVersion, Source source, List<ApiSpec> apis) {

    /** The current format version. */
    public static final int VERSION = 1;

    /** In an API method's parameter list, {@code owner#name(...)}: any parameter types. */
    public static final String ANY_PARAMETERS = "...";

    /** The classpath resource holding the specs. */
    public static final String RESOURCE = "/crypto-api-specs.yaml";

    /**
     * Reads the specs shipped with the tool.
     *
     * @return the specs
     * @throws IOException if the resource is missing or can't be parsed
     */
    public static ApiSpecs load() throws IOException {
        try (InputStream in = ApiSpecs.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IOException("Missing resource " + RESOURCE);
            }
            final ApiSpecs specs = new YAMLMapper().readValue(in, ApiSpecs.class);
            if (specs.specVersion() != VERSION) {
                throw new IOException(RESOURCE + " has format version " + specs.specVersion() + ", expected " + VERSION);
            }
            return specs;
        }
    }

    /**
     * Where specs come from.
     *
     * @param name the project the specs are derived from
     * @param version its version
     * @param license its license
     */
    @JsonPropertyOrder({"name", "version", "license"})
    public record Source(String name, String version, String license) {}

    /**
     * What calls to one API method contribute.
     *
     * @param api the method: {@code owner#name(parameter types)}, with binary class names, or
     *     {@code owner#name(...)} for a method with any parameter types
     * @param subtypes whether calls on subtypes of the owner match too
     * @param library the API family, e.g. {@code Jca}, {@code Bc}, {@code SSL}
     * @param context the kind of crypto object, and the default role of what the call contributes
     * @param root whether a call reports a finding on its own; otherwise it only contributes to an
     *     object reported through another API
     * @param action what the call itself states, e.g. the algorithm a constructor implements
     * @param args what the arguments contribute, by position
     * @param next API methods called on the object this call creates that contribute to it, in
     *     the order sonar-cryptography's rules list them, which its translation depends on
     * @param nextRoles roles of those calls that differ from their own context
     */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @JsonPropertyOrder({"api", "subtypes", "library", "context", "root", "action", "args", "next", "nextRoles"})
    public record ApiSpec(
            String api,
            boolean subtypes,
            String library,
            Context context,
            boolean root,
            Factory action,
            List<Arg> args,
            List<String> next,
            List<Role> nextRoles) {

        /** Normalizes missing lists, which the YAML leaves out when empty, to empty lists. */
        public ApiSpec {
            args = args == null ? List.of() : List.copyOf(args);
            next = next == null ? List.of() : List.copyOf(next);
            nextRoles = nextRoles == null ? List.of() : List.copyOf(nextRoles);
        }
    }

    /**
     * A crypto object kind with an optional sub-kind and properties, as sonar-cryptography's
     * detection contexts.
     *
     * @param type the context type, e.g. {@code CipherContext}
     * @param kind the sub-kind, e.g. {@code EC} for a key context
     * @param properties further properties, e.g. {@code kind: MGF1}
     */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @JsonPropertyOrder({"type", "kind", "properties"})
    public record Context(String type, String kind, Map<String, String> properties) {

        /** Normalizes missing properties to an empty map; keeps keys sorted. */
        public Context {
            properties = sorted(properties);
        }
    }

    /**
     * A sonar-cryptography value or action factory with its configuration.
     *
     * @param factory the factory class's simple name, or {@code lambda} for a rule-specific function
     * @param config the factory's configuration fields, e.g. {@code value: AESEngine}
     * @param result for a rule-specific function, what it produces, e.g. {@code Mode GCM}
     */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @JsonPropertyOrder({"factory", "config", "result"})
    public record Factory(String factory, Map<String, String> config, String result) {

        /** Normalizes missing configuration to an empty map; keeps keys sorted. */
        public Factory {
            config = sorted(config);
        }
    }

    /**
     * What an argument contributes.
     *
     * @param index the parameter position
     * @param type the parameter type
     * @param value the factory turning the argument's constant values into a property, if any
     * @param movedUnder for a value, the parameter position of the child it belongs to instead
     * @param link whether the argument is an object to link, as created by other API methods
     * @param roles roles of linked objects that differ from their own context
     */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    @JsonPropertyOrder({"index", "type", "value", "movedUnder", "link", "roles"})
    public record Arg(int index, String type, Factory value, Integer movedUnder,
            @JsonInclude(JsonInclude.Include.NON_DEFAULT) boolean link, List<Role> roles) {

        /** Normalizes missing roles to an empty list. */
        public Arg {
            roles = roles == null ? List.of() : List.copyOf(roles);
        }
    }

    /**
     * The role objects linked through an argument or next call play, where it differs from the
     * context of the API method that created them, e.g. a digest used as MGF1.
     *
     * @param when the parent's own context this role applies under, or {@code null} for always:
     *     some wrappers pass their role on, e.g. an encoding used by a signer makes its engine a
     *     signature engine
     * @param api the API method creating the linked object this role is for, or {@code null} for
     *     any linked object
     * @param context the linked object's context in this role
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonPropertyOrder({"when", "api", "context"})
    public record Role(Context when, String api, Context context) {}

    /** An unmodifiable copy iterating in key order, so the YAML is the same in every run. */
    private static Map<String, String> sorted(Map<String, String> map) {
        return map == null || map.isEmpty() ? Map.of() : Collections.unmodifiableMap(new TreeMap<>(map));
    }
}
