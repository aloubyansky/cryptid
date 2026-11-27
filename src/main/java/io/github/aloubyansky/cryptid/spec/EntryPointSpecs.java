package io.github.aloubyansky.cryptid.spec;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Specifications of an application's entry points, the methods something outside the analyzed code
 * calls, and of the classes that are instantiated without a {@code new} the analysis can see, as
 * data: {@code src/main/resources/entry-point-specs.yaml}, and sources added to it.
 *
 * @param specVersion the format version
 * @param entryPoints the entry-point specs, in order: a method matching several is of the first
 * @param authentication the annotations stating whether calling an entry point needs
 *     authentication
 * @param instantiated what makes a class instantiated without a visible {@code new}
 */
public record EntryPointSpecs(int specVersion, List<EntryPointSpec> entryPoints, Authentication authentication,
        Instantiated instantiated) {

    /** The current format version. */
    public static final int VERSION = 1;

    /** The classpath resource holding the specs that ship. */
    public static final String RESOURCE = "/entry-point-specs.yaml";

    private static final YAMLMapper YAML = (YAMLMapper) new YAMLMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

    /** Normalizes missing parts to empty ones. */
    public EntryPointSpecs {
        entryPoints = entryPoints == null ? List.of() : List.copyOf(entryPoints);
        authentication = authentication == null ? new Authentication(null, null) : authentication;
        instantiated = instantiated == null ? new Instantiated(null, false, false) : instantiated;
    }

    /**
     * How a method is recognized as an entry point, and what it is then.
     *
     * @param id identifies the spec; a later source's spec of the same id replaces it
     * @param kind the entry points' kind, e.g. {@code http}
     * @param exposure {@code external} or {@code internal}
     * @param methodAnnotations a method carrying one of these
     * @param classAnnotations a public method of a class carrying one of these
     * @param parameterAnnotations a method with a parameter carrying one of these
     * @param overrides a method overriding one of these, {@code owner#name(parameter types)} with
     *     binary names, or {@code (...)} for any parameters
     * @param signature a method of this name and descriptor
     * @param mainClass with {@code signature}: only the class the artifact's manifest names as
     *     {@code Main-Class}, when it names one
     * @param inherited with {@code methodAnnotations}: also a method overriding an annotated method
     *     of a supertype
     * @param address how to build the entry point's address from annotation values
     */
    public record EntryPointSpec(String id, String kind, String exposure, List<String> methodAnnotations,
            List<String> classAnnotations, List<String> parameterAnnotations, List<String> overrides, Signature signature,
            boolean mainClass, boolean inherited, Address address) {

        /** Normalizes missing lists to empty ones. */
        public EntryPointSpec {
            methodAnnotations = methodAnnotations == null ? List.of() : List.copyOf(methodAnnotations);
            classAnnotations = classAnnotations == null ? List.of() : List.copyOf(classAnnotations);
            parameterAnnotations = parameterAnnotations == null ? List.of() : List.copyOf(parameterAnnotations);
            overrides = overrides == null ? List.of() : List.copyOf(overrides);
        }
    }

    /**
     * A method signature an entry point has.
     *
     * @param name the method's name
     * @param descriptor its descriptor
     * @param isStatic whether it must be static
     * @param isPublic whether it must be public
     */
    public record Signature(String name, String descriptor, @JsonProperty("static") boolean isStatic,
            @JsonProperty("public") boolean isPublic) {}

    /**
     * How an entry point's address is built.
     *
     * @param verb {@code annotation}: the HTTP method, from the matched annotation's name, e.g.
     *     {@code GET}, or from its {@code method} element
     * @param path annotations whose {@code value} or {@code path} gives a path: the class's, then
     *     the method's; the matched annotation's own {@code value} or {@code path} counts for the
     *     method
     * @param value an annotation whose {@code value} is the address, e.g. a channel name
     */
    public record Address(String verb, List<String> path, String value) {

        /** Normalizes a missing list to an empty one. */
        public Address {
            path = path == null ? List.of() : List.copyOf(path);
        }
    }

    /**
     * The annotations saying whether calling an entry point needs authentication. The method's
     * annotations decide, else its class's.
     *
     * @param required annotations meaning it does
     * @param notRequired annotations meaning it doesn't
     */
    public record Authentication(List<String> required, List<String> notRequired) {

        /** Normalizes missing lists to empty ones. */
        public Authentication {
            required = required == null ? List.of() : List.copyOf(required);
            notRequired = notRequired == null ? List.of() : List.copyOf(notRequired);
        }
    }

    /**
     * What makes a class instantiated without a {@code new} the analysis sees.
     *
     * @param beanAnnotations a class carrying one of these, in any artifact, e.g. a CDI bean
     * @param services whether the providers {@code META-INF/services} names are
     * @param entryPointClasses whether the class declaring an entry point is
     */
    public record Instantiated(List<String> beanAnnotations, boolean services, boolean entryPointClasses) {

        /** Normalizes a missing list to an empty one. */
        public Instantiated {
            beanAnnotations = beanAnnotations == null ? List.of() : List.copyOf(beanAnnotations);
        }
    }

    /**
     * Reads the specs that ship.
     *
     * @return the specs
     * @throws IOException if the resource is missing or can't be parsed
     */
    public static EntryPointSpecs load() throws IOException {
        try (InputStream in = EntryPointSpecs.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IOException("Missing resource " + RESOURCE);
            }
            return parse(in, RESOURCE);
        }
    }

    /**
     * Reads specs.
     *
     * @param in the YAML
     * @param name names the source in errors
     * @return the specs
     * @throws IOException if they can't be parsed or are of another format version
     */
    public static EntryPointSpecs parse(InputStream in, String name) throws IOException {
        final EntryPointSpecs specs = YAML.readValue(in, EntryPointSpecs.class);
        if (specs.specVersion() != VERSION) {
            throw new IOException(name + " has format version " + specs.specVersion() + ", expected " + VERSION);
        }
        return specs;
    }

    /**
     * Combines these specs with others: their entry-point specs replace those of the same id and
     * come after the others, and their annotations are added to these.
     *
     * @param other the specs to add
     * @return the combined specs
     */
    public EntryPointSpecs with(EntryPointSpecs other) {
        final Map<String, EntryPointSpec> byId = new LinkedHashMap<>();
        entryPoints.forEach(e -> byId.put(e.id(), e));
        other.entryPoints().forEach(e -> {
            byId.remove(e.id());
            byId.put(e.id(), e);
        });
        return new EntryPointSpecs(VERSION, new ArrayList<>(byId.values()),
                new Authentication(union(authentication.required(), other.authentication().required()),
                        union(authentication.notRequired(), other.authentication().notRequired())),
                new Instantiated(union(instantiated.beanAnnotations(), other.instantiated().beanAnnotations()),
                        instantiated.services() || other.instantiated().services(),
                        instantiated.entryPointClasses() || other.instantiated().entryPointClasses()));
    }

    /**
     * Every annotation type the specs name, for reading only those from class files.
     *
     * @return binary names
     */
    public Set<String> annotationTypes() {
        final Set<String> result = new LinkedHashSet<>();
        for (EntryPointSpec e : entryPoints) {
            result.addAll(e.methodAnnotations());
            result.addAll(e.classAnnotations());
            result.addAll(e.parameterAnnotations());
            if (e.address() != null) {
                result.addAll(e.address().path());
                if (e.address().value() != null) {
                    result.add(e.address().value());
                }
            }
        }
        result.addAll(authentication.required());
        result.addAll(authentication.notRequired());
        result.addAll(instantiated.beanAnnotations());
        return Set.copyOf(result);
    }

    private static List<String> union(List<String> a, List<String> b) {
        final Set<String> all = new LinkedHashSet<>(a);
        all.addAll(b);
        return List.copyOf(all);
    }
}
