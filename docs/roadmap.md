# Roadmap

The single list of what's next, in order, written 2026-11-26. It draws on the [foundation review](foundation.md), the [design review](design-review.md), the [detection redesign](detection-redesign.md), the [reachability design](reachability-design.md), the [coverage gaps](coverage-gaps.md) and [certificates](certificates.md). Those stay as design records, with their reasoning and measurements. Status is kept here.

Each step is checked the usual way: `FixtureConformanceTest`, `PipelineEquivalenceTest`, `ReproducibilityIT`, `SampleSbomIT`, `KeycloakEndToEndIT`, and a per-occurrence comparison of the Keycloak 26.8.2 CBOM, with each difference reviewed.

## Done

- **Design review**: reproducible results (F1), the metadata version (F2), analyzing once (F3), object flow across methods (F7). Of F6, `CryptoCallGraph` is removed and `com.ibm:rules` is gone.
- **Detection redesign**: steps 1 to 4 and 6. Specs as data, hand-maintained since 2026-11-09. The object graph within and across methods. Our own detection tree and model builder. No SonarSource class and no rule engine at runtime.
- **Coverage gaps fixed**: constants returned by methods, assets merged by content, XML encryption, Bouncy Castle's content signers and JCA names, Argon2, fields set from constructor parameters.
- **Reachability step 1**: the call graph across all JARs (`CallGraph`, `Hierarchy`), method references to crypto APIs detected, dispatch to the most specific default method.
- **Decided non-goals**: certificates (2026-11-10); deployment and runtime scanning.

## Next

### 1. Housekeeping before more measurements

These are small and independent. Each one makes the comparisons in later steps more reliable.

1. ~~**Work directory cache keyed by cryptid's build and the SBOM's JARs.**~~ Done 2026-11-26: per-artifact CBOMs are kept under `cbom/<key>/`, a digest of cryptid's version, build time and specs, the `--classpath` mode and every resolved JAR (`CacheKey`).
2. ~~**JDK-only supertypes (F4).**~~ Done 2026-11-26: scanning reads classes outside the JARs from `jrt:/` only (`Types.jdk`). Keycloak's CBOM is unchanged.
3. **Order-independent attachment (redesign 3b-2).** A detection without nodes of its own takes the first child with nodes. Choose by kind instead, and review each difference.
4. **F6 leftovers.** Stop attaching empty child events where no call matches.

### 2. Foundation: result model and analysis API

The [foundation review](foundation.md) found that the results lack a model of their own, the analysis lacks an API, there are two class hierarchies, and phase A interprets the whole program to answer a few questions. The steps below fix that before reachability is built on today's shapes. See its *Order of work*.

1. ~~**Result model and in-memory assembly** (design review F5).~~ Done 2026-11-27; see [foundation.md](foundation.md#phase-1-api-decided-2026-11-26) for the API and the Keycloak figures.
   - `CryptoInventory`, `CryptoAsset`, `AssetOccurrence`, `CodeLocation` and `MethodId`, with properties of our own.
   - Assets merged by content across all artifacts.
   - CycloneDX written from the inventory, with the enclosing method as each occurrence's `symbol`.
   - No per-artifact JSON round trip, and no UUID and prefix heuristics.

   The set of asset contents, locations and lines stays the same on Keycloak.
2. ~~**Analysis API.**~~ Done 2026-11-27: `Cryptid`, `InputArtifact` and `AnalysisOptions`, with `CryptoInventory` as the result; the library owns the cache; `GenerateCbomCommand` is an adapter. See [foundation.md](foundation.md#phase-2-api-decided-2026-11-27).
3. ~~**One program model.**~~ Done 2026-11-27: one class table for spec matching and dispatch, every class visible to every artifact, and `ClasspathScope` and `--classpath` removed. The interned method index moved into step 4. See [foundation.md](foundation.md#phase-3-one-class-table-decided-2026-11-27).
4. **Detection-driven analysis.** See *Detection-driven analysis* in [foundation.md](foundation.md#detection-driven-analysis).
   - ~~Closures: interpret a set of methods with the values interpreting the whole JAR gives.~~ Done 2026-11-27.
   - ~~Answers about callers through the call graph (`DemandCallIndex`), compared with `CallIndex`.~~ Done 2026-11-27.
   - ~~The pipeline switched: phase A only reads, phase B interprets each JAR's candidates' closure, `CallIndex` is in the tests.~~ Done 2026-11-27: Keycloak takes about 12 s instead of 20, with the same CBOM; see [foundation.md](foundation.md#design-2026-11-27).
   - **Per-JAR cache by validation.** Detection records its open questions instead of asking them during the scan, so that a JAR's own result can be kept without the answers, which depend on the whole SBOM. The result is kept with the classes it looked up outside its JAR, and reused while they resolve the same way. Changing one JAR then re-detects that JAR and those that looked up its classes. The questions can use the call graph's method ids, the interned method index left from step 3.

   Output identical per occurrence.
5. **Closures across JARs.** Field values, and constants returned by exact methods, followed into other JARs: today they stop at the JAR boundary, and only arguments passed into parameters cross it. With step 4's closures only the methods involved are interpreted. Output changes, each difference reviewed. See *Closures across JARs* in [foundation.md](foundation.md#design-2026-11-27).

### 2b. Before reachability

1. ~~**API for reachability.**~~ Done 2026-11-27: `AnalysisInput`, `InputArtifact` with `application`, `EntryPoint`, `CryptoInventory.entryPoints`, `AssetOccurrence` with reachability, and `CbomWriter` in the library. See [foundation.md](foundation.md#phase-4-api-for-reachability-decided-2026-11-27).
2. ~~**A call-graph node per copy** of a class in several artifacts, so that a shaded copy isn't reached because the original is.~~ Done 2026-11-27: a type per copy, methods per type, and each artifact's calls resolved to the copies it sees, as spec matching does. Keycloak: 786,908 methods instead of 737,718, and 1,221,942 calls; the same time, and still in a 2 GB heap. `DemandCallIndex` takes the callers of every copy of a method, so its answers and the CBOM are unchanged.
3. ~~**Integer dispatch in the call graph**.~~ Done 2026-11-27: each type's superclass and interfaces as type ids, its methods a sorted range of member ids, and `dispatch` cached per type and member. Its speed is measured with the reachability walk, its first user.

### 3. Reachability and endpoints

This continues [reachability-design.md](reachability-design.md), steps 2 and 3. It is extended by *Endpoints as origins of crypto use* in [foundation.md](foundation.md): crypto use traced from the endpoints external users interact with.

1. ~~**Entry points and instantiated classes.**~~ Done 2026-11-27:
   - Phase A reads annotations (class, method, parameter, with constant values), `META-INF/services` and the manifest's `Main-Class`.
   - `src/main/resources/entry-point-specs.yaml` (`EntryPointSpecs`, which combines sources): JAX-RS, Spring MVC, Quarkus routes, servlets, WebSockets, gRPC, reactive messaging, the Vert.x event bus, scheduled methods, CDI observers, lifecycle methods and `main`. Each spec has a kind and an exposure; addresses are built from constant annotation values; authentication from the method's annotations, else its class's.
   - Instantiated: beans in any artifact, service providers, the classes declaring entry points.
   - `EntryPoint.artifact()` says whose copy of the class it is.
   - CLI: `--application`, by default the artifacts with the SBOM metadata component's `groupId`, and `--entry-points`.

   Keycloak (38 `org.keycloak` artifacts): 638 entry points, 625 of them HTTP, 467 with a path and 158 with a partial address (sub-resources, mounted by locators). Of the 415 operations Keycloak's admin REST API documents (`openapi.json`), 361 match a detected entry point by method and path suffix; the other 54 are collection roots, served by verb-only sub-resource methods, of which there are more than enough, and spot checks match. No authentication is known: Keycloak checks permissions in code, not with annotations. The CBOM is unchanged: entry points come into it with step 3.
2. **Uses and provisions, and exercised entry points**, before the walk (decided 2026-11-27):
   1. ~~cyclonedx-core-java 13, which can write `provides`; the CBOM byte-identical.~~ Done 2026-11-27: 13.5.0, pinned over sonar-cryptography's 12.2.0; Keycloak's CBOM byte-identical.
   2. ~~`AssetOccurrence.role()`: uses and provisions.~~ Done 2026-11-27: a provision when the occurrence's class implements a type of `crypto-implementation-specs.yaml` (the JCA SPIs and providers, Bouncy Castle's primitive interfaces and provider registrations), or when the occurrence calls a specified crypto API of its own artifact, as a library composing its own primitives does; a use otherwise, also where a caller passes a value to a wrapper of its own. Components `dependsOn` the assets of their uses and `provides` those of their provisions. Code that only names an algorithm (xmlsec's `JCEMapper`) counts as a use until a third role is needed.

      Keycloak: 2,449 provisions, 2,447 of them in bcprov and 2 in Elytron's credential module, and 2,055 uses. Component links: 850 `dependsOn` and 501 `provides`, instead of 1,345 `dependsOn`; bcprov provides 499 assets and depends on 22. Assets and occurrences unchanged. Known gap: 50 of bcprov's occurrences stay uses, 21 of them its implementation's own helpers that implement no listed type (`CompositeMLKEMEngine`, `BcKeyStoreSpi`'s inner classes); the others are bcprov calling the JDK's JCA, which are uses.
   3. ~~Roots and callbacks.~~ Done 2026-11-27:
      - Specs gain `callback`, for methods the framework calls on objects that exist, `requiredClassAnnotations`, and `mainClassAnnotations`.
      - Roots: JAX-RS methods and locators in classes with `@Path`, Spring MVC in controllers, WebSocket endpoints in their endpoint classes, servlets, scheduled methods, messaging, `@Startup`, `QuarkusApplication.run`, and `main` only in a manifest's `Main-Class` or a `@QuarkusMain` class.
      - Callbacks: JAX-RS sub-resource methods and locators, CDI observers, `@PostConstruct`. The walk adds them as their classes become instantiated.
      - JAX-RS locators are entry points of their own kind, `http-locator`, with a path and no verb.

      Keycloak: 35 roots (19 HTTP methods, 14 locators, `KeycloakMain.main` and `run`) and 722 callbacks in 145 classes, instead of 638 entry points; the shaded and tool `main`s are gone. The CBOM is unchanged.
3. ~~**Reachability walk and CBOM marking.**~~ Done 2026-11-27:
   - `ReachabilityWalk`: breadth first from the roots, over exact calls, virtual calls dispatched to the instantiated subtypes (also those instantiated later), method handles, static initializers, and the overrides of JDK methods (`Runnable.run`) of instantiated types. The runtime-instantiated classes' constructors are reached with no entry point; an instantiated class's callbacks become entry points.
   - The set of entry points reaching each method, as bitsets propagated over the walk's edges, and a shortest path from the first one: `AssetOccurrence.reachedBy()` and `path()`, set through `CryptoInventory.Builder.reachability`. Without entry points, `unknown`.
   - The CBOM: each occurrence has a `bom-ref`; an asset has `cryptid:reachability` (`reached`, `not-reached`, `unknown`), a `cryptid:reached` per reached occurrence (its `bom-ref`, the number of entry points, the first one), and `evidence.callstack` of its shortest path from an entry point. `metadata` has `cryptid:reachability` and the entry points by kind, exposure and source.
   - Reached and not-reached counts in the log.
   - `--paths` deferred: the call stack gives one path per asset.

   Keycloak: 151,656 of 786,908 methods reached from 745 entry points (35 roots, 710 callbacks), 14,952 types instantiated, in about 1 s; 930 of 4,320 occurrences reached (252 of them only by the runtime) and 209 of 725 assets; the whole run 13 s in a 2 GB heap. Not reached, as expected: `keycloak-admin-cli` (not yet an entry point), most of bcprov's 2,497, client-side `JWTClientSecretCredentialsProvider`. To check: xmlsec has 386 of its 410 occurrences reached, which looks high; the cause may be its static initializers, or a virtual call dispatched to every instantiated subtype.
4. **Services.** Endpoints written as CycloneDX `services` that `dependsOn` the assets they reach, from the sets step 3 computes.
5. **Review the open encoding questions** against real output: property names, services per method or per resource class, whether paths belong in the CBOM, and the `unknown` state.
6. **Facts cache.** The graph facts (edges, instantiations, matched annotations, services) are cached per JAR content too, as detection's results are since step 2.4.

What this unlocks in the backlog:
- *Dispatch precision*: the instantiated-class set can narrow `I.m` to the implementations that can actually run.
- *Provided and used algorithms*: `provides` against `dependsOn`, now with reachability as evidence. It needs a role on `AssetOccurrence`, which phase 1 left room for but didn't add.

### 4. Library and CLI split

This is reachability step 4. With the API of step 2.2 in place, it moves packages into modules without changing the API. It also moves writing the CBOM into the library, in a shape the Quarkus extension can use, and takes `public` off what isn't API.

- A library module whose input is `InputArtifact`s and optional entry points.
- The CLI on top of it: SBOM reading, Maven resolution and the CycloneDX file.

### 5. Independence from sonar-cryptography

This is reachability step 5. It can be done at any point before publishing.

1. Events hold values of our own: the spec argument, the constant and the `CodeLocation`. Translation into sonar-cryptography's types then happens in `model` only (foundation G2).
2. Replace `java` and `engine` with our own code: records for the roughly 70 value and context classes, and our own dispatch in place of the 11 context translators. This removes the reflection in `CryptoAssetModeler`, the `Tree` stand-in and the exclusions in `pom.xml`.
3. Copy the sources of `mapper`, `enricher` and `output` into a module, with a NOTICE and a POM of its own. First check that they build on their own.
4. Ask upstream to publish those three modules to Central. This is worth doing whatever the outcome of 3.

This also closes these backlog items: *Distribution* (the `Tree` marker) and *Upstream changes to sonar-cryptography*.

Measure: the fixture baseline and the Keycloak CBOM are unchanged, and the build needs nothing outside Maven Central.

### 6. Quarkus extension

This needs a separate design once steps 2 to 5 hold up. It supplies `InputArtifact`s from the application model, and entry points with full HTTP paths from the build.

## Detection backlog

Pull from this list between steps, or when a coverage comparison points at an item. It is ordered by value: Keycloak misses first, then precision, then breadth.

| Item | Why now | Source |
| --- | --- | --- |
| Values derived from parameters (concatenation recipes, arrays and varargs) | 3 Keycloak misses: `SHAPasswordEncoder`, and `SAMLEncryptionAlgorithms` ×2 | backlog, coverage gaps |
| Overriding dispatch in the object graph | 1 Keycloak miss: `DefaultRsaKeyEncryption256JWEAlgorithmProvider`. Reuses the `Hierarchy` from the call graph | coverage gaps, *Object flow limits* |
| Fields merged over objects (field values per allocation site) | xmlsec's `JCEMapper` over-approximation; 41 algorithms on one secret key | backlog |
| Alternative calls merged, and values merged across branches | Wrong results (webauthn4j PSS, DESede sizes). Needs control flow, then bounded path sensitivity | backlog |
| Variants an API rejects, for more APIs | Only `Signature`, `Mac`, `MessageDigest` and secret keys are checked | backlog |
| Bouncy Castle FIPS API | `keycloak-crypto-fips1402` is unreported by any tool. Needs owner-qualified static fields and a names table | backlog |
| Argon2 parameters, scrypt, bcrypt | Spec work with `returnsReceiver` | backlog |
| Fixture gaps (about 8) | Tracked by `FixtureConformanceTest` | backlog |
| IVs as assets | 4 Keycloak occurrences; low priority | coverage gaps |
| Shaded code attribution | Open question: the shading component or the original library | backlog |
| Shipped command-line tools | Keycloak's distribution ships `kcadm` and `kcreg` (`KcAdmMain`, `KcRegMain`), which its users run. They're applications of their own, left out of the default entry points since 2026-11-27; a user can supply them with `--entry-points`. Tracking them means telling a distribution's tools apart from shaded and build-time `main`s, e.g. from its launch scripts (`bin/kcadm.sh`) or the SBOM's file components, and reporting their reachability apart from the server's | step 2 review |
| Dependencies per occurrence | `dependsOn` is the union over an asset's occurrences, e.g. one generic `secret-key` depending on 192 algorithms. Recording it per occurrence makes it precise, and suits reachability | [foundation.md](foundation.md#phase-1-api-decided-2026-11-26) |

## Performance and operations

- **Memory and archives.** Keycloak completes in a 2 GB heap but not in 1.5 GB, before and after detection-driven analysis: what bounds it isn't measured yet. Candidates are the call graph, the class table, the JARs parsed by 16 threads at once, and `JarCache` keeping every JAR open; a bound on open JARs (smallrye-common-archive) may help.
- **Analysis on demand (redesign step 5)** moved into the foundation work as step 2.4, *Detection-driven analysis*.
- **Positions.** Column offsets, and lines for classes without line tables. The enclosing method is in the result model since step 2.1, and in the CBOM as `symbol`; the bytecode offset isn't.

## Open decisions

Collected from the design docs, so that none of them gets lost:

- **Reachability calls to confirm**:
  - instantiated-only dispatch;
  - overrides of JDK methods are reached;
  - method handles are reached when they are created;
  - entry points are searched for in top-level artifacts only.
- **CBOM encoding** of reachability: property names, and where paths go.
- **Endpoints** ([foundation.md](foundation.md#open-questions)):
  - one service per handler method or per resource class;
  - the exposure of messaging;
  - which authentication annotations to read;
  - whether endpoint sets fit the time target.
- **The rule-based reference tests** after the sonar-cryptography step: keep them as test-only, or retire them with a frozen baseline.
- **Name of the Quarkus extension**: `quarkus-cbom` or `quarkus-cryptid`.
- **Shared data**: check how much of `mapper` the CycloneDX registry covers. This decides how far the alignment can go.
- **Certificate-handling APIs** as PKIX evidence, without calling them certificates: set aside, and not ruled out.
