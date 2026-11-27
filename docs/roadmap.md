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
2. ~~**Analysis API.**~~ Done 2026-11-27: `Cryptid`, `InputArtifact`, `AnalysisOptions` and `ClasspathScope`, with `CryptoInventory` as the result; `GenerateCbomCommand` is an adapter. See [foundation.md](foundation.md#phase-2-api-decided-2026-11-27).
3. ~~**One program model.**~~ Done 2026-11-27: one class table for spec matching and dispatch, every class visible to every artifact, and `ClasspathScope` and `--classpath` removed. The interned method index moved into step 4. See [foundation.md](foundation.md#phase-3-one-class-table-decided-2026-11-27).
4. **Detection-driven analysis.** See *Detection-driven analysis* in [foundation.md](foundation.md#detection-driven-analysis).
   - Read every JAR's instructions only: hierarchy, call graph, candidate methods, field writers.
   - Detect per JAR, recording open questions where a spec argument comes from a parameter.
   - Answer them by interpreting only the callers asked about, through the call graph's reverse edges.
   - Replaces the 306,000-call `CallIndex` and phase A's interpretation of every method. Done 2026-11-27 but for the cache: Keycloak takes about 12 s instead of 20, with the same CBOM; see [foundation.md](foundation.md#design-2026-11-27).
   - The questions use the call graph's method ids, the interned method index left from step 3.
   - Results are cached per JAR content.

   Output identical per occurrence.
5. **Closures across JARs.** Field values, and constants returned by exact methods, followed into other JARs: today they stop at the JAR boundary, and only arguments passed into parameters cross it. With step 4's closures only the methods involved are interpreted. Output changes, each difference reviewed. See *Closures across JARs* in [foundation.md](foundation.md#design-2026-11-27).

### 3. Reachability and endpoints

This continues [reachability-design.md](reachability-design.md), steps 2 and 3. It is extended by *Endpoints as origins of crypto use* in [foundation.md](foundation.md): crypto use traced from the endpoints external users interact with.

1. **Entry points and instantiated classes.**
   - Entry-point specs as data: annotation, parameter annotation, override and signature forms.
   - Each spec has a kind and an exposure, external or internal.
   - Endpoints carry the protocol, address and authentication where the code states them.
   - Bean specs and `META-INF/services`.
   - Top-level artifacts named by the user, with a default.
   - `--entry-points` for entry points supplied as data.

   Measure: the entry points found in `org.keycloak:*`, by kind and exposure, against Keycloak's known REST endpoints.
2. **Reachability walk and CBOM marking.**
   - The forward walk to a fixpoint over instantiated classes.
   - Each occurrence marked on its `Site`, or as `unknown` when nothing was searched.
   - Metadata on the search.
   - `--paths` for the paths.
   - Reached and not-reached counts in the summary.

   Measure: the share of Keycloak's occurrences reached, and a manual check of a sample of each outcome. Target: under a minute, in the same heap.
3. **Endpoint sets and services.**
   - For each occurrence, the set of entry points reaching it, propagated as bitsets over the resolved graph.
   - Endpoints written as CycloneDX `services` that `dependsOn` the assets they reach.
4. **Review the open encoding questions** against real output: property names, services per method or per resource class, whether paths belong in the CBOM, and the `unknown` state.
5. **Facts cache.** The graph facts (edges, instantiations, matched annotations, services) are cached per JAR content too, as detection's results are since step 2.4.

What this unlocks in the backlog:
- *Dispatch precision*: the instantiated-class set can narrow `I.m` to the implementations that can actually run.
- *Provided and used algorithms*: `provides` against `dependsOn`, now with reachability as evidence. `Finding` has a role for it from step 2.1.

### 4. Library and CLI split

This is reachability step 4. With the API of step 2.2 in place, it moves packages into modules without changing the API.

- A library module whose input is `Artifact`s and optional entry points.
- The CLI on top of it: SBOM reading, Maven resolution and the CycloneDX file.

### 5. Independence from sonar-cryptography

This is reachability step 5. It can be done at any point before publishing.

1. Events hold values of our own: the spec argument, the constant and the `Site`. Translation into sonar-cryptography's types then happens in `model` only (foundation G2).
2. Replace `java` and `engine` with our own code: records for the roughly 70 value and context classes, and our own dispatch in place of the 11 context translators. This removes the reflection in `CryptoAssetModeler`, the `Tree` stand-in and the exclusions in `pom.xml`.
3. Copy the sources of `mapper`, `enricher` and `output` into a module, with a NOTICE and a POM of its own. First check that they build on their own.
4. Ask upstream to publish those three modules to Central. This is worth doing whatever the outcome of 3.

This also closes these backlog items: *Distribution* (the `Tree` marker) and *Upstream changes to sonar-cryptography*.

Measure: the fixture baseline and the Keycloak CBOM are unchanged, and the build needs nothing outside Maven Central.

### 6. Quarkus extension

This needs a separate design once steps 2 to 5 hold up. It supplies `Artifact`s from the application model, and entry points with full HTTP paths from the build.

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
