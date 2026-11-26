# Roadmap

The single list of what's next, in order, written 2026-11-26. It draws on the [design review](design-review.md), the [detection redesign](detection-redesign.md), the [reachability design](reachability-design.md), the [coverage gaps](coverage-gaps.md) and [certificates](certificates.md). Those stay as design records, with their reasoning and measurements. Status is kept here.

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
2. **JDK-only supertypes (F4).** `Types` falls back to the system class loader, which is the runner JAR. Read JDK classes from `jrt:/` instead.
3. **Order-independent attachment (redesign 3b-2).** A detection without nodes of its own takes the first child with nodes. Choose by kind instead, and review each difference.
4. **F6 leftovers.** Stop attaching empty child events where no call matches.

### 2. Reachability (current track)

This continues [reachability-design.md](reachability-design.md), steps 2 and 3.

1. **Entry points and instantiated classes.**
   - Entry-point specs as data: annotation, parameter annotation, override and signature forms.
   - Bean specs, read from class, method and parameter annotations.
   - `META-INF/services` read per JAR.
   - Top-level artifacts named by the user, with a default.
   - `--entry-points` for entry points supplied as data.

   Measure: the entry points found in `org.keycloak:*`, by kind, against Keycloak's known REST endpoints.
2. **Occurrences record their enclosing method.** Assembly needs it to look up reachability. It also covers the `symbol` half of *Positions* in the backlog.
3. **Reachability walk and CBOM marking.**
   - The forward walk to a fixpoint over instantiated classes.
   - `cryptid:reachability` and `cryptid:reached` on assets, metadata on the search, `unknown` when nothing was searched.
   - `--paths` for the paths.
   - Reached and not-reached counts in the summary.
   - Graph facts cached per artifact; the walk runs on every invocation.

   Measure: the share of Keycloak's occurrences reached, and a manual check of a sample of each outcome. Target: under a minute, in the same heap.
4. **Review the open encoding questions** against real output: property names, whether paths belong in the CBOM, and the `unknown` state.

What this unlocks in the backlog:
- *Dispatch precision*: the instantiated-class set can narrow `I.m` to the implementations that can actually run.
- *Provided and used algorithms*: `provides` against `dependsOn`, now with reachability as evidence.

### 3. Library and CLI split, with in-memory assembly

This is reachability step 4 together with design review F5 and steps 5 and 6. Both need the same change: assembly without CDI, from results keyed by `Site`.

- A library module whose input is artifacts (JAR, coordinates, dependencies), which of them are top-level, and optional entry points and instantiated classes.
- The CLI on top of it: SBOM reading and Maven resolution.
- In-memory results keyed by `Site`, with JSON used only as the cache format. This drops the UUID-stripping and owner-prefix heuristics.

Done after step 2, so that a working implementation shapes the API.

### 4. Independence from sonar-cryptography

This is reachability step 5. It can be done at any point before publishing.

1. Replace `java` and `engine` with our own code: records for the roughly 70 value and context classes, and our own dispatch in place of the 11 context translators. This removes the reflection in `CryptoAssetModeler`, the `Tree` stand-in and the exclusions in `pom.xml`.
2. Copy the sources of `mapper`, `enricher` and `output` into a module, with a NOTICE and a POM of its own. First check that they build on their own.
3. Ask upstream to publish those three modules to Central. This is worth doing whatever the outcome of 2.

This also closes these backlog items: *Distribution* (the `Tree` marker) and *Upstream changes to sonar-cryptography*.

Measure: the fixture baseline and the Keycloak CBOM are unchanged, and the build needs nothing outside Maven Central.

### 5. Quarkus extension

This needs a separate design once steps 2 to 4 hold up.

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

## Performance and operations

- **Memory and archives.** A bound on open JARs (smallrye-common-archive) and a more compact call index. The current peak is 5.5 GB.
- **Analysis on demand (redesign step 5).** Method summaries instead of interpreting every method up to 10 rounds. This is only worth taking up if reachability pushes past the time or memory target.
- **Positions.** Column offsets, and lines for classes without line tables. The enclosing method comes with reachability step 2.

## Open decisions

Collected from the design docs, so that none of them gets lost:

- **Reachability calls to confirm**:
  - instantiated-only dispatch;
  - overrides of JDK methods are reached;
  - method handles are reached when they are created;
  - entry points are searched for in top-level artifacts only.
- **CBOM encoding** of reachability: property names, and where paths go.
- **The rule-based reference tests** after the sonar-cryptography step: keep them as test-only, or retire them with a frozen baseline.
- **Name of the Quarkus extension**: `quarkus-cbom` or `quarkus-cryptid`.
- **Shared data**: check how much of `mapper` the CycloneDX registry covers. This decides how far the alignment can go.
- **Certificate-handling APIs** as PKIX evidence, without calling them certificates: set aside, and not ruled out.
