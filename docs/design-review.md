# Design review

Findings from reviewing the implementation against its [architecture](architecture.md), and a plan for a more direct design for Java. Reviewed 2026-11-08; the status column is kept up to date.

| | Finding | Kind | Status |
| --- | --- | --- | --- |
| F1 | Results vary between runs | defect | fixed |
| F2 | Wrong sonar-cryptography version in the CBOM metadata | defect | fixed |
| F3 | Every method is interpreted twice | design | fixed |
| F4 | The tool's own classpath leaks into the analysis | design | open |
| F5 | Results round-trip through JSON and string heuristics | design | open |
| F6 | Dead and unused weight | cleanup | partly done |
| F7 | Object flow stops at method boundaries | limit | done |

## F1. Results vary between runs (fixed)

Six single-threaded runs on one JAR reported `DSA-2048`, `DSA-256` and `DSA--1` at wildfly-elytron-x500-cert `SelfSignedX509CertificateAndSigningKey.java:367`, a `KeyPairGenerator.initialize(keySize)` whose field holds −1, 256 or 2048 depending on the algorithm. Three causes:

- `AVal` held constants and origins in `Set.of`/`Set.copyOf`, whose iteration order the JDK randomizes per JVM, and `Detector` fed values to the factories in that order.
- All possible values of one argument went into one store, which translates into one asset with an arbitrary one of them.
- `CbomAssembler` de-duplicated on the asset name without its UUID, location and line, so keys of different sizes counted as duplicates; which one was kept depended on the random order of sonar-cryptography's output, and the dropped ones left dangling dependency entries.

Fix: sorted constants and origins in `AVal`, sorted call sites in `CallIndex`, one finding per value of a multi-valued detectable argument (up to 16 combinations; an over-approximation, since the analysis isn't path-sensitive), and de-duplication on asset content with assets sorted first and links of dropped duplicates redirected. `ReproducibilityIT` runs the CLI three times on that JAR and compares the CBOMs; two Keycloak runs are identical per occurrence.

## F2. Wrong sonar-cryptography version in the CBOM metadata (fixed)

`CbomAssembler` reads `Package.getImplementationVersion()`. In the uber-jar the merged manifest is the application's, so the CBOM reports sonar-cryptography `1.0.0-SNAPSHOT` instead of 1.7.0. Fix: `BuildInfo`, generated from `src/main/java-templates` by templating-maven-plugin, holds the tool's version and `${sonar-cryptography.version}` from the pom, and the metadata uses both. `SampleSbomIT` checks the tool versions in the CBOM written by the runner JAR.

## F3. Every method is interpreted twice (fixed)

Phase A and phase B each create an `Analyzer` and interpret the whole JAR. Phase B only needs methods calling one of the 515 matcher keys, and only 8.3% of Keycloak's 88,337 classes reference `javax/crypto`, `java/security`, `org/bouncycastle/{crypto,pqc}` or `javax/net/ssl` at all (an upper bound, since `java/security` also covers non-crypto classes). A constant-pool pre-filter, or keeping phase A's results, would skip most of phase B.

Fix: phase A keeps, for each JAR to be scanned, the methods with a call site that passes `Detector`'s pre-check (a root rule by method name whose owner types include the call's owner or, for non-exact rules, one of its supertypes), with their call sites from the final round of the field fixpoint. Phase B runs detection on those only and doesn't analyze the JAR again. `Detector` finds nothing in the other methods, so the CBOM is unchanged; the screen uses the same `Types` lookup as detection, so subclasses of crypto types are kept. Keycloak 26.8.2, same CBOM per occurrence:

| | before | after |
| --- | ---: | ---: |
| total | 34 s | 24 s |
| phase A (index) | 15 s | 21 s |
| methods scanned in phase B | all | 1,958 |
| peak RSS | 8.6 GB | 7.2 GB |

Phase A now carries the pre-check; the remaining cost is its interpretation of every method, up to 10 rounds per JAR until field values settle.

## F4. The tool's own classpath leaks into the analysis

`Types` falls back to `ClassLoader.getSystemClassLoader()` for supertypes, that is the runner JAR. A scanned class's hierarchy can then depend on which of the tool's dependencies are present, a set tree-shaking changes. The fallback should be the JDK only (`jrt:/`).

## F5. Results round-trip through JSON and string heuristics

Per-artifact nodes become a CycloneDX `Bom`, are edited, written as JSON and parsed back for assembly. Identity is then rebuilt from strings: UUIDs stripped from names to de-duplicate, owners guessed from the `g/a/v` prefix of locations. An in-memory model with the artifact and call site attached would need neither; JSON can stay as the cache format.

## F6. Dead and unused weight

- `CryptoCallGraph` (988 lines, the sources-era planner for joint scans of sources JARs) was unreferenced: removed.
- `com.ibm:rules` ships nothing (0 classes kept); it can move to test scope, where `FixtureConformanceTest` uses `InventoryRule`.
- `Detector.follow` attaches an empty child store for every next or depending rule even when no call matches; translation ignores them.
- engine `callstack` and `hooks` (23 classes) ship only because `DetectionStore` implements the hook observer.

## F7. Object flow stops at method boundaries

Constant values resolve across methods (`CallIndex`), but next and depending rules follow objects within one method only. A `Cipher` created in a factory method and initialized by its caller loses its `init` details.

Done: `CryptoObjectGraph` is built over all candidate methods of a JAR and follows objects through arguments into callees and through return values back to callers, up to 4 calls away, along a call path. A parameter resolves to the argument of the caller on the path; at the start of a path it doesn't climb to all callers, since each caller is a finding of its own. See [the step 6 findings](detection-redesign.md#step-6-findings-objects-across-methods).

## A more direct design for Java

[Detection redesign](detection-redesign.md) proposes going further than the steps below: API specifications as data and an object graph of crypto objects, instead of rule trees, which also removes the SonarSource libraries.

The analysis core (`Analyzer`, `AVal`, `CallIndex`) is independent of sonar. The complexity sits in the middle, where bytecode facts are reshaped into sonar-era abstractions (`Tree`, `IScanContext`, `DetectionStore` with hooks), and at the end, where identity is rebuilt from strings. The plan keeps sonar-cryptography's knowledge (rules as data, the node model, mappers, reorganizer, enricher, CycloneDX builders) and replaces the plumbing between them with a small model of our own.

| Keep | Replace or drop |
| --- | --- |
| `Analyzer`, `AVal`, `CallIndex`, `JarCache` | `DetectionStore` and `StoreAccess`, by our own `Detection` tree |
| sonar-cryptography's Java rules, read once at startup | the `ITranslator` subclass, by a direct walk calling the context translators |
| `IContextTranslation` translators, mappers, `Reorganizer`, `Enricher` | the `Tree` marker, `ScanContext` and `InputFile`, once stores are gone |
| CycloneDX builders, or a small builder over `INode` | the per-artifact JSON round trip, by in-memory results (JSON only as a cache) |
| Quarkus CLI, Maven resolution | `com.ibm:rules` at runtime |

Target model:

```text
RuleTable                       // built once from JavaDetectionRules.rules(), immutable
  Map<MethodKey(owner, name, descriptor pattern), List<RuleNode>>
  RuleNode(id, exactTypes, context, bundle, action, params[], next[])
  Param(index, ValueFactory?, movedUnder?, dependents[])
  ownerPrefilter: Set<internal name>   // for constant-pool screening

Facts (per JAR, from Analyzer)  // computed once; detection reads them, no re-interpretation (done: BytecodeScanner.Facts)
  MethodFacts(class, method, sourceFile, List<CallSite>)

Detection (our tree, instead of DetectionStore)
  Detection(RuleNode, Site at, List<Value(paramIndex, IValue)>, List<Detection> children)
  Site(artifact, class, method, line, matchedSignature)   // identity, no string parsing later

Translate: Detection -> List<INode>       // walk + IContextTranslation, then Reorganizer, Enricher
Assemble:  Map<Site, List<INode>> -> Bom  // owner = Site.artifact, de-duplicate on (asset content, Site)
```

Order of work, one step at a time, each checked by `SampleSbomIT`, `ReproducibilityIT`, `KeycloakEndToEndIT` and the fixture baseline:

1. **Reproducible results (F1)**: done.
2. **Metadata version (F2)**: done.
3. **Analyze once, screen early (F3)**: done; phase A keeps the methods detection needs.
4. **RuleTable**: done in part. `RuleTable` indexes the root rules by method name and owner type; a call's candidates are looked up with its owner and supertypes, and the rule's `MethodMatcher` still decides, so matching is unchanged (`RuleTableTest` compares the table with a brute-force search over all rules). Keycloak: index 21 s → 18 s, total 24 s → 20 s, same CBOM. sonar-analyzer-commons stays: every `MethodMatcher` constructor calls `SetUtils`, and sonar-cryptography's rule classes construct them when the rules load, so only the upstream `Set.of` change removes it. Converting the whole rule graph into our own records is left for when the detection tree (next step) needs it.
5. **Our own detection tree and translation walk**: reproduce `ITranslator.translate`'s traversal over `Detection`, calling the context translators directly (needs a close reading of how `ITranslator.translate` attaches child nodes). Then remove `StoreAccess`, `ScanContext` and `InputFile`; the `Tree` marker stays while the two `JcaGCMParameterSpec` lambdas need it.
6. **In-memory assembly (F5)**: pass `Site`-keyed results to the assembler; JSON only as a cache; drop the UUID and prefix heuristics.
7. **JDK-only supertypes and cleanup (F4, F6)**: read JDK classes from `jrt:/`; move `com.ibm:rules` to test scope; stop attaching empty child stores.
8. **Object flow across methods (F7)**: done, in the object graph instead of the call index.

Step 7 is independent and low-risk; 4 to 6 change internals behind stable inputs and outputs.

## Backlog

Gaps and improvements beyond the findings above, moved here from the README on 2026-11-08.

- **Values derived from parameters.** Only values passed through unchanged resolve from callers. Values built from a parameter (`"AES/" + mode`) don't, nor values a constructor stores in a field from its parameter (an enum's `getName()`, so commons-codec's `HmacUtils` yields nothing; Keycloak's `Pbkdf2PasswordHashProvider` and `SHAPasswordEncoder`). Constants returned by static, private and final methods do resolve (2026-11-09), as do arguments such a method returns unchanged; overridable methods don't, since an override may return something else. Carrying a recipe instead of plain provenance (concatenation with constants, fields set from constructor parameters) would resolve the rest.
- **Variants an API rejects.** A mapping method returning the names of a whole family (Keycloak's `JavaAlgorithm.getJavaAlgorithm`: RSA, ECDSA, EdDSA, HMAC and AES names) gives every call site all of them. Variants whose model the API can't create are dropped (`CryptoAssetModeler.fitsApi`: a `Signature`, `Mac` or `MessageDigest` modeled as another primitive, a secret key modeled as an asymmetric algorithm). Other APIs aren't checked, and names the mappers don't know (`SHA256withRSAandMGF1`) pass as they are.
- **Argon2's parameters.** `Argon2Parameters.Builder` takes the variant (Argon2id, i, d) and the version, memory, parallelism and iteration counts across several calls on the builder; with a spec for it (its setters return the builder, `returnsReceiver`), constant parameters could be reported on the Argon2 node. Keycloak's come from its configuration at runtime. scrypt (`SCrypt.generate`, a static method) and bcrypt need specs the same way; sonar-cryptography's `Scrypt` model class exists but no mapper reaches it.
- **JCA names the mappers don't read.** `Signature.getInstance("SHA256withRSAandMGF1")`, which Keycloak's `JavaAlgorithm` returns for PS256, is reported under that raw name instead of RSA-PSS with SHA-256. The `aliases` table added for Bouncy Castle's content signers maps exactly these (to `SHA256WITHRSASSA-PSS`); giving the JCA `Signature` specs an alias table would fix it, as a `correction` of entries from the rules.
- **Dispatch precision.** A constant passed to `I.m` counts for every implementation of `m`, and static methods with the same signature in a subclass and its superclass are treated like overrides. At worst this adds assets.
- **Fixture gaps** (about 8 cases): values held in parameter objects (ML-DSA-44, ML-KEM-1024), the digest inside OAEP, DH key sizes from `BigInteger` parameters, GOST naming, SSL parameter arrays. `FixtureConformanceTest` reports each improvement; record it with `-Dfixtures.updateBaseline=true`.
- **Positions.** Multi-line `new X(...)` expressions report the statement's first line; classes without line tables (Bouncy Castle's release JARs) report no line; there are no column offsets. Emitting `symbol` (the enclosing method) and de-duplicating on it plus the bytecode offset would identify occurrences more robustly.
- **Memory and archives.** `JarCache` keeps every JAR open for the whole run and reads them with `java.util.zip.ZipFile`, skipping multi-release variants; smallrye-common-archive, with a bound on open archives and a more compact call index, would cut the peak (5.5 GB on Keycloak).
- **Shaded code.** Binaries include classes that sources JARs lack; keycloak-admin-cli shades keycloak-common, so its copies are reported as separate locations. Whether to attribute shaded code to the shading component or to the original library is open.
- **Work directory cache.** Per-artifact CBOMs aren't invalidated when other artifacts of the SBOM change, nor when cryptid itself changes: a rebuilt cryptid reuses the CBOMs of the previous build (all 548 Keycloak artifacts on 2026-11-09). Keying them by cryptid's version and a hash of the specs would fix it; until then, use a fresh work directory to compare builds.
- **Alternative calls merged.** All calls of one API on an object form one child event, as all calls of a rule formed one rule tree, whether they run one after another or on exclusive branches. webauthn4j's `SignatureUtil` calls `setParameter` with a different `PSSParameterSpec` in each branch of an `if` chain; the three are merged and translation keeps one, depending on order (SHA-256, without the SHA-384 and SHA-512 ones and the salts). Telling exclusive branches apart needs control flow: `Analyzer` could record which call sites can reach which, and calls of the same API that can't reach each other would be choices, one finding each. (An *argument* that may be one of several objects, e.g. assigned in a `switch`, already gives one finding per object.)
- **Values merged across branches.** Where branches meet, a local's values are merged, and two locals set together in each branch lose their link. Bouncy Castle's `OpenSSHPrivateKeyUtil.decryptOpenSSHV1` sets `keyLen` (16, 24 or 32 bytes) and `kind` (AES-CTR, AES-CBC, DESede-CBC or AES-GCM) in each branch of an `if` chain on the cipher name, then creates one `KeyParameter(keyIV, 0, keyLen)` and switches on `kind`. Every cipher gets all three sizes: right for AES by chance, but DESede is reported as 128, 192 and 256 bits where only 192 is real. Keeping such values correlated needs path sensitivity in `Analyzer`, e.g. analyzing each branch's state on to its uses (bounded, like the 16 variants) instead of joining at the merge point.
- **Object flow limits (F7).** Objects aren't followed through fields, into other JARs, or into overriding methods (callees are matched by exact signature), and at most 4 calls away. A returned object goes to all callers at the start of a path, so a factory's finding merges the events of all its callers.
- **Distribution.** A legal confirmation of the `org.sonar.plugins.java.api.tree.Tree` marker interface. (`NOTICE` and the JAR's `META-INF/THIRD-PARTY.txt` were added on 2026-11-09.)
- **Upstream changes to sonar-cryptography** that would remove the remaining workarounds: a value factory instead of the two `Tree`-typed lambdas in `JcaGCMParameterSpec` (drops the marker), `Set.of` instead of `SetUtils` in `MethodMatcher`, an `IScanContext` without `InputFile`, a public `DetectionStore` builder (the last three only matter to the test reference now).

## How this was measured

- Class inventory: every `.class` entry of the runner JAR, built with tree-shaking, mapped to the dependency JAR containing the same entry.
- External references: `javap -v` on this project's compiled classes (constant pools, descriptors, signatures).
- Rule statistics: a program walking `JavaDetectionRules.rules()` and `JavaReorganizerRules.rules()`.
- CBOM figures: Keycloak 26.8.2 runs on the tree-shaken JAR.
- Crypto-reference share: a byte search over Keycloak's 534 resolved JARs.

No SonarSource SSAL component was used or run.
