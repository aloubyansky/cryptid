# Design review

Findings from reviewing the implementation against its [architecture](architecture.md), and a plan for a more direct design for Java. Reviewed 2026-11-08; the status column is kept up to date.

| | Finding | Kind | Status |
| --- | --- | --- | --- |
| F1 | Results vary between runs | defect | fixed |
| F2 | Wrong sonar-cryptography version in the CBOM metadata | defect | open |
| F3 | Every method is interpreted twice | design | open |
| F4 | The tool's own classpath leaks into the analysis | design | open |
| F5 | Results round-trip through JSON and string heuristics | design | open |
| F6 | Dead and unused weight | cleanup | partly done |
| F7 | Object flow stops at method boundaries | limit | open |

## F1. Results vary between runs (fixed)

Six single-threaded runs on one JAR reported `DSA-2048`, `DSA-256` and `DSA--1` at wildfly-elytron-x500-cert `SelfSignedX509CertificateAndSigningKey.java:367`, a `KeyPairGenerator.initialize(keySize)` whose field holds −1, 256 or 2048 depending on the algorithm. Three causes:

- `AVal` held constants and origins in `Set.of`/`Set.copyOf`, whose iteration order the JDK randomizes per JVM, and `Detector` fed values to the factories in that order.
- All possible values of one argument went into one store, which translates into one asset with an arbitrary one of them.
- `CbomAssembler` de-duplicated on the asset name without its UUID, location and line, so keys of different sizes counted as duplicates; which one was kept depended on the random order of sonar-cryptography's output, and the dropped ones left dangling dependency entries.

Fix: sorted constants and origins in `AVal`, sorted call sites in `CallIndex`, one finding per value of a multi-valued detectable argument (up to 16 combinations; an over-approximation, since the analysis isn't path-sensitive), and de-duplication on asset content with assets sorted first and links of dropped duplicates redirected. `ReproducibilityIT` runs the CLI three times on that JAR and compares the CBOMs; two Keycloak runs are identical per occurrence.

## F2. Wrong sonar-cryptography version in the CBOM metadata

`CbomAssembler` reads `Package.getImplementationVersion()`. In the uber-jar the merged manifest is the application's, so the CBOM reports sonar-cryptography `1.0.0-SNAPSHOT` instead of 1.7.0. `META-INF/maven/com.ibm/engine/pom.properties`, which the uber-jar keeps, has the right version.

## F3. Every method is interpreted twice

Phase A and phase B each create an `Analyzer` and interpret the whole JAR. Phase B only needs methods calling one of the 515 matcher keys, and only 8.3% of Keycloak's 88,337 classes reference `javax/crypto`, `java/security`, `org/bouncycastle/{crypto,pqc}` or `javax/net/ssl` at all (an upper bound, since `java/security` also covers non-crypto classes). A constant-pool pre-filter, or keeping phase A's results, would skip most of phase B.

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

## A more direct design for Java

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

Facts (per JAR, from Analyzer)  // computed once; detection reads them, no re-interpretation
  MethodFacts(class, method, sourceFile, List<CallSite>)

Detection (our tree, instead of DetectionStore)
  Detection(RuleNode, Site at, List<Value(paramIndex, IValue)>, List<Detection> children)
  Site(artifact, class, method, line, matchedSignature)   // identity, no string parsing later

Translate: Detection -> List<INode>       // walk + IContextTranslation, then Reorganizer, Enricher
Assemble:  Map<Site, List<INode>> -> Bom  // owner = Site.artifact, de-duplicate on (asset content, Site)
```

Order of work, one step at a time, each checked by `SampleSbomIT`, `ReproducibilityIT`, `KeycloakEndToEndIT` and the fixture baseline:

1. **Reproducible results (F1)**: done.
2. **Metadata version (F2)**: read the version from the `pom.properties` the uber-jar keeps.
3. **Analyze once, screen early (F3)**: keep each JAR's phase A results for phase B, or store them compactly, and skip classes whose constant pool names none of the rule owners.
4. **RuleTable**: convert the rule graph into our own records once, keeping the original rules for their factories; match with map lookups and `Types`, without `MethodMatcher`, `IType` or `SetUtils`, which drops sonar-analyzer-commons.
5. **Our own detection tree and translation walk**: reproduce `ITranslator.translate`'s traversal over `Detection`, calling the context translators directly (needs a close reading of how `ITranslator.translate` attaches child nodes). Then remove `StoreAccess`, `ScanContext` and `InputFile`; the `Tree` marker stays while the two `JcaGCMParameterSpec` lambdas need it.
6. **In-memory assembly (F5)**: pass `Site`-keyed results to the assembler; JSON only as a cache; drop the UUID and prefix heuristics.
7. **JDK-only supertypes and cleanup (F4, F6)**: read JDK classes from `jrt:/`; move `com.ibm:rules` to test scope; stop attaching empty child stores.
8. **Later: object flow across methods (F7)**, by recording receivers and returns of objects created by matched calls in the call index, as for constant arguments.

Steps 2, 3 and 7 are independent and low-risk; 4 to 6 change internals behind stable inputs and outputs.

## How this was measured

- Class inventory: every `.class` entry of the runner JAR, built with tree-shaking, mapped to the dependency JAR containing the same entry.
- External references: `javap -v` on this project's compiled classes (constant pools, descriptors, signatures).
- Rule statistics: a program walking `JavaDetectionRules.rules()` and `JavaReorganizerRules.rules()`.
- CBOM figures: Keycloak 26.8.2 runs on the tree-shaken JAR.
- Crypto-reference share: a byte search over Keycloak's 534 resolved JARs.

No SonarSource SSAL component was used or run.
