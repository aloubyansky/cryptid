# CBOM Generator: State and Next Steps

As of 2026-11-08.

## Summary

cbom-generator is a Quarkus CLI that turns a CycloneDX SBOM into a CBOM by analyzing the bytecode of each Maven component's JAR. It uses sonar-cryptography's Java detection rules and CBOM model (Apache-2.0), and no SonarSource analyzer under the Sonar Source-Available License (SSALv1).

- Keycloak SBOM: 548 JARs and 88,324 classes analyzed in 35 s, 2,563 findings in 74 components.
- Values passed between methods are resolved from their callers, within a JAR and across JARs, including calls through interfaces and superclasses, and reported where the value is chosen (e.g. SHA-1 at Keycloak's `DPoPUtil`, RSA through Keycloak's `CryptoProvider` SPI).
- sonar-cryptography's own Java test fixtures: 97.2% of the comparable expected detections reproduced, checked on every build.
- Main gap: values built from parameters (e.g. `"AES/" + mode`) or returned by getters don't resolve.
- Docs: [Architecture](docs/architecture.md) (pipeline diagram, input and output, library integration, what the runner JAR contains) [Design review](docs/design-review.md) (findings and refactoring plan) and [Detection redesign](docs/detection-redesign.md) (proposal).

## How it works

Steps 1, 2 and 7 run once; steps 3 to 6 run for each JAR in parallel. Each step is implemented in cbom-generator using the artifacts listed.

| Step | Implemented in cbom-generator | Using |
| --- | --- | --- |
| 1. Read SBOM, group by artifact | `GenerateCbomCommand`, `SbomReader` | cyclonedx-core-java, packageurl-java (SBOM and purl parsing) |
| 2. Resolve binary JARs (no sources JARs needed) | `ArtifactResolver` | quarkus-maven-resolver |
| 3. Interpret bytecode | `Analyzer`, `Types`, `JarCache`, `AVal`, `CallIndex` | jdk-classfile-backport (SmallRye) |
| 4. Detect from the crypto API specs (`crypto-api-specs.yaml`, exported from sonar-cryptography's 351 Java rules); objects followed through the method's object graph | `SpecDetector`, `ObjectGraph`, `ApiIndex`, `StoreAccess` | `com.ibm:engine` (value factories, `DetectionStore`) |
| 5. Translate to crypto assets: translate, reorganize, enrich | `Translation` | `com.ibm:mapper`, `com.ibm:java` (context translators, reorganizer rules), `com.ibm:enricher` |
| 6. Write each artifact's CBOM | `BytecodeScanner` | `com.ibm:output` (`CBOMOutputFile`) |
| 7. Merge and link assets to SBOM components | `CbomAssembler` | cyclonedx-core-java |

The dependency closure from the SBOM supplies supertypes for rule matching. [Architecture](docs/architecture.md) has the diagram and the details of each step.

## Licensing

The build does not contain any SSALv1 code. The only SonarSource code left is two LGPL-3.0 libraries.

Why it matters: SSALv1 limits use to a "Non-competitive Purpose", which excludes products with "substantially similar functionality as SonarQube". Clause (c) also excludes "artificial intelligence technology ... to ingest, interpret, analyze ... the data provided by the Program, or to engage with the Program in any manner". AI-driven work on the sonar-based pipeline was paused for that reason.

| Component | License | Status |
| --- | --- | --- |
| sonar-java, sonar-python, sonar-go analyzers | SSALv1 | Removed: excluded in the pom (sonar-cryptography's parent pom adds them to every module) |
| shaded `sonar-cryptography-plugin` JAR | embeds SSALv1 sonar-python, EPL, Apache, BSD code with notices stripped | Removed |
| cbomkit-lib | Apache-2.0 | Removed; it existed to drive sonar-java |
| sonar-cryptography modules `com.ibm:java`, `engine`, `mapper`, `enricher`, `output`, `rules`, `common` 1.7.0 | Apache-2.0 | Used: CBOM model, value factories, translation, output. The Java rules are exported once into `crypto-api-specs.yaml` (with attribution) and loaded only by tests |
| `sonar-analyzer-commons` 2.18 | LGPL-3.0 | Tests only: `MethodMatcher` uses its `SetUtils` when sonar-cryptography's rules load, and only the tests load them (as the reference for the spec-based detection, and to export the specs); not shipped |
| `sonar-plugin-api` 13.11 | LGPL-3.0 | Compile-only (`provided`): the `InputFile` type in `IScanContext`; not shipped |

Two workarounds remain, each removable by a small upstream change:

- `StoreAccess` sits in sonar-cryptography's `com.ibm.engine.detection` package, because building `DetectionStore` trees needs package-private members.
- An empty marker interface named `org.sonar.plugins.java.api.tree.Tree` (no SonarSource code) is shipped, because two lambdas in the `JcaGCMParameterSpec` rules are typed on it. The tool no longer loads the rules; the marker stays only while the tests run them as a reference. Worth a confirmation from legal.

Still needed for distribution: a third-party notices file covering the Apache and LGPL components.

## Results

The bytecode engine analyzes every artifact of the Keycloak SBOM in about half a minute, and resolves values passed between methods, JARs and interfaces.

| Run | Pipeline | Artifacts | Time | Findings | Components with assets |
| --- | --- | --- | --- | --- | --- |
| Keycloak 999.0.0-SNAPSHOT (573 Maven components) | bytecode, cross-method resolution with interface dispatch | 548 JARs, 0 failed; 301,941 calls indexed | 35 s (index 14 s), 6.8 GB peak | 2,563 | 74 |
| Keycloak, same SBOM | bytecode, cross-method resolution without interface dispatch | 548 JARs, 0 failed | 33 s, 7.7 GB peak | 2,480 (after removing 315 duplicates) | 74 |
| Keycloak, same SBOM | bytecode, within-method only | 548 JARs, 0 failed | 21 s, 5.9 GB peak | 2,557 | 71 |
| Sample SBOM (bcprov, commons-codec, netty-epoll) | bytecode, cross-method resolution | 4 JARs, 4,352 classes | 7 s | 1,365 | 2 |

Fixture conformance (`FixtureConformanceTest`: sonar-cryptography's Java test files, compiled with javac, analyzed with the call index, compared with their `// Noncompliant` annotations): 241 of 248 comparable expected issues matched (97.2%), up from 95.5% before the call index and with Bouncy Castle on the test classpath. 109 fixtures match fully, 7 differ, 13 don't compile (Bouncy Castle version-specific APIs or invalid Java; 36 expected issues). The two cross-file fixtures compile together; the caller's 2 extra issues are cross-file detections that sonar-cryptography's own test checks as CBOM nodes rather than issues.

Cross-method resolution recovers wrapper findings. commons-codec went from 0 findings to 16, in 12 assets (MD2, MD5, SHA-1, the SHA-2 and SHA-3 families), each at its `getXxxDigest()` method. Keycloak's `HashUtils.hash(String, byte[])` callers resolve across JARs: SHA-1 in `DPoPUtil`, SHA-256 in `AbstractX509ClientCertificateAuthenticator` and `CachingEmbeddedMetadataProvider`, SHA-384 in `AuthenticationSessionManager`, SHA-512 in `RecoveryAuthnCodesUtils`.

Interface dispatch added 83 occurrences and lost none. In Keycloak: RSA in `KeyUtils` and `DockerComposeCertsDirectory` and EC/ECDSA keys in `JWKParser`, through the `CryptoProvider` SPI; RSA, EC and EdDSA in `HardcodedPublicKeyLoader` (through `PemUtils`) and `DerUtils`; the `PemUtilsProvider` implementations in keycloak-crypto-default and keycloak-crypto-fips1402. In Bouncy Castle: 51 occurrences through its `JcaJceHelper` interfaces.

Bouncy Castle's release JARs have no line number tables, so its 1,664 occurrences carry no `line`.

## What was tried

Each approach below informed the next; newest first.

| Approach | What it did | Outcome and lesson |
| --- | --- | --- |
| Interface dispatch (current) | Resolving `C.m` also takes calls to `T.m` for every supertype `T` of `C` declaring `m`; calls to inherited default methods resolve through interfaces | +83 Keycloak occurrences, none lost, e.g. through `CryptoProvider` and BC's `JcaJceHelper`. Over-approximates: a constant passed to `I.m` counts for every implementation |
| Cross-method resolution | Interpreter tracks which parameters a value is passed through from; a call index of all JARs; each caller constant becomes its own finding at the caller | commons-codec 0 → 16 findings, Keycloak's `HashUtils` callers resolved. Attaching caller values as children of one store merged them into one wrong asset: sonar-cryptography's engine emits each hook store as a separate finding |
| Bytecode pass 1 | Interprets JAR bytecode with the SmallRye ClassFile backport; evaluates sonar-cryptography's 351 Java rules; reuses its translators, reorganizer, enricher, CycloneDX output | No SSAL; 21 s on Keycloak. Needed rule indexing and a terminating value lattice to be fast |
| Bytecode spike | Same engine against sonar-cryptography's fixtures, classpath without SSAL JARs | 95.5% parity; showed rules are data, and only 2 lambdas touch sonar's `Tree` |
| Sonar-based pipeline (removed) | Scanned sources JARs with sonar-java through cbomkit-lib, in worker JVMs, with joint scans for cross-component values | Replaced because SSALv1 excludes AI-driven use; its outputs and builds were deleted on 2026-11-08 |

## What's missing

The largest gap is values derived from parameters; the rest are fidelity details, resource limits and housekeeping.

- **Values derived from parameters.** Only values passed through unchanged resolve. Values built from a parameter (`"AES/" + mode`) or returned by methods (`HmacAlgorithms.getName()`, so commons-codec's `HmacUtils` yields nothing) don't.
- **Dispatch precision.** A constant passed to `I.m` counts for every implementation of `m`, and static methods with the same signature in a subclass and its superclass are treated like overrides. At worst this adds assets.
- **Deeper value resolution, about 8 fixture cases.** Values held in parameter objects (ML-DSA-44, ML-KEM-1024), nested engines (GMac over AES, the digest inside OAEP), DH key sizes from `BigInteger` parameters, GOST naming.
- **Positions.** Multi-line `new X(...)` expressions report the statement's first line; classes without line tables (Bouncy Castle's release JARs) report no line; no column offsets. Adding `symbol` (enclosing method) would identify occurrences more robustly.
- **Memory.** 6.8 GB peak on Keycloak with the call index: `JarCache` keeps every JAR open for the whole run, and the index holds 302k call sites.
- **Archive reading.** `JarCache` uses `java.util.zip.ZipFile` directly and skips multi-release variants; consider smallrye-common-archive instead.
- **De-duplication.** An occurrence is kept once per asset content (name without UUIDs, plus crypto properties), location and line; duplicates come from code shaded into several JARs, and their asset-to-asset links are redirected to the asset kept. Assets of the same content at the same line but matched by different calls keep only the first call's `additionalContext`.
- **Shaded and generated code.** Binaries include classes that sources JARs lack; keycloak-admin-cli shades keycloak-common, so its copies are reported as separate locations. Whether to attribute shaded code to the shading component or to the original library is open.
- **Tests.** Scanner tests (single JAR, two-hop cross-JAR, interface dispatch), SBOM-reader tests, and `FixtureConformanceTest` over 129 copied sonar-cryptography fixtures with a per-fixture baseline (`src/test/resources/fixture-baseline.tsv`). Integration tests run the packaged uber-jar as a process with [CLI Assured](https://central.sonatype.com/artifact/org.cli-assured/cli-assured) (failsafe, after `package`): `SampleSbomIT` and `ReproducibilityIT` (three runs on wildfly-elytron-x500-cert, compared) on every `mvn verify` (CBOM contents, work-directory reuse and `--rescan`, a missing SBOM); `KeycloakEndToEndIT` on the Keycloak 26.8.2 SBOM (548 JARs, about 40 s, 8 GB RSS), tagged `e2e`, only with `mvn verify -Pe2e`. It checks that every artifact is analyzed, lower bounds on totals, well-formed occurrences, the cross-JAR SHA-1 at `DPoPUtil`, and RSA-2048 at `KeyUtils` through the `CryptoProvider` interface.
- **Reproducibility.** The same input gives the same CBOM, apart from bom-refs, UUIDs in names and the timestamp (`ReproducibilityIT`, and two Keycloak runs compared per occurrence). Constants and origins iterate in sorted order, call-index sites are sorted, and the assembler sorts each artifact's assets before de-duplicating. A detectable argument with several possible constants yields one finding per value (up to 16 combinations per match), as values resolved from callers do: wildfly-elytron's key size field gives `DSA--1`, `DSA-256` and `DSA-2048`, which over-approximates, since the analysis isn't path-sensitive.
- **Distribution.** Third-party notices file.
- **Housekeeping.** `--threads` defaults to all CPUs; per-artifact CBOMs cached in the work directory aren't invalidated when other artifacts change.

## Next steps

In priority order. Cross-method value propagation and interface dispatch are done (2026-11-08); the next step recovers more findings, the rest harden the tool for 1000+ JAR SBOMs and for distribution.

1. **Values derived from parameters.** Carry a recipe instead of plain provenance: string concatenation with constants, and returns of simple getters (e.g. enum `getName()` returning a constant field), so values like `"AES/" + mode` and commons-codec's `HmacUtils` resolve.
2. **Archive reading with smallrye-common-archive.** Replace `JarCache`'s plain `ZipFile` use; handle multi-release JARs properly; bound how many archives stay open. Together with a more compact call index, cut the 6.8 GB peak.
3. **Remaining value-resolution features** from the fixture gaps: nested engines (GMac over AES), `BigInteger`-derived DH sizes, GOST naming, SSL parameter arrays. `FixtureConformanceTest` reports each improvement; record it with `-Dfixtures.updateBaseline=true`.
4. **Occurrence identity.** Emit `symbol` (enclosing method signature) on occurrences; de-duplicate on symbol plus bytecode offset rather than name, location and line.
5. **Upstream changes to sonar-cryptography.** A public `DetectionStore` builder (drops `StoreAccess`); a value factory instead of the two `Tree`-typed lambdas in `JcaGCMParameterSpec` (drops the marker interface); `Set.of` instead of `SetUtils` in `MethodMatcher` (drops sonar-analyzer-commons); an `IScanContext` without `InputFile` (drops sonar-plugin-api).
6. **Distribution and housekeeping.** Third-party notices; decide shaded-code attribution; invalidate cached per-artifact CBOMs when the SBOM changes.
7. **Legal confirmation** of the remaining LGPL components and the marker interface, and closing the SSAL pause formally.

## Reference

Paths are relative to `/home/aloubyansky/playground/cbom`.

| Item | Where | Notes |
| --- | --- | --- |
| CLI command | `src/main/java/org/acme/cbom/GenerateCbomCommand.java` | group by artifact, resolve, index calls (phase A), detect (phase B), merge |
| SBOM model | `SbomReader`, `MavenComponent` | purl parsing, de-duplication by bom-ref, artifact keys and paths, dependency closure |
| Resolver | `ArtifactResolver` | quarkus-maven-resolver |
| Merge | `CbomAssembler` | attributes assets by occurrence location, de-duplicates occurrences, CycloneDX 1.6 JSON |
| Bytecode engine | `src/main/java/org/acme/cbom/bytecode/` | `BytecodeScanner` (entry: `index`, `scan`), `Analyzer`, `AVal`, `CallSite`, `CallIndex`, `Types`, `JarCache`, `Detector`, `Translation`, `Loc` |
| Workarounds | `src/main/java/com/ibm/engine/detection/StoreAccess.java`, `src/main/java/org/sonar/plugins/java/api/tree/Tree.java` | see Licensing |
| Tests | `src/test/java/org/acme/cbom/bytecode/BytecodeScannerTest.java`, `SbomReaderTest` | single-JAR detection; two-hop resolution across two JARs; calls through an interface |
| Integration tests | `src/test/java/org/acme/cbom/SampleSbomIT.java`, `KeycloakEndToEndIT.java`, `Cli.java` | CLI Assured runs `java -jar` on the runner JAR (failsafe passes its path as `cbom.runner.jar`); `KeycloakEndToEndIT` is tagged `e2e`, run with `mvn verify -Pe2e` |
| Packaging | `src/main/resources/application.properties` | `uber-jar` with `quarkus.package.jar.tree-shake.mode=classes`: 19.6 MB and 10.6k classes instead of 27.4 MB and 15.9k, same CBOM on the sample and Keycloak SBOMs. `Translation` passes `Class.forName` compile-time constant names so the tree-shaker keeps the reflectively loaded rules and translators |
| Fixture conformance test | `FixtureConformanceTest`, `FixtureSupport` (test sources) | compiles each fixture with javac, compares with its annotations and with `src/test/resources/fixture-baseline.tsv`; `-Dfixtures.updateBaseline=true` rewrites the baseline |
| sonar-cryptography fixtures | `src/test/resources/sonar-cryptography-fixtures/` | 129 files from tag 1.7.0, Apache-2.0, with `LICENSE.txt` and `NOTICE.md`; Bouncy Castle 1.85 as test dependencies |
| Test SBOMs | `src/test/resources/sample-sbom.json`, `src/test/resources/keycloak-26.8.2.zip.cdx.json` | Keycloak SBOM: CycloneDX 1.7, 573 Maven components, full dependency graph; from a local 999.0.0-SNAPSHOT build with its Keycloak versions replaced by 26.8.2, so all artifacts resolve from Maven Central |

Prerequisite: sonar-cryptography's modules (`com.ibm:java`, `engine`, `mapper`, `enricher`, `output`, `rules`, `common` and the parent POM `com.ibm:sonar-cryptography`, all 1.7.0) aren't on Maven Central. Build them from source and install them into the local Maven repository once:

```
git clone --depth 1 --branch 1.7.0 https://github.com/cbomkit/sonar-cryptography.git
mvn -f sonar-cryptography/pom.xml install -pl java -am -DskipTests -Dspotless.skip -Dcheckstyle.skip -Dcyclonedx.skip
```

`-pl java -am` builds only the modules cbom-generator uses. That build still compiles against sonar-java, sonar-python and sonar-go (SSALv1), because sonar-cryptography's parent POM makes them dependencies of every module; so a person runs it, not an AI assistant. Alternatives: GitHub Packages with a `read:packages` token, if 1.7.0 is published there, or publishing the built JARs to a team repository.

Run:

```
mvn package
java -jar target/cbom-generator-1.0.0-SNAPSHOT-runner.jar <sbom.json> -o cbom.json [--work-dir DIR] [--classpath deps|all|none] [--threads N] [--rescan]
```

The build produces a single tree-shaken uber-jar. Tests:

```
mvn package         # unit tests
mvn verify          # plus integration tests on the runner JAR (SampleSbomIT)
mvn verify -Pe2e    # plus the Keycloak end-to-end test (resolves 548 JARs)
```
