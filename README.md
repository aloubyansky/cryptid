# cryptid

cryptid generates a CBOM (Cryptography Bill of Materials) from an SBOM. Give it a CycloneDX SBOM of a Java application, and it resolves the JAR of every Maven component, analyzes their bytecode for uses of cryptographic APIs, and writes a CycloneDX 1.6 CBOM listing the algorithms, keys and protocols the application uses, where it uses them, and which component each belongs to.

- Works on binary JARs, so no sources are needed.
- Knows the JCA/JCE and JSSE APIs and Bouncy Castle's lightweight API: 515 API methods, described as data in [`crypto-api-specs.yaml`](src/main/resources/crypto-api-specs.yaml).
- Follows values through a method (constants, fields, string concatenation) and from callers to the crypto call, across JARs and through interfaces, and reports a value where it's chosen.
- Links each asset to the SBOM component it's found in.

A Keycloak distribution's SBOM (548 JARs, 88,000 classes) takes about 20 seconds and gives 792 crypto assets with 2,589 occurrences in 74 components.

## Building

Requirements: Java 17 or later, and Maven 3.9.

cryptid uses modules of [sonar-cryptography](https://github.com/cbomkit/sonar-cryptography) (Apache-2.0) for its crypto model, which aren't on Maven Central. Install them into your local Maven repository once:

```shell
git clone --depth 1 --branch 1.7.0 https://github.com/cbomkit/sonar-cryptography.git
mvn -f sonar-cryptography/pom.xml install -pl java -am -DskipTests -Dspotless.skip -Dcheckstyle.skip -Dcyclonedx.skip
```

That build compiles against SonarSource's analyzers, which are under the Sonar Source-Available License (SSALv1). cryptid itself doesn't use or ship them, and they must not be added to it; see [Licensing](#licensing).

Then build cryptid:

```shell
mvn package
```

This produces `target/cryptid.jar`, a single executable JAR.

## Usage

```shell
java -jar target/cryptid.jar app.cdx.json -o cbom.json
```

| Option | Meaning |
| --- | --- |
| `SBOM` | the input CycloneDX SBOM, JSON or XML |
| `-o`, `--output` | the CBOM to write (default: `cbom.json`) |
| `--work-dir` | a directory for the per-artifact results; reusing it skips artifacts analyzed before (default: a temporary directory) |
| `--rescan` | analyze artifacts again even if `--work-dir` has results for them |
| `--classpath` | where to look up supertypes of analyzed classes: `deps` (the component's dependencies from the SBOM graph; the default), `all` (every JAR of the SBOM) or `none` |
| `--threads` | threads resolving and analyzing artifacts (default: the number of CPUs) |
| `-h`, `--help` | show the options |

JARs are resolved from your local Maven repository and the repositories in `~/.m2/settings.xml`, Maven Central by default. Components that aren't Maven JARs, or that can't be resolved, are skipped and reported in the log:

```text
INFO  Found 5 Maven components in sample-sbom.json
INFO  Resolved 4 of 5 artifacts
INFO  Loaded 515 crypto API specs
INFO  Indexed 20925 calls between 4352 classes in 3626 ms; 1153 methods may contain crypto events
INFO  Analyzed 4 artifacts (4352 classes), 0 reused from the work directory, 0 failed
INFO  2 of 4 analyzed components contain cryptographic assets
INFO  Wrote CBOM to cbom.json: 1386 findings in 2 components, total time 4s
```

Analyzing large SBOMs needs a few GB of heap; Keycloak's peaks at about 5.5 GB.

### The CBOM

The CBOM's `metadata.component` is the SBOM's root component. `components` lists every SBOM component with crypto assets, and the assets themselves. `dependencies` links each component to its assets, and assets to the assets they use, such as an algorithm to its key. An asset looks like this:

```json
{
  "type": "cryptographic-asset",
  "name": "SHA-256",
  "evidence": {
    "occurrences": [
      {
        "location": "commons-codec/commons-codec/1.17.1/org/apache/commons/codec/digest/Sha2Crypt.java",
        "line": 114,
        "additionalContext": "org.apache.commons.codec.digest.Sha2Crypt#sha2Crypt([BLjava/lang/String;Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;"
      }
    ]
  },
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": { "primitive": "hash", "parameterSetIdentifier": "256", "cryptoFunctions": ["digest"] },
    "oid": "2.16.840.1.101.3.4.2.1"
  }
}
```

An occurrence's `location` is the artifact path (`groupId/artifactId/version`) followed by the source file, as recorded in the class file. `line` is missing when the class has no line numbers. `additionalContext` is the method called there: the crypto API, or, where the value comes from a caller, the method the caller passes it to (here, `Sha2Crypt.java` line 114 calls `sha2Crypt` with `"SHA-256"`).

### Limitations

- Only Java bytecode, and only the APIs in the specs (JCA/JCE, JSSE, Bouncy Castle). Other libraries, such as Google Tink or Conscrypt, need spec entries.
- Values computed from a parameter (for example `"AES/" + mode`) or returned by other methods aren't resolved. Objects are followed within a method only: a `Cipher` created in one method and initialized in another loses its `init` details.
- Where a value can be one of several constants, each one is reported, since the analysis doesn't follow branches.
- Certificates aren't reported.

## Testing

```shell
mvn package         # unit tests
mvn verify          # plus integration tests that run the JAR on sample SBOMs
mvn verify -Pe2e    # plus the Keycloak end-to-end test (resolves 548 JARs, needs about 8 GB)
```

The tests include:
- sonar-cryptography's own Java test files, compiled and checked against a baseline (`FixtureConformanceTest`);
- a comparison with sonar-cryptography's rule-based detection, which the specs were exported from (`PipelineEquivalenceTest`);
- reproducibility across runs (`ReproducibilityIT`).

## Project layout

| Package (`io.github.aloubyansky.cryptid`) | Contents |
| --- | --- |
| root | the CLI (`GenerateCbomCommand`), SBOM reading, artifact resolution, CBOM assembly |
| `scan` | `BytecodeScanner`: analyzes a JAR, in two phases (an index of calls across all JARs, then detection) |
| `model` | `CryptoAssetModeler`, `AssetAssembler`: turn detected events into crypto assets |
| `detection` | `CryptoEventDetector`, `CryptoObjectGraph`, `CryptoEvent`: crypto objects and the calls on them |
| `spec` | `CryptoApiSpecs`, `CryptoApiMatcher`: the API specs and matching calls to them |
| `bytecode` | `Analyzer`, `CallIndex`: the abstract interpretation of bytecode |

The specs in `src/main/resources/crypto-api-specs.yaml` were exported from sonar-cryptography's Java detection rules by `RuleSpecExporter` (test sources); `RuleSpecExportTest` keeps them in sync.

More detail:
- [Architecture](docs/architecture.md): the pipeline, input and output, integration with sonar-cryptography, what the JAR contains;
- [Detection redesign](docs/detection-redesign.md): the specs and object model, and the migration to them;
- [Design review](docs/design-review.md): findings, the refactoring plan and the backlog.

## Licensing

cryptid uses these modules of sonar-cryptography 1.7.0 (Apache-2.0): `com.ibm:java` (context translators, reorganizer rules), `engine` (value and context model), `mapper`, `enricher` and `output`. `crypto-api-specs.yaml` is derived from its Java rules and carries its attribution. The test resources include 129 of its Java test files, with its license and notice (`src/test/resources/sonar-cryptography-fixtures/`).

No SonarSource analyzer is used or shipped. sonar-java, sonar-python and sonar-go are under SSALv1, whose terms exclude, among others, using artificial intelligence technology with them. sonar-cryptography's parent POM makes them dependencies of every module, so `pom.xml` excludes them explicitly. Two SonarSource libraries under LGPL-3.0, `sonar-analyzer-commons` and `sonar-plugin-api`, are test dependencies only, for the rule-based reference.

The runner JAR contains one class in a SonarSource package name, the empty interface `org.sonar.plugins.java.api.tree.Tree`. It's this project's own code, needed by the tests that run sonar-cryptography's rules.

A third-party notices file for distribution is still to be written.
