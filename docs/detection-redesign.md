# Detection redesign (proposal)

Status: for discussion, 2026-11-08. Builds on the [architecture](architecture.md) and the [design review](design-review.md).

Replacing `DetectionStore` with an equivalent tree of our own would only re-implement sonar-cryptography's engine. This proposal goes further. It changes what detection produces, so that the design is simpler, faster and easier to extend to new libraries and patterns. It also lets the SonarSource libraries go away.

## What we keep and what we don't

sonar-cryptography carries two kinds of knowledge, and they have different value for us.

| Knowledge | Where | Value for bytecode analysis |
| --- | --- | --- |
| Which APIs are cryptographic, and what each argument means | the Java rule graph (`com.ibm:java`, `com.ibm:engine`) | High as data, but it is encoded for sonar-java's syntax trees |
| How to turn names like `"AES/GCM/NoPadding"` into a crypto model | the string mappers (`com.ibm:mapper`, `mapper.jca`, `mapper.bc`, `mapper.ssl`) | High, and independent of the engine: `IMapper.parse(String, DetectionLocation)` |
| OIDs, default key sizes, functions | `com.ibm:enricher` | High, works on the `INode` model |
| CycloneDX output of the model | `com.ibm:output` | Useful, works on the `INode` model |
| How detections attach to each other | the store tree, `ITranslator`'s traverser, 19 reorganizer rules | Low: it exists to bring tree-shaped detections into the model's shape |

The rule graph is large because it encodes context for AST matching:

- 2,563 distinct rules share only 515 distinct method keys;
- 18,862 edges go to depending-parameter rules;
- 94% of the rules match constructors;
- the asset name comes from the rule itself in 2,361 rules.

The reorganizer then corrects the shape that store-tree translation produces. In this design, both layers go away.

## The idea: API usage facts, an object graph, and specifications as data

Instead of matching rule trees, detection records **facts about crypto objects**. Specifications that we own, as data, say what each API call contributes.

```text
API spec (data, per API key: owner, name, descriptor)
  javax.crypto.Cipher#getInstance(String)                -> creates Cipher; arg0 = transformation (JCA cipher mapper)
  javax.crypto.Cipher#init(int, Key, AlgorithmParameterSpec)
                                                         -> on receiver; arg0 = operation; arg1 = key object; arg2 = parameters object
  javax.crypto.spec.GCMParameterSpec#<init>(int, byte[]) -> creates parameters; arg0 = tag length (bits)
  org.bouncycastle.crypto.engines.AESEngine#<init>()     -> creates block cipher "AES"
  org.bouncycastle.crypto.modes.GCMBlockCipher#<init>(BlockCipher)
                                                         -> creates mode "GCM" over the arg0 object

Facts (from the bytecode analysis)
  object #17 Cipher   created at Foo.java:42 getInstance("AES/GCM/NoPadding")
                      init(ENCRYPT, key #9, params #18) at Foo.java:45
  object #18 GCMParameterSpec  tag length 128
  object #9  SecretKey from KeyGenerator #8 ("AES", init 256)

Model (built from facts and specs)
  AES-256-GCM, encrypt, tag 128, key 256  @ Foo.java:42, 45
```

Three layers, each with one job:

1. **Facts extraction** (our analysis). For each call to an API in the specs, record:
   - the call site;
   - the argument values: constants, values from the caller, or the object a value refers to;
   - the receiver and the created object.

   Objects are identified by allocation site, and identity is followed across methods through parameters and returns. The result is an object graph of crypto objects with the events applied to each.
2. **API specifications** (data, owned by us). For each API key: whether the call creates an object or configures its receiver, the kind of object, and what each argument contributes (a property, through which mapper, or a link to another object). The specs live in a resource file, not in code. API families with unusual semantics, such as Bouncy Castle's `CipherParameters` hierarchy, can have a small handler in code.
3. **Model building**, in two parts:
   - **3a, detection from the specs**: done. `SpecDetector` builds the `DetectionStore` trees from the object graph (`SpecRule` carries the library and context from the spec; the `GCMParameterSpec` functions are rebuilt from their recorded result), and translation, reorganizer, enricher and output are unchanged. sonar-cryptography's rules are no longer loaded; `-Dcbom.engine=rules` keeps the rule-based detection for comparison until 3b. See the step 3a findings below.
   - **3b, the model from the object graph**: replacing the store trees, `ITranslator`'s traversal and the reorganizer. At this point the specs become hand-maintained and the exporter turns into the opt-in diff tool (see above).

## Why this is better

**Design**

- Detection knows nothing about rules, contexts, bundles or stores. It records facts. Crypto knowledge is in the specs, and modeling is in one place.
- Identity is explicit. Every property carries its evidence (call site, and whether it is a constant, a field or a caller's value). De-duplication and attribution use that evidence instead of names with stripped UUIDs and location prefixes (F5).
- Multi-valued arguments are explicit: a property can hold possible values with their sites, without splitting findings into variants (F1's workaround).

**Efficiency**

- One API index keyed by exact method key, with each owner's hierarchy resolved once. Today's 2,563-rule graph is matched per call; specs need one lookup per call.
- Analysis on demand. Calls into spec'd APIs are found from constant pools and invoke instructions without interpreting anything. Then only the methods that contain such calls, and the callers needed to resolve their arguments, are interpreted, using memoized method summaries (which parameter reaches which crypto argument, and what a method returns). Today phase A interprets all 88,000 Keycloak classes for up to 10 rounds, and the call index keeps 300,000 call sites in memory.

**Flexibility for new cases**

- A new library or API is a spec entry, not a rule graph in Java code. Libraries that sonar-cryptography doesn't cover would become spec entries: Google Tink, Conscrypt, Netty's `SslContextBuilder`, Spring Security's `PasswordEncoder`s, Keycloak's crypto SPI.
- The object graph covers patterns the rule trees can't: an object created in a factory method and configured by its caller (F7), keys linked to the algorithms they come from (`KeyGenerator` → `SecretKey` → `Cipher.init`), and protocol configuration spread over `SSLContext`, `SSLParameters` and `SSLEngine`.
- Each spec entry can be tested in isolation, with a compiled snippet and its expected model.

**Dependencies**

| Dependency | Today | After |
| --- | --- | --- |
| sonar-plugin-api (LGPL, provided) | `IScanContext` signature | gone |
| sonar-analyzer-commons (LGPL, shipped) | `MethodMatcher`, run while the rules load | gone: no rules are loaded |
| `org.sonar…tree.Tree` marker | lambdas in the rules | gone |
| `StoreAccess` in sonar-cryptography's package | building stores | gone |
| `com.ibm:java`, `com.ibm:engine` | rules and stores | gone at runtime; used once, to bootstrap the specs |
| `com.ibm:mapper`, `enricher`, `output` (Apache-2.0) | used | still used, for the model, the mappers, the enrichment and the output; replaceable later |

## Room for source analysis later

Bytecode is the primary input, but it loses things source code has:

- column positions, and the extent of expressions that span several lines;
- the names of `static final` constants, which javac inlines into the using class;
- branches javac removes as dead code;
- annotations with source retention;
- local variable names in JARs compiled without `-g`.

A later step may consult sources JARs, when they resolve, to make findings more precise. The design keeps that possible without building it now:

- **Facts have a stable identity**: artifact, class, method and bytecode offset, plus the line when there is one. A source analysis can attach refinements to that identity, such as a precise position, the name of the constant used, or an expression the bytecode lost, without changing how facts are extracted.
- **Fact sources are pluggable.** Facts extraction sits behind an interface. Bytecode is the first implementation; a source-based refiner can be added later and run where sources are available.
- **Specs are keyed by API method** (owner, name, descriptor), which bytecode and type-resolved source share. The same specs apply to both.

A source refiner must not use sonar-java or any other SSALv1 analyzer. Possible parsers include the JDK's own compiler tree API (`com.sun.source`, with type resolution against the artifact's classpath), JavaParser (Apache-2.0 or LGPL) and Eclipse JDT (EPL). The choice belongs to that step.

## Bootstrapping the specs from the existing rules

The specs don't have to be written from scratch. A one-time exporter, a test-scope tool kept in the repo, walks `JavaDetectionRules.rules()` and emits the spec resource. It records:

- each rule's method key;
- whether its action creates or configures (from the action factory and next rules);
- what its detectable parameters contribute (from the value factory kind and context);
- links to objects (from depending-parameter rules).

The exporter also reports what it can't express, which is the list of handlers to write. The exported specs are derived from Apache-2.0 code, so the spec file keeps sonar-cryptography's attribution, and the project's NOTICE names it. Nothing under SSALv1 is involved.

## Step 1 findings: the rules as specifications

Measured on 2026-11-08 by walking all 2,563 distinct rules of sonar-cryptography 1.7.0's `JavaDetectionRules`:

- **One entry per API method.** The rules cover 515 distinct API methods (owner, name, parameter types). Comparing each method across every rule tree it appears in, all 515 agree on:
  - the rule kind, exact or subtype matching, and the library (JCA, Bouncy Castle, SSL);
  - the action (for example, "this constructor is the AESEngine");
  - what each detectable argument means (its value factory, and whether it moves under a child);
  - which arguments link to other objects, and whether calls on the created object follow.

  Only the detection context differs, in 120 methods.
- **The context is mostly the API's own.** For 9,015 of 9,155 (parent link, child API) pairs (98.5%), the child has one context everywhere. Kinds such as `KeyContext.EC` for `ECGenParameterSpec` or `SecretKeyContext.DES` for `DESKeySpec` belong to the child. Where a parent changes the child's role, the role belongs to the parent's link: a digest used as MGF1 in OAEP or PSS, PSS parameters, a member of an asset collection, `DHParameterSpec` as a key or an algorithm parameter.
- **Some roles pass through wrappers.** The remaining 140 pairs all sit under pass-through wrappers. A digest inside `NonMemoableDigest` or `ShortenedDigest` takes whatever role the wrapper has, and an asymmetric engine inside an OAEP, PKCS#1 or ISO 9796-1 encoding is a signature engine when the encoding serves a signer. Conditioned on the parent's own role, every one of them is determined.
- **The nesting is a cross product.** For example, `GCMBlockCipher(BlockCipher)` lists all 54 block-cipher constructors as its argument's possible creators, and each mode repeats them. That accounts for the 18,862 depending-parameter edges. In the object graph, a link is the object actually passed, so the spec only says "argument 0 is a block cipher".
- **Root or nested.** 351 methods start a finding on their own (the root rules); 164 only contribute to another object, such as `Cipher.init`, `SecretKeySpec` or `AEADParameters`.

So the whole rule graph fits in 515 entries with 49 roles, instead of 2,563 rules and about 20,000 edges. A role is stated once for all objects linked through an argument where it applies to all of them; 12 apply only when the parent itself has a given role. For example:

```text
javax.crypto.Cipher#getInstance(String)                        JCA  Cipher        root  arg0: algorithm
javax.crypto.Cipher#init(int, Key, AlgorithmParameterSpec)     JCA  Cipher        on receiver  arg0: operation mode  arg1: link key  arg2: link parameters
org.bouncycastle.crypto.engines.AESEngine#<init>()             BC   Cipher        root  name: AESEngine
org.bouncycastle.crypto.modes.GCMBlockCipher#<init>(BlockCipher)
                                                               BC   Cipher        root  name: GCMBlockCipher  arg0: link block cipher
org.bouncycastle.crypto.encodings.OAEPEncoding#<init>(AsymmetricBlockCipher, Digest, Digest, byte[])
                                                               BC   Cipher        root  name: OAEPEncoding  arg0: link cipher  arg1: link digest  arg2: link digest (role: MGF1)
```

`SpecExporter` (test sources) writes them to `src/main/resources/crypto-api-specs.yaml`, about 8,800 lines, and `SpecExportTest` keeps the file in sync with the rules: it fails when they differ, and `-Dspecs.update=true` rewrites it. Its report (`target/spec-export-report.txt`) lists what doesn't fit; for 1.7.0 that is nothing: no API method whose rules disagree beyond the context, and no role that depends on more than the parent's link and role. Two entries, the `GCMParameterSpec` constructors, carry a rule-specific function (`factory: lambda`, producing the GCM mode) and need a handler in code.

### When the exporter runs

- **Until the new pipeline uses the specs**: on every build. The specs are derived data, and `SpecExportTest` keeps the file in sync with the rules (under a second); `-Dspecs.update=true` rewrites it.
- **From the switch on**: the specs become hand-maintained, the project's own knowledge base, with handlers, fixes and new libraries. The exporter then never rewrites the file. It becomes an opt-in diff tool: it exports the rules of a sonar-cryptography version and reports what differs from our specs (new API methods, changed roles, removed entries), to port by hand. It's run when evaluating a sonar-cryptography upgrade, which keeps `com.ibm:java` as a test-scope dependency. Upgrading it still means a person builds sonar-cryptography from source, since that build compiles against the SSALv1 analyzers. The exporter itself only runs the Apache-2.0 rule definitions.

A generated base with a hand-maintained overlay was considered and not chosen: it keeps regeneration safe, but needs merge rules for overriding, removing and extending entries, and splits the knowledge over two files.

## Migration, step by step

Each step is checked against the current output: the fixture baseline, `ReproducibilityIT`, `SampleSbomIT`, and a per-occurrence comparison of the Keycloak CBOM, where each difference is reviewed as an improvement or a regression.

1. **Spec exporter and coverage report**: done. All 2,563 rules map to 515 spec entries; see the findings above.
2. **Facts extraction and object graph**: done for objects within a method; see the step 2 findings below.
3. **Model building** with the mappers, enricher and output, replacing `Detector`, the store tree, `Translation` and the reorganizer once the comparison is reviewed. At this point the specs become hand-maintained and the exporter turns into the opt-in diff tool (see above).
4. **Drop the rule engine at runtime**: `com.ibm:java` and `engine` out of the runtime classpath, along with sonar-analyzer-commons, sonar-plugin-api, the `Tree` marker and `StoreAccess`.
5. **Analysis on demand** with method summaries, replacing the global call index.
6. **Object flow across methods** (F7), and new spec families.

Steps 1 and 2 change no output, so they can be judged on their reports before committing to the rest.

## Step 2 findings: the object graph carries what the rule trees carry

Measured on 2026-11-08; no output changed yet.

- **Spec matching is the rules' matching.** `ApiIndex` matches a call by method name, owner (exact, or a supertype) and parameters. A class-typed parameter matches its subtypes too, because APIs narrow parameters over time, for example Bouncy Castle's `ShortenedDigest(ExtendedDigest, int)` against a spec of `(Digest, int)`. Rules written without parameter types accept any (116 API methods, `(...)` in the specs). `ApiIndexTest` checks that, on every call site of Bouncy Castle's provider JAR, the specs match the same API methods as all 2,563 rules' `MethodMatcher`s.
- **The graph has every line of the trees.** `ObjectGraph` records the calls to specified APIs in a method and relates calls to objects they create or are invoked on. `FactsEquivalenceTest` reads both the current detection trees and the graph into the same lines: each value and action, with its path of argument indices, contexts (including the spec roles) and libraries, produced by sonar-cryptography's factories rebuilt from the specs (`SpecFactories`). On the fixtures and Bouncy Castle's JAR, 561 findings with 1,085 lines lose nothing. On Keycloak's 534 JARs, run once outside the build, 883 findings with 1,291 lines lose nothing.
- **What the graph gains.** Links to objects the rule trees don't list as possible creators: a `GMac` over a GCM cipher from `GCMBlockCipher.newInstance` over `AESEngine.newInstance()` (a fixture gap), keys from `SecretKeyFactory.generateSecret` passed to `Cipher.init` (four in Keycloak), and `KeyFactory.generatePrivate` on the factory from `getInstance`. Each changes the CBOM, so they're reviewed with model building.

## Step 3a findings: detection from the specs

Measured on 2026-11-08 with the same runner JAR, `-Dcbom.engine=rules` against the default:

- **The CBOM is the same but for one link gain.** Keycloak 26.8.2: 2,589 occurrences instead of 2,588, all others equal per occurrence. The new one is `CAST6-GCM` in Bouncy Castle's provider (`CAST6$GMAC`), and the GMac asset there (named `unknown` by sonar-cryptography's translation) now links to the 11 GCM ciphers it may be built on. The other graph gains of step 2 translate to the same assets as before. The fixture conformance is unchanged (241 of 284 expected issues, 10 unexpected), and so are the sample SBOM, reproducibility and Keycloak end-to-end tests.
- **Translation depends on the order of children.** A first run attached the calls on a created object in bytecode order: for xmlsec's PSS signature verification, `setParameter` came before `verify`, and translation then reported SHA-256, MGF1 and the salt length as three assets instead of one signature. sonar-cryptography's traversal attaches nodes in order and merges into nodes that already exist. The specs now keep `next` in rule order and `SpecDetector` attaches in that order. Model building from the object graph (3b) should not depend on order.
- **Phase A keeps slightly fewer methods**: 1,926 instead of 1,958, since only calls to root APIs can start a finding, while the rule pre-check accepted any call passing a root rule's owner check.

## Open questions and risks

- **Semantics hidden in the rule graph.** `shouldBeMovedUnder`, contexts and depending rules sometimes encode modeling decisions, for example which node a size belongs to. The exporter has to translate them into spec properties, and its report shows where it can't.
- **Equivalence is a review, not a test.** The new model may be more precise than the reorganized store trees, so differences need judging. The fixture annotations (`// Noncompliant {{...}}`) stay the reference for what sonar-cryptography expects.
- **The `INode` model and `DetectionLocation`** still come from sonar-cryptography (Apache-2.0). `DetectionLocation` carries an `IBundle`, a small engine type, as the library tag. Replacing the model and the output with our own would remove `com.ibm` entirely; that is a later, separate decision.
- **Effort.** Steps 1 and 2 are days; step 3, with the review of differences, is the largest. The current pipeline stays the default until the new one is accepted.
