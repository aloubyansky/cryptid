# Foundation: model, API and endpoints

Status: review and proposal, 2026-11-26. It places foundation work before reachability step 3 of the [roadmap](roadmap.md). It builds on the [architecture](architecture.md), the [design review](design-review.md) and the [reachability design](reachability-design.md).

## Why

The roadmap builds four things on top of what exists:

- reachability from entry points;
- `provides` against `dependsOn`;
- a library with a CLI and a Quarkus extension on top;
- independence from sonar-cryptography.

All four need the same things:

- a result model of our own, with identity that is explicit rather than parsed back out of strings;
- an analysis API that callers other than the CLI can use;
- one model of the analyzed program.

Each of these is easier to build now than after reachability has been built on today's shapes.

This review also adds a goal the reachability design doesn't have. It traces crypto use from the application's **endpoints**, the points through which external users interact with it, so that a CBOM can say which crypto each endpoint exercises.

## What holds

These stay as they are:

- **Packages depend one way**: `bytecode` ← `spec` ← `detection` ← `model` ← `scan` ← CLI, with no cycles. `bytecode` and `spec` use no sonar-cryptography types.
- **Specs are data**: versioned YAML (`CryptoApiSpecs`), with the matching separate (`CryptoApiMatcher`).
- **The call graph** (`CallGraph`) is compact, with interned ids, and knows nothing about crypto.
- **The safety net**: the equivalence, conformance and reproducibility tests and the Keycloak comparison.

## Gaps

### G1. There is no result model; identity is held in strings

Results pass through four shapes:

1. `CallSite`, the bytecode fact;
2. `CryptoEvent`, the detection tree;
3. `INode`, sonar-cryptography's model;
4. a per-JAR CycloneDX `Bom`, written as JSON, read back and merged by `CbomAssembler`.

Along the way, identity is reduced to strings and later rebuilt from them:

- **The artifact** is folded into the location: `locationPrefix + "/" + sourceFile`. `CbomAssembler.owner()` splits the location again to find the owning component.
- **Assets** are de-duplicated by content: serialized to JSON with random UUIDs stripped by regular expressions (`AssetCollector.contentKey`). This works around sonar-cryptography's output generating random bom-refs.
- **The location of a finding** (`Loc`) holds the file, line and called method. It has no artifact, no enclosing method and no bytecode offset. For a value resolved from a caller, the enclosing method exists in `CallIndex.Site.callerMethod`, but is dropped when the `Loc` is made.

Reachability needs each occurrence's enclosing method in the program model, and a mark on the occurrence. `provides` needs a decision per finding. The Quarkus extension needs results in memory. On today's shapes, all three would be done on CycloneDX components, matched by location strings. This gap is the design review's F5, with the `Site` it proposed.

### G2. sonar-cryptography's types sit at the centre of detection

`CryptoEvent` stores sonar-cryptography's engine types: `IValue<Loc>`, `IAction<Loc>`, `IDetectionContext` and `IBundle`. `Loc` implements sonar's `Tree` marker.

Replacing `engine` (roadmap, *Independence from sonar-cryptography*) would therefore rewrite the detection core. If events held values of our own (the spec argument, the constant, the site), the translation into sonar-cryptography's types would happen in `model` alone. The replacement would then touch one package.

### G3. The orchestration lives in the CLI command

`GenerateCbomCommand` does all of the following:

- groups components and resolves their JARs;
- creates the `CallIndex` and the `CallGraph`;
- runs phase A and calls `finish()` on both;
- hands each JAR's `CandidateMethods` from phase A to phase B;
- reads and writes the cache;
- assembles the CBOM.

`BytecodeScanner.index` and `scan` take six or seven positional parameters, and their callers must follow the phase protocol. Reachability adds another whole-program phase: entry points, instantiated classes and the walk. A Quarkus extension would have to repeat all of this.

The input is also tied to the SBOM. `MavenComponent` carries a bom-ref and the SBOM's component, which an extension doesn't have.

### G4. Two class hierarchies and two kinds of method identity

There are two class hierarchies:

| | `Types` | `Hierarchy` |
| --- | --- | --- |
| Built | per JAR | once, over all analyzed classes |
| Classes from | JARs and `jrt:/` | the analyzed classes |
| JARs it sees | the `--classpath` mode decides | all; of duplicates, the first artifact's copy |
| Used for | matching specs | dispatch |

In one run, matching and dispatch can see different class sets. `Types` also parses class files that the analysis has already read.

There are also two kinds of method identity. `CallIndex`, `CallSite.method` and `MethodFacts` use `owner.name+descriptor` strings, while `CallGraph` interns ints. Joining findings to the graph means converting between the two. The reachability design already calls for "a compact method identity".

### G5. The cache sits at the wrong layer

Since 2026-11-26 the cached per-artifact CBOMs are invalidated by any change to the SBOM, which is correct, since each depends on all the JARs. The cache therefore only helps an exact rerun. Reachability's walk runs on every invocation anyway.

The layer worth caching is per-artifact facts, keyed by each JAR's content:

- class infos;
- graph facts;
- matched annotations and services;
- interpreted call sites, later.

The reachability design proposes this for graph facts.

### G7. Phase A interprets the whole program for a few questions

On Keycloak, phase A takes about 15 of the run's 17 seconds (2026-11-27). It interprets all 737,718 methods, some JARs up to 10 rounds until their field values settle, and keeps 305,906 calls in `CallIndex`. Detection then runs on 2,535 candidate methods, and asks the index only about the methods whose parameters reach a spec argument.

Not all of phase A depends on detection in the same way:

| Job | Needs interpretation? | Needed for |
| --- | --- | --- |
| class hierarchy | no, read from class headers | matching and dispatch |
| call graph | no, read from instructions (about 4 s with the hierarchy) | reachability, which needs the whole program |
| candidate methods | no; the instructions show which methods call a specified API | detection |
| value index | yes, every method | which constants reach a parameter |

The cost is in the value index, and the value index is the part that can be driven by detection. See *Detection-driven analysis* below.

### G6. Smaller issues

- Nearly everything is `public` because packages use each other, so nothing marks what the API is.
- `Analyzer.failedMethods` is a mutable public field.
- The specs load from one hard-coded resource (`CryptoApiSpecs.load()`). Entry-point and bean specs, and specs a user adds, need the same loading from several sources.

## Endpoints as origins of crypto use

### What is asked

The reachability design marks each finding as reached or not, and keeps the first entry point it was reached from. That answers "is this crypto used?". Two more questions matter to whoever secures or migrates an application:

- **Per endpoint**: which crypto does `POST /realms/{realm}/protocol/openid-connect/token` exercise? This tells a reviewer what an external caller can make the application do, and which endpoints a migration affects.
- **Per finding**: which endpoints reach it? There may be many, not just the first one found.

So the result model must relate endpoints to findings **many to many**, even if the first version computes only part of that relation.

### Entry points and endpoints

An *entry point* is any method called from outside the analyzed code. An *endpoint* is an entry point through which an external party interacts with the application. The difference is the entry point's **exposure**:

| Exposure | Kinds | Examples |
| --- | --- | --- |
| external | `http`, `grpc`, `websocket`, `messaging` (from a broker), `servlet` | JAX-RS and Spring resource methods, gRPC services, `@ServerEndpoint`, `@Incoming`, `HttpServlet.doPost` |
| internal | `scheduled`, `lifecycle`, `observer`, `main` | `@Scheduled`, `@Startup`, `@Observes StartupEvent`, `main` |

Exposure is a property of the entry-point spec, kept as data like the kind. Messaging is external or internal depending on the broker, so its default is external, and a caller supplying entry points can override it.

An endpoint carries what the bytecode tells about it:

- the **protocol** and its **address**: the HTTP method and path template from `@Path` on the class and the method, the gRPC service and method, the channel name;
- the **handler** method, as a method id in the program model;
- whether it is **authenticated**, where an annotation says so (`@RolesAllowed`, `@Authenticated`, `@PermitAll`, Spring's `@PreAuthorize`). A missing annotation means unknown, not unauthenticated: security is often configured outside the code, in Keycloak itself for example.

Supplied entry points (the Quarkus extension, `--entry-points`) carry the same fields. A Quarkus build knows the full HTTP paths, including the root path and any sub-resource locators the bytecode leaves incomplete.

### Computing the relation

One walk per endpoint over Keycloak's graph (737,732 methods) is too slow with hundreds of endpoints. Two passes avoid that:

1. **Instantiated classes**, once, over all entry points. This is the reachability design's forward fixpoint, which decides which implementations a virtual or interface call may dispatch to. Its result is the call graph with dispatch resolved.
2. **Endpoint sets**, propagated over the resolved graph.
   - Each entry point gets an index, and each method a bitset of the entry points that reach it. A method's set is the union of its callers' sets, computed to a fixpoint. Strongly connected components can be collapsed first.
   - Only the sets of methods that contain an occurrence are kept for the result.
   - At about 1,000 entry points, the bitsets of all methods take about 125 bytes each, roughly 90 MB for Keycloak's graph. With methods that reach no finding pruned first, it is less.
   - These figures are estimates, to be measured.

The first version may stop after pass 1, with one path per finding, as the reachability design plans. The model below already holds sets, so pass 2 adds no change to the model.

### In the CBOM

CycloneDX has a place for endpoints: `services`. The cyclonedx-core-java model in use (12.2.0, through sonar-cryptography's output module) has `Service` with:

- `endpoints`, the URLs or path templates;
- `authenticated`;
- `trustZone` and `x-trust-boundary`;
- data flows;
- `properties`.

So:

- each endpoint, or each group of endpoints on one resource class, becomes a service of the metadata component;
- a service `dependsOn` the crypto assets it reaches;
- the protocol, the kind and the handler method go into `properties`.

This states the endpoint-to-crypto relation in CycloneDX's own terms instead of in cryptid properties on assets. Whether endpoints are grouped per method or per resource class, and how big this makes Keycloak's CBOM, are *(open)* until there is real output to look at.

### Scope

- Endpoints are found from code only. Routes registered in code (`router.post("/x").handler(...)`) need the "function passed to this API" form, which the reachability design leaves for later.
- Nothing about whether an endpoint is reachable from the network: ports, proxies and configuration are deployment facts.
- No data-flow tracking from request parameters to crypto arguments. "Which endpoint lets a caller choose the algorithm" is a later question. The model's sites and values leave room for it.

## Detection-driven analysis

Replaces the value index (G7) with questions detection asks, answered on demand. This is the "analysis on demand" of the [detection redesign](detection-redesign.md), step 5.

### Stages

1. **Read every JAR's instructions, without interpreting them.** This gives:
   - the class hierarchy;
   - the call graph;
   - the candidate methods, those calling a specified API;
   - the field writers, meaning which methods store into which fields.

   Whole program, cheap.
2. **Detect per JAR, on its candidate methods.** Interpret the candidates, the writers of the fields their values come from, and the methods whose returned constants they use.

   Wherever a spec argument comes from a parameter of its method, or from a field stored from a parameter, detection records an **open question** instead of resolving it on the spot. The question holds the method, the parameter bits, and the spec argument with its context and value factory.

   The result depends on the JAR and its classpath only.
3. **Answer the open questions across JARs.**
   - Find each method's callers through the call graph's edges in reverse.
   - Interpret only those callers, each once, with the result remembered.
   - Take their constants, and climb further where a caller passes its own parameter or a stored field on, as `CallIndex.resolve` does today, up to 6 calls away.
   - Each answer is a finding located at the caller, as now. It is skipped when the caller's call is itself a finding of a root API.

### What it buys

- **Time and memory.** Only candidates, the callers they ask about, and the field writers and callees those depend on are interpreted. The 306,000-call index goes away.
- **Results that can be cached per JAR.** Stage 2 depends on one JAR and its classpath alone, so its result can be kept by the JAR's content (G5). Only stage 3, a much smaller job, depends on the whole SBOM. Today any changed JAR invalidates every cached result.
- **Detection without whole-program state.** Resolving at callers becomes a stage of its own instead of a side effect of `CryptoEventDetector`, which then works on one JAR.

### Risks

- **Field values.** Today each JAR runs a field fixpoint over all its methods. On demand, a field's value needs the methods writing it, found from their instructions. Their values may come from their own parameters, which raises more questions.
- **Returned constants** (`Analyzer.returnedBy`) need summaries of the callees, computed on demand.
- **Order.** Questions must be answered in an order independent of threads, so that results are the same in every run.

### The check

The output must be identical to today's, per occurrence, on the fixtures, Bouncy Castle and Keycloak. A difference is a bug, not a judgment call. Each stage can also be compared with the current pipeline on its own: the candidate methods, the open questions, and the answers against `CallIndex.resolve`.

## Target model

```text
Input
  Artifact(id, coordinates, jar, dependencies: [ArtifactId], topLevel)
  EntryPointInput(method, kind, exposure, address?, authenticated?)    // supplied, optional
  Options(classpath mode, specs sources, limits)

Program model (bytecode, whole program, no crypto knowledge)
  ClassTable      one table of analyzed classes, plus a JDK fallback; serves spec matching and dispatch
  MethodId        an int interned once; CallSite, CallIndex, CallGraph and findings all use it
  CallGraph       edges, instantiations, method handles; resolved dispatch after the fixpoint

Result model (ours; CycloneDX only at the edge)
  Site(artifact, method: MethodId, line, offset, called API)          // where an occurrence is
  Finding(site, event, variant, role: uses | provides)
  Asset(content key, nodes: INode, for now)                           // identified by content, not JSON
  Occurrence(asset, site, finding)
  EntryPoint(id, method, kind, exposure, address?, authenticated?, source: detected | supplied)
  Reachability(per occurrence: reached-by entry point set, or unknown; one path on request)
  Report(artifacts, assets, occurrences, entry points, reachability, statistics)

Output
  Report -> CycloneDX: assets and occurrences; components and dependencies;
            services for endpoints, dependsOn the assets they reach
  Report -> cache: per-artifact facts, keyed by JAR content
```

Two notes on the model:

- **Asset content** is still `INode` until the sonar-cryptography step. Its key is computed from the nodes, not from their CycloneDX JSON: name, kind and properties, recursively, without the generated ids.
- **Events** (G2) hold values of our own: the spec argument, the constant and the `Site`. `model` translates them into sonar-cryptography's `IValue` and contexts.

## Phase 1 API (decided 2026-11-26)

The result model replaces `Site`, `Asset`, `Occurrence` and `Report` of the sketch above with these names, all in the root package `io.github.aloubyansky.cryptid`. The CLI moves to `io.github.aloubyansky.cryptid.cli`.

```java
record ArtifactCoordinates(String groupId, String artifactId, String classifier, String type, String version) {
    ArtifactKey key();               // GACT, without the version
}
record ArtifactKey(String groupId, String artifactId, String classifier, String type) {}
record MethodId(String className, String name, String descriptor) {}   // binary class name
record CodeLocation(ArtifactCoordinates artifact, String sourceFile, MethodId method,
                    int line, MethodId invokedMethod) {}               // line 0: no line table
record AssetOccurrence(CodeLocation location) {}
final class CryptoAsset {            // identified by name and properties
    String name(); CryptoAssetProperties properties();
    List<AssetOccurrence> occurrences(); List<CryptoAsset> dependsOn();
}
sealed interface CryptoAssetProperties {    // Algorithm, RelatedMaterial, Protocol; own enums
    String oid();
}
record CipherSuite(String name, List<CryptoAsset> algorithms, List<String> identifiers) {}
record ArtifactAnalysis(ArtifactCoordinates artifact, int classes, int findings, int failedMethods) {}
record CryptoInventory(List<ArtifactAnalysis> artifacts, List<CryptoAsset> assets) {}
```

The choices behind it:

- **Properties are our own types, not CycloneDX's `CryptoProperties`.** Records give the content key as `equals`, without JSON and stripped UUIDs. Links are to objects, not bom-refs. The API doesn't follow cyclonedx-core-java's versions or the schema's changes from 1.6 to 1.7. Library users don't need cyclonedx-core-java to read results. The closed value sets are enums, mapped by name to CycloneDX's.
- **`ArtifactCoordinates`, not `ArtifactCoords`.** Quarkus has its own `ArtifactCoords`, which the extension sees too.
- **`MethodId`.** The internal interned int of phase 3 is then a *method index*.
- **No instruction index in `CodeLocation` yet.** Reachability needs only the method, and the instruction index would change which occurrences count as one. It comes with the backlog's *Positions*.
- **Assets are merged by content across all artifacts.** On Keycloak this makes 1,270 components 725, each linked from every artifact it occurs in. `dependsOn` is the union over an asset's occurrences, as within a JAR before, and grows a little (the generic `secret-key`: 160 → 192 algorithms). Dependencies per occurrence ("this secret key at `Foo.java:42` is for AES") are a later refinement.
- **Bom-refs and the `@` suffix of names** are derived from the content, so they are the same in every run.
- **`CryptoInventory.Builder`** creates assets and links them. After merging by content, assets can depend on each other in cycles, so an asset can't be complete when it is constructed. Per-artifact results and the merge over all artifacts both use it. Added during implementation, with the convenience factory `ArtifactCoordinates.jar(groupId, artifactId, version)`.
- **An occurrence is identified by its whole `CodeLocation`**, including the enclosing method and the called method. Before, the same asset at the same file and line was one occurrence. The CBOM writes the enclosing method as the occurrence's `symbol`, as `class#name(descriptor)` like `additionalContext`, so that occurrences in different methods of a class without line numbers can be told apart.

Measured on Keycloak 26.8.2, against the build before (2026-11-27):

- Every occurrence of before is still there, and the set of (asset content, location, line) is the same: 3,920 on both sides.
- 4,320 occurrences instead of 3,920. 182 are the same asset on the same line from another call, which was merged before. 218 are in other methods of the same file, 215 of them in bcprov, which has no line numbers.
- 725 asset components instead of 1,270, still linked from the same 77 SBOM components; 1,847 dependency links instead of 2,209.
- The same time and memory: 16.7 s, about 9 GB RSS.

## Analysis API

The input and the result are the library's API. Everything else is internal:

```java
Report report = Cryptid.analyze(artifacts, Options.defaults()
        .entryPoints(supplied)          // optional; added to or replacing detection
        .cache(cacheDir));              // optional
```

- The CLI turns an SBOM into `Artifact`s, resolves the JARs, calls `analyze` and writes the CycloneDX output.
- The Quarkus extension builds `Artifact`s from the application model and `EntryPointInput`s from the build, and calls the same method.
- The phase protocol of G3 (index, finish, candidate methods, scan) moves behind `analyze`.
- Within the single module, the API lives in its own package, and the internal packages lose `public` where they can. The module split (roadmap) then moves packages without changing the API.

## Order of work

Each step keeps the per-occurrence Keycloak CBOM unchanged, except where a step says it changes output.

1. ~~**Result model and in-memory assembly** (G1, G6).~~ Done 2026-11-27, as decided in *Phase 1 API*.
2. **Analysis API** (G3). `Artifact`, `Options`, `Cryptid.analyze` and the result; `GenerateCbomCommand` becomes an adapter; the API package is the only public surface.
3. **One program model** (G4). One class table serving both matching and dispatch, with the `--classpath` modes expressed as a view on it, and an interned method index used throughout. This changes output if the hierarchies disagreed somewhere, and each difference is reviewed.
4. **Detection-driven analysis** (G7, G5). The three stages above. Stage 2's results are cached by JAR content, replacing the per-artifact cache keyed by the whole SBOM. Output identical.
5. **Entry points and endpoints**: the reachability design's step 2, with exposure, addresses and authentication in the specs and in `EntryPoint`.
6. **Reachability**: the reachability design's step 3, pass 1, on the model above.
7. **Endpoint sets and services**: pass 2 and the CycloneDX services.
8. **Events in our own values** (G2): the first part of the sonar-cryptography step.

Step 4 needs step 3: it uses the method index and the call graph's reverse edges. Steps 5 to 7 build on what steps 3 and 4 leave of phase A: the instruction-level hierarchy and call graph. Step 8 is independent of 4 to 7.

## Open questions

- Endpoints in the CBOM: one service per handler method or per resource class, and the size of the result on Keycloak.
- The default exposure of messaging entry points, and whether CDI observers of HTTP events count as external.
- Which authentication annotations to read, and how to report security configured outside the code.
- Whether endpoint sets (pass 2) stay within the reachability time target of a minute on Keycloak.
- The asset content key without JSON: whether `INode` exposes enough (kind, value, children) to compute it, or whether it has to wait for the model of our own.
