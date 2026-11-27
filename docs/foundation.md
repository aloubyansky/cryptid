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

### Design (2026-11-27)

**What a method's values depend on.** `Analyzer` gives a field the union of every store into it within the JAR, and a call to an exact method (static, private, final, or in a final class) the constants that method returns. Both come from a fixpoint over the whole JAR, of at most 10 rounds. Since `Analyzer` runs per JAR, neither follows a value into another JAR, though programs pass values between JARs all the time (see *Closures across JARs* below). Within that behaviour, the values a method reads depend only on:

- the writers of the fields it reads;
- the exact methods of the same JAR it calls;
- transitively, the same for those methods.

Interpreting that **closure** to the same fixpoint gives every method in it the values it has today. The one exception is a JAR that hits the 10-round cap today: a smaller closure may converge where the whole JAR didn't. Implementation counts such JARs, and none is expected on Keycloak.

**Measured on Keycloak**, with the closures computed from instructions only:

| | Methods |
| --- | ---: |
| Interpreted today, in phase A | 777,498 |
| Stage 2: the closure of the 2,526 candidate methods | 8,078 |
| Stage 3: the closure of the 544 callers the 517 questions visit today | 1,904 |

Stage 3 will visit more callers than today's index lists. The call graph also has callers whose arguments don't resolve, which the index never recorded. Their count is the same order of magnitude.

**Stage 1, read.** As in phase A's read pass today, plus two more things:

- **Per JAR, a method's dependencies:** fields read, fields written, and exact callees within the JAR. These are kept until the JAR is detected, then dropped.
- **Call edges kept apart from method handles**, so that stage 3 interprets only real callers.

**Stage 2, detect per JAR.**

- Interpret the closure of the candidate methods, and detect on the candidates.
- A spec argument that comes from a parameter or a stored field becomes an **open question**:
  - the method and parameter bits, or the storing method and parameter;
  - the spec, its context, the argument and the value factory, all by reference to the specs;
  - the location of the call.
- Everything else becomes findings, modeled into assets as today.

**Stage 3, answer the questions across JARs.** For each question:

1. Find the callers through the call graph's reverse edges. These are calls to the method, or to the same method declared in a supertype, as `dispatchSources` does today.
2. Interpret each caller's closure in its own JAR, once, with the result kept for the duration of stage 3.
3. Take the constants at the asked argument positions. Ask again where a caller passes its own parameter or a stored field on, up to 6 calls away, with visited methods skipped.
4. Order the callers as `CallIndex` orders its sites: by file, line, calling method and signature.

Each answer is modeled into a finding located at the caller, and skipped where the caller's call is itself a finding of a root API. All of this is as today.

**Caching stage 2 by validation.** A JAR's stage-2 result depends on other JARs in two ways:

- spec matching resolves supertypes through the class table;
- a static field of a class outside the analysis becomes its name as a constant.

So the result is stored with what it consulted outside the JAR: every class it looked up, and whether it was analyzed, with the class info it resolved to. It is reused when:

- the JAR's content is the same;
- cryptid's build and the JDK version are the same;
- every class consulted resolves to the same info now.

That replaces today's key over the whole SBOM: changing one JAR re-detects that JAR and those that consulted its classes. Stage 3 is not cached; it is small and depends on the whole SBOM.

**Closures across JARs, a follow-up.** Today values cross JARs in only one way: an argument passed into a parameter, which `CallIndex` follows. The other ways aren't followed:

| How a value crosses JARs | Today |
| --- | --- |
| an argument passed into a parameter, e.g. `lib.digest("SHA-256")` called from the app | followed, up to 6 calls away |
| a field of a class in another JAR, e.g. lib reading a field that the app's code sets | not followed: unknown |
| a constant returned by an exact method of another JAR, e.g. a lib's static mapping method | not followed: unknown |
| a static field of a class outside the analysis, e.g. of the JDK or bc-fips | the field's name, which the mappers recognize |
| a compile-time constant, `static final String X = "AES"` | nothing to follow: javac copies the value into the using class |

Following the others was too expensive while every method of the SBOM had to be interpreted to one fixpoint. With closures it isn't: a closure continues into another JAR, with the writers of a field read there and the exact method called there, and only those methods are interpreted.

This comes after the steps below, which reproduce today's behaviour exactly and so can be checked exactly. It changes output, with new findings and more precise values, and each difference is reviewed. The stage-2 cache then also records the methods of other JARs a result depended on.

**Steps**, each checked by identical output:

1. ~~Closures: interpret a set of methods to a fixpoint with the same values as the whole JAR.~~ Done 2026-11-27: `Analyzer.closure` and `Analyzer.analyze(methods)`. `ClosureEquivalenceTest` compares, for every candidate method, its call sites and returned value with those of interpreting the whole JAR, origins compared by where they are. Bouncy Castle's provider and PKIX JARs are compared in the build. Keycloak's 534 JARs, run with `-Dclosure.jars`: 0 mismatches, and no JAR reaches the 10-round cap.
2. ~~Stage 3 on the call graph, next to `CallIndex`, with the answers compared on Keycloak.~~ Done 2026-11-27:
   - `DemandCallIndex` finds the call sites reaching a method through its callers in the call graph. `CallGraph.callers` holds real calls of every copy of a method, not method handles.
   - Each caller is interpreted as a closure in every artifact holding its class, since `Hierarchy.artifacts` lists shaded copies too.
   - It shares `CallIndex`'s resolution, behind the `CallResolver` interface detection now takes.
   - `DemandCallIndexEquivalenceTest` asks both indexes every question detection asks, and scans every JAR with each. Bouncy Castle's three JARs are compared in the build.
   - Keycloak, with `-Dclosure.jars`: all 233 distinct questions get the same 1,235 hits, and every JAR's scan the same assets, in the same order. Answering them interprets 3,802 methods, reading artifacts 234 times.
   - The test found that the order of assets and dependencies varied between runs: phase 1's `AssetCollector` took sonar-cryptography's components in the order of their random bom-refs. It now orders them by name, and `ReproducibilityIT` compares CBOMs in order, not sorted. Keycloak's CBOM is byte-identical between runs, but for the timestamp.
3. ~~Switch the pipeline: phase A's interpretation of every method and `CallIndex` go away.~~ Done 2026-11-27:
   - Phase A only reads. Phase B finds each JAR's candidates from the instructions (`Analyzer.methodsCalling`), interprets their closure, keeps the candidates the interpretation confirms (`BytecodeScanner.prepare`), and detects with `DemandCallIndex`.
   - `DemandCallIndex` keeps each artifact it interprets in, so further closures there don't read it again.
   - `CallIndex` is in the tests, as the reference the equivalence tests compare with. Its sites, hits and resolution are in `Callers`, and `ClassInfo` is a record of its own.
   - `DemandCallIndexEquivalenceTest` also checks that the candidates `prepare` finds are those of interpreting the whole JAR.
   - Keycloak: the same CBOM per occurrence. The questions about callers interpret 3,800 methods in 39 artifacts.

   Time and memory, against step 2 on the same machine (16 cores), with the same heap limit:

   | Heap limit | Step 2 | Step 3 |
   | --- | --- | --- |
   | 5.5 GB | 19.4 s | 12.5 s |
   | 3 GB | 20.5 s | 11.9 s |
   | 2 GB | 22.7 s | 12.7 s |
   | 1.5 GB | out of memory | out of memory |

   Time is down about 40%. The memory needed isn't: both need between 1.5 and 2 GB, far below the 5.5 GB given as the budget so far. The interpretation and the index weren't what bounds it. What does, perhaps the call graph and the class table or the JARs parsed by 16 threads at once, isn't measured yet.
4. Stage-2 cache by validation. Detection then has to record its open questions instead of asking them, so that a JAR's own result can be kept without the answers, which depend on the whole SBOM.

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

## Phase 2 API (decided 2026-11-27)

The analysis API, in the root package:

```java
final class Cryptid {
    static Builder builder();                  // cacheDirectory(Path), build(): loads the specs
    CryptoInventory analyze(List<InputArtifact> artifacts, AnalysisOptions options);
}
record InputArtifact(ArtifactCoordinates coordinates, Path jar,
                     List<ArtifactCoordinates> dependencies)   // direct; null = not known
final class AnalysisOptions {                  // builder(), defaults()
    ClasspathScope classpath(); int threads(); boolean rescan();   // classpath removed in phase 3
}
enum ClasspathScope { DEPENDENCIES, ALL, NONE }                  // removed in phase 3
record ArtifactAnalysis(ArtifactCoordinates artifact, Outcome outcome, int classes, int findings,
                        int failedMethods, String failure)    // Outcome: ANALYZED, CACHED, FAILED
```

The choices behind it:

- **`CryptoInventory` is the result of a whole analysis only.** A JAR's result is the internal `ArtifactScan`: its assets can have occurrences in other artifacts, so it isn't an inventory of anything, and after detection-driven analysis it becomes the JAR's findings and open questions.
- **The cache belongs to the library, not to the options.** Options are how to analyze and change per analysis. The cache outlives analyses, and whether an entry is still valid depends on what only the library knows: its build and specs, the JARs, their dependencies. So `Cryptid` is an instance holding the specs and the cache directory, and the cache's keys and format are internal. `rescan` is an option: it skips reading earlier results, and still keeps the new ones.
- **`InputArtifact.dependencies` are direct.** The library computes the closure, breadth first in the order listed. The CLI looks through components that aren't analyzed, such as POMs, to the analyzed artifacts behind them. `null` means not known, and resolves supertypes from all JARs.
- **`ArtifactAnalysis` has an outcome.** A failed artifact is in the inventory with its failure and no assets, instead of only in a log. An unreadable JAR now fails only itself: before, it failed the whole run.
- **Left for later:** writing the CBOM (stays in the CLI until the library and CLI split), choosing specs, `topLevel` on `InputArtifact` (with entry points), and a cache other than a directory.
- **Also added:** `CryptoInventory.Builder.addAssets(List<CryptoAsset>)`, which merges the assets of a JAR's scan.

Measured on Keycloak 26.8.2 (2026-11-27): the CBOM is identical to phase 1's, every occurrence with its bom-ref and `symbol` and every dependency, despite the new classpath order. A second run with the same `--work-dir` reuses all 548 results and takes under a second.

## Phase 3: one class table (decided 2026-11-27)

Measured first, on Keycloak's 534 JARs: 83,839 classes, 4,393 of them in more than one JAR, and 12 with copies whose bytes differ (mostly plexus-utils against plexus-xml). Of those, 6 differ in what the class table holds, supertypes and declared methods. So the two hierarchies of G4 hardly ever disagree on which copy applies. They disagreed more on visibility: spec matching saw an artifact's dependencies only, so an incomplete SBOM graph could hide a supertype.

What was decided:

- **One class table**, `Hierarchy`, filled from what phase A reads, with every copy of a class kept. Spec matching reads it through `Types.of(view)` instead of reading class files again, with the JDK after it.
- **One rule for which copy an artifact sees:** its own, then its dependencies breadth first, then the first artifact of the analysis, then the JDK. Every analyzed class is visible to every artifact.
- **`ClasspathScope` and `--classpath` are removed.** `DEPENDENCIES` is the rule's first steps; `ALL` differed only in which copy of those few classes; `NONE` hid library supertypes and lost real matches. `AnalysisOptions` has no classpath, and the cache key no scope.
- **Dispatch uses the class table's own choice** for classes whose copies differ, the first artifact's copy, instead of each caller's view as proposed. The call graph has one node per method, whose calls come from one copy; per-caller dispatch would need a node per copy, which isn't worth it for 6 classes. Before, the choice was the artifact whose path sorts first.
- **Phase A reads every JAR before indexing any**, since matching needs the whole class table. Each JAR is parsed twice; the read pass takes about 4 s on Keycloak, and phase A as a whole is no slower (about 15 s).
- **The interned method index is left to detection-driven analysis.** Its main user would be `CallIndex`, which that step replaces; the call graph interns its methods already.

Measured on Keycloak 26.8.2 (2026-11-27): the CBOM is identical to phase 2's, all 4,320 occurrences. Uncapped, the JVM's peak RSS is 10.4 to 10.6 GB, against 9.0 to 10.0 before; with a 5.5 GB heap the run takes the same time, at 6.1 GB RSS.

## Analysis API (first sketch)

Superseded by *Phase 2 API* above. The sketch had the cache in the options and the entry points among them; the cache now belongs to the `Cryptid` instance, and supplied entry points come with reachability.

## Order of work

Each step keeps the per-occurrence Keycloak CBOM unchanged, except where a step says it changes output.

1. ~~**Result model and in-memory assembly** (G1, G6).~~ Done 2026-11-27, as decided in *Phase 1 API*.
2. ~~**Analysis API** (G3).~~ Done 2026-11-27, as decided in *Phase 2 API*. The internal packages still have more `public` than they need; that waits for the library and CLI split.
3. ~~**One program model** (G4).~~ Done 2026-11-27, as decided in *Phase 3: one class table*.
4. **Detection-driven analysis** (G7, G5). The three stages above. Stage 2's results are cached per JAR, by validation, replacing the per-artifact cache keyed by the whole SBOM. Output identical.
5. **Closures across JARs.** Field values and returned constants followed into other JARs through the closures. Output changes, each difference reviewed.
6. **Entry points and endpoints**: the reachability design's step 2, with exposure, addresses and authentication in the specs and in `EntryPoint`.
7. **Reachability**: the reachability design's step 3, pass 1, on the model above.
8. **Endpoint sets and services**: pass 2 and the CycloneDX services.
9. **Events in our own values** (G2): the first part of the sonar-cryptography step.

Step 4 needs step 3: it uses the method index and the call graph's reverse edges. Step 5 needs step 4's closures. Steps 6 to 8 build on what steps 3 and 4 leave of phase A: the instruction-level hierarchy and call graph. Step 9 is independent of 4 to 8.

## Open questions

- Endpoints in the CBOM: one service per handler method or per resource class, and the size of the result on Keycloak.
- The default exposure of messaging entry points, and whether CDI observers of HTTP events count as external.
- Which authentication annotations to read, and how to report security configured outside the code.
- Whether endpoint sets (pass 2) stay within the reachability time target of a minute on Keycloak.
- The asset content key without JSON: whether `INode` exposes enough (kind, value, children) to compute it, or whether it has to wait for the model of our own.
