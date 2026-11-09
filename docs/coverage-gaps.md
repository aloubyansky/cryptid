# Coverage gaps, measured against a source scanner

Measured 2026-11-09 on Keycloak 26.8.2. Complements the [design review](design-review.md) and the
[detection redesign](detection-redesign.md): where those look at cryptid against its own
architecture, this one looks at what it detects against an independent tool.

## Method

Two CBOMs of the same release, from different inputs:

| | cryptid | source scanner |
| --- | --- | --- |
| Input | the distribution's SBOM, 548 resolved JARs, bytecode | the git working tree, source files |
| Analysis | the API specs, object graph | [crypto-finder](https://github.com/scanoss/crypto-finder) with [Opengrep](https://github.com/opengrep/opengrep), [crypto_rules](https://github.com/scanoss/crypto_rules) and [rh-crypto-rules](https://github.com/rh-pvsec/rh-crypto-rules) patterns |
| Packaging | — | Red Hat's `rh-crypto-scanner-image` |
| Run time | 19-22 s | 2 min 1 s (16 cores) |
| Components | 888 | 155 |
| Occurrences | 2,614 | 302 |
| Distinct algorithm names | 275 | 20 |
| Components with an OID | 249 | 17 |
| `library` components and a dependency graph | 74 libraries, 422 edges | none |

The scanner's run needed `-e LC_ALL=C.utf8`: the image sets `LANG` in its Containerfile but it isn't
set at runtime, and Opengrep then fails reading its own rule files with a `UnicodeDecodeError`.
Two runs of it were identical per occurrence, so the comparison below is stable.

The inputs overlap only in part, which bounds what the comparison can say:

- 232 of cryptid's 2,614 occurrences (9%) are in `org.keycloak` artifacts; the other 2,382 are in
  dependencies the source tree doesn't contain, 1,523 of them in Bouncy Castle's provider.
- The scanner covers modules that aren't in the distribution's SBOM at all: `adapters/saml`,
  `operator`, `test-framework`, `testsuite`, `crypto/elytron`. Those aren't cryptid misses.

Comparing Java source paths: 101 files for the scanner, 74 first-party files for cryptid, **28 in
common**. So the two agree on about a third of each other's first-party files, and the rest is
explained below.

## What cryptid misses

### 1. Argon2: an upstream rule gap

`crypto-api-specs.yaml` has no entry matching Argon2, scrypt or bcrypt. The cause is upstream:
`grep -rl Argon2 --include='*.java'` over sonar-cryptography 1.7.0 returns no files. (SCrypt matches
six files, all in its `csharp` module and all on the substring in `DESCryptoServiceProvider`.)

Keycloak's `Argon2PasswordHashProvider` calls `new Argon2BytesGenerator()` with
`org.bouncycastle.crypto.params.Argon2Parameters` — the Bouncy Castle lightweight API, which the
specs otherwise cover (12 classes in `org.bouncycastle.crypto.generators`). This is the default
password hashing of every Keycloak install since 24, and neither the algorithm nor the KDF appears
in the CBOM.

The specs were a faithful export of the rules, so fixing this meant owning them; see
[Spec maintenance](#spec-maintenance) below.

Fixed on 2026-11-09. The Keycloak CBOM gains exactly two occurrences, both Argon2, and no other
finding of the 2,614 changes: `keycloak-crypto-default`'s `Argon2PasswordHashProvider.java:130`,
and bcprov's own `ARGON2$BaseArgon2`. `Argon2Parameters` is still not read, so the variant
(id, i, d) and the memory, parallelism and iteration counts aren't reported.

### 2. The Bouncy Castle FIPS API: a whole library

`keycloak-crypto-fips1402` is built on `org.bouncycastle.crypto.fips.*` and
`org.bouncycastle.crypto.asymmetric.*` — the bc-fips jar's API, a different surface from bcprov's
lightweight API. sonar-cryptography has no rules for it either (0 files for `crypto.fips`,
`FipsAES`, `FipsRSA`, `FipsSHS`, `FipsKDF`, `crypto.asymmetric`, `SymmetricSecretKey`).

The module yields 10 occurrences today, all from the JCA calls it also makes (`AES-128-GCM`,
`AES-128-CBC-PKCS7Padding`, `EC`, `RSA-2048`). Everything it does through the FIPS API is invisible.
bc-fips itself is not in the default distribution's SBOM — only bcprov/bcpkix 1.86 — so this is
about first-party code calling the API, not about analyzing bc-fips.

Of the 214 non-exception `org.bouncycastle`, `javax.crypto` and `java.security` classes that
Keycloak's source imports, 26 are owners of a spec'd API method. Most of the remainder are data
types rather than APIs to detect (ASN.1 structures, `java.security.interfaces`, key specs), so the
ratio overstates the gap; the clusters that are real are BC-FIPS (9 + 5 classes), Argon2 (2), and
`org.bouncycastle.crypto.util`'s `DigestFactory`, `PrivateKeyFactory`, `PublicKeyFactory` and
`SubjectPublicKeyInfoFactory` (4).

### 3. A value through a constructor parameter into a field

Keycloak's PBKDF2 password hashing is not in the CBOM. The full path:

```text
Pbkdf2Sha512PasswordHashProviderFactory.PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA512"  [server-spi-private]
  -> new Pbkdf2PasswordHashProvider(ID, PBKDF2_ALGORITHM, ...)     constructor argument
  -> this.pbkdf2Algorithm                                          PUTFIELD
  -> getSecretKeyFactory() reads the field                         GETFIELD
  -> CryptoIntegration.getProvider().getSecretKeyFact(alg)         interface, keycloak-common
  -> DefaultCryptoProvider.getSecretKeyFact                        keycloak-crypto-default
  -> SecretKeyFactory.getInstance(alg, provider)                   the spec'd JCA API
```

`Analyzer.field` does track fields: `fields` is a merged map with a `fieldsChanged` fixpoint, and
`GETFIELD` reads what `PUTFIELD` wrote. What it writes here is the constructor's *parameter*, which
is `UNKNOWN`: a caller's argument value is not propagated into a field write. The string would then
still have to cross two JAR boundaries and an interface dispatch, which the object graph doesn't
follow either (see [F7's limits](design-review.md#backlog)).

This is the field case of *Values derived from parameters* in the backlog, and the most common shape
of the three gaps: a provider object configured once at construction and used later.

### 4. Certificates, by design

The scanner reports 116 certificate components, from `java.security.cert.*`, `CertPathValidator`,
`PKIXParameters`, `CertificateFactory` and `X509Certificate`. cryptid reports none; the README
states it. Worth revisiting only if a CBOM consumer asks for certificate assets, since the
occurrences are mostly certificate *handling*, not a cryptographic choice.

## What the source scanner misses

For balance, and because it bounds how much weight to give it as a reference:

- Everything in dependencies: no BouncyCastle, no JDBC drivers, no Netty, no Elytron.
- `Ed25519` at `GeneratedEddsaKeyProviderFactory` — cryptid finds it, the scanner has no EdDSA
  entry at all.
- Its `DES-56-ECB`, `RC4`, `MD2` and `SHA3-*` hits in `keycloak-admin-cli` are in *shaded* Apache
  HttpClient (`NTLMEngineImpl`) and commons-codec (`DigestUtils`), not Keycloak code. cryptid
  attributes them the same way; see *Shaded code* in the backlog.
- Its `ML-DSA-44/65/87` components come only from `String ML_DSA_44 = "ML-DSA-44";` constant
  declarations in `core/.../Algorithm.java`, not from call sites. The specs do cover
  `org.bouncycastle.pqc.crypto.mldsa` (5 classes); Keycloak reaches ML-DSA through JCA names
  instead, so cryptid reports none. Adopting findings like these means adopting the false-positive
  profile that comes with them.

## An output defect found on the way

247 of the 888 components carry a generated UUID in their name: `secret-key@76a847a1-...`,
`key@...`, `public-key@...`, `private-key@...`, `salt@...`, `iv@...`, `nonce@...`. That is every one
of the 247 `related-crypto-material` assets. A CBOM consumer sees the UUID as the asset's name.
F5 strips UUIDs when de-duplicating, but the name reaches the output with it. Fixing it belongs with
F5's in-memory model.

## Spec maintenance

Two of the three gaps above (Argon2, BC-FIPS) and the known
[bytes-read-as-bits error](design-review.md#backlog) in `KeyParameter(byte[], int, int)` all need the
same thing: the ability to correct and extend the specs by hand.

[Detection redesign](detection-redesign.md#when-the-exporter-runs) had already decided how: the
specs become hand-maintained and `RuleSpecExporter` becomes an opt-in diff tool that reports what a
sonar-cryptography version changed, to port by hand. A generated base with a hand-maintained
overlay was considered there and rejected: it needs merge rules for overriding, removing and
extending entries, and splits the knowledge over two files.

Nothing found here argued against that, and three independent reasons to reach it had accumulated,
so the switch was made on 2026-11-09, before step 3b-2. `RuleSpecDriftTest` replaced
`RuleSpecExportTest`: it keeps the file parseable and canonical, and reports drift without failing.

A spec entry alone turned out not to be enough. Translating a value into a model node goes through
sonar-cryptography's mappers, and each one's `default` branch builds an algorithm of its own kind
under the raw name: with only the spec entry added, `Argon2BytesGenerator` was modeled as a message
digest named after the implementation class, because `BcDerivationFunctionMapper` falls back to
`new Algorithm(name, MessageDigest.class, …)`. Values for APIs the rules don't cover therefore need
a node of our own, in `OwnNodes`, consulted before the context translators. Argon2 is now reported
as a `PasswordBasedKeyDerivationFunction` named Argon2, with the key-derivation function. The same
will be needed for each BC-FIPS entry: sonar-cryptography has no model class for those algorithms
either, though it does have `Scrypt`, which no Java rule can reach.

## Still open

What this comparison turned up and the spec switch of 2026-11-09 didn't close, roughly in the order
it is worth doing. Each line is a backlog entry in the [design review](design-review.md#backlog)
unless it says otherwise.

| | Open | Why it's next, or not |
| --- | --- | --- |
| 1 | **Argon2's parameters.** `Argon2Parameters` has no spec, so the variant (id, i, d), the version, and the memory, parallelism and iteration counts are missing; the asset is the bare algorithm. | Smallest increment on work already done, and the parameters are what a reviewer of password hashing actually wants. Needs a linked-object spec and the `Argon2Parameters.Builder` chain, whose values are set across several calls on the builder. |
| 2 | **The `KeyParameter` key size read as bits.** Bouncy Castle's `KeyParameter(byte[], int, int)` takes a length in bytes; the spec inherited from the rule reads it as a `BIT` key size, so `OpenSSHPrivateKeyUtil` reports AES-16, AES-24 and AES-32. | Now correctable in place, which is one of the three reasons the specs were made hand-maintained, so it should not stay open. Needs a byte-to-bit conversion, since the translators take a size as it comes. Other byte-length parameters should be checked for the same error, and it should be reported upstream. |
| 3 | **scrypt and bcrypt.** No rule upstream, as with Argon2, and no entry here yet. Both still need an `OwnNodes` node: no mapper reaches sonar-cryptography's `Scrypt` model class, and there is none for bcrypt, though scrypt's node is then one line. Bouncy Castle's `SCrypt.generate` is static, so the spec sits on a method rather than a constructor, unlike Argon2. | Cheap once Argon2 has shown the shape, and both are password hashing a CBOM is expected to name. Not reached by Keycloak, so it is coverage for other applications. |
| 4 | **The Bouncy Castle FIPS API.** 14 classes (`org.bouncycastle.crypto.fips.*`, `org.bouncycastle.crypto.asymmetric.*`), covering all of `keycloak-crypto-fips1402`. | The largest gap measured, and the largest piece of work: a spec family plus an `OwnNodes` node per algorithm, since sonar-cryptography models none of them. Worth scoping against how much a FIPS deployment's CBOM matters. |
| 5 | **A caller's argument stored in a field.** Keycloak's `Pbkdf2PasswordHashProvider` keeps `"PBKDF2WithHmacSHA512"` in a field set by its constructor, and nothing is reported. Folded into *Values derived from parameters*. | Touches the analyzer core rather than data, so it is the riskiest of these for precision and run time. But "a provider object configured at construction and used later" is a common shape, so it probably pays for more than this one case. |
| 6 | **UUIDs in asset names.** All 247 `related-crypto-material` assets are named `secret-key@76a847a1-…`. | A visible defect in every CBOM, and it also makes two runs textually different. Fix belongs with F5's in-memory model rather than on its own. |
| 7 | **Certificates.** Not reported, by design; the scanner finds 116 in Keycloak. | Open only as a question for CBOM consumers, not as a defect. Most of those occurrences are certificate handling, not a cryptographic choice. |

Two things outside this list, from reading the sources while measuring:

- `org.bouncycastle.crypto.util`'s `DigestFactory`, `PrivateKeyFactory`, `PublicKeyFactory` and
  `SubjectPublicKeyInfoFactory` have no specs. Keycloak uses them, and they produce objects other
  specified APIs then take, so they may be worth more than their four entries suggest.
- sonar-cryptography's mappers lose any name they don't know, silently and as the wrong kind: each
  `default` branch builds an algorithm of that mapper's kind under the raw name. A spec entry for an
  API they don't model therefore looks like it works while producing a wrong asset. Only `OwnNodes`
  prevents that, so every new spec entry outside the rules needs checking against the modeled
  output, not just against being detected.
