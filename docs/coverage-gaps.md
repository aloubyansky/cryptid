# Coverage gaps against a source scanner

Keycloak 26.8.2, measured on 2026-11-09, against [crypto-finder](https://github.com/scanoss/crypto-finder) 1.26.10 run on the source tree at tag `26.8.2`. The two inputs overlap only in part: cryptid analyzes the 548 JARs of the distribution's SBOM, including dependencies; crypto-finder analyzes the source tree, including modules the distribution doesn't ship (`adapters`, `operator`, `testsuite`, `test-framework`, `crypto/elytron`, `util/embedded-ldap`, `distribution`, `js`). Misses in those modules aren't cryptid misses.

| | cryptid | crypto-finder |
| --- | --- | --- |
| Occurrences | 2,992 | 302 |
| Components | 954 crypto assets, 75 libraries | 155, 116 of them certificates |

crypto-finder's occurrences were matched to cryptid's by source path and line (within 3 lines). Of its 75 algorithm and related-material occurrences, 31 are found at the same line, 16 more in the same file.

## Fixed

- **Constants returned by methods** (2026-11-09). Keycloak's JWS code passes algorithm names through mapping methods: `Signature.getInstance(getJavaAlgorithm(alg))` in `RSAProvider`, `Mac.getInstance(getJavaAlgorithm(alg))` in `HMACProvider`, and `JavaAlgorithm.getJavaAlgorithm` in the signer and verifier contexts. `Analyzer` now returns the constants of static, private and final methods to their call sites. Keycloak's own JARs gain their RSA, ECDSA, EdDSA, HMAC and SHA-2 findings, and dependencies gain theirs (Bouncy Castle's PKCS#12 MACs and ciphers, Netty's and JGroups' TLS versions, Elytron's digests). Since such a method maps a whole family, `Signature.getInstance` got the HMAC and AES names too; variants the API can't take are now dropped (see *Variants an API rejects* in the [backlog](design-review.md#backlog)).
- **Assets merged by name** (2026-11-09). sonar-cryptography's `CBOMOutputFile` merges two assets of the same name in a JAR, keeping the first one's properties, so more findings made more assets wrong: the `AES-128` of Keycloak's `SecretKeySpec` took the `sign` function of a signature variant. `AssetCollector` gives each finding its own output and merges by content. 346 occurrences that were already in the CBOM got their own properties back, e.g. Threefish's sizes, RC4's decrypt, and `BlockCipherMac`'s CBC MAC instead of "unknown, OAEP".

- **XML encryption** (2026-11-09). xmlsec's `XMLCipher.getInstance` and `getProviderInstance` have specs now, the first of cryptid's own after the specs became hand-maintained. Their algorithms are W3C URIs, which a `names` table in the specs translates to the JCA names xmlsec uses (`JCEMapper`), with the key size from the URI (`AES_128/CBC/ISO10126Padding`); URIs not in the table are dropped. `XMLEncryptionUtil` now reports AES-128, 192 and 256-CBC with `encrypt` and RSA 1.5 for the data, RSA-OAEP and AES key wrap for the key transport, and `BaseSAML2BindingBuilder` AES-256-GCM: 12 occurrences. All 11 of crypto-finder's `saml-core` findings are in those files; it reports the lines referencing the constants, cryptid the call sites. Its other 5, in `services`, aren't uses: `SamlProtocolUtils` compares a client's configured algorithm with the constants, and `SAMLEncryptionAlgorithms` is an enum storing them in fields from its constructor, the field case below.

## Open

In the modules the distribution ships, in the order worth doing:

| Miss | Occurrences | Cause | Fix |
| --- | --- | --- | --- |
| `JcaContentSignerBuilder("SHA256WithECDSA")` in `crypto-default` | 5 | No spec for Bouncy Castle's PKIX operator API. | A spec with the signature context; check that the mappers know Bouncy Castle's names (`SHA256WithRSAEncryption`). |
| Argon2 in `Argon2PasswordHashProvider` | 1 | No rule upstream, and no model class the mappers reach. | A spec, and a node of our own keyed on the spec, not on the value's name. |
| PBKDF2 in `Pbkdf2PasswordHashProvider`, SHA-1 in `SHAPasswordEncoder` | 3 | The algorithm is a constructor parameter stored in a field. | *Values derived from parameters* in the backlog. |
| RSA-OAEP with SHA-256 in `DefaultRsaKeyEncryption256JWEAlgorithmProvider` | 1 | The `Cipher` comes from the superclass through an overridden `initCipher`, with its name in a field. | Overriding dispatch in the object graph, and fields from constructor parameters. |
| IVs of `AesCbcHmacShaEncryptionProvider` and `AesGcmEncryptionProvider` | 4 | The ciphers are found; the IV isn't modeled as its own asset. | Low priority. |

Not worth adopting: crypto-finder's ML-DSA findings come from string constant declarations in `Algorithm.java`, not from calls, and its certificate findings are certificate handling, which cryptid doesn't report by design. Its `protocol` findings in `services` and `saml-core` are calls of Keycloak's own SAML signing API, with the algorithm chosen at runtime.

## Reproducing

cryptid: `java -jar target/cryptid.jar src/test/resources/keycloak-26.8.2.zip.cdx.json -o keycloak-cbom.json --work-dir <fresh directory>`. crypto-finder: run on a checkout of Keycloak at tag `26.8.2`. Neither CBOM is kept in the repository.
