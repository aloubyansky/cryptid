# Certificates in a CBOM

cryptid doesn't report certificates, and `certificate` is one of the four asset types CycloneDX defines. This records what a certificate entry in a CBOM is specified to contain, what other tools do, and what is actually present in the artifacts — the ones cryptid reads, and the ones it could be made to. Measured on 2026-11-10 against Keycloak 26.8.2, and against the 26.5.4 container image, the nearest one to hand.

## What the specification asks for

`cryptoProperties.assetType` has four values: `algorithm`, `certificate`, `protocol` and `related-crypto-material`. A certificate's `certificateProperties` (`org.cyclonedx.model.component.crypto.CertificateProperties`, cyclonedx-core-java 13.3.0) is:

| Field | |
| --- | --- |
| `subjectName`, `issuerName` | distinguished names |
| `notValidBefore`, `notValidAfter` | the validity window |
| `signatureAlgorithmRef` | `bom-ref` of the algorithm component that signed it |
| `subjectPublicKeyRef` | `bom-ref` of the public key component it carries |
| `certificateFormat`, `certificateExtension` | X.509, PEM, DER; `crt` |

Every field describes one concrete certificate. [CycloneDX's own example](https://cyclonedx.org/use-cases/cryptographic-certificate/) is a `google.com` certificate: `CN = www.google.com`, issuer `C = US, O = Google Trust Services LLC, CN = GTS CA 1C3`, a validity window of two dates, a `bom-ref` derived from the certificate's SHA-256 digest, `signatureAlgorithmRef` to a SHA512withRSA component and `subjectPublicKeyRef` to an RSA-2048 public key, which in turn has an `algorithmRef` to RSA. One certificate is four linked components. The motivation it cites — NIST SP 1800-38B for a post-quantum readiness inventory, SP 800-57 for renewal — needs expiry dates and signature algorithms, which exist only once a certificate has been parsed.

CycloneDX 1.7 (October 2025, the basis of ECMA-424 2nd edition) adds certificate lifecycle state to this. cryptid writes 1.6.

## What other tools do

The CBOMkit project, whose crypto model cryptid uses, splits the work in two, and the split falls exactly on this line.

- **CBOMkit-hyperion** is sonar-cryptography, the code scanner. It has no certificate support at all. In `com.ibm:mapper` 1.7.0 the model has `IAlgorithm`, `Key`, `PublicKey`, `PrivateKey`, `SecretKey`, `Protocol` and `CipherSuite`, and no certificate node; `com.ibm:output` 1.7.0 has three component builders, `AlgorithmComponentBuilder`, `ProtocolComponentBuilder` and `RelatedCryptoMaterialComponentBuilder`. Nothing cryptid inherits can express a certificate.
- **[CBOMkit-theia](https://github.com/cbomkit/cbomkit-theia)** does certificates, and does not scan code. It reads deployment artifacts — container images, directories — finds X.509 files, and emits the certificate together with its signature algorithm, its public key and that key's algorithm, as CycloneDX 1.6. It exists, in the project's own framing, to fill the gap where source scanning misses runtime material.

crypto-finder takes the other route and reports certificate *handling* under the same asset type. In the Keycloak CBOM that is 116 of its 302 occurrences, 66 of them from one rule whose dominant pattern is `X509Certificate $CERT = $EXPR;`, a variable declaration of that type: its single most frequent finding is `X509Certificate cert = null;`. None of the eight `certificateProperties` fields is filled, because a declaration carries none of them. A separate defect in its CycloneDX output puts the rule's metadata map in the component's `name`, so 115 of its 155 assets are named like `certificate:101:101:x509:X.509:algorithmPrimitive=other:api=java.security.cert.X509Certificate:library=JCA/JCE`. See [coverage gaps](coverage-gaps.md).

Its rules can't be borrowed in any case. They ship in the scanner image under `/usr/local/rules/crypto-rules/`, each file headed "Copyright © 2026 Scan Open Source Solutions SL (SCANOSS). All Rights Reserved … proprietary and confidential". The two open sibling repositories, `scanoss/open-crypto-rules` and `rh-pvsec/rh-crypto-rules`, are GPL-3.0 and contain no JCA rules.

## What is in the artifacts

Nothing to parse in what cryptid reads today; plenty one layer out, but none of it the application's.

- **The 534 resolvable JARs of the distribution's SBOM**: zero files matching `.pem`, `.crt`, `.cer`, `.der`, `.p12`, `.jks`, `.pfx`, `*keystore`, `*truststore` or `cacerts`. The hits for those words are all class names — `TruststoreProvider`, `KeystoreUtil$TruststoreFormat`, `JcaCertStore`. Source JARs would not change this: they hold `.java` files.
- **The distribution zip** (`keycloak-26.8.2.zip`, 522 entries, 483 of them JARs): zero certificates. It ships `conf/truststores/` as an empty directory, a place for the deployer to put them, and `conf/keycloak.conf` names the paths with both lines commented out:

  ```
  # The file path to a server certificate or certificate chain in PEM format.
  #https-certificate-file=${kc.home.dir}/conf/server.crt.pem
  ```

- **The container image** (`quay.io/keycloak/keycloak:26.5.4`) is the first input that does contain certificates: 146 CA trust anchors in `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, the same set mirrored into `/etc/pki/java/cacerts`, `/etc/ssl/cert.pem`, `/etc/pki/tls/certs/ca-bundle.crt` and 440 hash-named per-certificate PEMs, plus one Red Hat product identity certificate (`CN=Red Hat Product ID […]`, RSA-4096, sha256WithRSA, valid to 2045). Every field a certificate entry needs parses from them, and an inventory of the 146 would read: 61 sha256WithRSA, 37 ecdsa-with-SHA384, 19 sha384WithRSA, 18 sha1WithRSA, 7 ecdsa-with-SHA256, 4 sha512WithRSA; 102 RSA keys and 44 EC, none post-quantum; none expired, two expiring within two years.

  They are all base image furniture, though — the UBI9 `ca-certificates` package, identical in any image built on it — and `opt/keycloak/conf/truststores/` is empty here too. The image carries no certificate of Keycloak's own.

Keycloak's certificates come into existence at deployment: mounted into `conf/truststores/`, configured through `https-certificate-file`, generated into a keystore on first start, or inherited from the JVM's `cacerts`. They are not a property of the build.

## What this means

A certificate entry that satisfies the specification can't be produced from an SBOM of Maven artifacts, because the certificates aren't in them. Reporting certificate-handling call sites under `assetType: certificate` would fill the gap in name only: the eight fields that make the entry useful would all be empty, and the Keycloak measurement shows what the matching produces instead.

**Certificates are a non-goal** (decided 2026-11-10). cryptid reads an SBOM and the artifacts it names, and those contain no certificates to report. Widening the input to the distribution archive wouldn't reach any either.

A container image would — but what it yields is the base image's trust store, the same 146 public CA anchors in every UBI9-derived image, and nothing of the application's. That is a useful inventory, and it is what CBOMkit-theia produces today by walking a deployment artifact's filesystem. It is a different product from reading an SBOM and analyzing the bytecode of the artifacts it names, not an extension of it. A CBOM that needs Keycloak's own certificates should be enriched by a tool that reads the deployment, where they first exist.

Two things were considered and set aside with it:

- **Reporting the handling APIs** (`CertificateFactory`, `CertPathBuilder`, `CertPathValidator`, `CertStore`, `PKIXParameters`, `TrustAnchor`, `X509CertSelector`) as algorithm and protocol evidence of PKIX path validation, without calling them certificates. This would fit the existing model and claim nothing the data can't support, but it isn't what the gap was about.
- **Reporting them as `assetType: certificate`**, the way crypto-finder does. This fills the gap in name only; all eight `certificateProperties` fields stay empty.

## Reproducing

```shell
# certificate files in the SBOM's artifacts
jq -r '.components[]|select(.purl? and (.purl|startswith("pkg:maven/")))|.purl' \
  src/test/resources/keycloak-26.8.2.zip.cdx.json |
  sed 's|pkg:maven/||;s|?.*||' |
  awk -F'[/@]' '{g=$1; gsub(/\./,"/",g); print ENVIRON["HOME"] "/.m2/repository/" g "/" $2 "/" $3 "/" $2 "-" $3 ".jar"}' |
  while read -r j; do [ -f "$j" ] && unzip -l "$j" | awk '{print $NF}'; done |
  grep -viE '\.class$' |
  grep -iE '\.(pem|crt|cer|der|p12|jks|pfx|keystore|truststore)$|(^|/)cacerts$'

# certificate files in the distribution
unzip -l keycloak-26.8.2.zip | awk '{print $NF}' | grep -viE '\.(jar|class)$'

# certificates in the container image
cid=$(podman create quay.io/keycloak/keycloak:26.5.4); podman export "$cid" > fs.tar; podman rm -f "$cid"
tar -tf fs.tar | grep -iE '\.(pem|crt|cer|der|p12|jks|pfx)$|cacerts'
tar -xf fs.tar -C . etc/pki/ca-trust/extracted/pem
csplit -z -f c -b '%03d.pem' etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
  '/-----BEGIN CERTIFICATE-----/' '{*}'
for f in c*.pem; do openssl x509 -in "$f" -noout -text | grep -m1 'Signature Algorithm'; done |
  awk '{print $3}' | sort | uniq -c | sort -rn

# the model cryptid inherits
unzip -l ~/.m2/repository/com/ibm/mapper/1.7.0/mapper-1.7.0.jar | grep -i certificate
unzip -l ~/.m2/repository/com/ibm/output/1.7.0/output-1.7.0.jar  | grep ComponentBuilder
```
