# mach-pki

X.509 certificates and CMS signed data for Mach: strict parsing, loading,
certification path validation, signing, and signature verification. Parsing and validation borrow their input and allocate nothing. TLS, CMS and PDF signing share this one
certificate model. It depends on mach-std and mach-crypto only.

## Modules

- `pki.cert` holds the borrowed handles the other modules pass around: a
  `Certificate` (one DER encoding), a leaf-first `Chain`, a `TrustStore` of
  anchors, and the `KeyFormat` of a DER private key.
- `pki.x509` parses a certificate, compares distinguished names, and looks up
  extensions.
- `pki.name` checks DNS and IP reference and presented identities and matches
  them.
- `pki.load` loads DER and PEM certificates and chains, and DER and PEM private
  keys.
- `pki.verify` builds and validates a certification path for a purpose, checks
  a certificate's DNS or IP identity, and checks a signature under a
  certificate's key.
- `pki.signer` is the signing contract: a key that never leaves its signer,
  whether in memory, on a token, in an HSM or behind a remote service.
- `pki.key_signer` signs with a private key held in memory and its PEM chain.
- `pki.cms` builds CMS signed data through a signer, and parses and verifies
  it.

`use pki;` binds `pki.lib.pki`, which re-exports these modules.

## Use

```mach
use crypto.contracts;
use pki.cert;
use pki.load;
use pki.verify;
use pki.x509;

# pem holds a PEM chain, trust a cert.TrustStore, at the time.Time to
# validate at, and server_name the name the client asked for
# chain_pem decodes a leaf-first PEM chain into caller storage
var der:          [16384]u8;
var certificates: [verify.MAX_CHAIN_DEPTH]cert.Certificate;
var presented:    cert.Chain;
val loaded: contracts.Operation = load.chain_pem(pem,
    contracts.Buffer{data: ?der[0], capacity: 16384},
    ?certificates[0], verify.MAX_CHAIN_DEPTH, ?presented);

var options: verify.Options;
options.purpose              = verify.server_auth();
options.now                  = at;
options.max_depth            = verify.MAX_CHAIN_DEPTH;
options.max_signature_checks = verify.MAX_SIGNATURE_CHECKS;
val verified: verify.Error = verify.chain(?trust, ?presented, ?options);

# a tls client also checks the server name against the leaf
var leaf: x509.Certificate;
x509.parse(contracts.Bytes{data: certificates[0].der,
    len: certificates[0].der_len}, ?leaf);
val named: bool = verify.identity(?leaf, server_name);
```

## Parsing

`x509.parse` borrows its input: every slice in a parsed certificate points into
the DER it was given and is valid only while that input stays put. On failure
the output is left untouched. Parsing refuses malformed DER, duplicate
extensions, unknown critical extensions, invalid time forms, invalid names,
mismatched inner and outer signature identifiers, noncanonical defaults,
malformed key encodings, invalid extension placement, and an extended key usage
that lists a purpose twice.

A caller that processes a critical extension this parser does not know names it
in `x509.Options.critical` and parses with `x509.parse_with`, then reads it with
`x509.extension`. Every extension is also kept whole in `Extensions.encoded`.

`x509.parse_trust_anchor` reads a configured anchor. An anchor's
self-signature is not part of path validation, so it accepts an otherwise valid
anchor whose self-signature algorithm is unsupported, and three encodings RFC
5280 asks issuers to avoid that deployed roots carry: a zero or negative serial
number, a `GeneralizedTime` validity before 2050, and a key usage bit string
with trailing zero bits. Every other certificate is held to the strict forms.

Distinguished names compare exact encodings first. PrintableString and ASCII
UTF8String values also get case folding, leading and trailing space removal,
and internal space compression. Non-ASCII UTF8String values match only exactly.

## Keys and signatures

Subject public keys are Ed25519, P-256, P-384, P-521, and RSA with 2048 through
4096-bit moduli. Certificate signatures are Ed25519, ECDSA with SHA-256, SHA-384
or SHA-512 over a key on any of the three curves (the digest is independent of
the curve), RSA-PSS with SHA-256, SHA-384 or SHA-512, and RSA PKCS #1 v1.5 with
SHA-256, SHA-384 or SHA-512. RSA-PSS parameters must name the same supported
hash for the message and MGF1 and a salt as long as the hash.

SHA-1 signatures (sha1WithRSAEncryption, ecdsa-with-SHA1) parse so they can be
named, report `UNSUPPORTED_ALGORITHM` and never `BAD_SIGNATURE`, and
`x509.weak` tells them apart.

`verify.message` checks a signature over any content under a certificate's
public key with one of these algorithms.

## Path validation

`verify.chain` takes a leaf-first presented chain whose intermediates may come
in any order. It backtracks across issuer candidates and trust anchors up to
`max_depth` certificates and `max_signature_checks` public-key operations,
refuses duplicate presented certificates, checks authority and subject key
identifiers when both exist, and authenticates every link before it reports
success. A spent bound reports `RESOURCE_LIMIT` without another public-key
operation.

A `verify.Purpose` says what the leaf is accepted for: the key usage bits a leaf
with a key usage extension must assert one of, and the extended key usage that
the leaf and every intermediate carrying that extension must list, unless it
lists any purpose. The constructors are `server_auth`, `client_auth`,
`code_signing`, `email_protection`, `time_stamping`, and `document_signing`.
`document_signing` accepts what PDF validators accept: RFC 9336 document
signing, `emailProtection`, Adobe Authentic Documents, or Microsoft document
signing, besides no extended key usage or any purpose. A purpose lists such
alternatives in `alternatives`. A caller builds its own for any other purpose.

Intermediates must carry a critical CA basic constraint and, when key usage is
present, `keyCertSign`. Path length excludes the leaf and self-issued rollover
certificates as RFC 5280 requires. DNS, IP, and directory name constraints
apply to every subordinate certificate, and excluded subtrees always win. A
constrained name form this library cannot process causes rejection when it
appears in a subordinate certificate. Self-issued intermediates are exempt from
name constraints, the leaf never is.

The trust anchor's validity, extensions, and self-signature are not processed.
Its subject and public key identify it.

`verify.Error` tells a caller's mistake (`INVALID_INPUT`) and a spent bound
(`RESOURCE_LIMIT`) apart from a certificate that fails (`BAD_CERTIFICATE`,
`CERTIFICATE_EXPIRED`, `UNKNOWN_CA`, `UNSUPPORTED_ALGORITHM`, `BAD_SIGNATURE`).

## Identity

`verify.identity` matches a DNS or IP reference identity against the
certificate's subject alternative names, by RFC 6125. The subject common name
is never consulted.

DNS names use strict ASCII preferred-name syntax, with one trailing root dot
normalized. A wildcard is valid only as the whole leftmost label and matches
exactly one label. Partial-label wildcards and two-label wildcard names are
refused. IPv4 text refuses leading zeroes. IPv6 accepts full, compressed, and
embedded IPv4 forms. Zone identifiers and bracketed literals are not
identities.

## Loading

`load.certificate_der` validates one borrowed DER certificate.
`load.certificate_pem` decodes one `CERTIFICATE` block into caller storage.
`load.chain_pem` accepts one or more `CERTIFICATE` blocks separated only by
ASCII whitespace, and measures and validates them all before it publishes the
chain. Input and output storage must not overlap.

`load.private_der` loads PKCS #8, SEC 1, or RSA PKCS #1 DER into an owned
`crypto.encoding.keys.PrivateKey`, and `load.private_pem` accepts `PRIVATE
KEY`, `EC PRIVATE KEY`, and `RSA PRIVATE KEY` blocks. The caller destroys the
key with `crypto.encoding.keys.destroy_private`.

## Signing

A `signer.Signer` takes the bytes to sign and a `x509.SignatureAlgorithm` and
returns the signature. The signer hashes when its algorithm hashes first. An
implementation backed by a device or service that accepts only digests hashes
locally before sending, and one that takes the message (Ed25519, RFC 8419)
sends it unchanged. The key never crosses the contract, so a PKCS #11 token, an
HSM or a remote signing service drops in with no change to callers.

The chain and the supported algorithms are fixed once a signer is open, so a
caller can build signed attributes from the leaf before signing.
`signer.algorithm` lists the algorithms in the signer's preference order,
`signer.supports` asks for one, and `signer.signature_size` bounds the output.
Only `signer.sign` may block, and it may fail transiently: `UNAVAILABLE` means
the same call may succeed later (`signer.transient`), while `DENIED` and
`FAILED` do not. `signer.sign` refuses an unsupported algorithm or a short
output before the signer is reached.

`key_signer.open_pem` opens a signer from a `PRIVATE KEY`, `EC PRIVATE KEY` or
`RSA PRIVATE KEY` block and a leaf-first PEM chain, and `key_signer.open` from a
loaded key and chain. Both refuse a key that is not the private half of the
leaf's public key with `KEY_MISMATCH`. It signs Ed25519, ECDSA P-256 with
SHA-256, and RSA-PSS with SHA-256 or SHA-384 with a salt from the operating
system. ECDSA P-384 and RSA PKCS #1 v1.5 signing wait on mach-crypto, and the
contract already names both.

```mach
use crypto.contracts;
use crypto.secret;
use pki.key_signer;
use pki.signer;
use pki.x509;

# key_pem holds the private key, chain_pem the leaf-first chain, and tbs the
# bytes to sign
var der:   [16384]u8;
var owner: secret.Allocator = secret.system_allocator();
var keyed: key_signer.KeySigner;
val opened: signer.Error = key_signer.open_pem(?keyed, key_pem, chain_pem,
    contracts.Buffer{data: ?der[0], capacity: 16384}, ?owner);

var value:     signer.Signer = key_signer.signer(?keyed);
var signature: [512]u8;
val made: signer.Result = signer.sign(?value, x509.ED25519, tbs,
    contracts.Buffer{data: ?signature[0], capacity: 512});
key_signer.close(?keyed);
```

## CMS signed data

`cms.build` signs content through a `signer.Signer` into RFC 5652 signed data,
with the content encapsulated (`ATTACHED`), left with the caller (`DETACHED`),
or given only as its digest (`DETACHED_DIGEST`), such as a PDF byte range
hashed with `cms.digest_init`, `digest_update` and `digest_final`. The signed
attributes are content-type, message-digest, ESS signing-certificate-v2 (RFC
5035) naming the leaf by its SHA-256 hash, and signing-time when the caller
supplies one. Nothing reads a clock. The signer's chain is included and the
leaf is identified by issuer and serial number. The same inputs always encode
the same bytes, so a signer with a deterministic algorithm makes reproducible
signed data.

The algorithm is the one the caller names or the signer's first, and the digest
algorithm follows it (`cms.digest_algorithm`): the algorithm's own hash, and
SHA-512 for Ed25519, which signs the signed attributes directly (RFC 8419).
RSA-PSS carries its RSASSA-PSS parameters. The encodings for the other ECDSA digests and
RSA PKCS #1 v1.5 are in place for signers that offer them. `cms.build` measures
its output before the signer is asked, so a short output reports the size
needed and never spends a signature.

`cms.attach_unsigned` adds unsigned attributes to the sole signer after
signing, such as an RFC 3161 time-stamp token over its signature, without
touching a signed byte.

`cms.verify` checks every signer: its certificate among the included ones, its
signature with `verify.message`, its message digest against the content or the
caller's digest, its signing-certificate-v2 attribute when present, and its
path with `verify.chain` against the caller's trust store and options. It
accepts the signer identified by issuer and serial number or by subject key
identifier, and RSA PKCS #1 v1.5 named by `rsaEncryption`. `cms.parse` and
`cms.signer_info` read signed data without verifying it, for a caller that
needs the digest algorithm before it hashes detached content.

Signed data may be BER, as NSS (Okular, poppler), Acrobat and other pdf tools
write it: indefinite lengths and octet strings built from segments are read in
the envelope. What a signature covers stays strict DER: the signed attributes,
the signer's issuer name and the certificates are refused otherwise. Nesting is
bounded and every read is checked against the input. `cms.encoded_length` gives
the length of the BER or DER element at the start of a buffer, for signed data
followed by padding. `cms.attach_unsigned` rewrites DER signed data and refuses
BER it cannot.

```mach
use crypto.contracts;
use pki.cms;
use pki.signer;
use std.types.bool.true;

# value is an open signer.Signer, content the bytes to sign and at the
# signing time
var options: cms.Options;
options.form                 = cms.DETACHED;
options.content              = content;
options.signing_time_present = true;
options.signing_time         = at;
var output: [16384]u8;
val built:  cms.Result = cms.build(?value, ?options,
    contracts.Buffer{data: ?output[0], capacity: 16384});
```

## Fuzzing

`test/fuzz` replays retained inputs against the parser and searches for new
ones. It runs locally, and [`test/fuzz/README.md`](test/fuzz/README.md) has the
commands.

## Interop

`test/interop/run.sh` checks CMS against OpenSSL in both directions with fresh
keys: OpenSSL verifies what `cms.build` makes for every algorithm, attached and
detached, and `cms.verify` checks what `openssl cms -sign` makes. It runs
locally. The unit tests replay vectors from `test/interop/generate.sh`, kept in
`test/vectors/cms`.

## Build

```sh
mach dep pull .
mach build .
mach test . --timeout 5m
```

## Workflow

`dev` is the default branch. Work branches from it as `feat/<issue>` or
`fix/<issue>` and merges back through a pull request. `main` only takes release
merges from `dev`. A `hotfix/<issue>` branches from `main` and merges into both.

Both branches require a pull request and a passing `gate` check. Neither can be
deleted or force-pushed, and pull requests merge with a merge commit. Repository
admins can bypass these rules to cut a release. Once a `v*` tag is pushed, only
an admin can move or delete it.

Commits follow [Conventional Commits](https://www.conventionalcommits.org), with
the issue number as the scope: `fix(#12): reject a negative length`.

Issues are labeled on independent axes:

| axis | labels |
| --- | --- |
| semver magnitude | `patch`, `minor`, `major` |
| kind of work | `feature`, `fix`, `removal`, `chore`, `performance` |
| where, omitted for core code | `testing`, `tooling`, `doc` |
| severity and state | `critical`, `blocked`, `parked`, `security` |
| discussion | `discussion` |

## CI

`.github/workflows/ci.yml` runs on pull requests, on Linux. It checks formatting,
builds every artifact for every target in `mach.toml`, and runs the unit tests of
the targets the runner can execute. Targets no runner executes, such as riscv, are
built, never tested. Nothing runs under emulation.

To test on other hosts before merging, such as a darwin-specific change, dispatch
it on the branch: `gh workflow run CI --ref <branch> -f runners='["macos-15"]'`.
A project whose primary host is not Linux changes the default runner list in the
`test` job's matrix.

CI checks that the project builds and its unit tests pass. Integration, load or
demo suites are not CI jobs. Run them locally.

`gate` is the check the branch rules require. It fails if any job it needs
failed or was cancelled.

The compiler version is `MACH_VERSION`, an exact release, in `ci.yml` and
`cd.yml`. Change it together with the `mach` range in `mach.toml`.

## Releases

1. Set `version` in `mach.toml` and merge that into `dev`.
2. Merge `dev` into `main`.
3. Tag `main` and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.

`.github/workflows/cd.yml` checks that the tag matches the manifest version,
runs CI in the release profile on every host the project ships to (the
`runners` list in `cd.yml`, trimmed to the targets it declares), cross-builds
every artifact for every target in release, and publishes a GitHub release. Each artifact is packaged per target
(`.zip` for Windows, `.tar.gz` elsewhere) with `SHA256SUMS`. Names and paths come
from `mach build --plan`, so a new target or artifact needs no workflow change.
The notes are the version's `CHANGELOG.md` section, or generated from merged pull
requests when there is none. A tag with a prerelease part, such as `v1.0.0-rc.1`,
is published as a prerelease.

## License

MIT. See [LICENSE](LICENSE).
