# Offline PKI Forensics Adjudication Service

A pure-backend service for air-gapped network-forensics teams.  It ingests
code-signing evidence (certificates, cross-signing certificates, CRLs, delta
CRLs and OCSP responses archived at known times), seals it into immutable
evidence sets, and adjudicates whether a signed artifact was validly signed
**at the moment it was signed**, given exactly the evidence the team already
possessed at a declared knowledge cutoff.

The service never fetches anything from the network, never consults the
system clock for adjudication, and never trusts client-parsed fields: every
signature, constraint and revocation fact is re-verified from the raw DER.

* [Quick start (Docker only)](#quick-start)
* [Time model](#time-model-two-axes)
* [Supported RFC 5280 profile](#supported-rfc-5280-profile)
* [Path building and selection](#path-building-and-selection)
* [Revocation evidence selection](#revocation-evidence-selection)
* [Canonicalization and tie-breaking](#canonicalization-and-tie-breaking)
* [Idempotency, sealing, concurrency](#idempotency-sealing-concurrency)
* [Evidence packs and offline verification](#evidence-packs-and-offline-verification)
* [Resource limits](#resource-limits)
* [HTTP API reference](#http-api-reference)
* [Reproduction](#reproduction)

## Quick start

Only Docker is required:

```sh
docker compose up --build --exit-code-from verify
```

This builds the image, starts **two** API instances (`api-a`, `api-b`)
sharing one persistent volume, and runs the one-shot `verify` acceptance
service, which exercises the whole API against both instances and finishes
with `ACCEPTANCE PASSED` (exit code 0).

The API is exposed on the host at `http://localhost:${API_PORT:-8080}`
(instance `api-a`).  To use a different host port:

```sh
API_PORT=9090 docker compose up --build
```

State persists in the `pki-data` volume.  `docker compose down -v` wipes it.

## Time model (two axes)

The service uses **no wall-clock time** in any adjudication output.  All
times come from the client or from the evidence itself:

* **`signed_at`** — the moment the artifact was signed (adjudication input).
  Certificate validity windows, revocation conclusions and the artifact
  signature are all judged at this instant.
* **`knowledge_cutoff`** — the moment up to which the forensic party had
  already acquired evidence (adjudication input).  Every evidence object
  carries a client-declared **`received_at`**; a *revocation evidence*
  object (CRL, delta CRL, OCSP response) is admissible only when
  `received_at <= knowledge_cutoff`.  Certificates are not time-gated:
  they form the archived certificate graph as seized.

Consequences, by construction:

* A response archived later (`received_at > knowledge_cutoff`) **cannot**
  impersonate contemporaneous knowledge: it is excluded with reason
  `RECEIVED_AFTER_CUTOFF` and recorded in `evidence_accounting`.
* Evidence obtained before the cutoff that declares a revocation dated
  before `signed_at` **must** affect the historical verdict: the revocation
  conclusion is always drawn at `signed_at`, never at `knowledge_cutoff` and
  never at "now".

## Supported RFC 5280 profile

Everything not listed here is out of profile.  Out-of-profile objects are
stored (they may be irrelevant noise) but are never silently accepted: any
adjudication path that depends on them fails with a structured `UNSUPPORTED`
outcome, and a verdict of `UNSUPPORTED` is returned when no valid path
exists and at least one explored branch failed that way.

**Signature algorithms** (certificates, CRLs, OCSP responses, artifact
signatures):

| algorithm | parameters |
|---|---|
| `rsa-pss-sha256` / `rsa-pss-sha384` / `rsa-pss-sha512` | RSASSA-PSS, MGF-1 with the same hash, RSA key 2048–8192 bits, any salt length (recovered at verification) |
| `ecdsa-p256-sha256` | ECDSA with SHA-256 on NIST P-256 only |
| `ed25519` | pure Ed25519 |

**Public keys:** RSA 2048–8192, EC P-256, Ed25519.  RSA PKCS#1 v1.5, DSA,
P-384/P-521, Ed448, SHA-1/MD5-based signatures etc. are `UNSUPPORTED`.

**Artifact signature input:** `signature_algorithm` is one of
`rsa-pss-sha256`, `ecdsa-p256-sha256`, `ed25519`.  The signed message is
defined as the **32 raw bytes** of `artifact_digest` (the lowercase-hex
SHA-256 of the artifact); the signature is verified over those bytes with
the leaf public key (PSS: SHA-256/MGF-1-SHA-256, salt length recovered;
ECDSA: SHA-256; Ed25519: pure).

**Certificate extensions:** BasicConstraints, KeyUsage, ExtendedKeyUsage,
SAN (dNSName, uniformResourceIdentifier, directoryName), NameConstraints
(dNSName, URI, directoryName), certificatePolicies (no qualifiers),
policyMappings, policyConstraints, inhibitAnyPolicy, SKI, AKI
(keyIdentifier form only).  Unknown **critical** extensions, other
SAN/constraint name forms, policy qualifiers and AKI issuer/serial forms
are `UNSUPPORTED`; unknown non-critical extensions are ignored.

**Path validation rules** (all genuinely verified): certificate signatures,
validity at `signed_at` (including the trust anchor's), BasicConstraints
CA=TRUE for issuers, `pathLenConstraint`, KeyUsage (`keyCertSign` for
issuers, `digitalSignature` for the leaf when present), leaf EKU **must**
contain `id-kp-codeSigning`, name constraints (below), policy processing
(below).  The trust anchor is trusted by fiat: its signature and revocation
are not checked, but its validity at `signed_at` is.

**Name constraints:** DNS constraint `example.com` matches the host itself
and any subdomain.  URI constraint `example.com` matches exactly that host;
`.example.com` matches any subdomain but not the apex.  directoryName
constraints match by RDN-subtree prefix.  Constraints accumulate down the
path and apply to SAN names and the subject DN of every certificate below
the constraining CA.

**Policy processing:** `valid_policy_set` starts as `{anyPolicy}` at the
anchor and is narrowed per certificate.  A certificate without
certificatePolicies collapses the set to NULL (sticky).  policyMappings of
the issuer rewrite child policies unless inhibited by
`policyConstraints.inhibitPolicyMapping`; `anyPolicy` keeps the set open
unless inhibited by `inhibitAnyPolicy`.  Skip-count semantics: a constraint
value `k` exempts the `k` certificates immediately below and takes effect
at the `(k+1)`-th; multiple constraints combine with MIN.  Final
acceptance: `requireExplicitPolicy` (when effective at the leaf) requires a
non-NULL, non-anyPolicy-only set; the set must intersect the request's
`initial_policy_set` (default `["anyPolicy"]`; `anyPolicy` in the valid set
satisfies any specific initial policy).  policyMappings containing
`anyPolicy` fail the path (`POLICY_MAPPING_ANY`).

**CRLs:** complete and delta CRLs.  Supported extensions: AKI
(keyIdentifier), cRLNumber, deltaCRLIndicator, issuingDistributionPoint
(only full-name URI/directoryName distribution points; scoped
`onlyContains*`/`onlySomeReasons`/indirect CRLs are `UNSUPPORTED`).  Entry
extensions: reasonCode (including `removeFromCRL`, which is
`UNSUPPORTED` outside delta CRLs); `certificateIssuer` (indirect CRL) and
unknown critical entry extensions are `UNSUPPORTED`.

**OCSP:** basic responses with a successful status, certID hashes SHA-1 or
SHA-256.  The response must be signed by the certificate's issuer directly,
or by a delegated responder whose certificate is embedded in the response,
is issued by the same issuer, verifies with the issuer's key, carries EKU
`id-kp-OCSPSigning`, and is valid at the response's `producedAt`; the
responderID (byKey SHA-1 or byName) must match the signer.  Unknown
critical response/single-response extensions are `UNSUPPORTED`.

## Path building and selection

Path building runs over the **whole certificate graph** of the sealed set:
cross-signed certificates (same key+subject under different issuers),
duplicate certificates (deduplicated by DER fingerprint) and cycles (cut by
never repeating a certificate within a candidate path) are all handled.
Issuers are matched by exact DER-encoded name plus AKI→SKI key pinning when
the child carries an AKI key identifier.

Only paths passing **all** cryptographic, hierarchy, name, policy and
temporal-revocation checks are candidates — the engine never fixes a
shortest chain first and checks revocation afterwards.  Revocation is
evaluated per certificate (it is path-independent) with the actual issuing
key, and every non-anchor certificate on a candidate path must be `GOOD`.

Search order is deterministic: iterative deepening by path length, sibling
issuers in ascending fingerprint order.  Among all valid paths the winner
is therefore unique:

1. **fewest certificates**;
2. then the **lexicographically smallest sequence of DER SHA-256
   fingerprints** (leaf → anchor, lowercase hex).

When no valid path exists, the result contains a **rejection proof**
covering every explored candidate branch (not just the last one): each
branch is a fingerprint path plus the first failing rule
(`CERT_PROFILE/UNSUPPORTED`, `VALIDITY`, `SIGNATURE`, `BASIC_CONSTRAINTS`,
`KEY_USAGE`, `EKU`, `PATHLEN`, `NAME_CONSTRAINTS`, `POLICIES`,
`REVOCATION`, `NO_ISSUER`, `NO_TRUSTED_ANCHOR`).  An anchor-reachability
prefilter prunes branches that cannot terminate at a trust anchor; it is
part of the deterministic search and is reproduced by the offline verifier.

## Revocation evidence selection

Per certificate (with its actual issuing key), over admissible evidence
(`received_at <= knowledge_cutoff`, parses, profile-supported, in scope,
signature/authorization valid):

1. **Candidate views:** every valid complete CRL; every compatible
   (base, delta) pair merged; every matching OCSP response.
2. **Delta compatibility:** same issuer name, equal AKI key identifiers
   (or both absent), equal issuingDistributionPoint (or both absent),
   `delta.baseCRLNumber == base.cRLNumber`, and
   `delta.cRLNumber > base.cRLNumber`.  Merging applies delta entries over
   the base; `removeFromCRL` entries remove the serial.  A delta without a
   compatible base is defective (`NO_COMPATIBLE_BASE`).
3. **Selection:** the view with the greatest `as_of` wins (CRL: thisUpdate;
   merged: the delta's thisUpdate; OCSP: the single response's thisUpdate).
   Ties break on the lexicographically smallest view id
   (`crl:<fp>`, `crl:<base>+<delta>`, `ocsp:<fp>`).
4. **Conclusion at `signed_at`:**
   * `REVOKED` — the view lists the serial with `revocationTime <= signed_at`;
   * `GOOD` — no such entry, and the view covers `signed_at`
     (`as_of >= signed_at`, or `nextUpdate >= signed_at`);
   * `STALE` — the view is too old to cover `signed_at`;
   * `UNKNOWN` — no admissible evidence at all (or OCSP `unknown`);
   * `MALFORMED_EVIDENCE` — only defective evidence (bad signature,
     unauthorized responder, unsupported encoding, unusable delta).

Every evaluated evidence object is recorded in `evidence_accounting` with
its disposition (`used` / `excluded`) and reason
(`RECEIVED_AFTER_CUTOFF`, `SIGNATURE_INVALID`, `KEY_MISMATCH`,
`RESPONDER_UNAUTHORIZED`, `UNSUPPORTED`, `NO_COMPATIBLE_BASE`, ...).

## Canonicalization and tie-breaking

All API responses, stored records and evidence packs are **canonical
JSON**: UTF-8, no whitespace, keys sorted by code point, minimal string
escapes, integers only, no duplicate keys.  Fingerprints and digests are
lowercase-hex SHA-256; timestamps are RFC 3339 normalized to UTC
(`YYYY-MM-DDTHH:MM:SSZ`, optional fractional seconds); DER is standard
base64.  All ordering (manifest objects, batches, accounting, path
selection, view selection) is derived from content, never from insertion
order, so identical evidence + input + configuration produce
**byte-identical** results and pack digests across API instances, upload
orders and process restarts.

## Idempotency, sealing, concurrency

* Every mutating endpoint takes a client **`request_id`**.  Replaying the
  same id with the same *normalized* request returns the stored original
  response; the same id with different content returns `409
  IDEMPOTENCY_CONFLICT`.  A retry after a lost response therefore never
  creates a semantically different object.  Normalization: JSON keys are
  order-insensitive; upload batches are treated as **unordered sets** of
  objects (with canonicalized `received_at`); adjudication inputs are
  normalized (`trust_anchors` and `initial_policy_set` are deduplicated and
  sorted, timestamps canonicalized, base64 canonicalized).  Unknown request
  fields are rejected (`VALIDATION`).
* **Sealing** is atomic: under a single immediate transaction the manifest
  (sorted object list + counts + limits) is frozen and its
  `content_digest` (SHA-256 of the canonical manifest) is stored.  Two
  instances sealing concurrently obtain the same single immutable manifest;
  sealing an already-sealed set returns the existing seal.
* **Adjudications are content-addressed**:
  `adjudication_id = "adj_" + SHA-256(canonical({content_digest, input}))`.
  An adjudication pins the sealed set's `content_digest`; concurrent
  uploads or seals of *other* sets cannot leak in, and identical
  adjudications on any instance return the same stored result.
* Persistence is SQLite (WAL, `synchronous=FULL`) on the shared volume;
  all writes run in `BEGIN IMMEDIATE` transactions, so concurrent uploads
  deduplicate by content fingerprint and never produce divergent state.

## Evidence packs and offline verification

`GET /v1/adjudications/{id}/evidence-pack` returns a single canonical-JSON
pack containing: the adjudication input, the sealed-set content digest and
full manifest, **every DER object the engine actually referenced** (path or
rejection-proof certificates and all evaluated revocation evidence), the
selected path or complete rejection proof, per-rule intermediate
conclusions, per-certificate revocation outcomes, the evidence accounting
and the final verdict.  The `X-Evidence-Pack-SHA256` header carries the
pack digest.

The offline verifier reads **only** the pack file — no service, database or
network:

```sh
python -m app.verify evidence-pack.json     # exits 0 on VERIFY OK
```

It re-parses every DER object, re-verifies all raw signatures, the path,
the two-axis revocation rules and every digest, re-runs the deterministic
adjudication engine on the pack contents, and requires the recomputed
result to be byte-identical to the recorded one.  It never compares
service-written hashes alone: tampering with any input, DER object, rule
conclusion or the final verdict makes verification fail.

## Resource limits

Per sealed evidence set (enforced atomically at upload):

| limit | value |
|---|---|
| certificates | 100,000 |
| CRL + OCSP evidence objects | 2,000 |
| revocation entries (CRL entries + OCSP responses) | 1,000,000 |
| single DER object | 32 MiB |
| objects per upload batch | 4,096 |
| decoded bytes per upload batch | 128 MiB |
| candidate path length | 32 |
| explored branches per adjudication | 65,536 |

Ingest parses each object once and indexes it; adjudication parses only
objects relevant to the explored subgraph (never the whole set) and caches
signature verifications, so large noise sets do not slow down verdicts.

## HTTP API reference

All bodies are canonical JSON.  Errors are
`{"error": {"code", "message", "details?"}}` with codes `VALIDATION`,
`NOT_FOUND`, `IDEMPOTENCY_CONFLICT`, `EVIDENCE_SET_SEALED`,
`EVIDENCE_SET_NOT_SEALED`, `LEAF_NOT_FOUND`, `UNSUPPORTED`,
`LIMIT_EXCEEDED`, `RESOURCE_EXHAUSTED`, `INTERNAL`.

| method | path | purpose |
|---|---|---|
| GET | `/healthz` | health check |
| GET | `/v1/profile` | supported profile + limits |
| POST | `/v1/evidence-sets` | create set: `{request_id, label?}` → `201 {evidence_set_id, status}` |
| GET | `/v1/evidence-sets/{id}` | status + counts (+ `content_digest` once sealed) |
| GET | `/v1/evidence-sets/{id}/manifest` | sealed manifest (canonical) |
| POST | `/v1/evidence-sets/{id}/objects` | batch add: `{request_id, objects:[{type, der, received_at}]}` with `type ∈ {certificate, crl, ocsp}` → `{added, duplicates, rejected, counts}`. `received_at` (RFC 3339) is required for `crl`/`ocsp` and optional for `certificate` |
| POST | `/v1/evidence-sets/{id}/seal` | atomic seal: `{request_id}` → `{status:"SEALED", content_digest, counts}` |
| POST | `/v1/adjudications` | adjudicate: `{request_id, evidence_set_id, input}` → `201` result |
| GET | `/v1/adjudications/{id}` | adjudication result |
| GET | `/v1/adjudications/{id}/evidence-pack` | evidence pack (+ `X-Evidence-Pack-SHA256`) |

Adjudication `input`:

```json
{
  "artifact_digest": "<64 hex>",
  "signature": "<base64>",
  "signature_algorithm": "rsa-pss-sha256 | ecdsa-p256-sha256 | ed25519",
  "signed_at": "2024-06-01T00:00:00Z",
  "knowledge_cutoff": "2025-01-01T00:00:00Z",
  "leaf_fingerprint": "<64 hex>",
  "initial_policy_set": ["anyPolicy"],
  "trust_anchors": ["<64 hex>", "..."]
}
```

Verdicts: `VALID` (artifact signature valid and a valid path exists),
`INVALID`, `UNSUPPORTED` (no valid path and at least one explored branch
failed on out-of-profile cryptography/encodings — nothing is ever
downgraded to accepted).

## Reproduction

```sh
# full acceptance (build, start two instances, run verify service)
docker compose up --build --exit-code-from verify

# run the API only, on a chosen host port
API_PORT=8080 docker compose up --build api-a api-b

# offline verification of a downloaded pack (any machine with the repo:
# the verifier needs only the pack file)
pip install -r requirements.txt
python -m app.verify evidence-pack.json

# ... or inside a running container
docker compose cp evidence-pack.json api-a:/tmp/pack.json
docker compose exec api-a python -m app.verify /tmp/pack.json

# local development (no Docker)
pip install -r requirements.txt
DATA_DIR=/tmp/pki python -m app.api          # serves on :8080
python -m pytest tests/ -q                   # unit + API tests
```

Layout: `app/` (service: `canonical`, `profile`, `pki`, `derutil`,
`revocation`, `graph`, `adjudicate`, `objmeta`, `store`, `api`, `verify`),
`acceptance/` (fixture generator + the `verify` acceptance service),
`tests/` (pytest suites), `Dockerfile`, `docker-compose.yml`.
