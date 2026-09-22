"""The supported RFC 5280 profile: algorithms, encodings and resource limits.

Everything not explicitly listed here is out of profile.  Out-of-profile
objects are never silently accepted: they are flagged at parse time and any
adjudication that depends on them fails with a structured UNSUPPORTED outcome.

Supported signature algorithms
  * RSASSA-PSS (1.2.840.113549.1.1.10) with SHA-256/384/512, MGF1 with the
    same hash, RSA key 2048..8192 bits.  Any salt length is accepted at
    verification time (the salt length is recovered from the signature).
  * ECDSA with SHA-256 (1.2.840.10045.4.3.2) on NIST P-256 (secp256r1) only.
  * Ed25519 (1.3.101.112).

Supported public key algorithms
  * rsaEncryption (1.2.840.113549.1.1.1), 2048..8192 bits.
  * id-ecPublicKey (1.2.840.10045.2.1) with secp256r1 only.
  * Ed25519 (1.3.101.112).

Anything else (RSA PKCS#1 v1.5 signatures, DSA, ECDSA P-384/P-521, Ed448,
SHA-1/MD5 based signatures, GOST, ...) is UNSUPPORTED.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.x509.oid import SignatureAlgorithmOID

# ---------------------------------------------------------------------------
# Resource limits (per sealed evidence set)
# ---------------------------------------------------------------------------
MAX_CERTIFICATES = 100_000
MAX_REVOCATION_EVIDENCE = 2_000          # CRLs + OCSP responses combined
MAX_REVOCATION_ENTRIES = 1_000_000       # CRL entries + OCSP single responses
MAX_OBJECT_BYTES = 32 * 1024 * 1024      # per DER object
MAX_BATCH_OBJECTS = 4_096                # per upload batch
MAX_BATCH_BYTES = 128 * 1024 * 1024      # per upload batch (decoded DER)
MAX_PATH_LEN = 32                        # certificates in one candidate path
MAX_EXPLORED_BRANCHES = 65_536           # path-search exploration budget

LIMITS = {
    "max_certificates": MAX_CERTIFICATES,
    "max_revocation_evidence": MAX_REVOCATION_EVIDENCE,
    "max_revocation_entries": MAX_REVOCATION_ENTRIES,
    "max_object_bytes": MAX_OBJECT_BYTES,
    "max_batch_objects": MAX_BATCH_OBJECTS,
    "max_batch_bytes": MAX_BATCH_BYTES,
    "max_path_len": MAX_PATH_LEN,
    "max_explored_branches": MAX_EXPLORED_BRANCHES,
}

# ---------------------------------------------------------------------------
# Algorithm descriptors
# ---------------------------------------------------------------------------
ALG_RSA_PSS_SHA256 = "rsa-pss-sha256"
ALG_RSA_PSS_SHA384 = "rsa-pss-sha384"
ALG_RSA_PSS_SHA512 = "rsa-pss-sha512"
ALG_ECDSA_P256_SHA256 = "ecdsa-p256-sha256"
ALG_ED25519 = "ed25519"

ARTIFACT_SIGNATURE_ALGORITHMS = (ALG_RSA_PSS_SHA256, ALG_ECDSA_P256_SHA256, ALG_ED25519)

_HASH_BY_NAME = {"sha256": SHA256, "sha384": SHA384, "sha512": SHA512}
_PSS_BY_HASH = {
    "sha256": ALG_RSA_PSS_SHA256,
    "sha384": ALG_RSA_PSS_SHA384,
    "sha512": ALG_RSA_PSS_SHA512,
}

OID_RSASSA_PSS = SignatureAlgorithmOID.RSASSA_PSS.dotted_string
OID_ECDSA_SHA256 = SignatureAlgorithmOID.ECDSA_WITH_SHA256.dotted_string
OID_ED25519 = SignatureAlgorithmOID.ED25519.dotted_string


def signature_algorithm_descriptor(sig_oid: str, sig_params, hash_alg) -> dict | None:
    """Map a signature algorithm OID (+parsed params) to a profile descriptor.

    Returns None when the algorithm is out of profile.
    """
    if sig_oid == OID_RSASSA_PSS:
        if hash_alg is None:
            return None
        name = hash_alg.name
        if name not in _PSS_BY_HASH:
            return None
        desc = {"algorithm": _PSS_BY_HASH[name], "hash": name}
        if sig_params is not None and isinstance(sig_params, padding.PSS):
            mgf_hash = getattr(sig_params._mgf, "_algorithm", None)
            desc["mgf_hash"] = getattr(mgf_hash, "name", None)
            desc["salt_length"] = sig_params._salt_length
            if desc["mgf_hash"] != name:
                return None  # profile requires MGF-1 hash == signature hash
        return desc
    if sig_oid == OID_ECDSA_SHA256:
        return {"algorithm": ALG_ECDSA_P256_SHA256, "hash": "sha256"}
    if sig_oid == OID_ED25519:
        return {"algorithm": ALG_ED25519}
    return None


def public_key_descriptor(pub) -> dict | None:
    """Describe a public key; None when out of profile."""
    if isinstance(pub, rsa.RSAPublicKey):
        bits = pub.key_size
        if bits < 2048 or bits > 8192:
            return None
        return {"algorithm": "rsa", "key_size": bits}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        if not isinstance(pub.curve, ec.SECP256R1):
            return None
        return {"algorithm": "ec-p256", "key_size": 256}
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return {"algorithm": "ed25519", "key_size": 256}
    return None


def verify_signature(pub, descriptor: dict, signature: bytes, data: bytes) -> bool:
    """Verify *signature* over *data*; returns True/False (never raises)."""
    try:
        alg = descriptor["algorithm"]
        if alg.startswith("rsa-pss-"):
            hash_alg = _HASH_BY_NAME[descriptor["hash"]]()
            pub.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.AUTO),
                hash_alg,
            )
            return True
        if alg == ALG_ECDSA_P256_SHA256:
            pub.verify(signature, data, ec.ECDSA(SHA256()))
            return True
        if alg == ALG_ED25519:
            pub.verify(signature, data)
            return True
        return False
    except InvalidSignature:
        return False
    except Exception:
        return False


def artifact_algorithm_matches_key(descriptor_alg: str, key_desc: dict) -> bool:
    """True when an artifact signature algorithm fits the leaf key type."""
    if key_desc is None:
        return False
    if descriptor_alg == ALG_RSA_PSS_SHA256:
        return key_desc["algorithm"] == "rsa"
    if descriptor_alg == ALG_ECDSA_P256_SHA256:
        return key_desc["algorithm"] == "ec-p256"
    if descriptor_alg == ALG_ED25519:
        return key_desc["algorithm"] == "ed25519"
    return False
