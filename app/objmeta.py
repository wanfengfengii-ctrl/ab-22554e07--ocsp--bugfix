"""Object metadata extraction.

Metadata is a pure function of the DER bytes, computed once at ingest time
and used to index objects without re-parsing DER at adjudication time.  The
offline verifier recomputes the same metadata from the evidence pack.
"""
from __future__ import annotations

from .canonical import canon_time
from .pki import parse_certificate
from .revocation import parse_crl, parse_ocsp

OBJECT_TYPES = ("certificate", "crl", "ocsp")


def compute_meta(otype: str, der: bytes) -> dict:
    if otype == "certificate":
        info = parse_certificate(der)
        return {
            "subject_der_hex": info.subject_der.hex(),
            "issuer_der_hex": info.issuer_der.hex(),
            "ski": info.ski,
            "aki_keyid": info.aki_keyid,
            "serial_hex": info.serial_hex,
            "not_before": canon_time(info.not_before),
            "not_after": canon_time(info.not_after),
            "is_ca": info.is_ca,
            "profile_ok": info.profile_ok,
        }
    if otype == "crl":
        info = parse_crl(der)
        return {
            "issuer_der_hex": info.issuer_der.hex(),
            "aki_keyid": info.aki_keyid,
            "crl_number": info.crl_number,
            "base_crl_number": info.base_crl_number,
            "is_delta": info.is_delta,
            "this_update": canon_time(info.this_update),
            "next_update": canon_time(info.next_update) if info.next_update else None,
            "entry_count": len(info.entries),
            "idp_der_hex": info.idp_der_hex,
            "profile_ok": info.profile_ok,
        }
    if otype == "ocsp":
        info = parse_ocsp(der)
        return {
            "produced_at": canon_time(info.produced_at),
            "response_count": len(info.responses),
            "responses": [
                {
                    "serial_hex": format(r.serial, "x"),
                    "issuer_name_hash": r.issuer_name_hash.hex(),
                    "issuer_key_hash": r.issuer_key_hash.hex(),
                    "hash_alg": r.hash_alg,
                }
                for r in info.responses
            ],
            "profile_ok": info.profile_ok,
        }
    raise ValueError(f"unknown object type {otype!r}")


def revocation_entry_count(otype: str, meta: dict) -> int:
    if otype == "crl":
        return meta.get("entry_count", 0)
    if otype == "ocsp":
        return meta.get("response_count", 0)
    return 0
