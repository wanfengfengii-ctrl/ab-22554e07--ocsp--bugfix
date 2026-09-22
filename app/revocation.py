"""Revocation evidence: complete CRLs, delta CRLs and OCSP responses.

Two independent time axes (see README):
  * ``signed_at``         - when the artifact was signed; the revocation
                            *conclusion* is always drawn at this instant.
  * ``knowledge_cutoff``  - evidence is admissible only when its
                            client-declared ``received_at`` <= knowledge_cutoff.

Deterministic evidence selection (README "Revocation evidence selection"):
  1. admissible = received in time, parses, profile-supported, in scope
     (issuer name + issuing key), signature/authorization valid;
  2. candidate views = every complete CRL, every compatible (base, delta)
     pair merged, every matching OCSP response;
  3. the view with the greatest ``as_of`` (CRL/delta: thisUpdate of the
     freshest element; OCSP: thisUpdate of the single response) wins; ties
     break on the lexicographically smallest view id.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

from . import profile
from .canonical import canon_time, parse_time, sha256_hex
from .errors import ParseError
from .pki import EKU_OCSP_SIGNING, CertInfo

# CRL entry reason names (RFC 5280 5.3.1)
_REASON_BY_CODE = {
    0: "unspecified",
    1: "keyCompromise",
    2: "cACompromise",
    3: "affiliationChanged",
    4: "superseded",
    5: "cessationOfOperation",
    6: "certificateHold",
    8: "removeFromCRL",
    9: "privilegeWithdrawn",
    10: "aACompromise",
}
REMOVE_FROM_CRL = "removeFromCRL"

# cryptography ReasonFlags enum name -> RFC 5280 reason name
_ENUM_REASON_NAMES = {
    "unspecified": "unspecified",
    "key_compromise": "keyCompromise",
    "ca_compromise": "cACompromise",
    "affiliation_changed": "affiliationChanged",
    "superseded": "superseded",
    "cessation_of_operation": "cessationOfOperation",
    "certificate_hold": "certificateHold",
    "privilege_withdrawn": "privilegeWithdrawn",
    "aa_compromise": "aACompromise",
    "remove_from_crl": "removeFromCRL",
}

SUPPORTED_CERTID_HASHES = {"sha1": hashes.SHA1, "sha256": hashes.SHA256}

CRL_SUPPORTED_EXTENSION_OIDS = {
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string,
    ExtensionOID.CRL_NUMBER.dotted_string,
    ExtensionOID.DELTA_CRL_INDICATOR.dotted_string,
    ExtensionOID.ISSUING_DISTRIBUTION_POINT.dotted_string,
}


def _unsupported(code: str, detail: str) -> dict:
    return {"code": code, "detail": detail}


@dataclass
class CrlInfo:
    fingerprint: str
    der: bytes
    crl: x509.CertificateRevocationList
    issuer_der: bytes
    aki_keyid: str | None
    crl_number: int | None
    base_crl_number: int | None
    is_delta: bool
    this_update: datetime
    next_update: datetime | None
    entries: dict  # serial int -> (revocation datetime, reason str|None)
    idp_der_hex: str | None
    sig_alg: dict | None
    unsupported: list = field(default_factory=list)

    @property
    def issuer_hex(self) -> str:
        return self.issuer_der.hex()

    @property
    def profile_ok(self) -> bool:
        return not self.unsupported


@dataclass
class SingleResponse:
    serial: int
    status: str  # "good" | "revoked" | "unknown"
    this_update: datetime
    next_update: datetime | None
    revocation_time: datetime | None
    revocation_reason: str | None
    issuer_name_hash: bytes
    issuer_key_hash: bytes
    hash_alg: str


@dataclass
class OcspInfo:
    fingerprint: str
    der: bytes
    produced_at: datetime
    responses: list
    responder_key_hash: bytes | None
    responder_name_der: bytes | None
    responder_certs: list  # list of DER bytes
    signature: bytes
    tbs: bytes
    sig_alg: dict | None
    unsupported: list = field(default_factory=list)

    @property
    def profile_ok(self) -> bool:
        return not self.unsupported


def parse_crl(der: bytes, fingerprint: str | None = None) -> CrlInfo:
    try:
        crl = x509.load_der_x509_crl(der)
    except Exception as exc:
        raise ParseError("CRL_PARSE_ERROR", f"not a DER X.509 CRL: {exc}")
    fp = fingerprint or sha256_hex(der)
    unsupported: list = []

    sig_oid = crl.signature_algorithm_oid.dotted_string
    try:
        hash_alg = crl.signature_hash_algorithm
    except Exception:
        hash_alg = None
    try:
        sig_params = crl.signature_algorithm_parameters
    except Exception:
        sig_params = None
    sig_alg = profile.signature_algorithm_descriptor(sig_oid, sig_params, hash_alg)
    if sig_alg is None:
        unsupported.append(
            _unsupported("UNSUPPORTED_SIGNATURE_ALGORITHM", f"signature algorithm OID {sig_oid}")
        )

    aki_keyid = None
    crl_number = None
    base_crl_number = None
    idp_der_hex = None
    for ext in crl.extensions:
        oid = ext.oid.dotted_string
        if oid not in CRL_SUPPORTED_EXTENSION_OIDS:
            if ext.critical:
                unsupported.append(
                    _unsupported("UNSUPPORTED_CRITICAL_EXTENSION", f"extension OID {oid}")
                )
            continue
        val = ext.value
        if oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string:
            if val.authority_cert_issuer is not None or val.authority_cert_serial_number is not None:
                unsupported.append(
                    _unsupported("UNSUPPORTED_AKI_FORM", "authorityCertIssuer/Serial in CRL AKI")
                )
            aki_keyid = val.key_identifier.hex() if val.key_identifier is not None else None
        elif oid == ExtensionOID.CRL_NUMBER.dotted_string:
            crl_number = val.crl_number
        elif oid == ExtensionOID.DELTA_CRL_INDICATOR.dotted_string:
            base_crl_number = val.crl_number  # BaseCRLNumber of the delta
        elif oid == ExtensionOID.ISSUING_DISTRIBUTION_POINT.dotted_string:
            idp_der_hex = val.public_bytes().hex()
            if (
                val.only_contains_user_certs
                or val.only_contains_ca_certs
                or val.only_contains_attribute_certs
                or val.only_some_reasons is not None
                or val.indirect_crl
            ):
                unsupported.append(
                    _unsupported(
                        "UNSUPPORTED_IDP_SCOPE",
                        "issuingDistributionPoint with scope/reason/indirect restrictions",
                    )
                )
            if val.full_name:
                for gn in val.full_name:
                    if not isinstance(gn, (x509.UniformResourceIdentifier, x509.DirectoryName)):
                        unsupported.append(
                            _unsupported(
                                "UNSUPPORTED_IDP_NAME",
                                f"distributionPoint name {type(gn).__name__}",
                            )
                        )
            if val.relative_name is not None:
                unsupported.append(
                    _unsupported("UNSUPPORTED_IDP_NAME", "relative distributionPoint name")
                )

    is_delta = base_crl_number is not None
    entries: dict = {}
    from .derutil import (
        _OID_CERT_ISSUER,
        _OID_INVALIDITY_DATE,
        _OID_REASON_CODE,
        iter_crl_entries,
        iter_extensions,
        parse_reason_code,
    )

    for serial, rev_date, ext_tlv in iter_crl_entries(der):
        reason = None
        if ext_tlv is not None:
            for oid, critical, value in iter_extensions(ext_tlv):
                if oid == _OID_REASON_CODE:
                    try:
                        reason = _REASON_BY_CODE.get(parse_reason_code(value), "unspecified")
                    except ValueError:
                        unsupported.append(
                            _unsupported("MALFORMED_ENTRY_EXTENSION", "bad reasonCode")
                        )
                elif oid == _OID_INVALIDITY_DATE:
                    if critical:
                        unsupported.append(
                            _unsupported("UNSUPPORTED_CRITICAL_ENTRY_EXTENSION",
                                         "invalidityDate")
                        )
                elif oid == _OID_CERT_ISSUER:
                    unsupported.append(
                        _unsupported(
                            "UNSUPPORTED_ENTRY_EXTENSION", "certificateIssuer (indirect CRL)"
                        )
                    )
                elif critical:
                    unsupported.append(
                        _unsupported("UNSUPPORTED_CRITICAL_ENTRY_EXTENSION",
                                     f"OID {oid.hex()}")
                    )
        if reason == REMOVE_FROM_CRL and not is_delta:
            unsupported.append(
                _unsupported("REMOVEFROMCRL_IN_COMPLETE_CRL", "removeFromCRL outside delta CRL")
            )
        entries[serial] = (rev_date, reason)

    if is_delta and crl_number is None:
        unsupported.append(_unsupported("MISSING_CRL_NUMBER", "delta CRL without cRLNumber"))

    return CrlInfo(
        fingerprint=fp,
        der=der,
        crl=crl,
        issuer_der=crl.issuer.public_bytes(),
        aki_keyid=aki_keyid,
        crl_number=crl_number,
        base_crl_number=base_crl_number,
        is_delta=is_delta,
        this_update=crl.last_update_utc,
        next_update=crl.next_update_utc,
        entries=entries,
        idp_der_hex=idp_der_hex,
        sig_alg=sig_alg,
        unsupported=unsupported,
    )


def parse_ocsp(der: bytes, fingerprint: str | None = None) -> OcspInfo:
    from cryptography.x509.ocsp import OCSPResponseStatus, load_der_ocsp_response

    try:
        resp = load_der_ocsp_response(der)
    except Exception as exc:
        raise ParseError("OCSP_PARSE_ERROR", f"not a DER OCSP response: {exc}")
    fp = fingerprint or sha256_hex(der)
    if resp.response_status != OCSPResponseStatus.SUCCESSFUL:
        raise ParseError(
            "OCSP_STATUS_NOT_SUCCESSFUL", f"OCSP response status {resp.response_status.name}"
        )
    unsupported: list = []

    sig_oid = resp.signature_algorithm_oid.dotted_string
    if sig_oid == profile.OID_RSASSA_PSS:
        # cryptography does not expose PSS parameters for OCSP responses
        from .derutil import extract_ocsp_signature_algorithm, pss_params_hash_name

        try:
            _oid, params = extract_ocsp_signature_algorithm(der)
            hash_name = pss_params_hash_name(params)
        except ValueError:
            hash_name = None
        sig_alg = (
            {"algorithm": f"rsa-pss-{hash_name}", "hash": hash_name}
            if hash_name in ("sha256", "sha384", "sha512")
            else None
        )
    else:
        try:
            hash_alg = resp.signature_hash_algorithm
        except Exception:
            hash_alg = None
        sig_alg = profile.signature_algorithm_descriptor(sig_oid, None, hash_alg)
    if sig_alg is None:
        unsupported.append(
            _unsupported("UNSUPPORTED_SIGNATURE_ALGORITHM", f"signature algorithm OID {sig_oid}")
        )

    for ext in resp.extensions:
        if ext.critical:
            unsupported.append(
                _unsupported(
                    "UNSUPPORTED_CRITICAL_EXTENSION", f"response extension {ext.oid.dotted_string}"
                )
            )

    responses: list = []
    try:
        singles = list(resp.responses())
    except Exception:
        singles = []
        if resp.serial_number is not None:
            singles = [resp]
    for single in singles:
        hash_name = single.hash_algorithm.name if single.hash_algorithm else None
        if hash_name not in SUPPORTED_CERTID_HASHES:
            unsupported.append(
                _unsupported("UNSUPPORTED_CERTID_HASH", f"certID hash {hash_name}")
            )
        for ext in getattr(single, "extensions", []) or []:
            if ext.critical:
                unsupported.append(
                    _unsupported(
                        "UNSUPPORTED_CRITICAL_EXTENSION",
                        f"single response extension {ext.oid.dotted_string}",
                    )
                )
        status_name = single.certificate_status.name.lower()
        rev_reason = None
        if status_name == "revoked" and single.revocation_reason is not None:
            rev_reason = _ENUM_REASON_NAMES.get(
                single.revocation_reason.name, single.revocation_reason.name
            )
        responses.append(
            SingleResponse(
                serial=single.serial_number,
                status=status_name,
                this_update=single.this_update_utc,
                next_update=single.next_update_utc,
                revocation_time=single.revocation_time_utc,
                revocation_reason=rev_reason,
                issuer_name_hash=single.issuer_name_hash,
                issuer_key_hash=single.issuer_key_hash,
                hash_alg=hash_name,
            )
        )

    responder_certs = [
        c.public_bytes(serialization.Encoding.DER) for c in resp.certificates
    ]
    return OcspInfo(
        fingerprint=fp,
        der=der,
        produced_at=resp.produced_at_utc,
        responses=responses,
        responder_key_hash=resp.responder_key_hash,
        responder_name_der=resp.responder_name.public_bytes() if resp.responder_name else None,
        responder_certs=responder_certs,
        signature=resp.signature,
        tbs=resp.tbs_response_bytes,
        sig_alg=sig_alg,
        unsupported=unsupported,
    )


def public_key_bitstring_bytes(pub) -> bytes:
    """The subjectPublicKey BIT STRING contents (used by OCSP key hashes)."""
    if isinstance(pub, rsa.RSAPublicKey):
        return pub.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1
        )
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return pub.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    raise ValueError("unsupported public key type")


def issuer_certid_hashes(issuer: CertInfo) -> dict:
    """{hash_name: (issuer_name_hash_hex, issuer_key_hash_hex)} for an issuer."""
    pub = issuer.public_key()
    key_bytes = public_key_bitstring_bytes(pub)
    out = {}
    for name, factory in SUPPORTED_CERTID_HASHES.items():
        h1 = hashes.Hash(factory())
        h1.update(issuer.subject_der)
        h2 = hashes.Hash(factory())
        h2.update(key_bytes)
        out[name] = (h1.finalize().hex(), h2.finalize().hex())
    return out


def _verify_crl_signature(crl: CrlInfo, issuer: CertInfo) -> bool:
    if crl.sig_alg is None or issuer.key_alg is None:
        return False
    return profile.verify_signature(
        issuer.public_key(), crl.sig_alg, crl.crl.signature, crl.crl.tbs_certlist_bytes
    )


def _responder_id_matches(ocsp: OcspInfo, cert: CertInfo) -> bool:
    if ocsp.responder_key_hash is not None:
        digest = hashes.Hash(hashes.SHA1())
        digest.update(public_key_bitstring_bytes(cert.public_key()))
        return digest.finalize() == ocsp.responder_key_hash
    if ocsp.responder_name_der is not None:
        return cert.subject_der == ocsp.responder_name_der
    return False


def _verify_ocsp_authorization(ocsp: OcspInfo, issuer: CertInfo) -> tuple:
    """Validate the OCSP responder authorization chain.

    Returns (ok, responder_description, verifying_cert_or_None).
    """
    from .pki import parse_certificate

    if ocsp.sig_alg is None:
        return False, "unsupported response signature algorithm", None
    # (a) response signed directly by the issuer
    if issuer.key_alg is not None and _responder_id_matches(ocsp, issuer):
        if profile.verify_signature(issuer.public_key(), ocsp.sig_alg, ocsp.signature, ocsp.tbs):
            return True, "issuer", issuer
    # (b) delegated responder: certificate embedded in the response
    for der in ocsp.responder_certs:
        try:
            rcert = parse_certificate(der)
        except Exception:
            continue
        if rcert.issuer_der != issuer.subject_der:
            continue
        if rcert.unsupported:
            continue
        if rcert.eku is None or EKU_OCSP_SIGNING not in rcert.eku:
            continue
        if not (rcert.not_before <= ocsp.produced_at <= rcert.not_after):
            continue
        if not _responder_id_matches(ocsp, rcert):
            continue
        if rcert.sig_alg is None or not profile.verify_signature(
            issuer.public_key(), rcert.sig_alg, rcert.cert.signature, rcert.cert.tbs_certificate_bytes
        ):
            continue
        if profile.verify_signature(rcert.public_key(), ocsp.sig_alg, ocsp.signature, ocsp.tbs):
            return True, f"delegated:{rcert.fingerprint}", rcert
    return False, "no authorized responder", None


# ---------------------------------------------------------------------------
# Evidence views and status computation
# ---------------------------------------------------------------------------

VIEW_CRL = "crl"
VIEW_OCSP = "ocsp"


def _view_id_crl(fp: str) -> str:
    return f"crl:{fp}"


def _view_id_merged(base_fp: str, delta_fp: str) -> str:
    return f"crl:{base_fp}+{delta_fp}"


def _view_id_ocsp(fp: str) -> str:
    return f"ocsp:{fp}"


class RevocationEvaluator:
    """Computes per-certificate revocation outcomes for one adjudication."""

    def __init__(self, crl_index: dict, ocsp_fps: list, metas: dict,
                 get_crl, get_ocsp, signed_at: datetime, knowledge_cutoff: datetime):
        self._crl_index = crl_index            # issuer_hex -> [fp]
        self._ocsp_fps = ocsp_fps              # [fp]
        self._metas = metas                    # fp -> meta dict (with received_at, type)
        self._get_crl = get_crl
        self._get_ocsp = get_ocsp
        self._signed_at = signed_at
        self._cutoff = knowledge_cutoff
        self._cache: dict = {}
        self.outcomes: dict = {}               # cert_fp -> outcome
        self.accounting: dict = {}             # evidence fp -> disposition record
        self.touched: set = set()

    # -- public -------------------------------------------------------------
    def status(self, cert: CertInfo, issuer: CertInfo) -> dict:
        key = (cert.fingerprint, issuer.key_fp)
        if key in self._cache:
            return self._cache[key]
        outcome = self._compute(cert, issuer)
        self._cache[key] = outcome
        self.outcomes[cert.fingerprint] = outcome
        return outcome

    # -- internals ----------------------------------------------------------
    def _record(self, fp: str, otype: str, disposition: str, reason: str, detail=None):
        prev = self.accounting.get(fp)
        if prev is not None and not (
            prev["disposition"] != "used" and disposition == "used"
        ):
            return prev
        rec = {"fingerprint": fp, "type": otype, "disposition": disposition,
               "reason": reason}
        if detail is not None:
            rec["detail"] = detail
        self.accounting[fp] = rec
        return rec

    def _compute(self, cert: CertInfo, issuer: CertInfo) -> dict:
        signed_at = self._signed_at
        cutoff = self._cutoff
        evaluated: dict = {}
        views: list = []
        defective = 0

        def exclude(fp, otype, reason, detail=None, is_defective=False):
            nonlocal defective
            if is_defective:
                defective += 1
            rec = self._record(fp, otype, "excluded", reason, detail)
            evaluated.setdefault(fp, rec)

        # ---- CRL evidence --------------------------------------------------
        crl_infos: dict = {}
        delta_fps: list = []
        valid_complete: list = []
        for fp in sorted(self._crl_index.get(cert.issuer_hex, [])):
            self.touched.add(fp)
            meta = self._metas[fp]
            if parse_time(meta["received_at"]) > cutoff:
                exclude(fp, "crl", "RECEIVED_AFTER_CUTOFF",
                         f"received_at {meta['received_at']} after knowledge cutoff")
                continue
            crl = self._get_crl(fp)
            crl_infos[fp] = crl
            if crl.unsupported:
                exclude(fp, "crl", "UNSUPPORTED", crl.unsupported, is_defective=True)
                continue
            if crl.aki_keyid is not None and issuer.ski is not None and crl.aki_keyid != issuer.ski:
                exclude(fp, "crl", "KEY_MISMATCH", "CRL AKI does not match issuer SKI")
                continue
            if not _verify_crl_signature(crl, issuer):
                exclude(fp, "crl", "SIGNATURE_INVALID", "CRL signature does not verify",
                        is_defective=True)
                continue
            if crl.is_delta:
                delta_fps.append(fp)
            else:
                valid_complete.append(crl)
                views.append({
                    "view_id": _view_id_crl(fp),
                    "kind": VIEW_CRL,
                    "as_of": crl.this_update,
                    "next_update": crl.next_update,
                    "entries": crl.entries,
                    "evidence": [fp],
                })
        # delta CRLs merge with compatible *valid* complete CRLs
        for fp in delta_fps:
            delta = crl_infos[fp]
            bases = []
            for base in valid_complete:
                if base.issuer_der != delta.issuer_der:
                    continue
                if base.aki_keyid != delta.aki_keyid:
                    continue
                if base.idp_der_hex != delta.idp_der_hex:
                    continue
                if base.crl_number is None or delta.base_crl_number != base.crl_number:
                    continue
                if delta.crl_number is not None and delta.crl_number <= base.crl_number:
                    continue
                bases.append(base)
            if not bases:
                exclude(fp, "crl", "NO_COMPATIBLE_BASE",
                        "no compatible complete CRL for this delta", is_defective=True)
                continue
            for base in sorted(bases, key=lambda b: b.fingerprint):
                merged = dict(base.entries)
                for serial, (rtime, reason) in delta.entries.items():
                    if reason == REMOVE_FROM_CRL:
                        merged.pop(serial, None)
                    else:
                        merged[serial] = (rtime, reason)
                views.append({
                    "view_id": _view_id_merged(base.fingerprint, fp),
                    "kind": VIEW_CRL,
                    "as_of": delta.this_update,
                    "next_update": delta.next_update,
                    "entries": merged,
                    "evidence": [base.fingerprint, fp],
                })

        # ---- OCSP evidence -------------------------------------------------
        id_hashes = issuer_certid_hashes(issuer)
        for fp in sorted(self._ocsp_fps):
            meta = self._metas[fp]
            matched_meta = None
            for r in meta.get("responses", []):
                alg = r.get("hash_alg")
                if alg in id_hashes and r.get("serial_hex") == cert.serial_hex:
                    nh, kh = id_hashes[alg]
                    if r.get("issuer_name_hash") == nh and r.get("issuer_key_hash") == kh:
                        matched_meta = r
                        break
            if matched_meta is None:
                continue
            self.touched.add(fp)
            if parse_time(meta["received_at"]) > cutoff:
                exclude(fp, "ocsp", "RECEIVED_AFTER_CUTOFF",
                        f"received_at {meta['received_at']} after knowledge cutoff")
                continue
            ocsp = self._get_ocsp(fp)
            if ocsp.unsupported:
                exclude(fp, "ocsp", "UNSUPPORTED", ocsp.unsupported, is_defective=True)
                continue
            single = None
            for r in ocsp.responses:
                if r.serial == cert.cert.serial_number and r.hash_alg in id_hashes:
                    nh, kh = id_hashes[r.hash_alg]
                    if r.issuer_name_hash.hex() == nh and r.issuer_key_hash.hex() == kh:
                        single = r
                        break
            if single is None:
                exclude(fp, "ocsp", "SERIAL_MISMATCH", "no single response for this certificate")
                continue
            ok, responder_desc, _rcert = _verify_ocsp_authorization(ocsp, issuer)
            if not ok:
                exclude(fp, "ocsp", "RESPONDER_UNAUTHORIZED", responder_desc, is_defective=True)
                continue
            if single.status == "revoked" and single.revocation_time is None:
                exclude(fp, "ocsp", "INVALID_REVOKED_ENTRY",
                        "revoked single response without revocationTime", is_defective=True)
                continue
            views.append({
                "view_id": _view_id_ocsp(fp),
                "kind": VIEW_OCSP,
                "as_of": single.this_update,
                "next_update": single.next_update,
                "ocsp_status": single.status,
                "revocation_time": single.revocation_time,
                "revocation_reason": single.revocation_reason,
                "evidence": [fp],
                "responder": responder_desc,
            })

        # ---- selection & conclusion ---------------------------------------
        outcome = {
            "certificate": cert.fingerprint,
            "issuer_certificate": issuer.fingerprint,
            "signed_at": canon_time(signed_at),
            "knowledge_cutoff": canon_time(cutoff),
        }
        if not views:
            outcome["status"] = "MALFORMED_EVIDENCE" if defective else "UNKNOWN"
            outcome["selected_view"] = None
            outcome["selected_evidence"] = []
            outcome["evaluated_evidence"] = [evaluated[k] for k in sorted(evaluated)]
            return outcome

        views.sort(key=lambda v: (_neg_time(v["as_of"]), v["view_id"]))
        view = views[0]
        for fp in view["evidence"]:
            rec = self._record(fp, self._metas[fp]["type"], "used", "selected view")
            evaluated[fp] = rec
        for other in views[1:]:
            for fp in other["evidence"]:
                rec = self._record(fp, self._metas[fp]["type"], "excluded",
                                   "NOT_SELECTED",
                                   "superseded by a view with greater as_of")
                evaluated.setdefault(fp, rec)
        outcome["selected_view"] = view["view_id"]
        outcome["selected_evidence"] = sorted(view["evidence"])
        outcome["view_as_of"] = canon_time(view["as_of"])
        outcome["view_next_update"] = canon_time(view["next_update"]) if view["next_update"] else None
        outcome["evaluated_evidence"] = [evaluated[k] for k in sorted(evaluated)]

        if view["kind"] == VIEW_OCSP and view["ocsp_status"] == "unknown":
            outcome["status"] = "UNKNOWN"
            return outcome

        revoked_at = None
        reason = None
        if view["kind"] == VIEW_OCSP:
            if view["ocsp_status"] == "revoked":
                revoked_at = view["revocation_time"]
                reason = view["revocation_reason"]
        else:
            entry = view["entries"].get(cert.cert.serial_number)
            if entry is not None:
                revoked_at, reason = entry

        if revoked_at is not None and revoked_at <= signed_at:
            outcome["status"] = "REVOKED"
            outcome["revocation_time"] = canon_time(revoked_at)
            if reason:
                outcome["revocation_reason"] = reason
            return outcome
        if view["as_of"] >= signed_at or (
            view["next_update"] is not None and view["next_update"] >= signed_at
        ):
            outcome["status"] = "GOOD"
            return outcome
        outcome["status"] = "STALE"
        return outcome


def _neg_time(dt: datetime):
    # sort key for descending datetime
    return -dt.timestamp()
