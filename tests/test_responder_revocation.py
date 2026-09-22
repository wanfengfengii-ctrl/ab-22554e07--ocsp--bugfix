"""Delegated OCSP responder revocation.

A delegated OCSP responder is itself a certificate.  Its status is adjudicated
at the response's ``producedAt`` (never the server clock), with the same
deterministic evidence selection and the request's ``knowledge_cutoff``.  A
response signed by a responder that is not GOOD at ``producedAt`` must never be
a candidate view for the certificate it speaks about; the evidence used to
judge the responder must be accounted for and land in the offline pack; and
self/mutual responder references must not establish authority.
"""
from __future__ import annotations

import base64
import hashlib

from acceptance.pki_fixtures import (
    artifact_algorithm_for,
    make_ca,
    make_crl,
    make_leaf,
    make_ocsp,
    sign_data,
)
from app.adjudicate import DictObjectSource, run_engine, validate_input
from app.canonical import sha256_hex
from tests.conftest import Bag, CUTOFF, EARLY, T, adjudicate

OCSP_EKU = ["1.3.6.1.5.5.7.3.9"]
CS_EKU = ["1.3.6.1.5.5.7.3.3"]
PRODUCED = T("2024-05-21")


def _mini_pki():
    root = make_ca("Root", "ec", not_before=T("2020-01-01"),
                   not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=CS_EKU)
    return root, inter, leaf


def _responder(inter, cn="Responder", kind="ec"):
    return make_leaf(inter, cn, kind, not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=OCSP_EKU,
                     key_usage=("digitalSignature",))


def crl(issuer, *, entries=(), number=1, this_update=None, next_update=None,
        received=EARLY):
    return make_crl(
        issuer, entries=list(entries), crl_number=number,
        this_update=this_update or T("2024-05-01"),
        next_update=next_update if next_update is not None else T("2024-07-01"),
    ), received


def ocsp(inter, serial, *, responder=None, produced_at=PRODUCED,
         this_update=None, next_update=None, status="good",
         revocation_time=None, reason=None, received=EARLY):
    return make_ocsp(
        inter, serial=serial, status=status,
        this_update=this_update or T("2024-05-20"),
        next_update=next_update if next_update is not None else T("2024-06-20"),
        revocation_time=revocation_time, reason=reason,
        responder=responder, produced_at=produced_at,
    ), received


def test_revoked_delegated_responder_does_not_vouch_for_leaf():
    """The reported vulnerability: responder revoked before producedAt.

    The only leaf evidence is an archived CRL that is stale for the leaf at
    signed_at (but lists the responder, revoked before producedAt) plus the
    responder's newer GOOD OCSP response for the leaf.
    """
    bag = Bag()
    root, inter, leaf = _mini_pki()
    resp = _responder(inter)
    for e in (root, inter, leaf, resp):
        bag.cert(e)
    # root CRL keeps the intermediate GOOD
    bag.add(crl(root)[0], "crl", EARLY)
    # single archived inter CRL: responder revoked 2024-03-10 (<= producedAt);
    # stale for the leaf at signed_at (nextUpdate 2024-02-20 < 2024-06-01)
    stale_crl, _ = crl(
        inter,
        entries=[(resp.cert.serial_number, T("2024-03-10"), "keyCompromise")],
        number=2, this_update=T("2024-01-20"), next_update=T("2024-02-20"),
    )
    bag.add(stale_crl, "crl", EARLY)
    resp_ocsp, _ = ocsp(inter, leaf.cert.serial_number, responder=resp)
    bag.add(resp_ocsp, "ocsp", EARLY)

    leaf_fp = sha256_hex(leaf.der)
    resp_fp = sha256_hex(resp.der)
    crl_fp = sha256_hex(stale_crl)
    ocsp_fp = sha256_hex(resp_ocsp)

    res = adjudicate(bag, leaf_fp, [sha256_hex(root.der)], leaf_key=leaf.key)

    assert res["verdict"] == "INVALID"
    leaf_out = res["revocation"][leaf_fp]
    assert leaf_out["status"] == "STALE"
    assert leaf_out["selected_view"] == f"crl:{crl_fp}"
    assert leaf_out["selected_evidence"] == [crl_fp]
    # responder adjudicated at producedAt -> REVOKED
    assert res["responder_revocation"][resp_fp]["status"] == "REVOKED"
    # the responder-signed OCSP is not a candidate view
    dispositions = {r["fingerprint"]: r for r in res["evidence_accounting"]}
    assert dispositions[ocsp_fp]["disposition"] == "excluded"
    assert dispositions[ocsp_fp]["reason"] == "RESPONDER_REVOKED"


def test_responder_judgment_uses_produced_at_not_signed_at():
    """Responder revoked between producedAt and signed_at is still GOOD at
    producedAt, so its response for a pre-revocation artifact is admissible."""
    bag = Bag()
    root, inter, leaf = _mini_pki()
    resp = _responder(inter)
    for e in (root, inter, leaf, resp):
        bag.cert(e)
    bag.add(crl(root)[0], "crl", EARLY)
    # CRL covers both moments; responder revoked 2024-05-25, i.e. AFTER
    # producedAt (2024-05-21) but BEFORE signed_at (2024-06-01)
    inter_crl, _ = crl(
        inter,
        entries=[(resp.cert.serial_number, T("2024-05-25"), "keyCompromise")],
    )
    bag.add(inter_crl, "crl", EARLY)
    bag.add(ocsp(inter, leaf.cert.serial_number, responder=resp)[0], "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "VALID"
    resp_fp = sha256_hex(resp.der)
    assert res["responder_revocation"][resp_fp]["status"] == "GOOD"


def test_responder_revocation_evidence_after_cutoff_is_inadmissible():
    """The knowledge cutoff gates responder evidence exactly like leaf evidence."""
    bag = Bag()
    root, inter, leaf = _mini_pki()
    resp = _responder(inter)
    for e in (root, inter, leaf, resp):
        bag.cert(e)
    bag.add(crl(root)[0], "crl", EARLY)
    bag.add(crl(inter)[0], "crl", EARLY)
    late_crl, _ = crl(
        inter,
        entries=[(resp.cert.serial_number, T("2024-03-10"), "keyCompromise")],
        number=7,
    )
    bag.add(late_crl, "crl", "2025-06-01T00:00:00Z")  # after cutoff
    bag.add(ocsp(inter, leaf.cert.serial_number, responder=resp)[0], "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "VALID"
    dispositions = {r["fingerprint"]: r["reason"] for r in res["evidence_accounting"]}
    assert dispositions[sha256_hex(late_crl)] == "RECEIVED_AFTER_CUTOFF"


def test_direct_issuer_ocsp_needs_no_responder_adjudication():
    bag = Bag()
    root, inter, leaf = _mini_pki()
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(crl(root)[0], "crl", EARLY)
    bag.add(ocsp(inter, leaf.cert.serial_number)[0], "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "VALID"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "GOOD"
    assert res["responder_revocation"] == {}


def test_good_delegated_responder_with_covering_window():
    bag = Bag()
    root, inter, leaf = _mini_pki()
    resp = _responder(inter)
    for e in (root, inter, leaf, resp):
        bag.cert(e)
    bag.add(crl(root)[0], "crl", EARLY)
    bag.add(crl(inter)[0], "crl", EARLY)  # silent about the responder, covers producedAt
    bag.add(ocsp(inter, leaf.cert.serial_number, responder=resp)[0], "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "VALID"
    assert res["responder_revocation"][sha256_hex(resp.der)]["status"] == "GOOD"


def test_delegated_responder_without_covering_evidence_is_not_good():
    """No admissible evidence about the responder: it cannot vouch for the leaf."""
    bag = Bag()
    root, inter, leaf = _mini_pki()
    resp = _responder(inter)
    for e in (root, inter, leaf, resp):
        bag.cert(e)
    bag.add(crl(root)[0], "crl", EARLY)
    bag.add(ocsp(inter, leaf.cert.serial_number, responder=resp)[0], "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    # the responder is UNKNOWN; the leaf's only candidate view (the
    # responder-signed OCSP) was therefore defective evidence
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "MALFORMED_EVIDENCE"
    assert res["responder_revocation"][sha256_hex(resp.der)]["status"] == "UNKNOWN"


def test_self_referencing_responder_is_rejected():
    """A responder whose only status evidence is its own OCSP response is a
    circular reference and cannot establish authority (deterministic)."""
    bag = Bag()
    root, inter, leaf = _mini_pki()
    resp = _responder(inter)
    for e in (root, inter, leaf, resp):
        bag.cert(e)
    bag.add(crl(root)[0], "crl", EARLY)
    bag.add(ocsp(inter, resp.cert.serial_number, responder=resp)[0], "ocsp", EARLY)
    bag.add(ocsp(inter, leaf.cert.serial_number, responder=resp)[0], "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    reasons = {r["reason"] for r in res["evidence_accounting"]}
    assert "RESPONDER_CIRCULAR" in reasons


def test_mutually_referencing_responders_are_rejected():
    bag = Bag()
    root, inter, leaf = _mini_pki()
    a = _responder(inter, "Responder A")
    b = _responder(inter, "Responder B")
    for e in (root, inter, leaf, a, b):
        bag.cert(e)
    bag.add(crl(root)[0], "crl", EARLY)
    bag.add(ocsp(inter, leaf.cert.serial_number, responder=a)[0], "ocsp", EARLY)
    bag.add(ocsp(inter, a.cert.serial_number, responder=b)[0], "ocsp", EARLY)
    bag.add(ocsp(inter, b.cert.serial_number, responder=a)[0], "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    reasons = {r["reason"] for r in res["evidence_accounting"]}
    assert "RESPONDER_CIRCULAR" in reasons


def test_responder_cycle_broken_by_direct_issuer_evidence_still_valid():
    """A cycle is harmless when direct issuer evidence grounds one responder."""
    bag = Bag()
    root, inter, leaf = _mini_pki()
    a = _responder(inter, "Responder A")
    b = _responder(inter, "Responder B")
    for e in (root, inter, leaf, a, b):
        bag.cert(e)
    bag.add(crl(root)[0], "crl", EARLY)
    bag.add(ocsp(inter, leaf.cert.serial_number, responder=a)[0], "ocsp", EARLY)
    bag.add(ocsp(inter, a.cert.serial_number, responder=b)[0], "ocsp", EARLY)
    # issuer vouches directly for b (no delegation) -> grounds the chain
    bag.add(ocsp(inter, b.cert.serial_number)[0], "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "VALID"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "GOOD"


def test_responder_evidence_is_in_the_offline_pack_and_reverifies():
    """The CRL/cert used to revoke the responder must be in the touched set so
    the standalone offline verifier reproduces the verdict byte-for-byte."""
    from app.verify import CheckLog, verify_pack
    from app.canonical import b64e, dumps

    bag = Bag()
    root, inter, leaf = _mini_pki()
    resp = _responder(inter)
    for e in (root, inter, leaf, resp):
        bag.cert(e)
    root_crl, _ = crl(root)
    bag.add(root_crl, "crl", EARLY)
    stale_crl, _ = crl(
        inter,
        entries=[(resp.cert.serial_number, T("2024-03-10"), "keyCompromise")],
        number=2, this_update=T("2024-01-20"), next_update=T("2024-02-20"),
    )
    bag.add(stale_crl, "crl", EARLY)
    resp_ocsp, _ = ocsp(inter, leaf.cert.serial_number, responder=resp)
    bag.add(resp_ocsp, "ocsp", EARLY)

    digest = hashlib.sha256(b"the artifact").hexdigest()
    sig = sign_data(leaf.key, bytes.fromhex(digest))
    inp = validate_input({
        "artifact_digest": digest,
        "signature": base64.b64encode(sig).decode(),
        "signature_algorithm": artifact_algorithm_for(leaf.key),
        "signed_at": "2024-06-01T00:00:00Z",
        "knowledge_cutoff": CUTOFF,
        "leaf_fingerprint": sha256_hex(leaf.der),
        "trust_anchors": [sha256_hex(root.der)],
    })
    source = DictObjectSource(bag.objects)
    # build the sealed manifest over the whole source, compute its digest, then
    # run the engine against that digest so adjudication_id matches the pack
    manifest = {
        "format": "evidence-set-manifest/1", "counts": {}, "limits": {},
        "objects": sorted(
            ({"fingerprint": fp, "type": m["type"], "received_at": m["received_at"]}
             for fp, m in source.metas().items()),
            key=lambda o: o["fingerprint"],
        ),
    }
    content_digest = sha256_hex(dumps(manifest))
    result, touched = run_engine(source, inp, content_digest)
    assert result["verdict"] == "INVALID"
    # responder cert, its CRL and its OCSP are all in the offline object set
    assert sha256_hex(resp.der) in touched
    assert sha256_hex(stale_crl) in touched
    assert sha256_hex(resp_ocsp) in touched
    objects = [
        {"fingerprint": fp, "type": source.metas()[fp]["type"],
         "received_at": source.metas()[fp]["received_at"],
         "der": b64e(source.der(fp))}
        for fp in sorted(touched)
    ]
    pack = {
        "pack_version": 1,
        "adjudication_id": result["adjudication_id"],
        "input": inp,
        "evidence_set": {"content_digest": content_digest, "manifest": manifest},
        "objects": objects,
        "result": result,
    }
    pack_bytes = dumps(pack)
    log = CheckLog()
    assert verify_pack(pack_bytes, log), "\n".join(log.lines)
