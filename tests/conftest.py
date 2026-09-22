"""Shared engine test dataset."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

import pytest

from app.adjudicate import DictObjectSource, run_engine, validate_input
from app.canonical import sha256_hex
from acceptance.pki_fixtures import (
    artifact_algorithm_for,
    make_ca,
    make_crl,
    make_leaf,
    make_ocsp,
    sign_data,
)

UTC = timezone.utc
T = lambda s: datetime.fromisoformat(s + "T00:00:00+00:00")

SIGNED_AT = "2024-06-01T00:00:00Z"
CUTOFF = "2025-01-01T00:00:00Z"
EARLY = "2024-01-01T00:00:00Z"
LATE = "2025-06-01T00:00:00Z"


class Bag:
    def __init__(self):
        self.objects = {}

    def add(self, der, otype, received_at=EARLY):
        fp = sha256_hex(der)
        self.objects[fp] = {"type": otype, "der": der, "received_at": received_at}
        return fp

    def cert(self, entity, received_at=EARLY):
        return self.add(entity.der, "certificate", received_at)


def adjudicate(bag: Bag, leaf_fp, anchors, *, signed_at=SIGNED_AT, cutoff=CUTOFF,
               leaf_key=None, bad_sig=False, initial_policy_set=None,
               artifact_digest=None):
    digest = artifact_digest or hashlib.sha256(b"the artifact").hexdigest()
    if leaf_key is not None:
        sig = sign_data(leaf_key, bytes.fromhex(digest))
        alg = None
        from acceptance.pki_fixtures import artifact_algorithm_for as af
        alg = af(leaf_key)
    else:
        sig = b"\x00" * 64
        alg = "ed25519"
    if bad_sig:
        sig = bytes([sig[0] ^ 1]) + sig[1:]
    inp = {
        "artifact_digest": digest,
        "signature": base64.b64encode(sig).decode(),
        "signature_algorithm": alg,
        "signed_at": signed_at,
        "knowledge_cutoff": cutoff,
        "leaf_fingerprint": leaf_fp,
        "trust_anchors": list(anchors),
    }
    if initial_policy_set is not None:
        inp["initial_policy_set"] = initial_policy_set
    inp = validate_input(inp)
    result, touched = run_engine(DictObjectSource(bag.objects), inp, "0" * 64)
    return result


@pytest.fixture(scope="session")
def dataset():
    """A dataset exercising cross-signing, cycles, revocation flavors."""
    bag = Bag()
    d = {}
    root_a = make_ca("Root A", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    root_b = make_ca("Root B", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    # cross-signed intermediate: same key + subject under both roots
    inter_key = None
    inter_by_a = make_ca("Inter X", "ec", issuer=root_a, key=inter_key,
                         not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    inter_key = inter_by_a.key
    inter_by_b = make_ca("Inter X", "ec", issuer=root_b, key=inter_key,
                         subject_name=inter_by_a.cert.subject,
                         not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    leaf_ok = make_leaf(inter_by_a, "Leaf OK", "ed", not_before=T("2022-01-01"),
                        not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    leaf_rev = make_leaf(inter_by_a, "Leaf Revoked", "rsa", not_before=T("2022-01-01"),
                         not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    leaf_late = make_leaf(inter_by_a, "Leaf LateRevoke", "ec", not_before=T("2022-01-01"),
                          not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])

    for e in (root_a, root_b, inter_by_a, inter_by_b, leaf_ok, leaf_rev, leaf_late):
        bag.cert(e)
    d.update(root_a=root_a, root_b=root_b, inter_by_a=inter_by_a,
             inter_by_b=inter_by_b, leaf_ok=leaf_ok, leaf_rev=leaf_rev,
             leaf_late=leaf_late)
    d["fps"] = {name: sha256_hex(e.der) for name, e in d.items()}

    # intermediate CRL: revokes leaf_rev (before signed_at) and leaf_late
    # (after signed_at); covers the other leaves by omission.
    inter_crl = make_crl(
        inter_by_a,
        entries=[
            (leaf_rev.cert.serial_number, T("2024-03-01"), "keyCompromise"),
            (leaf_late.cert.serial_number, T("2024-07-15"), "cessationOfOperation"),
        ],
        crl_number=5, this_update=T("2024-05-01"), next_update=T("2024-07-01"),
    )
    bag.add(inter_crl, "crl", EARLY)
    # root CRLs: root A revokes nothing; root B revokes nothing
    bag.add(make_crl(root_a, entries=[], crl_number=3, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root_b, entries=[], crl_number=3, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    return d, bag
