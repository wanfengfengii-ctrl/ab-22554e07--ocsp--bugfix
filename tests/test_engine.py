"""Engine-level tests: paths, revocation, policies, name constraints, cycles."""
from __future__ import annotations

from datetime import datetime, timezone

from app.canonical import dumps, sha256_hex
from acceptance.pki_fixtures import (
    make_ca,
    make_crl,
    make_leaf,
    make_ocsp,
)
from tests.conftest import Bag, CUTOFF, EARLY, LATE, SIGNED_AT, T, adjudicate

UTC = timezone.utc


def simple_chain(bag: Bag, *, root_kind="rsa", inter_kind="ec", leaf_kind="ed",
                 with_inter_crl=True, with_root_crl=True, root_crl_entries=(),
                 inter_crl_entries=(), inter_crl_kw=None, root_crl_kw=None,
                 **leaf_kw):
    root = make_ca("Root", root_kind, not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", inter_kind, issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", leaf_kind, not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), **leaf_kw)
    for e in (root, inter, leaf):
        bag.cert(e)
    if with_inter_crl:
        kw = dict(crl_number=1, this_update=T("2024-05-01"), next_update=T("2024-07-01"))
        kw.update(inter_crl_kw or {})
        bag.add(make_crl(inter, entries=list(inter_crl_entries), **kw), "crl", EARLY)
    if with_root_crl:
        kw = dict(crl_number=1, this_update=T("2024-05-01"), next_update=T("2024-07-01"))
        kw.update(root_crl_kw or {})
        bag.add(make_crl(root, entries=list(root_crl_entries), **kw), "crl", EARLY)
    return root, inter, leaf


def test_valid_basic_chain():
    bag = Bag()
    root, inter, leaf = simple_chain(bag, eku=["1.3.6.1.5.5.7.3.3"])
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    assert res["decision"]["path"][0] == sha256_hex(leaf.der)
    assert len(res["decision"]["path"]) == 3


def test_cross_signed_prefers_shorter_then_lexicographic(dataset):
    d, bag = dataset
    fps = d["fps"]
    # both anchors trusted: two equal-length paths; the lexicographically
    # smallest fingerprint sequence must win deterministically.
    res = adjudicate(bag, fps["leaf_ok"], [fps["root_a"], fps["root_b"]],
                     leaf_key=d["leaf_ok"].key)
    assert res["verdict"] == "VALID"
    path = res["decision"]["path"]
    assert len(path) == 3
    inter_options = sorted([fps["inter_by_a"], fps["inter_by_b"]])
    assert path[1] == inter_options[0]
    # only root B trusted: path must go through inter_by_b
    res2 = adjudicate(bag, fps["leaf_ok"], [fps["root_b"]], leaf_key=d["leaf_ok"].key)
    assert res2["verdict"] == "VALID"
    assert res2["decision"]["path"][1] == fps["inter_by_b"]
    assert res2["decision"]["path"][2] == fps["root_b"]


def test_revoked_leaf_rejected(dataset):
    d, bag = dataset
    fps = d["fps"]
    res = adjudicate(bag, fps["leaf_rev"], [fps["root_a"]], leaf_key=d["leaf_rev"].key)
    assert res["verdict"] == "INVALID"
    assert "REVOKED" in res["summary"]["failure_codes"]
    rev = res["revocation"][fps["leaf_rev"]]
    assert rev["status"] == "REVOKED"
    assert rev["revocation_time"] == "2024-03-01T00:00:00Z"


def test_revocation_after_signed_at_is_good(dataset):
    d, bag = dataset
    fps = d["fps"]
    # leaf_late is revoked with revocationDate 2024-07-15 > signed_at: the
    # artifact signed 2024-06-01 must be judged GOOD.
    res = adjudicate(bag, fps["leaf_late"], [fps["root_a"]], leaf_key=d["leaf_late"].key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    assert res["revocation"][fps["leaf_late"]]["status"] == "GOOD"


def test_evidence_after_cutoff_is_inadmissible(dataset):
    d, bag = dataset
    fps = d["fps"]
    # a brand-new CRL revoking leaf_ok, archived after the knowledge cutoff
    late_crl = make_crl(
        d["inter_by_a"],
        entries=[(d["leaf_ok"].cert.serial_number, T("2024-03-01"), "keyCompromise")],
        crl_number=9, this_update=T("2024-05-10"), next_update=T("2024-07-01"),
    )
    bag.add(late_crl, "crl", LATE)  # received after cutoff
    res = adjudicate(bag, fps["leaf_ok"], [fps["root_a"]], leaf_key=d["leaf_ok"].key)
    assert res["verdict"] == "VALID"
    # but the late CRL must be recorded as excluded
    late_fp = sha256_hex(late_crl)
    dispositions = {r["fingerprint"]: r["reason"] for r in res["evidence_accounting"]}
    assert dispositions[late_fp] == "RECEIVED_AFTER_CUTOFF"


def test_in_time_evidence_of_prior_revocation_controls(dataset):
    d, bag = dataset
    fps = d["fps"]
    late_crl = make_crl(
        d["inter_by_a"],
        entries=[(d["leaf_ok"].cert.serial_number, T("2024-03-01"), "keyCompromise")],
        crl_number=9, this_update=T("2024-05-10"), next_update=T("2024-07-01"),
    )
    bag.add(late_crl, "crl", "2024-12-01T00:00:00Z")  # before cutoff
    res = adjudicate(bag, fps["leaf_ok"], [fps["root_a"]], leaf_key=d["leaf_ok"].key)
    assert res["verdict"] == "INVALID"
    assert res["revocation"][fps["leaf_ok"]]["status"] == "REVOKED"


def test_stale_crl():
    bag = Bag()
    root, inter, leaf = simple_chain(
        bag, eku=["1.3.6.1.5.5.7.3.3"],
        inter_crl_kw=dict(this_update=T("2024-01-01"), next_update=T("2024-02-01")),
    )
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "STALE"


def test_unknown_when_no_evidence():
    bag = Bag()
    root, inter, leaf = simple_chain(bag, eku=["1.3.6.1.5.5.7.3.3"],
                                     with_inter_crl=False)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "UNKNOWN"


def test_delta_crl_merge_and_remove_from_crl():
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf_a = make_leaf(inter, "LeafA", "ed", not_before=T("2022-01-01"),
                       not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    leaf_b = make_leaf(inter, "LeafB", "ed", not_before=T("2022-01-01"),
                       not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter, leaf_a, leaf_b):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    # base CRL revokes A and B
    base = make_crl(inter, entries=[
        (leaf_a.cert.serial_number, T("2024-03-01"), "certificateHold"),
        (leaf_b.cert.serial_number, T("2024-03-01"), "keyCompromise"),
    ], crl_number=5, this_update=T("2024-05-01"), next_update=T("2024-07-01"))
    # delta on base removes A (removeFromCRL)
    delta = make_crl(inter, entries=[
        (leaf_a.cert.serial_number, T("2024-05-10"), "removeFromCRL"),
    ], crl_number=6, this_update=T("2024-05-15"), next_update=T("2024-07-01"),
        delta_base_number=5)
    bag.add(base, "crl", EARLY)
    bag.add(delta, "crl", EARLY)
    # A: removed by delta -> GOOD
    res_a = adjudicate(bag, sha256_hex(leaf_a.der), [sha256_hex(root.der)],
                       leaf_key=leaf_a.key)
    assert res_a["verdict"] == "VALID", dumps(res_a["decision"]).decode()
    assert res_a["revocation"][sha256_hex(leaf_a.der)]["status"] == "GOOD"
    # B: still revoked via merged view
    res_b = adjudicate(bag, sha256_hex(leaf_b.der), [sha256_hex(root.der)],
                       leaf_key=leaf_b.key)
    assert res_b["verdict"] == "INVALID"
    assert res_b["revocation"][sha256_hex(leaf_b.der)]["status"] == "REVOKED"


def test_delta_without_base_is_malformed():
    bag = Bag()
    root, inter, leaf = simple_chain(bag, eku=["1.3.6.1.5.5.7.3.3"],
                                     with_inter_crl=False)
    delta = make_crl(inter, entries=[], crl_number=6, this_update=T("2024-05-15"),
                     next_update=T("2024-07-01"), delta_base_number=5)
    bag.add(delta, "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "MALFORMED_EVIDENCE"


def test_ocsp_direct_and_delegated():
    from acceptance.pki_fixtures import make_leaf as ml
    # direct issuer-signed OCSP
    bag = Bag()
    root, inter, leaf = simple_chain(bag, eku=["1.3.6.1.5.5.7.3.3"],
                                     with_inter_crl=False)
    ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="good",
                     this_update=T("2024-05-20"), next_update=T("2024-06-20"))
    bag.add(ocsp, "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "GOOD"

    # delegated responder
    bag2 = Bag()
    root2, inter2, leaf2 = simple_chain(bag2, eku=["1.3.6.1.5.5.7.3.3"],
                                        with_inter_crl=False)
    responder = make_leaf(inter2, "OCSP Responder", "ec", not_before=T("2022-01-01"),
                          not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.9"],
                          key_usage=("digitalSignature",))
    bag2.cert(responder)
    ocsp2 = make_ocsp(inter2, serial=leaf2.cert.serial_number, status="good",
                      this_update=T("2024-05-20"), next_update=T("2024-06-20"),
                      responder=responder)
    bag2.add(ocsp2, "ocsp", EARLY)
    res2 = adjudicate(bag2, sha256_hex(leaf2.der), [sha256_hex(root2.der)],
                      leaf_key=leaf2.key)
    assert res2["verdict"] == "VALID", dumps(res2["decision"]).decode()


def test_ocsp_revoked_and_bad_signature():
    bag = Bag()
    root, inter, leaf = simple_chain(bag, eku=["1.3.6.1.5.5.7.3.3"],
                                     with_inter_crl=False)
    ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="revoked",
                     this_update=T("2024-05-20"), next_update=T("2024-06-20"),
                     revocation_time=T("2024-03-01"), reason="keyCompromise")
    bag.add(ocsp, "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "REVOKED"

    # tampered OCSP bytes -> malformed
    bag2 = Bag()
    root2, inter2, leaf2 = simple_chain(bag2, eku=["1.3.6.1.5.5.7.3.3"],
                                        with_inter_crl=False)
    ocsp2 = bytearray(make_ocsp(inter2, serial=leaf2.cert.serial_number, status="good",
                                this_update=T("2024-05-20"), next_update=T("2024-06-20")))
    ocsp2[-5] ^= 0xFF
    bag2.add(bytes(ocsp2), "ocsp", EARLY)
    res2 = adjudicate(bag2, sha256_hex(leaf2.der), [sha256_hex(root2.der)],
                      leaf_key=leaf2.key)
    assert res2["verdict"] == "INVALID"
    assert res2["revocation"][sha256_hex(leaf2.der)]["status"] == "MALFORMED_EVIDENCE"


def test_cycle_does_not_hang_and_rejects():
    bag = Bag()
    ca_x = make_ca("CA X", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    ca_y = make_ca("CA Y", "ec", issuer=ca_x, not_before=T("2020-01-01"),
                   not_after=T("2040-01-01"))
    # X re-issued by Y (cycle), same key+subject for X
    ca_x2 = make_ca("CA X", "ec", issuer=ca_y, key=ca_x.key,
                    subject_name=ca_x.cert.subject,
                    not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    leaf = make_leaf(ca_x, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (ca_x, ca_y, ca_x2, leaf):
        bag.cert(e)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(ca_x.der)], leaf_key=leaf.key)
    # anchor is ca_x (self-signed); leaf->ca_x direct path exists
    assert res["verdict"] == "INVALID"  # no revocation evidence
    assert "UNKNOWN" in res["summary"]["failure_codes"]
    # and with an unreachable anchor: NO_TRUSTED_ANCHOR branches
    res2 = adjudicate(bag, sha256_hex(leaf.der), ["0" * 64], leaf_key=leaf.key)
    assert res2["verdict"] == "INVALID"
    assert res2["decision"]["rejection_proof"] is not None


def test_unsupported_signature_algorithm():
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"),
                   pkcs1v15=True)  # self-signed with PKCS#1 v1.5: out of profile
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "UNSUPPORTED"


def test_name_constraints_dns():
    from cryptography import x509
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    nc = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None
    )
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), name_constraints=nc)
    leaf_ok = make_leaf(inter, "LeafOK", "ed", not_before=T("2022-01-01"),
                        not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                        san_dns=["www.example.com"])
    leaf_bad = make_leaf(inter, "LeafBad", "ed", not_before=T("2022-01-01"),
                         not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                         san_dns=["evil.org"])
    for e in (root, inter, leaf_ok, leaf_bad):
        bag.cert(e)
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    res_ok = adjudicate(bag, sha256_hex(leaf_ok.der), [sha256_hex(root.der)],
                        leaf_key=leaf_ok.key)
    assert res_ok["verdict"] == "VALID", dumps(res_ok["decision"]).decode()
    res_bad = adjudicate(bag, sha256_hex(leaf_bad.der), [sha256_hex(root.der)],
                         leaf_key=leaf_bad.key)
    assert res_bad["verdict"] == "INVALID"
    assert "NAME_CONSTRAINT_NOT_PERMITTED" in res_bad["summary"]["failure_codes"]


def test_policies_and_mappings():
    P1, P2, P3 = "1.3.6.1.4.1.99999.1", "1.3.6.1.4.1.99999.2", "1.3.6.1.4.1.99999.3"
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), policies=[P1],
                    policy_mappings=[(P1, P2)])
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                     policies=[P2])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    # leaf asserts P2, mapped to issuer's P1 -> valid for initial set [P1]
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, initial_policy_set=[P1])
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    # initial set [P3] does not intersect
    res2 = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                      leaf_key=leaf.key, initial_policy_set=[P3])
    assert res2["verdict"] == "INVALID"
    assert "POLICY_INITIAL_SET_MISMATCH" in res2["summary"]["failure_codes"]


def test_inhibit_any_policy():
    P1 = "1.3.6.1.4.1.99999.1"
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), policies=[P1], inhibit_any=0)
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                     policies=["2.5.29.32.0"])  # anyPolicy only
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, initial_policy_set=[P1])
    # anyPolicy in the leaf is inhibited -> no P1 assertion -> mismatch
    assert res["verdict"] == "INVALID"
    assert "POLICY_INITIAL_SET_MISMATCH" in res["summary"]["failure_codes"]


def test_pathlen_exceeded():
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"),
                   path_len=0)
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    assert "PATHLEN_EXCEEDED" in res["summary"]["failure_codes"]


def test_expired_and_not_yet_valid():
    bag = Bag()
    root, inter, leaf = simple_chain(bag, eku=["1.3.6.1.5.5.7.3.3"])
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, signed_at="2041-01-01T00:00:00Z")
    assert res["verdict"] == "INVALID"
    assert "EXPIRED" in res["summary"]["failure_codes"]


def test_artifact_signature_invalid():
    bag = Bag()
    root, inter, leaf = simple_chain(bag, eku=["1.3.6.1.5.5.7.3.3"])
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key, bad_sig=True)
    assert res["verdict"] == "INVALID"
    assert res["artifact_signature"]["valid"] is False


def test_determinism_byte_identical(dataset):
    d, bag = dataset
    fps = d["fps"]
    r1 = adjudicate(bag, fps["leaf_ok"], [fps["root_a"], fps["root_b"]],
                    leaf_key=d["leaf_ok"].key)
    r2 = adjudicate(bag, fps["leaf_ok"], [fps["root_b"], fps["root_a"]],
                    leaf_key=d["leaf_ok"].key)
    assert dumps(r1) == dumps(r2)
