"""Engine tests, part 2: path selection, PSS-OCSP, URI constraints, more."""
from __future__ import annotations

from datetime import datetime, timezone

from app.adjudicate import DictObjectSource, run_engine, validate_input
from app.canonical import dumps, sha256_hex
from acceptance.pki_fixtures import make_ca, make_crl, make_leaf, make_ocsp
from tests.conftest import Bag, EARLY, LATE, T, adjudicate

UTC = timezone.utc


def test_shorter_path_revoked_longer_path_valid():
    """The engine must not lock onto the shortest chain before revocation."""
    bag = Bag()
    root_a = make_ca("Root A", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    root_b = make_ca("Root B", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    bridge = make_ca("Bridge", "ec", issuer=root_b, not_before=T("2021-01-01"),
                     not_after=T("2035-01-01"))
    inter = make_ca("Inter", "ec", issuer=root_a, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    # same key+subject also issued by bridge (longer path)
    inter2 = make_ca("Inter", "ec", issuer=bridge, key=inter.key,
                     subject_name=inter.cert.subject,
                     not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root_a, root_b, bridge, inter, inter2, leaf):
        bag.cert(e)
    # root A revokes inter (the short path's intermediate)
    bag.add(make_crl(root_a, entries=[(inter.cert.serial_number, T("2024-03-01"),
                                       "keyCompromise")],
                     crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root_b, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(bridge, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    anchors = [sha256_hex(root_a.der), sha256_hex(root_b.der)]
    res = adjudicate(bag, sha256_hex(leaf.der), anchors, leaf_key=leaf.key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    path = res["decision"]["path"]
    assert len(path) == 4  # the longer, still-valid path wins
    assert path[1] == sha256_hex(inter2.der)
    assert path[2] == sha256_hex(bridge.der)


def test_pss_ocsp_response():
    """OCSP response signed with RSA-PSS (fixture DER surgery)."""
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "rsa", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="good",
                     this_update=T("2024-05-20"), next_update=T("2024-06-20"))
    bag.add(ocsp, "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "GOOD"


def test_ocsp_unknown_status():
    bag = Bag()
    root = make_ca("Root", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="unknown",
                     this_update=T("2024-05-20"), next_update=T("2024-06-20"))
    bag.add(ocsp, "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "UNKNOWN"


def test_stale_crl_with_old_revocation_still_revokes():
    """A stale CRL that recorded a revocation before signed_at still proves it."""
    bag = Bag()
    root = make_ca("Root", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    # stale CRL (nextUpdate < signed_at) but lists the leaf revoked long ago
    bag.add(make_crl(inter, entries=[(leaf.cert.serial_number, T("2024-01-15"),
                                      "keyCompromise")],
                     crl_number=1, this_update=T("2024-01-20"),
                     next_update=T("2024-02-20")), "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    assert res["revocation"][sha256_hex(leaf.der)]["status"] == "REVOKED"


def test_uri_name_constraints():
    from cryptography import x509

    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    nc = x509.NameConstraints(
        permitted_subtrees=[x509.UniformResourceIdentifier(".example.com")],
        excluded_subtrees=[x509.UniformResourceIdentifier("bad.example.com")],
    )
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), name_constraints=nc)
    leaf_ok = make_leaf(inter, "LeafOK", "ed", not_before=T("2022-01-01"),
                        not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                        san_uri=["https://www.example.com/app"])
    leaf_excl = make_leaf(inter, "LeafExcl", "ed", not_before=T("2022-01-01"),
                          not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                          san_uri=["https://bad.example.com/app"])
    leaf_apex = make_leaf(inter, "LeafApex", "ed", not_before=T("2022-01-01"),
                          not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                          san_uri=["https://example.com/app"])
    for e in (root, inter, leaf_ok, leaf_excl, leaf_apex):
        bag.cert(e)
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    anchor = sha256_hex(root.der)
    res_ok = adjudicate(bag, sha256_hex(leaf_ok.der), [anchor], leaf_key=leaf_ok.key)
    assert res_ok["verdict"] == "VALID", dumps(res_ok["decision"]).decode()
    res_excl = adjudicate(bag, sha256_hex(leaf_excl.der), [anchor], leaf_key=leaf_excl.key)
    assert res_excl["verdict"] == "INVALID"
    assert "NAME_CONSTRAINT_EXCLUDED" in res_excl["summary"]["failure_codes"]
    # ".example.com" permits subdomains only, not the apex host
    res_apex = adjudicate(bag, sha256_hex(leaf_apex.der), [anchor], leaf_key=leaf_apex.key)
    assert res_apex["verdict"] == "INVALID"
    assert "NAME_CONSTRAINT_NOT_PERMITTED" in res_apex["summary"]["failure_codes"]


def test_require_explicit_policy():
    P1 = "1.3.6.1.4.1.99999.1"
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"), policies=[P1],
                    policy_constraints={"require_explicit": 0})
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                     policies=[P1])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    anchor = sha256_hex(root.der)
    res = adjudicate(bag, sha256_hex(leaf.der), [anchor], leaf_key=leaf.key,
                     initial_policy_set=[P1])
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    # with a leaf that asserts nothing, explicit policy required -> fail
    bag2 = Bag()
    root2 = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter2 = make_ca("Inter", "ec", issuer=root2, not_before=T("2021-01-01"),
                     not_after=T("2035-01-01"), policies=[P1],
                     policy_constraints={"require_explicit": 0})
    leaf2 = make_leaf(inter2, "Leaf", "ed", not_before=T("2022-01-01"),
                      not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root2, inter2, leaf2):
        bag2.cert(e)
    bag2.add(make_crl(inter2, entries=[], crl_number=1, this_update=T("2024-05-01"),
                      next_update=T("2024-07-01")), "crl", EARLY)
    bag2.add(make_crl(root2, entries=[], crl_number=1, this_update=T("2024-05-01"),
                      next_update=T("2024-07-01")), "crl", EARLY)
    res2 = adjudicate(bag2, sha256_hex(leaf2.der), [sha256_hex(root2.der)],
                      leaf_key=leaf2.key, initial_policy_set=[P1])
    assert res2["verdict"] == "INVALID"
    assert "POLICY" in ",".join(res2["summary"]["failure_codes"])


def test_cross_signed_different_keys_aki_selects_parent():
    """Same subject name, different keys: AKI/SKI pins the right parent."""
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter_k1 = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                       not_after=T("2035-01-01"))
    # same subject name, DIFFERENT key, same issuer
    inter_k2 = make_ca("Inter", "ec", issuer=root, subject_name=inter_k1.cert.subject,
                       not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    leaf = make_leaf(inter_k1, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter_k1, inter_k2, leaf):
        bag.cert(e)
    # CRL signed by inter_k1's key (the real issuer of leaf)
    bag.add(make_crl(inter_k1, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    assert res["decision"]["path"][1] == sha256_hex(inter_k1.der)


def test_rejection_proof_covers_all_branches():
    """With two candidate issuers both failing, the proof lists both branches."""
    bag = Bag()
    root_a = make_ca("Root A", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    root_b = make_ca("Root B", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root_a, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    inter_b = make_ca("Inter", "ec", issuer=root_b, key=inter.key,
                      subject_name=inter.cert.subject,
                      not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root_a, root_b, inter, inter_b, leaf):
        bag.cert(e)
    # no CRLs at all -> every branch fails with revocation UNKNOWN
    res = adjudicate(bag, sha256_hex(leaf.der),
                     [sha256_hex(root_a.der), sha256_hex(root_b.der)], leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    proof = res["decision"]["rejection_proof"]
    assert proof is not None
    paths = [tuple(b["path"]) for b in proof["branches"]]
    assert len(paths) >= 2, proof
    inters = {p[1] for p in paths}
    assert sha256_hex(inter.der) in inters
    assert sha256_hex(inter_b.der) in inters
    for b in proof["branches"]:
        assert "failure" in b and "rule" in b["failure"]


def test_ocsp_sha256_certid():
    from cryptography.hazmat.primitives import hashes

    bag = Bag()
    root = make_ca("Root", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter, leaf):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="good",
                     this_update=T("2024-05-20"), next_update=T("2024-06-20"),
                     hash_alg=hashes.SHA256())
    bag.add(ocsp, "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()


def _delegated_responder_setup():
    """root -> inter -> code-signing leaf, plus a delegated OCSP responder
    directly issued by inter.  No revocation evidence is added yet."""
    bag = Bag()
    root = make_ca("Root", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    responder = make_leaf(inter, "OCSP Responder", "ec", not_before=T("2022-01-01"),
                          not_after=T("2030-01-01"),
                          eku=["1.3.6.1.5.5.7.3.9"],
                          key_usage=("digitalSignature",))
    for e in (root, inter, leaf, responder):
        bag.cert(e)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    return bag, root, inter, leaf, responder


def test_revoked_delegated_responder_cannot_vouch_for_leaf():
    """The reported vulnerability: a responder revoked before producedAt must
    not make a leaf GOOD; with only a stale leaf CRL the leaf is STALE and
    the verdict INVALID, and the responder-revocation CRL is accounted for
    and part of the offline object set."""
    bag, root, inter, leaf, responder = _delegated_responder_setup()
    # leaf-only CRL: stale at signed_at (nextUpdate 2024-02-01)
    stale_crl = make_crl(inter, entries=[], crl_number=1,
                         this_update=T("2024-01-01"), next_update=T("2024-02-01"))
    bag.add(stale_crl, "crl", EARLY)
    # archived CRL revoking the responder at 2024-04-01.  Its window closes
    # 2024-05-22: stale for the leaf at signed_at (2024-06-01), yet the
    # recorded revocation (2024-04-01) still proves the responder REVOKED at
    # producedAt (2024-05-25) - a revoked entry dominates staleness.
    responder_crl = make_crl(inter, entries=[
        (responder.cert.serial_number, T("2024-04-01"), "keyCompromise"),
    ], crl_number=2, this_update=T("2024-05-20"), next_update=T("2024-05-22"))
    bag.add(responder_crl, "crl", EARLY)
    # delegated OCSP: producedAt 2024-05-25 (after the responder revocation),
    # window covers the 2024-06-01 signing time, claims the leaf GOOD
    ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="good",
                     this_update=T("2024-05-20"), next_update=T("2024-07-01"),
                     responder=responder, produced_at=T("2024-05-25"))
    ocsp_fp = bag.add(ocsp, "ocsp", EARLY)

    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "INVALID", dumps(res["decision"]).decode()
    leaf_out = res["revocation"][sha256_hex(leaf.der)]
    assert leaf_out["status"] == "STALE"
    # the delegated OCSP must never be the selected view
    assert leaf_out["selected_view"].startswith("crl:")
    assert ocsp_fp not in leaf_out["selected_evidence"]
    # the delegated OCSP must not have been selected
    acct = {r["fingerprint"]: r for r in res["evidence_accounting"]}
    assert acct[ocsp_fp]["reason"] == "RESPONDER_REVOKED"
    # the responder-revocation CRL is part of evidence accounting and marked
    # as used (it decided the responder's status)
    r_crl_fp = sha256_hex(responder_crl)
    assert r_crl_fp in acct
    assert acct[r_crl_fp]["disposition"] == "used"
    # intermediate responder conclusion at producedAt
    r_out = {o["certificate"]: o for o in res["responder_revocation"]}
    rr = r_out[sha256_hex(responder.der)]
    assert rr["status"] == "REVOKED"
    assert rr["evaluated_at"] == "2024-05-25T00:00:00Z"
    assert rr["revocation_time"] == "2024-04-01T00:00:00Z"
    # the responder CRL is in the offline review (touched) object set
    _, touched = _rerun(res, bag)
    assert r_crl_fp in touched
    assert ocsp_fp in touched


def _rerun(res, bag):
    inp = validate_input(res["input"])
    return run_engine(DictObjectSource(bag.objects), inp, "0" * 64)


def test_responder_revocation_after_produced_at_still_allows_response():
    """A responder revoked after producedAt was GOOD when it signed; the
    response remains a valid leaf view."""
    bag, root, inter, leaf, responder = _delegated_responder_setup()
    # responder revoked after producedAt.  Such a CRL is necessarily at least
    # as fresh as the response (thisUpdate >= revocationTime > producedAt);
    # evaluated at producedAt the responder is GOOD because the revocation is
    # in the future and the window covers producedAt.
    bag.add(make_crl(inter, entries=[
        (responder.cert.serial_number, T("2024-06-10"), "keyCompromise"),
    ], crl_number=2, this_update=T("2024-06-15"), next_update=T("2024-07-15")),
        "crl", EARLY)
    ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="good",
                     this_update=T("2024-05-20"), next_update=T("2024-07-01"),
                     responder=responder, produced_at=T("2024-05-25"))
    bag.add(ocsp, "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    leaf_out = res["revocation"][sha256_hex(leaf.der)]
    assert leaf_out["status"] == "GOOD"
    r_out = {o["certificate"]: o for o in res["responder_revocation"]}
    assert r_out[sha256_hex(responder.der)]["status"] == "GOOD"
    assert r_out[sha256_hex(responder.der)]["evaluated_at"] == "2024-05-25T00:00:00Z"


def test_responder_revocation_evidence_after_cutoff_is_inadmissible():
    """The responder check shares the knowledge cutoff: an only-after-cutoff
    revocation of the responder cannot be used, but the response still needs
    the responder GOOD at producedAt from admissible evidence."""
    bag, root, inter, leaf, responder = _delegated_responder_setup()
    # no in-time responder evidence: only a late CRL revoking the responder
    bag.add(make_crl(inter, entries=[
        (responder.cert.serial_number, T("2024-04-01"), "keyCompromise"),
    ], crl_number=2, this_update=T("2024-05-20"), next_update=T("2024-07-01")),
        "crl", LATE)
    ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="good",
                     this_update=T("2024-05-20"), next_update=T("2024-07-01"),
                     responder=responder, produced_at=T("2024-05-25"))
    ocsp_fp = bag.add(ocsp, "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    # without admissible responder status evidence the response is not
    # authorized; the leaf has no evidence at all -> UNKNOWN -> INVALID
    assert res["verdict"] == "INVALID"
    acct = {r["fingerprint"]: r for r in res["evidence_accounting"]}
    assert acct[ocsp_fp]["reason"] == "RESPONDER_UNAUTHORIZED"


def test_delegated_responder_self_endorsing_cycle_is_cut():
    """An OCSP response for the leaf whose responder can only establish its
    own GOOD through itself must not authorize (self endorsement)."""
    bag, root, inter, leaf, responder = _delegated_responder_setup()
    # OCSP A: responder vouches for the leaf; responder's own status must be
    # proven - the only evidence is an OCSP response for the responder signed
    # by the very same responder, claiming GOOD.
    leaf_ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="good",
                          this_update=T("2024-05-20"), next_update=T("2024-07-01"),
                          responder=responder, produced_at=T("2024-05-25"))
    self_ocsp = make_ocsp(inter, serial=responder.cert.serial_number,
                          status="good", this_update=T("2024-05-20"),
                          next_update=T("2024-07-01"), responder=responder,
                          produced_at=T("2024-05-25"))
    leaf_fp = bag.add(leaf_ocsp, "ocsp", EARLY)
    self_fp = bag.add(self_ocsp, "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    acct = {r["fingerprint"]: r for r in res["evidence_accounting"]}
    # the self-endorsing edge must be recorded as a cycle
    cycle_reasons = {acct[self_fp]["reason"], acct[leaf_fp]["reason"]}
    assert "RESPONDER_CYCLE" in cycle_reasons
    # determinism: a second run is byte-identical
    res2, _ = run_engine(DictObjectSource(bag.objects),
                         validate_input(res["input"]), "0" * 64)
    assert dumps(res2) == dumps(res)


def test_mutual_responder_endorsement_is_cut():
    """Two responders vouching for each other form a cycle that proves
    neither, regardless of which response is examined first."""
    bag, root, inter, leaf, resp_a = _delegated_responder_setup()
    resp_b = make_leaf(inter, "OCSP Responder B", "ec", not_before=T("2022-01-01"),
                       not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.9"],
                       key_usage=("digitalSignature",))
    bag.cert(resp_b)
    # leaf: vouched by A.  A: GOOD only via B.  B: GOOD only via A.
    leaf_ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="good",
                          this_update=T("2024-05-20"), next_update=T("2024-07-01"),
                          responder=resp_a, produced_at=T("2024-05-25"))
    a_by_b = make_ocsp(inter, serial=resp_a.cert.serial_number, status="good",
                       this_update=T("2024-05-20"), next_update=T("2024-07-01"),
                       responder=resp_b, produced_at=T("2024-05-25"))
    b_by_a = make_ocsp(inter, serial=resp_b.cert.serial_number, status="good",
                       this_update=T("2024-05-20"), next_update=T("2024-07-01"),
                       responder=resp_a, produced_at=T("2024-05-25"))
    bag.add(leaf_ocsp, "ocsp", EARLY)
    bag.add(a_by_b, "ocsp", EARLY)
    bag.add(b_by_a, "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "INVALID"
    reasons = {r["reason"] for r in res["evidence_accounting"]
               if r["type"] == "ocsp"}
    assert "RESPONDER_CYCLE" in reasons
    # adding an independent CRL that genuinely says A is GOOD breaks the
    # dependence on the cycle and makes the leaf VALID via A
    bag.add(make_crl(inter, entries=[], crl_number=9,
                     this_update=T("2024-05-01"), next_update=T("2024-07-01")),
            "crl", EARLY)
    res2 = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                      leaf_key=leaf.key)
    assert res2["verdict"] == "VALID", dumps(res2["decision"]).decode()


def test_responder_produced_at_equal_signed_at_field_shape():
    """When producedAt coincides with signed_at, the shared conclusion cache
    must not leak the internal ``evaluated_at`` key into the top-level path
    revocation output (it must always carry ``signed_at``)."""
    bag, root, inter, leaf, responder = _delegated_responder_setup()
    bag.add(make_crl(inter, entries=[], crl_number=2,
                     this_update=T("2024-05-01"), next_update=T("2024-07-01")),
            "crl", EARLY)
    ocsp = make_ocsp(inter, serial=leaf.cert.serial_number, status="good",
                     this_update=T("2024-05-20"), next_update=T("2024-07-01"),
                     responder=responder, produced_at=T("2024-06-01"))
    bag.add(ocsp, "ocsp", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                     leaf_key=leaf.key)
    assert res["verdict"] == "VALID", dumps(res["decision"]).decode()
    top = res["revocation"][sha256_hex(leaf.der)]
    assert "signed_at" in top and "evaluated_at" not in top
    nested = {o["certificate"]: o for o in res["responder_revocation"]}
    n = nested[sha256_hex(responder.der)]
    assert n.get("evaluated_at") == "2024-06-01T00:00:00Z"
    assert "signed_at" not in n


def test_responder_chain_depth_is_bounded_deterministically():
    """An implausibly long chain of nested delegated responders is rejected
    deterministically rather than overflowing the evaluator."""
    from app.revocation import MAX_RESPONDER_CHAIN

    bag, root, inter, leaf, _ = _delegated_responder_setup()
    responders = [
        make_leaf(inter, f"Chain Responder {i}", "ec",
                  not_before=T("2022-01-01"), not_after=T("2030-01-01"),
                  eku=["1.3.6.1.5.5.7.3.9"], key_usage=("digitalSignature",))
        for i in range(MAX_RESPONDER_CHAIN + 2)
    ]
    for r in responders:
        bag.cert(r)
    # leaf vouched by responders[0]; each responders[i] vouched by [i+1]
    bag.add(make_ocsp(inter, serial=leaf.cert.serial_number, status="good",
                      this_update=T("2024-05-20"), next_update=T("2024-07-01"),
                      responder=responders[0], produced_at=T("2024-05-25")),
            "ocsp", EARLY)
    for i, r in enumerate(responders[:-1]):
        bag.add(make_ocsp(inter, serial=r.cert.serial_number, status="good",
                          this_update=T("2024-05-20"), next_update=T("2024-07-01"),
                          responder=responders[i + 1],
                          produced_at=T("2024-05-25")), "ocsp", EARLY)
    res1 = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)],
                      leaf_key=leaf.key)
    assert res1["verdict"] == "INVALID"
    res2, _ = run_engine(DictObjectSource(bag.objects),
                         validate_input(res1["input"]), "0" * 64)
    assert dumps(res2) == dumps(res1)


def test_duplicate_cert_objects_do_not_duplicate_paths():
    bag = Bag()
    root = make_ca("Root", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter", "ec", issuer=root, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    leaf = make_leaf(inter, "Leaf", "ed", not_before=T("2022-01-01"),
                     not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    for e in (root, inter, leaf):
        bag.cert(e)
        bag.cert(e)  # duplicate upload -> same fingerprint, deduped
    bag.add(make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    bag.add(make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01")), "crl", EARLY)
    res = adjudicate(bag, sha256_hex(leaf.der), [sha256_hex(root.der)], leaf_key=leaf.key)
    assert res["verdict"] == "VALID"
    assert len(res["decision"]["path"]) == 3
