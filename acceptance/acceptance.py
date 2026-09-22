"""One-shot acceptance service (docker-compose service ``verify``).

Drives the public HTTP API of two independent API instances that share one
persistent volume, then downloads an evidence pack and verifies it offline.
Exits 0 only when every acceptance check passes.
"""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.canonical import dumps, sha256_hex  # noqa: E402
from acceptance.pki_fixtures import (  # noqa: E402
    artifact_algorithm_for,
    make_ca,
    make_crl,
    make_key,
    make_leaf,
    make_ocsp,
    sign_data,
)

UTC = timezone.utc
T = lambda s: datetime.fromisoformat(s + "T00:00:00+00:00")

API_A = os.environ.get("API_A_URL", "http://api-a:8080")
API_B = os.environ.get("API_B_URL", "http://api-b:8080")

# request ids are namespaced per run: the persistent store legitimately
# remembers ids from earlier runs
RUN = os.environ.get("ACCEPTANCE_RUN_ID") or hashlib.sha256(
    f"{time.time()}-{os.getpid()}".encode()).hexdigest()[:12]

SIGNED_AT = "2024-06-01T00:00:00Z"
CUTOFF = "2025-01-01T00:00:00Z"
EARLY = "2024-01-01T00:00:00Z"

_failures = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" - {detail}" if detail and not cond else ""), flush=True)
    if not cond:
        _failures.append(name)


def wait_healthy(url, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{url}/healthz", timeout=3)
            if r.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(1)
    return False


def post(url, path, obj, expect=None):
    r = requests.post(f"{url}{path}", data=dumps(obj),
                      headers={"Content-Type": "application/json"}, timeout=120)
    if expect is not None and r.status_code != expect:
        raise AssertionError(f"POST {path} -> {r.status_code}: {r.text[:500]}")
    return r


def build_dataset():
    """A rich dataset: cross-signing, a cycle, revocation flavors, noise."""
    d = {}
    objects = []  # (name, der, otype, received_at)

    root_a = make_ca("Root A", "rsa", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    root_b = make_ca("Root B", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
    inter = make_ca("Inter X", "ec", issuer=root_a, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    inter_b = make_ca("Inter X", "ec", issuer=root_b, key=inter.key,
                      subject_name=inter.cert.subject,
                      not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    leaf_ok = make_leaf(inter, "Leaf OK", "ed", not_before=T("2022-01-01"),
                        not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    leaf_rev = make_leaf(inter, "Leaf Revoked", "rsa", not_before=T("2022-01-01"),
                         not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    leaf_ocsp = make_leaf(inter, "Leaf OCSP", "ec", not_before=T("2022-01-01"),
                          not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    leaf_delta = make_leaf(inter, "Leaf Delta", "ed", not_before=T("2022-01-01"),
                           not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    leaf_unsup = make_leaf(root_a, "Leaf Unsupported", "ed", not_before=T("2022-01-01"),
                           not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"],
                           pkcs1v15=True)
    # a CA whose only revocation evidence is stale at signed_at
    stale_ca = make_ca("Stale CA", "ec", issuer=root_a, not_before=T("2021-01-01"),
                       not_after=T("2035-01-01"))
    leaf_stale = make_leaf(stale_ca, "Leaf Stale", "ec", not_before=T("2022-01-01"),
                           not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    # cycle: two CAs cross-signing each other, anchored nowhere
    cyc_x = make_ca("Cycle X", "ec", not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    cyc_y = make_ca("Cycle Y", "ec", issuer=cyc_x, not_before=T("2021-01-01"),
                    not_after=T("2035-01-01"))
    cyc_x2 = make_ca("Cycle X", "ec", issuer=cyc_y, key=cyc_x.key,
                     subject_name=cyc_x.cert.subject,
                     not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    leaf_cycle = make_leaf(cyc_x2, "Leaf Cycle", "ed", not_before=T("2022-01-01"),
                           not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])

    certs = [root_a, root_b, inter, inter_b, leaf_ok, leaf_rev, leaf_stale,
             leaf_ocsp, leaf_delta, leaf_unsup, stale_ca, cyc_x, cyc_y, cyc_x2,
             leaf_cycle]
    d.update(root_a=root_a, root_b=root_b, inter=inter, inter_b=inter_b,
             leaf_ok=leaf_ok, leaf_rev=leaf_rev, leaf_stale=leaf_stale,
             leaf_ocsp=leaf_ocsp, leaf_delta=leaf_delta, leaf_unsup=leaf_unsup,
             stale_ca=stale_ca, cyc_x=cyc_x, cyc_y=cyc_y, cyc_x2=cyc_x2,
             leaf_cycle=leaf_cycle)

    # noise: unrelated certs (cross-signed ring + junk) that must not disturb
    rng = random.Random(20240919)
    noise = []
    noise_keys = []
    for i in range(60):
        kind = ("rsa", "ec", "ed")[i % 3]
        noise_keys.append((f"noise-{i}", make_key(kind)))
    noise_cas = []
    for i in range(12):
        name, key = noise_keys[i]
        ca = make_ca(f"Noise CA {i}", "ec", key=key, not_before=T("2020-01-01"),
                     not_after=T("2040-01-01"))
        noise_cas.append(ca)
        noise.append(ca)
    # cross-signed noise ring
    for i in range(12):
        ca = noise_cas[i]
        issuer = noise_cas[(i + 1) % 12]
        cross = make_ca(f"Noise CA {i}", "ec", issuer=issuer, key=ca.key,
                        subject_name=ca.cert.subject, not_before=T("2020-01-01"),
                        not_after=T("2040-01-01"))
        noise.append(cross)
    for i in range(36):
        issuer = noise_cas[i % 12]
        leaf = make_leaf(issuer, f"Noise Leaf {i}", ("rsa", "ec", "ed")[i % 3],
                         not_before=T("2022-01-01"), not_after=T("2030-01-01"),
                         eku=["1.3.6.1.5.5.7.3.3"])
        noise.append(leaf)
    for e in noise:
        certs.append(e)

    for e in certs:
        objects.append((f"cert:{e.cn}:{sha256_hex(e.der)[:8]}", e.der, "certificate", EARLY))

    # revocation evidence
    inter_crl = make_crl(
        inter,
        entries=[(leaf_rev.cert.serial_number, T("2024-03-01"), "keyCompromise")],
        crl_number=5, this_update=T("2024-05-01"), next_update=T("2024-07-01"))
    objects.append(("crl:inter", inter_crl, "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:stale", make_crl(
        inter, entries=[], crl_number=4, this_update=T("2024-01-01"),
        next_update=T("2024-02-01")), "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:root-a", make_crl(
        root_a, entries=[], crl_number=3, this_update=T("2024-05-01"),
        next_update=T("2024-07-01")), "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:root-b", make_crl(
        root_b, entries=[], crl_number=3, this_update=T("2024-05-01"),
        next_update=T("2024-07-01")), "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:stale-ca", make_crl(
        stale_ca, entries=[], crl_number=1, this_update=T("2024-01-01"),
        next_update=T("2024-02-01")), "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:cycle-x", make_crl(
        cyc_x, entries=[], crl_number=1, this_update=T("2024-05-01"),
        next_update=T("2024-07-01")), "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:cycle-y", make_crl(
        cyc_y, entries=[], crl_number=1, this_update=T("2024-05-01"),
        next_update=T("2024-07-01")), "crl", "2024-06-15T00:00:00Z"))
    # delta CRL chain: base carries leaf_rev forward, delta adds leaf_delta
    objects.append(("crl:delta-base", make_crl(
        inter, entries=[(leaf_rev.cert.serial_number, T("2024-03-01"),
                         "keyCompromise")],
        crl_number=8, this_update=T("2024-05-01"),
        next_update=T("2024-07-01")), "crl", "2024-06-15T00:00:00Z"))
    objects.append(("crl:delta", make_crl(
        inter, entries=[(leaf_delta.cert.serial_number, T("2024-03-01"),
                         "keyCompromise")],
        crl_number=9, this_update=T("2024-05-20"), next_update=T("2024-07-01"),
        delta_base_number=8), "crl", "2024-06-15T00:00:00Z"))
    # OCSP: direct for leaf_ocsp (good), delegated responder for a second case
    objects.append(("ocsp:leaf-ocsp", make_ocsp(
        inter, serial=leaf_ocsp.cert.serial_number, status="good",
        this_update=T("2024-05-30"), next_update=T("2024-06-30")), "ocsp",
        "2024-06-15T00:00:00Z"))
    responder = make_leaf(inter, "OCSP Responder", "ec", not_before=T("2022-01-01"),
                          not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.9"])
    objects.append(("cert:responder", responder.der, "certificate", EARLY))
    d["responder"] = responder
    # the delegated responder must itself be GOOD at the response producedAt;
    # an empty issuer CRL covering that historical window (older than the
    # 05-20 OCSP view so it never wins view selection for any leaf)
    objects.append(("crl:responder-good", make_crl(
        inter, entries=[], crl_number=6, this_update=T("2024-04-15"),
        next_update=T("2024-07-01")), "crl", "2024-06-15T00:00:00Z"))
    objects.append(("ocsp:leaf-ok-delegated", make_ocsp(
        inter, serial=leaf_ok.cert.serial_number, status="good",
        this_update=T("2024-05-28"), next_update=T("2024-06-28"),
        responder=responder, produced_at=T("2024-05-28")), "ocsp",
        "2024-06-15T00:00:00Z"))
    # a late-archived CRL revoking leaf_ok (must be inadmissible)
    objects.append(("crl:late", make_crl(
        inter, entries=[(leaf_ok.cert.serial_number, T("2024-03-01"),
                         "keyCompromise")],
        crl_number=10, this_update=T("2024-05-25"), next_update=T("2024-07-01")),
        "crl", "2025-06-01T00:00:00Z"))

    # ------------------------------------------------------------------
    # Revoked-delegated-responder scenario, on an isolated CA so the main
    # inter CRLs cannot vouch for the leaf.  The responder is revoked (CRL
    # dated before the response producedAt); the CRL that proves it is stale
    # for the leaf at signed_at, and the leaf's own CRL is stale too.
    rr_root = make_ca("RR Root", "ec", not_before=T("2020-01-01"),
                      not_after=T("2040-01-01"))
    rr_inter = make_ca("RR Inter", "ec", issuer=rr_root, not_before=T("2021-01-01"),
                       not_after=T("2035-01-01"))
    leaf_rr = make_leaf(rr_inter, "Leaf RevokedResponder", "ed",
                        not_before=T("2022-01-01"), not_after=T("2030-01-01"),
                        eku=["1.3.6.1.5.5.7.3.3"])
    rev_responder = make_leaf(rr_inter, "Revoked OCSP Responder", "ec",
                              not_before=T("2022-01-01"), not_after=T("2030-01-01"),
                              eku=["1.3.6.1.5.5.7.3.9"])
    for e in (rr_root, rr_inter, leaf_rr, rev_responder):
        objects.append((f"cert:{e.cn}:{sha256_hex(e.der)[:8]}", e.der,
                        "certificate", EARLY))
    d.update(rr_root=rr_root, rr_inter=rr_inter, leaf_rr=leaf_rr,
             rev_responder=rev_responder)
    # rr_inter is GOOD on the path via an empty root CRL
    objects.append(("crl:rr-root", make_crl(
        rr_root, entries=[], crl_number=1, this_update=T("2024-05-01"),
        next_update=T("2024-07-01")), "crl", "2024-06-15T00:00:00Z"))
    # the leaf's own CRL: stale at signed_at (window ends 2024-02-15)
    rr_stale_crl = make_crl(rr_inter, entries=[], crl_number=1,
                            this_update=T("2024-01-15"), next_update=T("2024-02-15"))
    objects.append(("crl:rr-leaf-stale", rr_stale_crl, "crl",
                    "2024-06-15T00:00:00Z"))
    d["rr_stale_crl"] = rr_stale_crl
    # archived CRL revoking the responder 2024-04-01; its window ends
    # 2024-05-22 (stale for the leaf at signed_at) but it still proves the
    # responder REVOKED at the response producedAt 2024-05-25
    rr_resp_crl = make_crl(rr_inter, entries=[
        (rev_responder.cert.serial_number, T("2024-04-01"), "keyCompromise"),
    ], crl_number=2, this_update=T("2024-05-20"), next_update=T("2024-05-22"))
    objects.append(("crl:rr-responder-revoked", rr_resp_crl, "crl",
                    "2024-06-15T00:00:00Z"))
    d["rr_resp_crl"] = rr_resp_crl
    # delegated OCSP: window covers the signing time, claims the leaf GOOD,
    # producedAt AFTER the responder revocation
    rr_ocsp = make_ocsp(rr_inter, serial=leaf_rr.cert.serial_number, status="good",
                        this_update=T("2024-05-20"), next_update=T("2024-07-01"),
                        responder=rev_responder, produced_at=T("2024-05-25"))
    objects.append(("ocsp:rr-leaf-good", rr_ocsp, "ocsp", "2024-06-15T00:00:00Z"))
    d["rr_ocsp"] = rr_ocsp

    # ------------------------------------------------------------------
    # Responder self-/mutual-endorsement scenarios, again on an isolated CA
    # with only a root CRL, so no independent evidence can rescue the leaves.
    cy_root = make_ca("RespCycle Root", "ec", not_before=T("2020-01-01"),
                      not_after=T("2040-01-01"))
    cy_inter = make_ca("RespCycle Inter", "ec", issuer=cy_root,
                       not_before=T("2021-01-01"), not_after=T("2035-01-01"))
    leaf_self = make_leaf(cy_inter, "Leaf SelfResponder", "ed",
                          not_before=T("2022-01-01"), not_after=T("2030-01-01"),
                          eku=["1.3.6.1.5.5.7.3.3"])
    self_responder = make_leaf(cy_inter, "Self OCSP Responder", "ec",
                               not_before=T("2022-01-01"), not_after=T("2030-01-01"),
                               eku=["1.3.6.1.5.5.7.3.9"])
    leaf_mut = make_leaf(cy_inter, "Leaf MutualResponder", "ed",
                         not_before=T("2022-01-01"), not_after=T("2030-01-01"),
                         eku=["1.3.6.1.5.5.7.3.3"])
    resp_a = make_leaf(cy_inter, "Mutual Responder A", "ec",
                       not_before=T("2022-01-01"), not_after=T("2030-01-01"),
                       eku=["1.3.6.1.5.5.7.3.9"])
    resp_b = make_leaf(cy_inter, "Mutual Responder B", "ec",
                       not_before=T("2022-01-01"), not_after=T("2030-01-01"),
                       eku=["1.3.6.1.5.5.7.3.9"])
    for e in (cy_root, cy_inter, leaf_self, self_responder, leaf_mut, resp_a, resp_b):
        objects.append((f"cert:{e.cn}:{sha256_hex(e.der)[:8]}", e.der,
                        "certificate", EARLY))
    d.update(cy_root=cy_root, cy_inter=cy_inter, leaf_self=leaf_self,
             self_responder=self_responder, leaf_mut=leaf_mut,
             resp_a=resp_a, resp_b=resp_b)
    objects.append(("crl:cy-root", make_crl(
        cy_root, entries=[], crl_number=1, this_update=T("2024-05-01"),
        next_update=T("2024-07-01")), "crl", "2024-06-15T00:00:00Z"))
    # leaf vouched by self_responder; self_responder's own GOOD is claimed by
    # an OCSP response signed by itself
    objects.append(("ocsp:cy-leaf-self", make_ocsp(
        cy_inter, serial=leaf_self.cert.serial_number, status="good",
        this_update=T("2024-05-20"), next_update=T("2024-07-01"),
        responder=self_responder, produced_at=T("2024-05-25")), "ocsp",
        "2024-06-15T00:00:00Z"))
    objects.append(("ocsp:cy-self-self", make_ocsp(
        cy_inter, serial=self_responder.cert.serial_number, status="good",
        this_update=T("2024-05-20"), next_update=T("2024-07-01"),
        responder=self_responder, produced_at=T("2024-05-25")), "ocsp",
        "2024-06-15T00:00:00Z"))
    # mutual: leaf via A; A GOOD only via B; B GOOD only via A
    objects.append(("ocsp:cy-leaf-mut", make_ocsp(
        cy_inter, serial=leaf_mut.cert.serial_number, status="good",
        this_update=T("2024-05-20"), next_update=T("2024-07-01"),
        responder=resp_a, produced_at=T("2024-05-25")), "ocsp",
        "2024-06-15T00:00:00Z"))
    objects.append(("ocsp:cy-a-by-b", make_ocsp(
        cy_inter, serial=resp_a.cert.serial_number, status="good",
        this_update=T("2024-05-20"), next_update=T("2024-07-01"),
        responder=resp_b, produced_at=T("2024-05-25")), "ocsp",
        "2024-06-15T00:00:00Z"))
    objects.append(("ocsp:cy-b-by-a", make_ocsp(
        cy_inter, serial=resp_b.cert.serial_number, status="good",
        this_update=T("2024-05-20"), next_update=T("2024-07-01"),
        responder=resp_a, produced_at=T("2024-05-25")), "ocsp",
        "2024-06-15T00:00:00Z"))
    return d, objects


def adjudication_input(leaf, anchors, artifact=b"acceptance artifact"):
    digest = hashlib.sha256(artifact).hexdigest()
    sig = sign_data(leaf.key, bytes.fromhex(digest))
    return {
        "artifact_digest": digest,
        "signature": base64.b64encode(sig).decode(),
        "signature_algorithm": artifact_algorithm_for(leaf.key),
        "signed_at": SIGNED_AT,
        "knowledge_cutoff": CUTOFF,
        "leaf_fingerprint": sha256_hex(leaf.der),
        "trust_anchors": [sha256_hex(a.der) for a in anchors],
    }


def main():
    print(f"acceptance: API_A={API_A} API_B={API_B}", flush=True)
    check("api-a healthy", wait_healthy(API_A))
    check("api-b healthy", wait_healthy(API_B))
    if _failures:
        return 1

    d, objects = build_dataset()
    by_fp = {}
    for name, der, otype, rcv in objects:
        by_fp[sha256_hex(der)] = (name, der, otype, rcv)

    # -- create evidence set -------------------------------------------------
    create = post(API_A, "/v1/evidence-sets", {"request_id": f"acc-{RUN}-create-1",
                                               "label": "acceptance"}, 201)
    set_id = json.loads(create.content)["evidence_set_id"]
    # idempotent replay + conflict
    replay = post(API_B, "/v1/evidence-sets", {"request_id": f"acc-{RUN}-create-1",
                                               "label": "acceptance"})
    check("create idempotent replay", replay.content == create.content)
    conflict = post(API_A, "/v1/evidence-sets", {"request_id": f"acc-{RUN}-create-1",
                                                 "label": "different"})
    check("create idempotency conflict", conflict.status_code == 409)

    # -- upload in shuffled batches across both instances --------------------
    rng = random.Random(7)
    order = list(objects)
    rng.shuffle(order)
    batches = [order[i : i + 17] for i in range(0, len(order), 17)]
    apis = [API_A, API_B]
    total_added = 0
    for i, batch in enumerate(batches):
        body = {
            "request_id": f"acc-{RUN}-add-{i}",
            "objects": [
                {"type": otype, "der": base64.b64encode(der).decode(),
                 "received_at": rcv}
                for (_name, der, otype, rcv) in batch
            ],
        }
        r = post(apis[i % 2], f"/v1/evidence-sets/{set_id}/objects", body, 200)
        parsed = json.loads(r.content)
        check(f"batch {i} accepted", not parsed["rejected"],
              json.dumps(parsed["rejected"])[:300])
        total_added += len(parsed["added"])
        if i == 0:
            # identical replay returns the original response
            r2 = post(apis[1], f"/v1/evidence-sets/{set_id}/objects", body)
            check("batch replay identical", r2.content == r.content)
            # same request id, different content -> conflict
            body2 = dict(body)
            body2["objects"] = body["objects"][:1]
            r3 = post(API_A, f"/v1/evidence-sets/{set_id}/objects", body2)
            check("batch id conflict", r3.status_code == 409)
    check("all objects uploaded", total_added == len(objects),
          f"{total_added} != {len(objects)}")

    # -- concurrent seal from both instances ---------------------------------
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_a = pool.submit(post, API_A, f"/v1/evidence-sets/{set_id}/seal",
                          {"request_id": f"acc-{RUN}-seal-a"})
        f_b = pool.submit(post, API_B, f"/v1/evidence-sets/{set_id}/seal",
                          {"request_id": f"acc-{RUN}-seal-b"})
        seal_a, seal_b = f_a.result(), f_b.result()
    check("concurrent seal ok", seal_a.status_code == 200 and seal_b.status_code == 200)
    digest_a = json.loads(seal_a.content)["content_digest"]
    digest_b = json.loads(seal_b.content)["content_digest"]
    check("single immutable manifest", digest_a == digest_b)
    content_digest = digest_a

    # uploads after seal are rejected
    late = post(API_A, f"/v1/evidence-sets/{set_id}/objects", {
        "request_id": f"acc-{RUN}-after-seal",
        "objects": [{"type": "certificate",
                     "der": base64.b64encode(d["root_a"].der).decode(),
                     "received_at": EARLY}]})
    check("sealed set immutable", late.status_code == 409)

    # -- upload-order independence: a second set with the same objects in a
    #    different order must seal to the identical manifest digest ----------
    create2 = post(API_B, "/v1/evidence-sets", {"request_id": f"acc-{RUN}-create-2"}, 201)
    set_id2 = json.loads(create2.content)["evidence_set_id"]
    order2 = list(objects)
    rng.shuffle(order2)
    for i in range(0, len(order2), 29):
        batch = order2[i : i + 29]
        body = {
            "request_id": f"acc-{RUN}-add2-{i}",
            "objects": [
                {"type": otype, "der": base64.b64encode(der).decode(),
                 "received_at": rcv}
                for (_name, der, otype, rcv) in batch
            ],
        }
        post(apis[i % 2], f"/v1/evidence-sets/{set_id2}/objects", body, 200)
    seal2 = post(API_A, f"/v1/evidence-sets/{set_id2}/seal",
                 {"request_id": f"acc-{RUN}-seal-2"}, 200)
    digest2 = json.loads(seal2.content)["content_digest"]
    check("upload order does not affect manifest", digest2 == content_digest)

    # -- adjudications ---------------------------------------------------------
    cases = [
        ("valid-cross-signed", d["leaf_ok"], [d["root_a"], d["root_b"]], "VALID"),
        ("valid-single-anchor", d["leaf_ok"], [d["root_b"]], "VALID"),
        ("revoked-leaf", d["leaf_rev"], [d["root_a"]], "INVALID"),
        ("stale-evidence", d["leaf_stale"], [d["root_a"]], "INVALID"),
        ("ocsp-good", d["leaf_ocsp"], [d["root_a"]], "VALID"),
        ("delta-revoked", d["leaf_delta"], [d["root_a"]], "INVALID"),
        ("cycle-leaf", d["leaf_cycle"], [d["root_a"]], "INVALID"),
        ("unsupported-leaf", d["leaf_unsup"], [d["root_a"]], "UNSUPPORTED"),
        ("revoked-delegated-responder", d["leaf_rr"], [d["rr_root"]], "INVALID"),
        ("responder-self-cycle", d["leaf_self"], [d["cy_root"]], "INVALID"),
        ("responder-mutual-cycle", d["leaf_mut"], [d["cy_root"]], "INVALID"),
    ]
    results = {}
    for idx, (name, leaf, anchors, expected) in enumerate(cases):
        inp = adjudication_input(leaf, anchors)
        r_a = post(API_A, "/v1/adjudications",
                   {"request_id": f"acc-{RUN}-adj-{idx}", "evidence_set_id": set_id,
                    "input": inp})
        check(f"{name}: adjudicated", r_a.status_code == 201, r_a.text[:300])
        body = json.loads(r_a.content)
        check(f"{name}: verdict {expected}", body["verdict"] == expected,
              f"got {body['verdict']}")
        results[name] = body
        # same adjudication via the other instance must be byte-identical
        r_b = post(API_B, "/v1/adjudications",
                   {"request_id": f"acc-{RUN}-adj-b-{idx}", "evidence_set_id": set_id,
                    "input": inp})
        check(f"{name}: cross-instance determinism", r_b.content == r_a.content)
        # idempotent replay
        r_re = post(API_A, "/v1/adjudications",
                    {"request_id": f"acc-{RUN}-adj-{idx}", "evidence_set_id": set_id,
                     "input": inp})
        check(f"{name}: idempotent replay", r_re.content == r_a.content)

    # late CRL must have been excluded for the valid leaf
    acct = {r["fingerprint"]: r for r in results["valid-cross-signed"]["evidence_accounting"]}
    late_fp = sha256_hex([o for o in objects if o[0] == "crl:late"][0][1])
    check("late evidence excluded", acct.get(late_fp, {}).get("reason") == "RECEIVED_AFTER_CUTOFF")
    check("late evidence did not change verdict",
          results["valid-cross-signed"]["verdict"] == "VALID")

    # -- delegated responder: legal path still selected ---------------------
    delegated = results["valid-cross-signed"]
    leaf_ok_fp = sha256_hex(d["leaf_ok"].der)
    delegated_view = delegated["revocation"][leaf_ok_fp]["selected_view"]
    delegated_ocsp_fp = sha256_hex(
        [o for o in objects if o[0] == "ocsp:leaf-ok-delegated"][0][1])
    check("legal delegated OCSP is the selected leaf view",
          delegated_view == f"ocsp:{delegated_ocsp_fp}", delegated_view)
    dresp = {o["certificate"]: o for o in delegated["responder_revocation"]}
    check("legal delegated responder GOOD at producedAt",
          dresp.get(sha256_hex(d["responder"].der), {}).get("status") == "GOOD")

    # direct issuer-signed OCSP regression
    direct = results["ocsp-good"]
    check("direct issuer OCSP selects an ocsp view",
          direct["revocation"][sha256_hex(d["leaf_ocsp"].der)]["selected_view"]
          .startswith("ocsp:"))

    # -- revoked delegated responder: the reported vulnerability ------------
    rr = results["revoked-delegated-responder"]
    rr_leaf_fp = sha256_hex(d["leaf_rr"].der)
    rr_out = rr["revocation"][rr_leaf_fp]
    check("revoked-responder leaf is STALE", rr_out["status"] == "STALE",
          json.dumps(rr_out)[:300])
    check("revoked-responder leaf fell back to a stale CRL view",
          rr_out["selected_view"].startswith("crl:"), rr_out["selected_view"])
    rr_ocsp_fp = sha256_hex(d["rr_ocsp"])
    check("the delegated OCSP is not the selected leaf evidence",
          rr_ocsp_fp not in rr_out.get("selected_evidence", []))
    rr_acct = {r["fingerprint"]: r for r in rr["evidence_accounting"]}
    check("revoked-responder OCSP excluded with RESPONDER_REVOKED",
          rr_acct.get(rr_ocsp_fp, {}).get("reason") == "RESPONDER_REVOKED",
          json.dumps(rr_acct.get(rr_ocsp_fp)))
    rr_resp_crl_fp = sha256_hex(d["rr_resp_crl"])
    check("responder revocation CRL is accounted and used",
          rr_acct.get(rr_resp_crl_fp, {}).get("disposition") == "used",
          json.dumps(rr_acct.get(rr_resp_crl_fp)))
    rr_resp = {o["certificate"]: o for o in rr["responder_revocation"]}
    rr_resp_out = rr_resp.get(sha256_hex(d["rev_responder"].der), {})
    check("responder adjudicated at producedAt (not signed_at/now)",
          rr_resp_out.get("evaluated_at") == "2024-05-25T00:00:00Z"
          and rr_resp_out.get("status") == "REVOKED"
          and rr_resp_out.get("revocation_time") == "2024-04-01T00:00:00Z",
          json.dumps(rr_resp_out)[:300])

    # its pack must include the responder cert, the responder-revocation CRL
    # and the rejected OCSP in the offline review object set, and verify cold
    rr_pack_resp = requests.get(
        f"{API_A}/v1/adjudications/{rr['adjudication_id']}/evidence-pack",
        timeout=120)
    check("revoked-responder pack download", rr_pack_resp.status_code == 200)
    rr_pack = json.loads(rr_pack_resp.content)
    rr_pack_fps = {o["fingerprint"] for o in rr_pack["objects"]}
    check("offline set has responder cert",
          sha256_hex(d["rev_responder"].der) in rr_pack_fps)
    check("offline set has responder revocation CRL",
          rr_resp_crl_fp in rr_pack_fps)
    check("offline set has the rejected delegated OCSP", rr_ocsp_fp in rr_pack_fps)
    with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
        fh.write(rr_pack_resp.content)
        rr_pack_path = fh.name
    proc = subprocess.run([sys.executable, "-m", "app.verify", rr_pack_path],
                          capture_output=True, text=True,
                          cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    check("revoked-responder pack offline verification", proc.returncode == 0,
          proc.stdout[-500:] + proc.stderr[-500:])

    # -- responder self/mutual endorsement cycles ---------------------------
    for cyc_name in ("responder-self-cycle", "responder-mutual-cycle"):
        cyc = results[cyc_name]
        reasons = {r["reason"] for r in cyc["evidence_accounting"]
                   if r["type"] == "ocsp"}
        check(f"{cyc_name}: cyclic OCSP rejected RESPONDER_CYCLE",
              "RESPONDER_CYCLE" in reasons, json.dumps(sorted(reasons)))
        check(f"{cyc_name}: verdict INVALID", cyc["verdict"] == "INVALID")

    # -- evidence pack + offline verification --------------------------------
    adj_id = results["valid-cross-signed"]["adjudication_id"]
    pack = requests.get(f"{API_B}/v1/adjudications/{adj_id}/evidence-pack",
                        timeout=120)
    check("pack download", pack.status_code == 200)
    pack_digest = hashlib.sha256(pack.content).hexdigest()
    check("pack digest header",
          pack.headers.get("X-Evidence-Pack-SHA256") == pack_digest)
    with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
        fh.write(pack.content)
        pack_path = fh.name
    proc = subprocess.run([sys.executable, "-m", "app.verify", pack_path],
                          capture_output=True, text=True,
                          cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    print(proc.stdout, flush=True)
    check("offline pack verification", proc.returncode == 0,
          proc.stdout[-500:] + proc.stderr[-500:])

    # tampered packs must fail
    pack_obj = json.loads(pack.content)
    for tname, mutate in [
        ("verdict", lambda p: p["result"].__setitem__("verdict", "INVALID")),
        ("input", lambda p: p["input"].__setitem__("signed_at", "2024-06-02T00:00:00Z")),
        ("manifest", lambda p: p["evidence_set"].__setitem__("content_digest", "0" * 64)),
    ]:
        tampered = json.loads(dumps(pack_obj))
        mutate(tampered)
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
            fh.write(dumps(tampered))
            tpath = fh.name
        proc = subprocess.run([sys.executable, "-m", "app.verify", tpath],
                              capture_output=True, text=True,
                              cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        check(f"tamper-{tname} detected", proc.returncode != 0)

    # rejection-proof case also produces a verifiable pack
    adj_bad = results["revoked-leaf"]["adjudication_id"]
    pack_bad = requests.get(f"{API_A}/v1/adjudications/{adj_bad}/evidence-pack",
                            timeout=120)
    with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as fh:
        fh.write(pack_bad.content)
        bad_path = fh.name
    proc = subprocess.run([sys.executable, "-m", "app.verify", bad_path],
                          capture_output=True, text=True,
                          cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    check("rejection pack verification", proc.returncode == 0)

    if _failures:
        print(f"\nACCEPTANCE FAILED ({len(_failures)} checks): {_failures}", flush=True)
        return 1
    print("\nACCEPTANCE PASSED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
