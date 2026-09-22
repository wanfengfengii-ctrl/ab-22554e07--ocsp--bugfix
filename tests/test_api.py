"""API-level tests: idempotency, sealing, concurrency semantics, packs."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading

import pytest

from app.canonical import dumps, sha256_hex
from acceptance.pki_fixtures import artifact_algorithm_for, sign_data
from tests.conftest import Bag
from tests.test_engine import simple_chain


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    from app.api import create_app

    app = create_app()
    app.testing = True
    with app.test_client() as c:
        yield c


def _post(c, url, obj, expect=None):
    resp = c.post(url, data=dumps(obj), content_type="application/json")
    if expect is not None:
        assert resp.status_code == expect, resp.get_data(as_text=True)[:800]
    return resp


def _get(c, url, expect=200):
    resp = c.get(url)
    assert resp.status_code == expect, resp.get_data(as_text=True)[:800]
    return resp


def _chain_objects():
    from tests.test_engine import simple_chain

    bag = Bag()
    root, inter, leaf = simple_chain(bag, eku=["1.3.6.1.5.5.7.3.3"])
    return bag, root, inter, leaf


def _make_set_with_objects(c, bag, request_prefix="r"):
    set_id = json.loads(
        _post(c, "/v1/evidence-sets", {"request_id": f"{request_prefix}-create"}).data
    )["evidence_set_id"]
    objects = [
        {"type": o["type"], "der": base64.b64encode(o["der"]).decode(),
         "received_at": o["received_at"]}
        for o in bag.objects.values()
    ]
    resp = _post(c, f"/v1/evidence-sets/{set_id}/objects",
                 {"request_id": f"{request_prefix}-add", "objects": objects})
    body = json.loads(resp.data)
    assert not body["rejected"], body["rejected"]
    return set_id


def test_create_idempotent_and_conflict(client):
    r1 = _post(client, "/v1/evidence-sets", {"request_id": "x1", "label": "a"}, 201)
    r2 = _post(client, "/v1/evidence-sets", {"request_id": "x1", "label": "a"}, 201)
    assert r1.data == r2.data
    r3 = _post(client, "/v1/evidence-sets", {"request_id": "x1", "label": "b"})
    assert r3.status_code == 409
    assert json.loads(r3.data)["error"]["code"] == "IDEMPOTENCY_CONFLICT"


def test_idempotency_equivalent_timestamps(client):
    bag, root, inter, leaf = _chain_objects()
    set_id = json.loads(_post(client, "/v1/evidence-sets", {"request_id": "c"}).data)[
        "evidence_set_id"]
    objects = [
        {"type": o["type"], "der": base64.b64encode(o["der"]).decode(),
         "received_at": o["received_at"]}
        for o in bag.objects.values()
    ]
    r1 = _post(client, f"/v1/evidence-sets/{set_id}/objects",
               {"request_id": "b1", "objects": objects})
    # equivalent timestamps written differently -> same normalized request
    objects2 = [dict(o, received_at=o["received_at"].replace("Z", "+00:00"))
                for o in objects]
    r2 = _post(client, f"/v1/evidence-sets/{set_id}/objects",
               {"request_id": "b1", "objects": objects2})
    assert r2.data == r1.data


def test_idempotency_uses_normalized_requests(client):
    bag, root, inter, leaf = _chain_objects()
    set_id = json.loads(_post(client, "/v1/evidence-sets", {"request_id": "c"}).data)[
        "evidence_set_id"]
    objects = [
        {"type": o["type"], "der": base64.b64encode(o["der"]).decode(),
         "received_at": o["received_at"]}
        for o in bag.objects.values()
    ]
    r1 = _post(client, f"/v1/evidence-sets/{set_id}/objects",
               {"request_id": "b1", "objects": objects})
    # same objects, different order, same request id -> replay, not conflict
    r2 = _post(client, f"/v1/evidence-sets/{set_id}/objects",
               {"request_id": "b1", "objects": list(reversed(objects))})
    assert r2.data == r1.data
    _post(client, f"/v1/evidence-sets/{set_id}/seal", {"request_id": "seal"})
    digest = hashlib.sha256(b"artifact").hexdigest()
    sig = sign_data(leaf.key, bytes.fromhex(digest))
    inp = {
        "artifact_digest": digest,
        "signature": base64.b64encode(sig).decode(),
        "signature_algorithm": artifact_algorithm_for(leaf.key),
        "signed_at": "2024-06-01T00:00:00Z",
        "knowledge_cutoff": "2025-01-01T00:00:00Z",
        "leaf_fingerprint": sha256_hex(leaf.der),
        "trust_anchors": [sha256_hex(root.der)],
    }
    a1 = _post(client, "/v1/adjudications",
               {"request_id": "a1", "evidence_set_id": set_id, "input": inp}, 201)
    # reordered trust anchors + policies -> same normalized request
    inp2 = dict(inp, trust_anchors=[sha256_hex(root.der), sha256_hex(root.der)],
                initial_policy_set=["2.5.29.32.0", "anyPolicy"])
    inp2["initial_policy_set"] = ["anyPolicy"]
    a2 = _post(client, "/v1/adjudications",
               {"request_id": "a1", "evidence_set_id": set_id, "input": inp2})
    assert a2.data == a1.data
    # different content -> conflict
    inp3 = dict(inp, signed_at="2024-06-02T00:00:00Z")
    a3 = _post(client, "/v1/adjudications",
               {"request_id": "a1", "evidence_set_id": set_id, "input": inp3})
    assert a3.status_code == 409


def test_seal_immutability_and_single_manifest(client):
    bag, root, inter, leaf = _chain_objects()
    set_id = _make_set_with_objects(client, bag)
    s1 = _post(client, f"/v1/evidence-sets/{set_id}/seal", {"request_id": "s1"})
    s2 = _post(client, f"/v1/evidence-sets/{set_id}/seal", {"request_id": "s2"})
    assert s1.status_code == s2.status_code == 200
    d1, d2 = json.loads(s1.data), json.loads(s2.data)
    assert d1["content_digest"] == d2["content_digest"]
    # uploads after seal are rejected
    resp = _post(client, f"/v1/evidence-sets/{set_id}/objects",
                 {"request_id": "after-seal", "objects": [{
                     "type": "certificate",
                     "der": base64.b64encode(root.der).decode(),
                     "received_at": "2024-01-01T00:00:00Z"}]})
    assert resp.status_code == 409
    assert json.loads(resp.data)["error"]["code"] == "EVIDENCE_SET_SEALED"


@pytest.fixture()
def app_and_client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    from app.api import create_app

    app = create_app()
    app.testing = True
    with app.test_client() as c:
        yield app, c


def test_concurrent_seal_single_manifest(app_and_client):
    app, client = app_and_client
    bag, root, inter, leaf = _chain_objects()
    set_id = _make_set_with_objects(client, bag)
    results = []

    def do_seal(rid):
        with app.test_client() as c:
            results.append(c.post(f"/v1/evidence-sets/{set_id}/seal",
                                  data=dumps({"request_id": rid}),
                                  content_type="application/json"))

    threads = [threading.Thread(target=do_seal, args=(f"seal-{i}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    digests = {json.loads(r.data)["content_digest"] for r in results}
    assert len(digests) == 1
    assert all(r.status_code == 200 for r in results)


def test_adjudication_flow_and_pack(client):
    bag, root, inter, leaf = _chain_objects()
    set_id = _make_set_with_objects(client, bag)
    _post(client, f"/v1/evidence-sets/{set_id}/seal", {"request_id": "seal"})
    digest = hashlib.sha256(b"artifact").hexdigest()
    sig = sign_data(leaf.key, bytes.fromhex(digest))
    inp = {
        "artifact_digest": digest,
        "signature": base64.b64encode(sig).decode(),
        "signature_algorithm": artifact_algorithm_for(leaf.key),
        "signed_at": "2024-06-01T00:00:00Z",
        "knowledge_cutoff": "2025-01-01T00:00:00Z",
        "leaf_fingerprint": sha256_hex(leaf.der),
        "trust_anchors": [sha256_hex(root.der)],
    }
    r1 = _post(client, "/v1/adjudications",
               {"request_id": "adj-1", "evidence_set_id": set_id, "input": inp}, 201)
    body1 = json.loads(r1.data)
    assert body1["verdict"] == "VALID"
    adj_id = body1["adjudication_id"]
    # idempotent replay
    r2 = _post(client, "/v1/adjudications",
               {"request_id": "adj-1", "evidence_set_id": set_id, "input": inp})
    assert r2.data == r1.data
    # same input, new request id -> same adjudication id
    r3 = _post(client, "/v1/adjudications",
               {"request_id": "adj-2", "evidence_set_id": set_id, "input": inp})
    assert json.loads(r3.data)["adjudication_id"] == adj_id
    # GET result + pack
    g = _get(client, f"/v1/adjudications/{adj_id}")
    assert g.data == r1.data
    pack = _get(client, f"/v1/adjudications/{adj_id}/evidence-pack")
    assert pack.headers.get("X-Evidence-Pack-SHA256") == hashlib.sha256(pack.data).hexdigest()
    # offline verification of the pack
    from app.verify import CheckLog, verify_pack

    log = CheckLog()
    assert verify_pack(pack.data, log), "\n".join(log.lines)


def test_tampered_pack_fails_verification(client):
    bag, root, inter, leaf = _chain_objects()
    set_id = _make_set_with_objects(client, bag)
    _post(client, f"/v1/evidence-sets/{set_id}/seal", {"request_id": "seal"})
    digest = hashlib.sha256(b"artifact").hexdigest()
    sig = sign_data(leaf.key, bytes.fromhex(digest))
    inp = {
        "artifact_digest": digest,
        "signature": base64.b64encode(sig).decode(),
        "signature_algorithm": artifact_algorithm_for(leaf.key),
        "signed_at": "2024-06-01T00:00:00Z",
        "knowledge_cutoff": "2025-01-01T00:00:00Z",
        "leaf_fingerprint": sha256_hex(leaf.der),
        "trust_anchors": [sha256_hex(root.der)],
    }
    r = _post(client, "/v1/adjudications",
              {"request_id": "adj-1", "evidence_set_id": set_id, "input": inp}, 201)
    adj_id = json.loads(r.data)["adjudication_id"]
    pack_bytes = _get(client, f"/v1/adjudications/{adj_id}/evidence-pack").data
    pack = json.loads(pack_bytes)

    from app.verify import CheckLog, verify_pack

    # 1. tamper with the verdict
    p1 = json.loads(dumps(pack))
    p1["result"]["verdict"] = "INVALID"
    assert not verify_pack(dumps(p1), CheckLog())
    # 2. tamper with an input timestamp
    p2 = json.loads(dumps(pack))
    p2["input"]["signed_at"] = "2024-06-02T00:00:00Z"
    p2["result"]["input"]["signed_at"] = "2024-06-02T00:00:00Z"
    assert not verify_pack(dumps(p2), CheckLog())
    # 3. tamper with a DER object
    p3 = json.loads(dumps(pack))
    der = bytearray(base64.b64decode(p3["objects"][0]["der"]))
    der[-1] ^= 1
    p3["objects"][0]["der"] = base64.b64encode(bytes(der)).decode()
    assert not verify_pack(dumps(p3), CheckLog())
    # 4. remove an object
    p4 = json.loads(dumps(pack))
    p4["objects"] = p4["objects"][1:]
    assert not verify_pack(dumps(p4), CheckLog())


def test_validation_errors(client):
    _post(client, "/v1/evidence-sets", {"request_id": "s"}, 201)
    r = _post(client, "/v1/evidence-sets", {})
    assert r.status_code == 400
    assert json.loads(r.data)["error"]["code"] == "VALIDATION"
    r2 = client.post("/v1/evidence-sets", data=b"{not json",
                     content_type="application/json")
    assert r2.status_code == 400
