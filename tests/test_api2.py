"""API tests, part 2: limits, duplicates, restart determinism, UNSUPPORTED."""
from __future__ import annotations

import base64
import hashlib
import json

import pytest

from app.canonical import dumps, sha256_hex
from acceptance.pki_fixtures import artifact_algorithm_for, sign_data
from tests.conftest import Bag
from tests.test_api import _chain_objects, _make_set_with_objects, _post
from tests.test_engine import simple_chain


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    from app.api import create_app

    app = create_app()
    app.testing = True
    with app.test_client() as c:
        yield c


def test_batch_duplicates_and_rejected(client):
    bag = Bag()
    root, inter, leaf = simple_chain(bag, eku=["1.3.6.1.5.5.7.3.3"])
    set_id = json.loads(_post(client, "/v1/evidence-sets", {"request_id": "c"}).data)[
        "evidence_set_id"]
    der_b64 = base64.b64encode(root.der).decode()
    body = {
        "request_id": "b1",
        "objects": [
            {"type": "certificate", "der": der_b64, "received_at": "2024-01-01T00:00:00Z"},
            {"type": "certificate", "der": der_b64, "received_at": "2024-01-01T00:00:00Z"},
            {"type": "certificate", "der": "!!!notbase64!!!",
             "received_at": "2024-01-01T00:00:00Z"},
            {"type": "crl", "der": der_b64, "received_at": "2024-01-01T00:00:00Z"},
        ],
    }
    resp = _post(client, f"/v1/evidence-sets/{set_id}/objects", body)
    parsed = json.loads(resp.data)
    assert len(parsed["added"]) == 1
    assert len(parsed["duplicates"]) == 1
    assert len(parsed["rejected"]) == 2
    codes = {r["error"]["code"] for r in parsed["rejected"]}
    assert "INVALID_DER" in codes
    assert "CRL_PARSE_ERROR" in codes
    # replay returns the identical response
    resp2 = _post(client, f"/v1/evidence-sets/{set_id}/objects", body)
    assert resp2.data == resp.data


def test_limits_enforced(client, monkeypatch):
    from app import profile

    monkeypatch.setattr(profile, "MAX_CERTIFICATES", 2)
    monkeypatch.setattr("app.api.profile.MAX_CERTIFICATES", 2)
    bag = Bag()
    root, inter, leaf = simple_chain(bag, eku=["1.3.6.1.5.5.7.3.3"])
    set_id = json.loads(_post(client, "/v1/evidence-sets", {"request_id": "c"}).data)[
        "evidence_set_id"]
    objects = [
        {"type": o["type"], "der": base64.b64encode(o["der"]).decode(),
         "received_at": o["received_at"]}
        for o in bag.objects.values()
    ]
    resp = _post(client, f"/v1/evidence-sets/{set_id}/objects",
                 {"request_id": "b1", "objects": objects})
    assert resp.status_code == 413
    assert json.loads(resp.data)["error"]["code"] == "LIMIT_EXCEEDED"
    # nothing was inserted (atomic)
    resp2 = _post(client, f"/v1/evidence-sets/{set_id}/objects",
                  {"request_id": "b2", "objects": objects[:2]})
    assert resp2.status_code == 200
    assert len(json.loads(resp2.data)["added"]) == 2


def test_restart_determinism(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    from app.api import create_app

    bag = Bag()
    root, inter, leaf = simple_chain(bag, eku=["1.3.6.1.5.5.7.3.3"])
    app1 = create_app()
    app1.testing = True
    with app1.test_client() as c1:
        set_id = _make_set_with_objects(c1, bag)
        _post(c1, f"/v1/evidence-sets/{set_id}/seal", {"request_id": "seal"})
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
        r1 = _post(c1, "/v1/adjudications",
                   {"request_id": "adj", "evidence_set_id": set_id, "input": inp}, 201)
    # simulate a process restart: brand-new app object on the same data dir
    app2 = create_app()
    app2.testing = True
    with app2.test_client() as c2:
        r2 = _post(c2, "/v1/adjudications",
                   {"request_id": "adj-new", "evidence_set_id": set_id, "input": inp})
        assert r2.data == r1.data
        adj_id = json.loads(r1.data)["adjudication_id"]
        pack2 = c2.get(f"/v1/adjudications/{adj_id}/evidence-pack")
        assert pack2.status_code == 200
        from app.verify import CheckLog, verify_pack

        assert verify_pack(pack2.data, CheckLog())


def test_unsupported_pack_verifies(client):
    bag = Bag()
    root, inter, leaf = simple_chain(bag, inter_kind="rsa", eku=["1.3.6.1.5.5.7.3.3"],
                                     pkcs1v15=True)
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
              {"request_id": "adj", "evidence_set_id": set_id, "input": inp}, 201)
    body = json.loads(r.data)
    assert body["verdict"] == "UNSUPPORTED"
    pack = client.get(f"/v1/adjudications/{body['adjudication_id']}/evidence-pack")
    from app.verify import CheckLog, verify_pack

    assert verify_pack(pack.data, CheckLog())


def test_certificate_without_received_at(client):
    bag, root, inter, leaf = _chain_objects()
    set_id = json.loads(_post(client, "/v1/evidence-sets", {"request_id": "c"}).data)[
        "evidence_set_id"]
    # certificates may omit received_at; CRLs may not
    crl_obj = next(o for o in bag.objects.values() if o["type"] == "crl")
    body = {"request_id": "b1", "objects": [
        {"type": "certificate", "der": base64.b64encode(root.der).decode()},
        {"type": "crl", "der": base64.b64encode(crl_obj["der"]).decode()},
    ]}
    resp = _post(client, f"/v1/evidence-sets/{set_id}/objects", body)
    parsed = json.loads(resp.data)
    assert len(parsed["added"]) == 1
    assert len(parsed["rejected"]) == 1
    assert parsed["rejected"][0]["error"]["code"] == "INVALID_RECEIVED_AT"


def test_unknown_endpoints(client):
    resp = client.get("/v1/evidence-sets/es_nonexistent")
    assert resp.status_code == 404
    resp = client.get("/v1/adjudications/adj_nonexistent")
    assert resp.status_code == 404
    resp = client.get("/nonexistent")
    assert resp.status_code == 404


def test_unsealed_and_leaf_errors(client):
    bag, root, inter, leaf = _chain_objects()
    set_id = _make_set_with_objects(client, bag)
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
    # adjudication on an unsealed set -> 409
    r = _post(client, "/v1/adjudications",
              {"request_id": "a1", "evidence_set_id": set_id, "input": inp})
    assert r.status_code == 409
    assert json.loads(r.data)["error"]["code"] == "EVIDENCE_SET_NOT_SEALED"
    # manifest on unsealed set -> 409
    assert client.get(f"/v1/evidence-sets/{set_id}/manifest").status_code == 409
    # seal, then adjudicate with an unknown leaf -> 422
    _post(client, f"/v1/evidence-sets/{set_id}/seal", {"request_id": "seal"})
    inp2 = dict(inp, leaf_fingerprint="1" * 64)
    r2 = _post(client, "/v1/adjudications",
               {"request_id": "a2", "evidence_set_id": set_id, "input": inp2})
    assert r2.status_code == 422
    assert json.loads(r2.data)["error"]["code"] == "LEAF_NOT_FOUND"
    # unsupported artifact signature algorithm -> 422 UNSUPPORTED
    inp3 = dict(inp, signature_algorithm="rsa-pkcs1-sha256")
    r3 = _post(client, "/v1/adjudications",
               {"request_id": "a3", "evidence_set_id": set_id, "input": inp3})
    assert r3.status_code == 422
    assert json.loads(r3.data)["error"]["code"] == "UNSUPPORTED"
