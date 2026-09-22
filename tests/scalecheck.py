"""Scale smoke test: many certs + a large CRL (not part of pytest runs)."""
import base64
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

sys.path.insert(0, "/workspace")
from app.canonical import dumps, sha256_hex
from acceptance.pki_fixtures import make_ca, make_crl, make_leaf, sign_data, artifact_algorithm_for

UTC = timezone.utc
T = lambda s: datetime.fromisoformat(s + "T00:00:00+00:00")
API = os.environ.get("API_A_URL", "http://127.0.0.1:18081")
N = int(os.environ.get("SCALE_N", "20000"))

t0 = time.time()
root = make_ca("Scale Root", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
inter = make_ca("Scale Inter", "ec", issuer=root, not_before=T("2021-01-01"), not_after=T("2035-01-01"))
leaf = make_leaf(inter, "Scale Leaf", "ed", not_before=T("2022-01-01"), not_after=T("2030-01-01"),
                 eku=["1.3.6.1.5.5.7.3.3"])
# noise certs: many certs issued by noise CAs (same key reused for speed)
noise_cas = [make_ca(f"Noise CA {i}", "ec", not_before=T("2020-01-01"), not_after=T("2040-01-01"))
             for i in range(4)]
noise = []
for i in range(N):
    ca = noise_cas[i % 4]
    n = make_leaf(ca, f"Noise Leaf {i}", "ed", not_before=T("2022-01-01"),
                  not_after=T("2030-01-01"), eku=["1.3.6.1.5.5.7.3.3"])
    noise.append(n.der)
print(f"generated {N} noise certs in {time.time()-t0:.1f}s", flush=True)

crl_inter = make_crl(inter, entries=[], crl_number=1, this_update=T("2024-05-01"),
                     next_update=T("2024-07-01"))
crl_root = make_crl(root, entries=[], crl_number=1, this_update=T("2024-05-01"),
                    next_update=T("2024-07-01"))

t0 = time.time()
r = requests.post(f"{API}/v1/evidence-sets", data=dumps({"request_id": f"scale-{N}-create"}),
                  headers={"Content-Type": "application/json"})
set_id = r.json()["evidence_set_id"]

objects = [(root.der, "certificate"), (inter.der, "certificate"), (leaf.der, "certificate"),
           (crl_inter, "crl"), (crl_root, "crl")] + [(d, "certificate") for d in noise]
B = 2000
for i in range(0, len(objects), B):
    batch = objects[i:i+B]
    body = {"request_id": f"scale-{N}-add-{i}",
            "objects": [{"type": t, "der": base64.b64encode(d).decode(),
                         "received_at": "2024-01-01T00:00:00Z"} for d, t in batch]}
    r = requests.post(f"{API}/v1/evidence-sets/{set_id}/objects", data=dumps(body),
                      headers={"Content-Type": "application/json"}, timeout=300)
    assert r.status_code == 200, r.text[:300]
    assert not r.json()["rejected"], r.json()["rejected"][:2]
print(f"uploaded {len(objects)} objects in {time.time()-t0:.1f}s", flush=True)

t0 = time.time()
r = requests.post(f"{API}/v1/evidence-sets/{set_id}/seal", data=dumps({"request_id": f"scale-{N}-seal"}),
                  headers={"Content-Type": "application/json"}, timeout=300)
print(f"seal in {time.time()-t0:.1f}s -> {r.json()['content_digest'][:16]}", flush=True)

import hashlib
digest = hashlib.sha256(b"scale artifact").hexdigest()
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
t0 = time.time()
r = requests.post(f"{API}/v1/adjudications",
                  data=dumps({"request_id": f"scale-{N}-adj", "evidence_set_id": set_id, "input": inp}),
                  headers={"Content-Type": "application/json"}, timeout=600)
body = r.json()
print(f"adjudication in {time.time()-t0:.1f}s -> {body.get('verdict')}", flush=True)
assert body["verdict"] == "VALID", dumps(body).decode()[:2000]
t0 = time.time()
r2 = requests.post(f"{API}/v1/adjudications",
                   data=dumps({"request_id": f"scale-{N}-adj2", "evidence_set_id": set_id, "input": inp}),
                   headers={"Content-Type": "application/json"}, timeout=600)
print(f"second adjudication (cached path) in {time.time()-t0:.2f}s, identical={r2.content == r.content}", flush=True)
print("SCALE OK", flush=True)
