"""The deterministic adjudication engine.

``run_engine`` is a pure function of (object source, adjudication input,
evidence-set content digest).  It is used identically by the HTTP API and by
the offline evidence-pack verifier, which guarantees that a verdict can be
reproduced byte-for-byte without the service, the database or the network.

Path search runs on a fixpoint of the "touched object" closure: the engine
explores the graph, records every object it touched, then re-runs on that
subset until the set no longer shrinks.  The evidence pack contains exactly
that fixpoint set, so the verifier's exploration observes exactly the same
graph (including the same anchor-reachability prefilter decisions).
"""
from __future__ import annotations

import re

from . import profile
from .canonical import (
    b64d,
    canon_time,
    canonical_hash,
    is_fingerprint,
    parse_time,
)
from .errors import ApiError
from .graph import Explorer
from .objmeta import OBJECT_TYPES
from .pki import check_name_constraints, evaluate_policies, parse_certificate
from .revocation import RevocationEvaluator, parse_crl, parse_ocsp

_OID_RE = re.compile(r"^(0|[1-9]\d*)(\.(0|[1-9]\d*))+$")


class DictObjectSource:
    """Object source backed by an in-memory dict (used by the verifier)."""

    def __init__(self, objects: dict):
        # objects: fp -> {"type", "der", "received_at", "meta" (optional)}
        self._objects = objects
        from .objmeta import compute_meta

        self._metas = {}
        for fp, obj in objects.items():
            meta = obj.get("meta")
            if meta is None:
                meta = compute_meta(obj["type"], obj["der"])
            self._metas[fp] = {
                "type": obj["type"],
                "received_at": obj["received_at"],
                "meta": meta,
            }

    def metas(self) -> dict:
        return self._metas

    def der(self, fp: str) -> bytes:
        return self._objects[fp]["der"]


def validate_input(raw) -> dict:
    """Validate and normalize an adjudication input; raises ApiError."""
    if not isinstance(raw, dict):
        raise ApiError("VALIDATION", "input must be an object", 400)

    def need(name):
        if name not in raw:
            raise ApiError("VALIDATION", f"missing input field {name!r}", 400)
        return raw[name]

    artifact_digest = need("artifact_digest")
    if not is_fingerprint(artifact_digest):
        raise ApiError("VALIDATION", "artifact_digest must be 64 lowercase hex chars", 400)
    signature = need("signature")
    if not isinstance(signature, str):
        raise ApiError("VALIDATION", "signature must be base64", 400)
    try:
        sig_bytes = b64d(signature)
    except ValueError as exc:
        raise ApiError("VALIDATION", str(exc), 400)
    if not sig_bytes:
        raise ApiError("VALIDATION", "signature must not be empty", 400)
    from .canonical import b64e

    signature = b64e(sig_bytes)  # canonical base64 form
    sig_alg = need("signature_algorithm")
    if sig_alg not in profile.ARTIFACT_SIGNATURE_ALGORITHMS:
        raise ApiError(
            "UNSUPPORTED",
            f"signature_algorithm {sig_alg!r} is not in the supported profile",
            422,
            {"supported": list(profile.ARTIFACT_SIGNATURE_ALGORITHMS)},
        )
    try:
        signed_at = canon_time(parse_time(need("signed_at")))
        knowledge_cutoff = canon_time(parse_time(need("knowledge_cutoff")))
    except ValueError as exc:
        raise ApiError("VALIDATION", str(exc), 400)
    leaf_fp = need("leaf_fingerprint")
    if not is_fingerprint(leaf_fp):
        raise ApiError("VALIDATION", "leaf_fingerprint must be 64 lowercase hex chars", 400)
    anchors = need("trust_anchors")
    if not isinstance(anchors, list) or not anchors:
        raise ApiError("VALIDATION", "trust_anchors must be a non-empty list", 400)
    for a in anchors:
        if not is_fingerprint(a):
            raise ApiError("VALIDATION", "trust_anchors must contain fingerprints", 400)
    anchors = sorted(set(anchors))
    initial = raw.get("initial_policy_set", ["anyPolicy"])
    if not isinstance(initial, list):
        raise ApiError("VALIDATION", "initial_policy_set must be a list", 400)
    for p in initial:
        if p != "anyPolicy" and not _OID_RE.match(p or ""):
            raise ApiError("VALIDATION", f"invalid policy OID {p!r}", 400)
    initial = sorted(set(initial)) if initial else ["anyPolicy"]
    return {
        "artifact_digest": artifact_digest,
        "signature": signature,
        "signature_algorithm": sig_alg,
        "signed_at": signed_at,
        "knowledge_cutoff": knowledge_cutoff,
        "leaf_fingerprint": leaf_fp,
        "initial_policy_set": initial,
        "trust_anchors": anchors,
    }


def compute_adjudication_id(content_digest: str, normalized_input: dict) -> str:
    return "adj_" + canonical_hash(
        {"evidence_set_content_digest": content_digest, "input": normalized_input}
    )


def _check_artifact_signature(leaf, inp: dict) -> tuple:
    alg = inp["signature_algorithm"]
    rec = {"algorithm": alg, "leaf_key_fingerprint": leaf.key_fp}
    unsupported = False
    if leaf.key_alg is None:
        rec["valid"] = False
        rec["detail"] = "leaf public key is out of the supported profile"
        unsupported = True
        return rec, unsupported
    if not profile.artifact_algorithm_matches_key(alg, leaf.key_alg):
        rec["valid"] = False
        rec["detail"] = "signature algorithm does not match the leaf key type"
        return rec, unsupported
    descriptor = {"algorithm": alg}
    if alg != profile.ALG_ED25519:
        descriptor["hash"] = "sha256"
    message = bytes.fromhex(inp["artifact_digest"])
    ok = profile.verify_signature(leaf.public_key(), descriptor, b64d(inp["signature"]), message)
    rec["valid"] = ok
    if not ok:
        rec["detail"] = "artifact signature verification failed"
    return rec, unsupported


class _Engine:
    def __init__(self, source, inp: dict):
        self.source = source
        self.inp = inp
        self.metas = source.metas()
        self.signed_at = parse_time(inp["signed_at"])
        self.cutoff = parse_time(inp["knowledge_cutoff"])
        self._cert_cache: dict = {}
        self._crl_cache: dict = {}
        self._ocsp_cache: dict = {}

    def get_cert(self, fp):
        if fp not in self._cert_cache:
            self._cert_cache[fp] = parse_certificate(self.source.der(fp), fp)
        return self._cert_cache[fp]

    def get_crl(self, fp):
        if fp not in self._crl_cache:
            self._crl_cache[fp] = parse_crl(self.source.der(fp), fp)
        return self._crl_cache[fp]

    def get_ocsp(self, fp):
        if fp not in self._ocsp_cache:
            self._ocsp_cache[fp] = parse_ocsp(self.source.der(fp), fp)
        return self._ocsp_cache[fp]

    def explore_once(self, active: set):
        metas = self.metas
        cert_metas = {
            fp: metas[fp]["meta"] for fp in active if metas[fp]["type"] == "certificate"
        }
        by_subject: dict = {}
        children: dict = {}
        for fp, m in cert_metas.items():
            by_subject.setdefault(m["subject_der_hex"], []).append(fp)
            children.setdefault(m["issuer_der_hex"], []).append(fp)
        for lst in by_subject.values():
            lst.sort()
        crl_index: dict = {}
        ocsp_fps: list = []
        eval_metas: dict = {}
        for fp in active:
            m = metas[fp]
            if m["type"] == "crl":
                crl_index.setdefault(m["meta"]["issuer_der_hex"], []).append(fp)
                eval_metas[fp] = {
                    "received_at": m["received_at"],
                    "type": "crl",
                    **m["meta"],
                }
            elif m["type"] == "ocsp":
                ocsp_fps.append(fp)
                eval_metas[fp] = {
                    "received_at": m["received_at"],
                    "type": "ocsp",
                    **m["meta"],
                }
        evaluator = RevocationEvaluator(
            crl_index, ocsp_fps, eval_metas, self.get_crl, self.get_ocsp,
            self.signed_at, self.cutoff,
        )
        explorer = Explorer(
            cert_metas, by_subject, children, self.get_cert,
            set(self.inp["trust_anchors"]), self.signed_at,
            self.inp["initial_policy_set"], evaluator,
            profile.MAX_PATH_LEN, profile.MAX_EXPLORED_BRANCHES,
        )
        leaf_fp = self.inp["leaf_fingerprint"]
        path, proof = explorer.search(leaf_fp)
        touched = set(explorer.touched) | set(evaluator.touched) | {leaf_fp}
        touched &= active
        return path, proof, touched, explorer, evaluator

    def run(self, content_digest: str):
        inp = self.inp
        leaf_fp = inp["leaf_fingerprint"]
        leaf_meta = self.metas.get(leaf_fp)
        if leaf_meta is None or leaf_meta["type"] != "certificate":
            raise ApiError(
                "LEAF_NOT_FOUND",
                "leaf certificate is not present in the sealed evidence set",
                422,
                {"leaf_fingerprint": leaf_fp},
            )
        leaf = self.get_cert(leaf_fp)
        artifact, artifact_unsupported = _check_artifact_signature(leaf, inp)

        active = set(self.metas.keys())
        while True:
            path, proof, touched, explorer, evaluator = self.explore_once(active)
            if touched == active:
                break
            active = touched

        # verdict
        unsupported_involved = artifact_unsupported or bool(leaf.unsupported)
        if proof:
            for branch in proof["branches"]:
                if branch["failure"].get("code") == "UNSUPPORTED":
                    unsupported_involved = True
                    break
        if artifact["valid"] and path is not None:
            verdict = "VALID"
        elif unsupported_involved:
            verdict = "UNSUPPORTED"
        else:
            verdict = "INVALID"

        decision = {}
        if path is not None:
            certs = [self.get_cert(fp) for fp in path]
            nc = check_name_constraints(certs)
            pol = evaluate_policies(certs, inp["initial_policy_set"])
            path_rules = [{"rule": "NAME_CONSTRAINTS", "result": nc["result"]}]
            pr = {"rule": "POLICIES", "result": pol["result"]}
            if pol.get("valid_policies") is not None:
                pr["valid_policies"] = pol["valid_policies"]
            path_rules.append(pr)
            decision["path"] = path
            decision["per_certificate"] = explorer.trace_path(path)
            decision["path_rules"] = path_rules
            decision["rejection_proof"] = None
        else:
            decision["path"] = None
            decision["per_certificate"] = None
            decision["path_rules"] = None
            decision["rejection_proof"] = proof

        revocation = {
            fp: evaluator.outcomes[fp] for fp in sorted(evaluator.outcomes.keys())
        }
        accounting = sorted(
            evaluator.accounting.values(), key=lambda r: (r["fingerprint"], r["reason"])
        )
        summary = {"verdict": verdict}
        if path is not None:
            summary["path_length"] = len(path)
        if proof is not None:
            summary["failure_codes"] = sorted(
                {b["failure"]["code"] for b in proof["branches"]}
            )
        result = {
            "adjudication_id": compute_adjudication_id(content_digest, inp),
            "verdict": verdict,
            "input": inp,
            "evidence_set": {"content_digest": content_digest},
            "artifact_signature": artifact,
            "decision": decision,
            "revocation": revocation,
            "evidence_accounting": accounting,
            "summary": summary,
        }
        return result, active


def run_engine(source, normalized_input: dict, content_digest: str):
    """Run adjudication; returns (result, touched_fingerprints)."""
    engine = _Engine(source, normalized_input)
    return engine.run(content_digest)
