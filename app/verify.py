"""Offline evidence-pack verifier.

Usage:  python -m app.verify <evidence-pack.json>

Reads ONLY the evidence pack file - never the service, a database or the
network.  It re-parses every referenced DER object, re-verifies all
signatures, the path, the two-axis revocation rules and every digest, then
re-runs the deterministic adjudication engine and requires the recomputed
result to be byte-for-byte identical to the one recorded in the pack.
Tampering with any input, DER object, rule conclusion or the final verdict
makes verification fail.
"""
from __future__ import annotations

import sys

from .adjudicate import DictObjectSource, compute_adjudication_id, run_engine, validate_input
from .canonical import b64d, canonical_hash, dumps, loads, sha256_hex
from .errors import ApiError
from .objmeta import OBJECT_TYPES, compute_meta


class CheckLog:
    def __init__(self):
        self.lines: list = []
        self.failures = 0

    def ok(self, msg: str):
        self.lines.append(f"PASS  {msg}")

    def fail(self, msg: str):
        self.lines.append(f"FAIL  {msg}")
        self.failures += 1

    def info(self, msg: str):
        self.lines.append(f"INFO  {msg}")


def verify_pack(pack_bytes: bytes, log: CheckLog | None = None) -> bool:
    log = log or CheckLog()
    # 1. canonical form
    try:
        pack = loads(pack_bytes)
    except ValueError as exc:
        log.fail(f"pack is not valid JSON: {exc}")
        return _finish(log)
    if dumps(pack) != pack_bytes:
        log.fail("pack is not in canonical JSON form")
        return _finish(log)
    log.ok("pack is canonical JSON")
    if not isinstance(pack, dict):
        log.fail("pack root is not an object")
        return _finish(log)
    for field in ("pack_version", "adjudication_id", "input", "evidence_set",
                  "objects", "result"):
        if field not in pack:
            log.fail(f"pack is missing field {field!r}")
            return _finish(log)
    if pack["pack_version"] != 1:
        log.fail(f"unsupported pack_version {pack['pack_version']!r}")
        return _finish(log)

    # 2. objects: fingerprints, parseability, metadata
    objects = {}
    obj_list = pack["objects"]
    if not isinstance(obj_list, list):
        log.fail("pack objects is not a list")
        return _finish(log)
    fps = []
    for entry in obj_list:
        try:
            fp = entry["fingerprint"]
            otype = entry["type"]
            der = b64d(entry["der"])
            received_at = entry["received_at"]
        except Exception as exc:
            log.fail(f"malformed object entry: {exc}")
            return _finish(log)
        if otype not in OBJECT_TYPES:
            log.fail(f"object {fp}: unknown type {otype!r}")
            return _finish(log)
        if sha256_hex(der) != fp:
            log.fail(f"object {fp}: fingerprint does not match DER bytes")
            return _finish(log)
        try:
            meta = compute_meta(otype, der)
        except Exception as exc:
            log.fail(f"object {fp}: DER does not parse as {otype}: {exc}")
            return _finish(log)
        objects[fp] = {"type": otype, "der": der, "received_at": received_at,
                       "meta": meta}
        fps.append(fp)
    if fps != sorted(fps) or len(set(fps)) != len(fps):
        log.fail("pack objects are not strictly sorted by fingerprint")
        return _finish(log)
    log.ok(f"verified {len(objects)} referenced DER objects (fingerprints + parsing)")

    # 3. manifest + content digest
    es = pack["evidence_set"]
    manifest = es.get("manifest")
    if not isinstance(manifest, dict):
        log.fail("evidence_set.manifest is missing")
        return _finish(log)
    recomputed_digest = sha256_hex(dumps(manifest))
    if recomputed_digest != es.get("content_digest"):
        log.fail("evidence set content digest does not match the manifest")
        return _finish(log)
    log.ok(f"evidence set content digest {recomputed_digest[:16]}... matches manifest")
    manifest_index = {}
    for mo in manifest.get("objects", []):
        manifest_index[mo["fingerprint"]] = mo
    for fp, obj in objects.items():
        mo = manifest_index.get(fp)
        if mo is None:
            log.fail(f"pack object {fp} is not listed in the evidence set manifest")
            return _finish(log)
        if mo["type"] != obj["type"] or mo["received_at"] != obj["received_at"]:
            log.fail(f"pack object {fp} does not match its manifest entry")
            return _finish(log)
    log.ok("all pack objects are covered by the sealed manifest")

    # 4. input normalization
    try:
        normalized = validate_input(pack["input"])
    except ApiError as exc:
        log.fail(f"adjudication input is invalid: {exc.message}")
        return _finish(log)
    if normalized != pack["input"]:
        log.fail("recorded adjudication input is not in normalized form")
        return _finish(log)
    log.ok("adjudication input is well-formed and normalized")

    # 5. adjudication id
    adj_id = compute_adjudication_id(es["content_digest"], pack["input"])
    if adj_id != pack["adjudication_id"]:
        log.fail("adjudication id does not match input + content digest")
        return _finish(log)
    if pack["result"].get("adjudication_id") != adj_id:
        log.fail("recorded result carries a different adjudication id")
        return _finish(log)
    log.ok("adjudication id binds input and evidence set digest")

    # 6. re-run the engine from the pack alone
    source = DictObjectSource(objects)
    try:
        result2, touched2 = run_engine(source, pack["input"], es["content_digest"])
    except Exception as exc:
        log.fail(f"re-adjudication failed: {type(exc).__name__}: {exc}")
        return _finish(log)
    if set(touched2) != set(objects.keys()):
        missing = sorted(set(touched2) - set(objects.keys()))
        extra = sorted(set(objects.keys()) - set(touched2))
        log.fail(f"touched-object set mismatch (missing={missing[:3]} extra={extra[:3]})")
        return _finish(log)
    log.ok("pack contains exactly the objects the engine references")
    if dumps(result2) != dumps(pack["result"]):
        log.fail("recomputed adjudication result differs from the recorded result")
        return _finish(log)
    verdict = pack["result"].get("verdict")
    log.ok(f"recomputed result is identical (verdict={verdict})")
    return _finish(log)


def _finish(log: CheckLog) -> bool:
    return log.failures == 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        print("usage: python -m app.verify <evidence-pack.json>", file=sys.stderr)
        return 2
    try:
        with open(argv[0], "rb") as fh:
            pack_bytes = fh.read()
    except OSError as exc:
        print(f"verify: cannot read {argv[0]}: {exc}", file=sys.stderr)
        return 2
    log = CheckLog()
    ok = verify_pack(pack_bytes, log)
    for line in log.lines:
        print(line)
    print("VERIFY OK" if ok else "VERIFY FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
