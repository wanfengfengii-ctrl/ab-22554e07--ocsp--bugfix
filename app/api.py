"""Versioned HTTP API (v1).  Pure backend: JSON in, canonical JSON out."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid

from flask import Flask, Response, request

from . import profile
from .adjudicate import compute_adjudication_id, run_engine, validate_input
from .canonical import (
    b64d,
    b64e,
    canonical_hash,
    canon_time,
    dumps,
    is_fingerprint,
    loads,
    parse_time,
    sha256_hex,
)
from .errors import ApiError, ParseError, ResourceExhausted
from .objmeta import OBJECT_TYPES, compute_meta, revocation_entry_count
from .store import Store

JSON = "application/json; charset=utf-8"


class DbObjectSource:
    """Lazy object source over the sealed set (metas eager, DER lazy)."""

    def __init__(self, conn, set_id: str):
        self._conn = conn
        self._set_id = set_id
        self._metas = Store.objects_meta(conn, set_id)
        self._der_cache: dict = {}

    def metas(self) -> dict:
        return self._metas

    def der(self, fp: str) -> bytes:
        if fp not in self._der_cache:
            der = Store.get_der(self._conn, self._set_id, fp)
            if der is None:
                raise KeyError(f"object {fp} not found")
            self._der_cache[fp] = bytes(der)
        return self._der_cache[fp]


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 192 * 1024 * 1024
    data_dir = os.environ.get("DATA_DIR", "/data")
    store = Store(os.path.join(data_dir, "pkiforensics.db"))

    # ------------------------------------------------------------------
    def respond(obj, status: int = 200) -> Response:
        return Response(dumps(obj), status=status, content_type=JSON)

    def parse_body() -> dict:
        raw = request.get_data()
        if not raw:
            raise ApiError("VALIDATION", "request body must be a JSON object", 400)
        try:
            body = loads(raw)
        except ValueError as exc:
            raise ApiError("VALIDATION", f"invalid JSON body: {exc}", 400)
        if not isinstance(body, dict):
            raise ApiError("VALIDATION", "request body must be a JSON object", 400)
        return body

    def require_request_id(body: dict) -> str:
        rid = body.get("request_id")
        if not isinstance(rid, str) or not rid or len(rid) > 200:
            raise ApiError(
                "VALIDATION",
                "request_id is required (string, 1..200 chars)",
                400,
            )
        return rid

    def reject_unknown_fields(body: dict, allowed: set):
        extra = sorted(set(body.keys()) - allowed)
        if extra:
            raise ApiError("VALIDATION", f"unknown request fields: {extra}", 400)

    def request_fingerprint(endpoint: str, parts: dict) -> str:
        """Canonical request fingerprint for idempotency.

        Two requests with the same request_id and the same *normalized*
        content yield the same fingerprint (object batches are treated as
        unordered sets; adjudication inputs are normalized); the same id
        with different content conflicts.
        """
        return canonical_hash({"endpoint": endpoint, **parts})

    def run_idempotent(endpoint: str, request_id: str, fingerprint: str, handler):
        """Execute *handler* under idempotency + a single immediate transaction.

        handler(conn) -> (status, response_obj).  Replays of the same
        request_id with the same canonical request return the stored
        response; the same id with different content conflicts.
        """
        conn = store.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = store.get_request(conn, request_id)
            if row is not None:
                if row["request_hash"] != fingerprint:
                    raise ApiError(
                        "IDEMPOTENCY_CONFLICT",
                        "request_id was already used with a different request",
                        409,
                    )
                conn.execute("COMMIT")
                return Response(row["response_body"], status=row["status_code"],
                                content_type=JSON)
            status, resp_obj = handler(conn)
            resp_str = dumps(resp_obj).decode("utf-8")
            store.put_request(conn, request_id, endpoint, fingerprint, status, resp_str)
            conn.execute("COMMIT")
            return Response(resp_str, status=status, content_type=JSON)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    @app.get("/healthz")
    def healthz():
        return respond({"status": "ok"})

    @app.get("/v1/profile")
    def get_profile():
        return respond({
            "profile_version": "rfc5280-profile/1",
            "signature_algorithms": [
                "rsa-pss-sha256", "rsa-pss-sha384", "rsa-pss-sha512",
                "ecdsa-p256-sha256", "ed25519",
            ],
            "artifact_signature_algorithms": list(
                profile.ARTIFACT_SIGNATURE_ALGORITHMS
            ),
            "key_algorithms": ["rsa-2048..8192", "ec-p256", "ed25519"],
            "limits": profile.LIMITS,
        })

    # ------------------------------------------------------------------
    @app.post("/v1/evidence-sets")
    def create_evidence_set():
        body = parse_body()
        request_id = require_request_id(body)
        reject_unknown_fields(body, {"request_id", "label"})
        label = body.get("label")
        if label is not None and (not isinstance(label, str) or len(label) > 500):
            raise ApiError("VALIDATION", "label must be a string of at most 500 chars", 400)
        fingerprint = request_fingerprint(
            "create_evidence_set", {"request_id": request_id, "label": label})

        def handler(conn):
            set_id = "es_" + uuid.uuid4().hex
            store.create_set(conn, set_id, request_id, label)
            return 201, {"evidence_set_id": set_id, "status": "OPEN"}

        return run_idempotent("create_evidence_set", request_id, fingerprint, handler)

    def _get_set_or_404(conn, set_id: str):
        if not isinstance(set_id, str):
            raise ApiError("VALIDATION", "invalid evidence set id", 400)
        row = store.get_set(conn, set_id)
        if row is None:
            raise ApiError("EVIDENCE_SET_NOT_FOUND", f"evidence set {set_id} not found", 404)
        return row

    @app.get("/v1/evidence-sets/<set_id>")
    def get_evidence_set(set_id):
        conn = store.connect()
        try:
            row = _get_set_or_404(conn, set_id)
            out = {"evidence_set_id": set_id, "status": row["status"]}
            if row["status"] == "SEALED":
                out["content_digest"] = row["content_digest"]
                out["counts"] = json.loads(row["counts_json"])
            else:
                out["counts"] = store.object_counts(conn, set_id)
            return respond(out)
        finally:
            conn.close()

    @app.get("/v1/evidence-sets/<set_id>/manifest")
    def get_manifest(set_id):
        conn = store.connect()
        try:
            row = _get_set_or_404(conn, set_id)
            if row["status"] != "SEALED":
                raise ApiError("EVIDENCE_SET_NOT_SEALED",
                               "evidence set is not sealed yet", 409)
            return Response(row["manifest_json"], status=200, content_type=JSON)
        finally:
            conn.close()

    # ------------------------------------------------------------------
    @app.post("/v1/evidence-sets/<set_id>/objects")
    def add_objects(set_id):
        body = parse_body()
        request_id = require_request_id(body)
        reject_unknown_fields(body, {"request_id", "objects"})
        items = body.get("objects")
        if not isinstance(items, list) or not items:
            raise ApiError("VALIDATION", "objects must be a non-empty list", 400)

        # a batch is an unordered set of objects for idempotency purposes;
        # timestamps are canonicalized before fingerprinting
        def _canon_for_fp(item):
            if isinstance(item, dict) and isinstance(item.get("received_at"), str):
                try:
                    item = dict(item, received_at=canon_time(parse_time(item["received_at"])))
                except ValueError:
                    pass
            return item

        canon_objects = sorted((_canon_for_fp(o) for o in items), key=lambda o: dumps(o))
        fingerprint = request_fingerprint(
            f"add_objects:{set_id}",
            {"request_id": request_id, "objects": canon_objects})

        def handler(conn):
            row = _get_set_or_404(conn, set_id)
            if row["status"] != "OPEN":
                raise ApiError("EVIDENCE_SET_SEALED",
                               "evidence set is sealed and immutable", 409)
            items = body["objects"]
            if len(items) > profile.MAX_BATCH_OBJECTS:
                raise ApiError("LIMIT_EXCEEDED",
                               f"batch has {len(items)} objects, limit is "
                               f"{profile.MAX_BATCH_OBJECTS}", 413)
            parsed = []
            rejected = []
            total_bytes = 0
            for idx, item in enumerate(items):
                try:
                    if not isinstance(item, dict):
                        raise ParseError("INVALID_OBJECT", "object entry must be an object")
                    otype = item.get("type")
                    if otype not in OBJECT_TYPES:
                        raise ParseError("INVALID_TYPE",
                                         f"type must be one of {list(OBJECT_TYPES)}")
                    der_b64 = item.get("der")
                    if not isinstance(der_b64, str):
                        raise ParseError("INVALID_DER", "der must be base64")
                    try:
                        der = b64d(der_b64)
                    except ValueError as exc:
                        raise ParseError("INVALID_DER", str(exc))
                    if not der or len(der) > profile.MAX_OBJECT_BYTES:
                        raise ParseError("OBJECT_TOO_LARGE",
                                         f"DER object exceeds {profile.MAX_OBJECT_BYTES} bytes")
                    received_at = item.get("received_at")
                    if received_at is None and otype == "certificate":
                        received_at = None  # certificates are not time-gated
                    else:
                        try:
                            received_at = canon_time(parse_time(received_at))
                        except ValueError as exc:
                            raise ParseError("INVALID_RECEIVED_AT", str(exc))
                    meta = compute_meta(otype, der)  # raises ParseError
                    parsed.append((idx, otype, der, received_at, meta))
                except ParseError as exc:
                    rejected.append({"index": idx,
                                     "error": {"code": exc.code, "message": exc.message}})
            total_bytes = sum(len(p[2]) for p in parsed)
            if total_bytes > profile.MAX_BATCH_BYTES:
                raise ApiError("LIMIT_EXCEEDED",
                               f"batch decodes to {total_bytes} bytes, limit is "
                               f"{profile.MAX_BATCH_BYTES}", 413)

            # dedupe within the batch and against the store
            seen: dict = {}
            unique = []
            duplicates = []
            for idx, otype, der, received_at, meta in parsed:
                fp = sha256_hex(der)
                if fp in seen:
                    duplicates.append({"fingerprint": fp, "type": otype})
                    continue
                seen[fp] = (idx, otype, der, received_at, meta)
                unique.append((fp, idx, otype, der, received_at, meta))
            existing = store.existing_fingerprints(
                conn, set_id, [u[0] for u in unique]) if unique else set()
            new_objects = []
            for fp, idx, otype, der, received_at, meta in unique:
                if fp in existing:
                    duplicates.append({"fingerprint": fp, "type": otype})
                else:
                    new_objects.append((fp, otype, der, received_at, meta))

            counts = store.object_counts(conn, set_id)
            new_certs = sum(1 for o in new_objects if o[1] == "certificate")
            new_rev_ev = sum(1 for o in new_objects if o[1] in ("crl", "ocsp"))
            new_entries = sum(
                revocation_entry_count(o[1], o[4]) for o in new_objects)
            if counts["certificates"] + new_certs > profile.MAX_CERTIFICATES:
                raise ApiError("LIMIT_EXCEEDED",
                               "certificate limit would be exceeded "
                               f"({profile.MAX_CERTIFICATES})", 413)
            if counts["revocation_evidence"] + new_rev_ev > profile.MAX_REVOCATION_EVIDENCE:
                raise ApiError("LIMIT_EXCEEDED",
                               "revocation evidence limit would be exceeded "
                               f"({profile.MAX_REVOCATION_EVIDENCE})", 413)
            if counts["revocation_entries"] + new_entries > profile.MAX_REVOCATION_ENTRIES:
                raise ApiError("LIMIT_EXCEEDED",
                               "revocation entry limit would be exceeded "
                               f"({profile.MAX_REVOCATION_ENTRIES})", 413)

            for fp, otype, der, received_at, meta in new_objects:
                store.insert_object(
                    conn, set_id, fp, otype, der, received_at,
                    revocation_entry_count(otype, meta),
                    dumps(meta).decode("utf-8"),
                )
            counts = store.object_counts(conn, set_id)
            added = sorted(
                ({"fingerprint": o[0], "type": o[1]} for o in new_objects),
                key=lambda x: x["fingerprint"],
            )
            duplicates.sort(key=lambda x: x["fingerprint"])
            return 200, {
                "evidence_set_id": set_id,
                "status": "OPEN",
                "added": added,
                "duplicates": duplicates,
                "rejected": rejected,
                "counts": counts,
            }

        return run_idempotent(f"add_objects:{set_id}", request_id, fingerprint, handler)

    # ------------------------------------------------------------------
    @app.post("/v1/evidence-sets/<set_id>/seal")
    def seal(set_id):
        body = parse_body()
        request_id = require_request_id(body)
        reject_unknown_fields(body, {"request_id"})
        fingerprint = request_fingerprint(f"seal:{set_id}", {"request_id": request_id})

        def handler(conn):
            row = _get_set_or_404(conn, set_id)
            if row["status"] == "SEALED":
                return 200, {
                    "evidence_set_id": set_id,
                    "status": "SEALED",
                    "content_digest": row["content_digest"],
                    "counts": json.loads(row["counts_json"]),
                }
            rows = store.list_objects(conn, set_id)
            objects = [
                {"fingerprint": r["fingerprint"], "type": r["otype"],
                 "received_at": r["received_at"]}
                for r in rows
            ]
            counts = store.object_counts(conn, set_id)
            counts_out = {
                "certificates": counts["certificates"],
                "crls": sum(1 for r in rows if r["otype"] == "crl"),
                "ocsp_responses": sum(1 for r in rows if r["otype"] == "ocsp"),
                "revocation_entries": counts["revocation_entries"],
                "total_objects": counts["total_objects"],
            }
            manifest = {
                "format": "evidence-set-manifest/1",
                "counts": counts_out,
                "limits": profile.LIMITS,
                "objects": objects,
            }
            manifest_str = dumps(manifest).decode("utf-8")
            content_digest = sha256_hex(manifest_str.encode("utf-8"))
            store.seal_set(conn, set_id, content_digest, manifest_str,
                           dumps(counts_out).decode("utf-8"))
            return 200, {
                "evidence_set_id": set_id,
                "status": "SEALED",
                "content_digest": content_digest,
                "counts": counts_out,
            }

        return run_idempotent(f"seal:{set_id}", request_id, fingerprint, handler)

    # ------------------------------------------------------------------
    @app.post("/v1/adjudications")
    def adjudicate():
        body = parse_body()
        request_id = require_request_id(body)
        reject_unknown_fields(body, {"request_id", "evidence_set_id", "input"})
        set_id = body.get("evidence_set_id")
        if not isinstance(set_id, str):
            raise ApiError("VALIDATION", "evidence_set_id is required", 400)
        inp = validate_input(body.get("input"))  # raises ApiError
        # idempotency is keyed on the normalized adjudication request
        request_hash = request_fingerprint(
            "adjudicate",
            {"request_id": request_id, "evidence_set_id": set_id, "input": inp})

        # phase 1: idempotency + sealed-set pin (short write tx)
        conn = store.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = store.get_request(conn, request_id)
            if row is not None:
                if row["request_hash"] != request_hash:
                    raise ApiError("IDEMPOTENCY_CONFLICT",
                                   "request_id was already used with a different request", 409)
                conn.execute("COMMIT")
                return Response(row["response_body"], status=row["status_code"],
                                content_type=JSON)
            set_row = _get_set_or_404(conn, set_id)
            if set_row["status"] != "SEALED":
                raise ApiError("EVIDENCE_SET_NOT_SEALED",
                               "adjudication requires a sealed evidence set", 409)
            content_digest = set_row["content_digest"]
            manifest_str = set_row["manifest_json"]
            adj_id = compute_adjudication_id(content_digest, inp)
            existing = store.get_adjudication(conn, adj_id)
            if existing is not None:
                store.put_request(conn, request_id, "adjudicate", request_hash,
                                  200, existing["result_json"])
                conn.execute("COMMIT")
                return Response(existing["result_json"], status=200, content_type=JSON)
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            conn.close()

        # phase 2: heavy deterministic compute outside any transaction
        conn = store.connect()
        try:
            source = DbObjectSource(conn, set_id)
            result, touched = run_engine(source, inp, content_digest)
            objects = []
            for fp in sorted(touched):
                meta = source.metas()[fp]
                objects.append({
                    "fingerprint": fp,
                    "type": meta["type"],
                    "received_at": meta["received_at"],
                    "der": b64e(source.der(fp)),
                })
            pack = {
                "pack_version": 1,
                "adjudication_id": adj_id,
                "input": inp,
                "evidence_set": {
                    "content_digest": content_digest,
                    "manifest": json.loads(manifest_str),
                },
                "objects": objects,
                "result": result,
            }
            pack_str = dumps(pack).decode("utf-8")
            pack_digest = sha256_hex(pack_str.encode("utf-8"))
            result_str = dumps(result).decode("utf-8")
        finally:
            conn.close()

        # phase 3: persist atomically (single winner under concurrency)
        conn = store.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = store.get_request(conn, request_id)
            if row is not None:
                if row["request_hash"] != request_hash:
                    raise ApiError("IDEMPOTENCY_CONFLICT",
                                   "request_id was already used with a different request", 409)
                conn.execute("COMMIT")
                return Response(row["response_body"], status=row["status_code"],
                                content_type=JSON)
            existing = store.get_adjudication(conn, adj_id)
            if existing is None:
                store.put_adjudication(conn, adj_id, request_id, set_id, content_digest,
                                       dumps(inp).decode("utf-8"), result_str, pack_str,
                                       pack_digest)
            else:
                result_str = existing["result_json"]
            store.put_request(conn, request_id, "adjudicate", request_hash, 201, result_str)
            conn.execute("COMMIT")
            return Response(result_str, status=201, content_type=JSON)
        except sqlite3.IntegrityError:
            conn.execute("ROLLBACK")
            row = None
            try:
                existing = store.get_adjudication(conn, adj_id)
                if existing is not None:
                    return Response(existing["result_json"], status=200, content_type=JSON)
            finally:
                conn.close()
            raise ApiError("INTERNAL", "adjudication persistence race", 500)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @app.get("/v1/adjudications/<adj_id>")
    def get_adjudication(adj_id):
        conn = store.connect()
        try:
            row = store.get_adjudication(conn, adj_id)
            if row is None:
                raise ApiError("ADJUDICATION_NOT_FOUND",
                               f"adjudication {adj_id} not found", 404)
            return Response(row["result_json"], status=200, content_type=JSON)
        finally:
            conn.close()

    @app.get("/v1/adjudications/<adj_id>/evidence-pack")
    def get_evidence_pack(adj_id):
        conn = store.connect()
        try:
            row = store.get_adjudication(conn, adj_id)
            if row is None:
                raise ApiError("ADJUDICATION_NOT_FOUND",
                               f"adjudication {adj_id} not found", 404)
            return Response(row["pack_json"], status=200, content_type=JSON,
                            headers={"X-Evidence-Pack-SHA256": row["pack_digest"]})
        finally:
            conn.close()

    # ------------------------------------------------------------------
    @app.errorhandler(ApiError)
    def _api_error(err: ApiError):
        return Response(dumps(err.body()), status=err.http_status, content_type=JSON)

    @app.errorhandler(ParseError)
    def _parse_error(err: ParseError):
        return Response(dumps({"error": {"code": err.code, "message": err.message}}),
                        status=400, content_type=JSON)

    @app.errorhandler(ResourceExhausted)
    def _exhausted(err: ResourceExhausted):
        return Response(dumps({"error": {"code": "RESOURCE_EXHAUSTED",
                                         "message": str(err)}}),
                        status=422, content_type=JSON)

    @app.errorhandler(404)
    def _not_found(_):
        return Response(dumps({"error": {"code": "NOT_FOUND",
                                         "message": "resource not found"}}),
                        status=404, content_type=JSON)

    @app.errorhandler(405)
    def _method_not_allowed(_):
        return Response(dumps({"error": {"code": "METHOD_NOT_ALLOWED",
                                         "message": "method not allowed"}}),
                        status=405, content_type=JSON)

    @app.errorhandler(413)
    def _too_large(_):
        return Response(dumps({"error": {"code": "PAYLOAD_TOO_LARGE",
                                         "message": "request entity too large"}}),
                        status=413, content_type=JSON)

    @app.errorhandler(Exception)
    def _internal(err: Exception):
        if isinstance(err, sqlite3.OperationalError):
            return Response(dumps({"error": {"code": "SERVICE_BUSY",
                                             "message": str(err)}}),
                            status=503, content_type=JSON)
        app.logger.exception("unhandled error: %s", err)
        return Response(dumps({"error": {"code": "INTERNAL", "message": str(err)}}),
                        status=500, content_type=JSON)

    return app


app = create_app()

if __name__ == "__main__":
    from waitress import serve

    port = int(os.environ.get("API_PORT", "8080"))
    serve(app, host="0.0.0.0", port=port, threads=16)
