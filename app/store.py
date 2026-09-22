"""SQLite persistence.

A single database file lives on the shared data volume; every API instance
opens its own connections.  All mutating operations run inside
``BEGIN IMMEDIATE`` transactions, which serializes writers across processes
and makes seal/idempotency decisions atomic.  WAL mode allows concurrent
readers while one writer is active.
"""
from __future__ import annotations

import json
import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_sets(
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  created_request_id TEXT NOT NULL,
  content_digest TEXT,
  manifest_json TEXT,
  counts_json TEXT
);
CREATE TABLE IF NOT EXISTS objects(
  set_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  otype TEXT NOT NULL,
  der BLOB NOT NULL,
  received_at TEXT,
  entry_count INTEGER NOT NULL DEFAULT 0,
  meta_json TEXT NOT NULL,
  PRIMARY KEY(set_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_objects_set_type ON objects(set_id, otype);
CREATE TABLE IF NOT EXISTS requests(
  request_id TEXT PRIMARY KEY,
  endpoint TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  response_body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS adjudications(
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  set_id TEXT NOT NULL,
  set_content_digest TEXT NOT NULL,
  input_json TEXT NOT NULL,
  result_json TEXT NOT NULL,
  pack_json TEXT NOT NULL,
  pack_digest TEXT NOT NULL
);
"""


class Store:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=60, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=60000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    # -- evidence sets ------------------------------------------------------
    @staticmethod
    def create_set(conn, set_id: str, request_id: str, label):
        conn.execute(
            "INSERT INTO evidence_sets(id, status, created_request_id) VALUES (?,?,?)",
            (set_id, "OPEN", request_id),
        )

    @staticmethod
    def get_set(conn, set_id: str):
        return conn.execute(
            "SELECT * FROM evidence_sets WHERE id=?", (set_id,)
        ).fetchone()

    @staticmethod
    def seal_set(conn, set_id: str, content_digest: str, manifest_json: str, counts_json: str):
        conn.execute(
            "UPDATE evidence_sets SET status='SEALED', content_digest=?, manifest_json=?,"
            " counts_json=? WHERE id=?",
            (content_digest, manifest_json, counts_json, set_id),
        )

    # -- objects ------------------------------------------------------------
    @staticmethod
    def object_counts(conn, set_id: str) -> dict:
        row = conn.execute(
            "SELECT"
            " COALESCE(SUM(CASE WHEN otype='certificate' THEN 1 ELSE 0 END),0) AS certs,"
            " COALESCE(SUM(CASE WHEN otype IN ('crl','ocsp') THEN 1 ELSE 0 END),0) AS rev_evidence,"
            " COALESCE(SUM(entry_count),0) AS rev_entries,"
            " COUNT(*) AS total"
            " FROM objects WHERE set_id=?",
            (set_id,),
        ).fetchone()
        return {
            "certificates": row["certs"],
            "revocation_evidence": row["rev_evidence"],
            "revocation_entries": row["rev_entries"],
            "total_objects": row["total"],
        }

    @staticmethod
    def existing_fingerprints(conn, set_id: str, fps: list) -> set:
        found = set()
        for i in range(0, len(fps), 500):
            chunk = fps[i : i + 500]
            marks = ",".join("?" for _ in chunk)
            rows = conn.execute(
                f"SELECT fingerprint FROM objects WHERE set_id=? AND fingerprint IN ({marks})",
                [set_id, *chunk],
            ).fetchall()
            found.update(r["fingerprint"] for r in rows)
        return found

    @staticmethod
    def insert_object(conn, set_id: str, fp: str, otype: str, der: bytes,
                      received_at: str, entry_count: int, meta_json: str):
        conn.execute(
            "INSERT OR IGNORE INTO objects(set_id, fingerprint, otype, der, received_at,"
            " entry_count, meta_json) VALUES (?,?,?,?,?,?,?)",
            (set_id, fp, otype, der, received_at, entry_count, meta_json),
        )

    @staticmethod
    def list_objects(conn, set_id: str) -> list:
        return conn.execute(
            "SELECT fingerprint, otype, received_at, entry_count FROM objects"
            " WHERE set_id=? ORDER BY fingerprint",
            (set_id,),
        ).fetchall()

    @staticmethod
    def objects_meta(conn, set_id: str) -> dict:
        rows = conn.execute(
            "SELECT fingerprint, otype, received_at, meta_json FROM objects WHERE set_id=?",
            (set_id,),
        ).fetchall()
        return {
            r["fingerprint"]: {
                "type": r["otype"],
                "received_at": r["received_at"],
                "meta": json.loads(r["meta_json"]),
            }
            for r in rows
        }

    @staticmethod
    def get_der(conn, set_id: str, fp: str) -> bytes | None:
        row = conn.execute(
            "SELECT der FROM objects WHERE set_id=? AND fingerprint=?", (set_id, fp)
        ).fetchone()
        return row["der"] if row else None

    # -- idempotency ----------------------------------------------------------
    @staticmethod
    def get_request(conn, request_id: str):
        return conn.execute(
            "SELECT * FROM requests WHERE request_id=?", (request_id,)
        ).fetchone()

    @staticmethod
    def put_request(conn, request_id: str, endpoint: str, request_hash: str,
                    status_code: int, response_body: str):
        conn.execute(
            "INSERT INTO requests(request_id, endpoint, request_hash, status_code,"
            " response_body) VALUES (?,?,?,?,?)",
            (request_id, endpoint, request_hash, status_code, response_body),
        )

    # -- adjudications --------------------------------------------------------
    @staticmethod
    def get_adjudication(conn, adj_id: str):
        return conn.execute(
            "SELECT * FROM adjudications WHERE id=?", (adj_id,)
        ).fetchone()

    @staticmethod
    def put_adjudication(conn, adj_id: str, request_id: str, set_id: str,
                         content_digest: str, input_json: str, result_json: str,
                         pack_json: str, pack_digest: str):
        conn.execute(
            "INSERT INTO adjudications(id, request_id, set_id, set_content_digest,"
            " input_json, result_json, pack_json, pack_digest) VALUES (?,?,?,?,?,?,?,?)",
            (adj_id, request_id, set_id, content_digest, input_json, result_json,
             pack_json, pack_digest),
        )
