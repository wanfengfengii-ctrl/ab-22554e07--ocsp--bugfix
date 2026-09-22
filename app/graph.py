"""Certification path discovery over the full certificate graph.

The search is deterministic:
  * iterative deepening by path length (fewest certificates first);
  * sibling issuers are tried in ascending fingerprint order, so the first
    valid path found at the minimal length is also the lexicographically
    smallest fingerprint sequence (leaf to anchor);
  * cycles are cut (no certificate repeats within a candidate path);
  * an anchor-reachability prefilter prunes branches that cannot terminate
    at a trust anchor (computed over name/AKI-SKI edges);
  * when no valid path exists, a rejection proof covering every explored
    candidate branch is produced, each annotated with the first failing rule.

Rule evaluation order (documented in README):
  leaf:      PROFILE, VALIDITY, KEY_USAGE, EKU
  extension: PROFILE(parent), SIGNATURE, VALIDITY(parent), BASIC_CONSTRAINTS,
             KEY_USAGE(parent), PATHLEN, REVOCATION(child)
  terminal:  PROFILE(anchor), VALIDITY(anchor), NAME_CONSTRAINTS, POLICIES
"""
from __future__ import annotations

from . import profile as profile_mod
from .errors import ResourceExhausted
from .pki import EKU_CODE_SIGNING, check_name_constraints, evaluate_policies

# rule codes
R_PROFILE = "CERT_PROFILE"
R_VALIDITY = "VALIDITY"
R_SIGNATURE = "SIGNATURE"
R_BASIC_CONSTRAINTS = "BASIC_CONSTRAINTS"
R_KEY_USAGE = "KEY_USAGE"
R_EKU = "EKU"
R_PATHLEN = "PATHLEN"
R_REVOCATION = "REVOCATION"
R_NAME_CONSTRAINTS = "NAME_CONSTRAINTS"
R_POLICIES = "POLICIES"
R_NO_ISSUER = "NO_ISSUER"
R_NO_ANCHOR = "NO_TRUSTED_ANCHOR"

# failures whose presence (with no valid path) yields verdict UNSUPPORTED
UNSUPPORTED_RULE_CODES = {"UNSUPPORTED"}


def _fail(certificate: str, rule: str, code: str, detail=None, details=None) -> dict:
    f = {"certificate": certificate, "rule": rule, "code": code}
    if detail is not None:
        f["detail"] = detail
    if details is not None:
        f["details"] = details
    return f


class Explorer:
    def __init__(self, cert_metas: dict, by_subject: dict, children: dict,
                 get_cert, anchors: set, signed_at, initial_policy_set,
                 rev_evaluator, max_path_len: int, max_branches: int):
        self._metas = cert_metas          # fp -> cert meta dict
        self._by_subject = by_subject     # subject_hex -> sorted [fp]
        self._children = children         # issuer_hex -> [fp]
        self._get_cert = get_cert         # fp -> CertInfo
        self._anchors = anchors
        self._signed_at = signed_at
        self._initial_policy_set = initial_policy_set
        self._rev = rev_evaluator
        self._max_path_len = max_path_len
        self._max_branches = max_branches
        self.touched: set = set()
        self._sig_cache: dict = {}
        self._anchor_reachable = self._compute_anchor_reachable()
        self._branches: list = []
        self._budget = 0

    # ------------------------------------------------------------------
    def _compute_anchor_reachable(self) -> set:
        reachable = set(self._anchors) & set(self._metas.keys())
        stack = list(reachable)
        while stack:
            fp = stack.pop()
            meta = self._metas[fp]
            for child_fp in self._children.get(meta["subject_der_hex"], []):
                if child_fp not in reachable and self._edge_key_matches(child_fp, fp):
                    reachable.add(child_fp)
                    stack.append(child_fp)
        return reachable

    def _edge_key_matches(self, child_fp: str, parent_fp: str) -> bool:
        child = self._metas[child_fp]
        parent = self._metas[parent_fp]
        aki = child.get("aki_keyid")
        if aki is not None:
            return parent.get("ski") == aki
        return True

    def _parents_of(self, cert) -> list:
        """Issuer candidates for *cert*, ascending fingerprint order."""
        out = []
        for fp in self._by_subject.get(cert.issuer_hex, []):
            if not self._edge_key_matches(cert.fingerprint, fp):
                continue
            out.append(fp)
        return sorted(out)

    def _spend(self, n=1):
        self._budget += n
        if self._budget > self._max_branches:
            raise ResourceExhausted(
                f"path exploration exceeded budget of {self._max_branches} branches"
            )

    # ------------------------------------------------------------------
    def search(self, leaf_fp: str):
        """Returns (path_fps or None, rejection_proof or None)."""
        self.touched.add(leaf_fp)
        leaf = self._get_cert(leaf_fp)
        leaf_failure = self._leaf_prechecks(leaf)
        if leaf_failure is not None:
            return None, {
                "exploration_complete": True,
                "branches": [{"path": [leaf_fp], "failure": leaf_failure}],
            }
        for depth in range(1, self._max_path_len + 1):
            self._cutoff_occurred = False
            found = self._dfs([leaf_fp], depth, record=False)
            if found is not None:
                return found, None
            if not self._cutoff_occurred:
                break
        # full exploration with proof recording
        self._branches = []
        self._dfs([leaf_fp], self._max_path_len, record=True)
        return None, {
            "exploration_complete": not self._cutoff_occurred,
            "branches": self._branches,
        }

    # ------------------------------------------------------------------
    def _leaf_prechecks(self, leaf) -> dict | None:
        if leaf.unsupported:
            return _fail(leaf.fingerprint, R_PROFILE, "UNSUPPORTED", details=leaf.unsupported)
        if self._signed_at < leaf.not_before:
            return _fail(leaf.fingerprint, R_VALIDITY, "NOT_YET_VALID",
                         f"notValidBefore {leaf.not_before} after signed_at")
        if self._signed_at > leaf.not_after:
            return _fail(leaf.fingerprint, R_VALIDITY, "EXPIRED",
                         f"notValidAfter {leaf.not_after} before signed_at")
        if leaf.key_usage is not None and "digitalSignature" not in leaf.key_usage:
            return _fail(leaf.fingerprint, R_KEY_USAGE, "NO_DIGITAL_SIGNATURE",
                         "leaf keyUsage lacks digitalSignature")
        if leaf.eku is None or EKU_CODE_SIGNING not in leaf.eku:
            return _fail(leaf.fingerprint, R_EKU, "MISSING_CODE_SIGNING",
                         "leaf EKU must contain id-kp-codeSigning")
        return None

    def _edge_checks(self, cert, parent, path_fps: list) -> dict | None:
        """Checks performed when extending the path with *parent*."""
        if parent.unsupported:
            return _fail(parent.fingerprint, R_PROFILE, "UNSUPPORTED",
                         details=parent.unsupported)
        if not self._verify_edge_signature(cert, parent):
            return _fail(cert.fingerprint, R_SIGNATURE, "SIGNATURE_INVALID",
                         f"signature of {cert.fingerprint} does not verify with "
                         f"{parent.fingerprint}")
        if self._signed_at < parent.not_before:
            return _fail(parent.fingerprint, R_VALIDITY, "NOT_YET_VALID",
                         f"notValidBefore {parent.not_before} after signed_at")
        if self._signed_at > parent.not_after:
            return _fail(parent.fingerprint, R_VALIDITY, "EXPIRED",
                         f"notValidAfter {parent.not_after} before signed_at")
        if not parent.is_ca:
            return _fail(parent.fingerprint, R_BASIC_CONSTRAINTS, "NOT_A_CA",
                         "issuer basicConstraints CA is not TRUE")
        if parent.key_usage is not None and "keyCertSign" not in parent.key_usage:
            return _fail(parent.fingerprint, R_KEY_USAGE, "NO_KEY_CERT_SIGN",
                         "issuer keyUsage lacks keyCertSign")
        if parent.path_len is not None:
            below = sum(
                1 for fp in path_fps
                if self._get_cert(fp).is_ca and not self._get_cert(fp).self_issued
            )
            if below > parent.path_len:
                return _fail(parent.fingerprint, R_PATHLEN, "PATHLEN_EXCEEDED",
                             f"pathLenConstraint {parent.path_len} exceeded")
        # revocation of the child (its issuing key is the parent's key)
        outcome = self._rev.status(cert, parent)
        if outcome["status"] != "GOOD":
            return _fail(cert.fingerprint, R_REVOCATION, outcome["status"],
                         f"revocation status {outcome['status']} at signed_at")
        return None

    def _verify_edge_signature(self, cert, parent) -> bool:
        key = (cert.fingerprint, parent.fingerprint)
        cached = self._sig_cache.get(key)
        if cached is not None:
            return cached
        ok = False
        if cert.sig_alg is not None and parent.key_alg is not None:
            ok = profile_mod.verify_signature(
                parent.public_key(), cert.sig_alg, cert.cert.signature,
                cert.cert.tbs_certificate_bytes,
            )
        self._sig_cache[key] = ok
        return ok

    def _terminal_checks(self, path_fps: list) -> dict | None:
        anchor = self._get_cert(path_fps[-1])
        if anchor.unsupported:
            return _fail(anchor.fingerprint, R_PROFILE, "UNSUPPORTED",
                         details=anchor.unsupported)
        if self._signed_at < anchor.not_before:
            return _fail(anchor.fingerprint, R_VALIDITY, "NOT_YET_VALID",
                         f"notValidBefore {anchor.not_before} after signed_at")
        if self._signed_at > anchor.not_after:
            return _fail(anchor.fingerprint, R_VALIDITY, "EXPIRED",
                         f"notValidAfter {anchor.not_after} before signed_at")
        path = [self._get_cert(fp) for fp in path_fps]
        nc = check_name_constraints(path)
        if nc["result"] != "pass":
            return _fail(nc.get("certificate", path_fps[0]), R_NAME_CONSTRAINTS,
                         nc["code"], nc.get("detail"))
        pol = evaluate_policies(path, self._initial_policy_set)
        if pol["result"] != "pass":
            return _fail(pol.get("certificate", path_fps[0]), R_POLICIES,
                         pol["code"], pol.get("detail"))
        return None

    # ------------------------------------------------------------------
    def _dfs(self, path_fps: list, depth_left: int, record: bool):
        self._spend()
        current_fp = path_fps[-1]
        if current_fp in self._anchors:
            failure = self._terminal_checks(path_fps)
            if failure is None:
                return list(path_fps)
            if record:
                self._branches.append({"path": list(path_fps), "failure": failure})
            return None
        current = self._get_cert(current_fp)
        in_path = set(path_fps)
        parents = [fp for fp in self._parents_of(current) if fp not in in_path]
        if not parents:
            if record:
                self._branches.append({
                    "path": list(path_fps),
                    "failure": _fail(current_fp, R_NO_ISSUER, "NO_ISSUER",
                                     "no issuer certificate in evidence set"),
                })
            return None
        for parent_fp in parents:
            self._spend()
            self.touched.add(parent_fp)
            parent = self._get_cert(parent_fp)
            failure = self._edge_checks(current, parent, path_fps)
            if failure is not None:
                if record:
                    self._branches.append({"path": path_fps + [parent_fp],
                                           "failure": failure})
                continue
            if parent_fp in self._anchors:
                found = self._dfs(path_fps + [parent_fp], depth_left - 1, record)
                if found is not None:
                    return found
                continue
            if parent_fp not in self._anchor_reachable:
                if record:
                    self._branches.append({
                        "path": path_fps + [parent_fp],
                        "failure": _fail(parent_fp, R_NO_ANCHOR, "NO_TRUSTED_ANCHOR",
                                         "issuer chain cannot reach a trust anchor"),
                    })
                continue
            if depth_left <= 1:
                self._cutoff_occurred = True
                continue
            found = self._dfs(path_fps + [parent_fp], depth_left - 1, record)
            if found is not None:
                return found
        return None

    # ------------------------------------------------------------------
    def trace_path(self, path_fps: list) -> list:
        """Full per-certificate rule trace for a selected (valid) path."""
        trace = []
        n = len(path_fps)
        path = [self._get_cert(fp) for fp in path_fps]
        for idx, cert in enumerate(path):
            role = "leaf" if idx == 0 else ("trust_anchor" if idx == n - 1 else "intermediate")
            rules = [{"rule": R_PROFILE, "result": "pass"}]
            rules.append({"rule": R_VALIDITY, "result": "pass"})
            if idx < n - 1:
                parent = path[idx + 1]
                rules.append({"rule": R_SIGNATURE, "result": "pass",
                              "detail": f"verifies with {parent.fingerprint}"})
            if idx == 0:
                rules.append({"rule": R_KEY_USAGE, "result": "pass"})
                rules.append({"rule": R_EKU, "result": "pass"})
            elif idx < n - 1:
                rules.append({"rule": R_BASIC_CONSTRAINTS, "result": "pass"})
                rules.append({"rule": R_KEY_USAGE, "result": "pass"})
                rules.append({"rule": R_PATHLEN, "result": "pass"})
            entry = {"certificate": cert.fingerprint, "role": role, "rules": rules}
            if idx < n - 1:
                outcome = self._rev.outcomes.get(cert.fingerprint)
                entry["revocation"] = outcome["status"] if outcome else None
            trace.append(entry)
        return trace
