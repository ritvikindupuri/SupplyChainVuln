"""
Evidence Store (SES — Security Evidence Store)
==============================================
Per-commit model. SecureChain walks the newest N commits and analyzes each
commit's diff independently. The interesting signal is what a NEW commit
INTRODUCES — not the repository's initial/clean state.

For each commit we store:
  - the deterministic scanner evidence for THAT commit's diff
  - whether the commit was "flagged" (introduced risk)
  - the AI consensus verdict (only computed for flagged commits — token-cheap)

In-memory store keyed by scan_id.
"""

import time
import uuid
import threading


class EvidenceStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._scans = {}

    def create_scan(self, repo_url: str) -> str:
        scan_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._scans[scan_id] = {
                "scan_id": scan_id,
                "repo_url": repo_url,
                "status": "pending",   # pending->streaming->scanning->reviewing->complete|error
                "created_at": time.time(),
                "repo": None,
                "commits": [],         # per-commit results (timeline)
                "events": [],
                "tokens_saved_commits": 0,   # clean commits that never reached the AI
                "error": None,
            }
        return scan_id

    def get(self, scan_id: str):
        with self._lock:
            return self._scans.get(scan_id)

    def update(self, scan_id: str, **fields):
        with self._lock:
            s = self._scans.get(scan_id)
            if s:
                s.update(fields)

    def set_repo(self, scan_id: str, repo: dict):
        with self._lock:
            s = self._scans.get(scan_id)
            if s:
                s["repo"] = repo

    def add_commit_result(self, scan_id: str, commit_result: dict):
        with self._lock:
            s = self._scans.get(scan_id)
            if s:
                s["commits"].append(commit_result)
                if not commit_result.get("flagged"):
                    s["tokens_saved_commits"] += 1

    def log_event(self, scan_id: str, message: str, kind: str = "info"):
        with self._lock:
            s = self._scans.get(scan_id)
            if s:
                s["events"].append({"t": time.time(), "kind": kind, "message": message})

    def aggregate(self, scan_id: str):
        """Roll up per-commit verdicts into a scan-level summary for the dashboard/report."""
        s = self.get(scan_id)
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        flagged_commits = []
        all_findings = []
        iocs = []
        if not s:
            return {"counts": counts, "flagged_commits": [], "overall_risk": "clean",
                    "findings": [], "iocs": [], "ioc_count": 0}

        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "noise": 0, "clean": 0}
        worst = "clean"
        for c in s["commits"]:
            verdict = c.get("verdict") or {}
            if c.get("flagged") and verdict.get("worth_alerting"):
                flagged_commits.append(c)
                for f in verdict.get("findings", []):
                    sev = (f.get("severity") or "low").lower()
                    if sev in counts:
                        counts[sev] += 1
                    fwith = {**f, "commit": c["short_sha"]}
                    all_findings.append(fwith)
                    # AI-validated IOCs (is_ioc true) become confirmed indicators.
                    if f.get("is_ioc"):
                        iocs.append(fwith)
                cr = (verdict.get("commit_risk") or "low").lower()
                if rank.get(cr, 0) > rank.get(worst, 0):
                    worst = cr
        return {
            "counts": counts,
            "flagged_commits": flagged_commits,
            "overall_risk": worst,
            "findings": all_findings,
            "iocs": iocs,
            "ioc_count": len(iocs),
        }


store = EvidenceStore()
