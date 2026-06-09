"""
SecureChain — Core Server (Central Control Hub)
===============================================
Analyst-focused supply-chain recon tool. Walks the newest N commits of a public
GitHub repository and analyzes EACH commit's diff independently.

Design principles (per security-team feedback):
  - The initial / clean state is never interesting. The signal is what a NEW
    commit INTRODUCES over time.
  - Token-efficient: deterministic scanners run on every commit (cheap), but the
    AI consensus is invoked ONLY for commits that introduced risk. Clean commits
    cost zero AI tokens.
  - The AI consensus runs in a separate, isolated container; this core server
    never holds AI keys or talks to external AI providers directly.

Pipeline per scan:
  1. GitHub Core Stream  -> fetch last N commit diff deltas (public repos)
  2. For each commit (newest..oldest):
       a. Run 3 scanner agents IN PARALLEL on that commit's diff
       b. If the commit introduced findings -> send to isolated AI service
          (Gemini orchestrates, Claude validates) for a per-commit verdict
       c. Otherwise mark clean (no tokens spent)
  3. Aggregate into an analyst timeline + customer-alert report (downloadable PDF)
"""

import os
import asyncio
import traceback
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

load_dotenv()

from github_stream import fetch_commit_deltas, suggest_commit_window, GitHubStreamError
from evidence_store import store
from scanners import package_checker, secret_scanner, network_tracer, ioc_matcher
import ai_client
from report_generator import build_report

app = FastAPI(title="SecureChain", version="2.0")

REPORTS_DIR = Path("/app/reports")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


class ScanRequest(BaseModel):
    repo_url: str
    # None / "auto" -> SecureChain sizes the window from repo activity (no AI, no tokens).
    max_commits: int | None = None


async def run_pipeline(scan_id: str, repo_url: str, max_commits):
    def log(msg, kind="info"):
        store.log_event(scan_id, msg, kind)

    try:
        # ---- 0. Auto-size the commit window (deterministic, zero tokens) ----
        store.update(scan_id, status="streaming")
        if max_commits is None:
            log("Sizing the commit window from repository activity (no AI tokens used)...", "stream")
            sug = await suggest_commit_window(repo_url)
            max_commits = sug["window"]
            log(f"Auto-selected {max_commits} commits. {sug['reason']}", "stream")
        else:
            max_commits = max(1, min(int(max_commits), 20))
            log(f"Using analyst-specified window of {max_commits} commits.", "stream")

        # ---- 1. GitHub Core Stream ----
        log(f"GitHub Core Stream: fetching the last {max_commits} commit diff deltas from {repo_url}", "stream")
        deltas = await fetch_commit_deltas(repo_url, max_commits=max_commits)
        store.set_repo(scan_id, deltas)
        repo_name = deltas["repo"]
        log(f"Fetched {len(deltas['commits'])} commits from {repo_name}. Walking commits newest -> oldest.", "stream")

        # ---- 2. Per-commit delta analysis ----
        store.update(scan_id, status="scanning")
        a1 = "Agent 1 — Package & Name Checker"
        a2 = "Agent 2 — Scrambled Code & Secret Leak Scanner"
        a3 = "Agent 3 — Hacker Connection Tracer"

        flagged_total = 0
        for idx, commit in enumerate(deltas["commits"], 1):
            commit_ctx = {
                "repo": repo_name,
                "short_sha": commit["short_sha"],
                "sha": commit["sha"],
                "message": commit["message"],
                "author": commit["author"],
                "date": commit["date"],
                "url": commit.get("url", ""),
                "files": commit["files"],
            }

            # 2a. Deterministic scanners (parallel) on THIS commit's diff
            log(f"[{idx}/{len(deltas['commits'])}] Scanning commit {commit['short_sha']} — {commit['message'][:60]}", "agent")

            async def run_agent(fn):
                return await asyncio.to_thread(fn, {"repo": repo_name, "commits": [commit]})

            results = await asyncio.gather(
                run_agent(package_checker.scan),
                run_agent(secret_scanner.scan),
                run_agent(network_tracer.scan),
                run_agent(ioc_matcher.scan),
            )
            evidence = [f for r in results for f in r]
            ioc_hits = [f for f in evidence if f.get("ioc")]
            if ioc_hits:
                log(f"Commit {commit['short_sha']}: matched {len(ioc_hits)} known IOC indicator(s).", "evidence")

            commit_result = {
                "short_sha": commit["short_sha"],
                "sha": commit["sha"],
                "message": commit["message"],
                "author": commit["author"],
                "date": commit["date"],
                "url": commit.get("url", ""),
                "files_changed": len(commit["files"]),
                "evidence": evidence,
                "iocs": ioc_hits,
                "flagged": bool(evidence),
                "verdict": None,
            }

            if not evidence:
                # Clean commit — never sent to the AI. Zero tokens.
                log(f"Commit {commit['short_sha']}: clean (no new risk introduced). Skipped AI review — 0 tokens.", "evidence")
                store.add_commit_result(scan_id, commit_result)
                continue

            # 2b. Flagged commit — isolated AI consensus review
            flagged_total += 1
            log(f"Commit {commit['short_sha']}: {len(evidence)} finding(s) introduced. Sending to isolated AI consensus...", "evidence")
            store.update(scan_id, status="reviewing")
            try:
                verdict = await ai_client.review_commit(commit_ctx, evidence)
                commit_result["verdict"] = verdict
                if verdict.get("worth_alerting"):
                    log(f"Commit {commit['short_sha']}: consensus = {verdict.get('commit_risk','?').upper()} "
                        f"(worth alerting). {len(verdict.get('findings', []))} validated finding(s).", "claude")
                else:
                    log(f"Commit {commit['short_sha']}: consensus = noise / not worth alerting "
                        f"({len(verdict.get('false_positives_removed', []))} false positive(s) removed).", "gemini")
            except ai_client.AIClientError as e:
                commit_result["verdict"] = {"error": str(e), "worth_alerting": False, "findings": []}
                log(f"AI consensus error on commit {commit['short_sha']}: {e}", "error")

            store.add_commit_result(scan_id, commit_result)
            store.update(scan_id, status="scanning")

        # ---- 3. Done ----
        agg = store.aggregate(scan_id)
        s = store.get(scan_id)
        store.update(scan_id, status="complete")
        log(f"Scan complete. {flagged_total} commit(s) introduced risk; "
            f"{s['tokens_saved_commits']} clean commit(s) skipped AI review. "
            f"Overall: {agg['overall_risk'].upper()}.", "done")

    except GitHubStreamError as e:
        store.update(scan_id, status="error", error=str(e))
        log(f"GitHub Core Stream error: {e}", "error")
    except Exception as e:
        traceback.print_exc()
        store.update(scan_id, status="error", error=f"{type(e).__name__}: {e}")
        log(f"Pipeline error: {e}", "error")


# ----------------------------------------------------------------------------
# API
# ----------------------------------------------------------------------------
@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    if not req.repo_url.strip():
        raise HTTPException(400, "repo_url is required")
    scan_id = store.create_scan(req.repo_url.strip())
    # max_commits may be None -> the pipeline auto-sizes the window (no tokens).
    asyncio.create_task(run_pipeline(scan_id, req.repo_url.strip(), req.max_commits))
    return {"scan_id": scan_id}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    agg = store.aggregate(scan_id)
    return JSONResponse({
        "scan_id": scan_id,
        "status": scan["status"],
        "repo_url": scan["repo_url"],
        "repo": scan["repo"],
        "commits": scan["commits"],
        "events": scan["events"],
        "tokens_saved_commits": scan["tokens_saved_commits"],
        "counts": agg["counts"],
        "overall_risk": agg["overall_risk"],
        "findings": agg["findings"],
        "flagged_count": len(agg["flagged_commits"]),
        "iocs": agg["iocs"],
        "ioc_count": agg["ioc_count"],
        "error": scan["error"],
    })


@app.post("/api/scan/{scan_id}/report")
async def generate_report(scan_id: str):
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    if scan["status"] != "complete":
        raise HTTPException(400, "scan is not complete yet")
    path = REPORTS_DIR / f"{scan_id}.pdf"
    await asyncio.to_thread(build_report, str(path), scan, store.aggregate(scan_id))
    return {"download_url": f"/api/scan/{scan_id}/report/download"}


@app.get("/api/scan/{scan_id}/report/download")
async def download_report(scan_id: str):
    path = REPORTS_DIR / f"{scan_id}.pdf"
    if not path.exists():
        raise HTTPException(404, "report not generated yet")
    repo = (store.get(scan_id) or {}).get("repo") or {}
    name = (repo.get("repo", "report") or "report").replace("/", "_")
    return FileResponse(str(path), media_type="application/pdf", filename=f"SecureChain_{name}.pdf")


@app.get("/api/health")
async def health():
    ai = await ai_client.health()
    return {
        "status": "ok",
        "ai_service": ai.get("status"),
        "gemini_configured": ai.get("gemini_configured", False),
        "claude_configured": ai.get("claude_configured", False),
    }


if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
