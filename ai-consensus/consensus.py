"""
Consensus Validation Engine  (ISOLATED AI SERVICE)
==================================================
Runs in its own container. It is the ONLY component that holds the Gemini /
Claude API keys and talks to external AI providers.

Per-commit, token-efficient design:
  - The core server only sends a commit to this service if deterministic
    scanners already flagged risk in that commit's diff (clean commits never
    reach the AI -> zero tokens).
  - Each request carries ONE small commit's evidence, so prompts stay tiny.

Two models reach consensus:
  - Google Gemini  : primary orchestrator (organizes evidence, initial verdict)
  - Anthropic Claude: peer validator (filters false positives, validates fixes)

No mock data: if a key/model is unavailable it raises a real error.
"""

import os
import json
import asyncio

import anthropic
from google import genai

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")


class ConsensusError(Exception):
    pass


def _commit_digest(commit: dict, evidence: list) -> str:
    lines = [
        f"COMMIT: {commit.get('short_sha')} -- {commit.get('message','')}",
        f"Author: {commit.get('author','')}  Date: {commit.get('date','')}",
        f"Repository: {commit.get('repo','')}",
        "",
        f"This single commit introduced {len(evidence)} scanner finding(s):",
        "",
    ]
    for i, f in enumerate(evidence, 1):
        ioc_tag = ""
        if f.get("ioc"):
            ioc_tag = f"\n     IOC MATCH: type={f.get('ioc_type','')} indicator={f.get('indicator','')}"
        lines.append(
            f"[{i}] ({f.get('severity','').upper()}) {f.get('agent','')} | pillar={f.get('pillar','')}\n"
            f"     title: {f.get('title','')}\n"
            f"     file: {f.get('filename','')}\n"
            f"     evidence: {f.get('evidence','')}\n"
            f"     detail: {f.get('detail','')}{ioc_tag}"
        )
    ioc_count = sum(1 for f in evidence if f.get("ioc"))
    if ioc_count:
        lines.append(f"\nNOTE: {ioc_count} of these finding(s) matched a curated Indicator-of-Compromise (IOC) list.")
    return "\n".join(lines)


GEMINI_PROMPT = """You are Google Gemini, the PRIMARY ORCHESTRATOR in SecureChain, a software supply-chain recon tool used by security analysts.

A single GitHub commit was flagged by deterministic scanners because its diff introduced potential supply-chain risk. The scanners cover:
- Identity (Agent 1): typosquatting, dependency confusion, install hooks
- Integrity (Agent 2): exposed secrets, obfuscated/scrambled code
- Network (Agent 3): suspicious endpoints, sockets, data exfiltration
- Indicators (IOC Matcher): matches against curated lists of known-malicious packages, C2/exfil hosts, high-risk TLDs, and download-execute patterns

Some findings may be tagged "IOC MATCH" -- these matched a curated indicator list. For each IOC, judge whether it is a GENUINE indicator of compromise in this commit's context, or a benign coincidence (e.g. a docs link, a test fixture, a security tool's own allowlist).

Review ONLY the documented evidence for THIS commit. Do not invent findings. Decide whether this commit is genuinely worth an analyst's attention.

Return STRICT JSON (no markdown/code fences):
{
  "commit_risk": "critical|high|medium|low|noise",
  "worth_alerting": true|false,
  "summary": "1-3 sentences: what this commit introduced and why it matters (or why it is noise)",
  "ioc_assessment": "1-2 sentences assessing any IOC matches in context (or 'no IOCs matched')",
  "findings": [
    {
      "title": "short title",
      "severity": "critical|high|medium|low",
      "category": "Identity|Integrity|Network|Indicators",
      "is_ioc": true|false,
      "explanation": "what was introduced and why it is a supply-chain risk",
      "remediation": "specific safe fix",
      "confidence": 0.0-1.0
    }
  ]
}

EVIDENCE FOR THIS COMMIT:
"""

CLAUDE_PROMPT = """You are Anthropic Claude, the PEER VALIDATOR in SecureChain.

Gemini reviewed a single flagged commit and produced an initial verdict. Peer-review it against the raw scanner evidence:
1. Confirm each finding is genuinely supported by the evidence for THIS commit.
2. Remove/downgrade false positives or noise (test fixtures, examples, placeholder values).
3. For findings tagged as IOC matches, validate whether they are GENUINE indicators of compromise in context, or benign (a docs link, an allowlist, a security tool's own test data). Set is_ioc accordingly.
4. Decide if this commit is truly worth alerting a customer about.
5. Verify remediations are safe.

Be strict and objective. An analyst will act on your output, so do not over-alert.

Return STRICT JSON (no markdown/code fences):
{
  "commit_risk": "critical|high|medium|low|noise",
  "worth_alerting": true|false,
  "summary": "final 1-3 sentence analyst-facing summary for this commit",
  "ioc_assessment": "1-2 sentences validating any IOC matches in context (or 'no IOCs matched')",
  "validated_findings": [
    {
      "title": "short title",
      "severity": "critical|high|medium|low",
      "category": "Identity|Integrity|Network|Indicators",
      "is_ioc": true|false,
      "ioc_type": "malicious_package|c2_exfil_host|suspicious_tld|malicious_pattern|null",
      "indicator": "the concrete indicator value, or null",
      "filename": "file involved",
      "evidence": "concrete evidence snippet",
      "explanation": "validated explanation",
      "remediation": "validated safe remediation",
      "confidence": 0.0-1.0,
      "validator_note": "what you confirmed/adjusted"
    }
  ],
  "false_positives_removed": [{"title": "...", "reason": "..."}]
}

RAW SCANNER EVIDENCE FOR THIS COMMIT:
{evidence}

GEMINI'S INITIAL VERDICT:
{gemini}
"""


def _extract_json(text: str) -> dict:
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip("` \n")
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ConsensusError(f"Model did not return JSON. Got: {text[:200]}")
    return json.loads(text[start:end + 1])


async def _run_gemini(evidence_text: str) -> dict:
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        raise ConsensusError("GEMINI_API_KEY is not configured in the AI service.")
    client = genai.Client(api_key=api_key)

    def _call():
        resp = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=GEMINI_PROMPT + evidence_text,
        )
        return resp.text

    return _extract_json(await asyncio.to_thread(_call))


async def _run_claude(evidence_text: str, gemini_verdict: dict) -> dict:
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ConsensusError("ANTHROPIC_API_KEY is not configured in the AI service.")
    client = anthropic.Anthropic(api_key=api_key)
    prompt = CLAUDE_PROMPT.replace("{evidence}", evidence_text).replace(
        "{gemini}", json.dumps(gemini_verdict, indent=2)
    )

    def _call():
        resp = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")

    return _extract_json(await asyncio.to_thread(_call))


async def review_commit(commit: dict, evidence: list) -> dict:
    """
    Run Gemini -> Claude consensus on ONE flagged commit's evidence.
    Returns the validated per-commit verdict.
    """
    evidence_text = _commit_digest(commit, evidence)
    gemini_verdict = await _run_gemini(evidence_text)
    claude_verdict = await _run_claude(evidence_text, gemini_verdict)

    return {
        "commit_risk": claude_verdict.get("commit_risk", gemini_verdict.get("commit_risk", "low")),
        "worth_alerting": bool(claude_verdict.get("worth_alerting",
                               gemini_verdict.get("worth_alerting", True))),
        "summary": claude_verdict.get("summary", gemini_verdict.get("summary", "")),
        "ioc_assessment": claude_verdict.get("ioc_assessment", gemini_verdict.get("ioc_assessment", "")),
        "findings": claude_verdict.get("validated_findings", []),
        "false_positives_removed": claude_verdict.get("false_positives_removed", []),
        "gemini_verdict": gemini_verdict,
        "models": {"orchestrator": GEMINI_MODEL, "validator": CLAUDE_MODEL},
    }
