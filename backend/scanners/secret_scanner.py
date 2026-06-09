"""
Agent 2 — Scrambled Code & Secret Leak Scanner  (Pillar: INTEGRITY — "What is inside the code?")
==============================================================================================
Checks newly added / modified code for:
  - Exposed secrets: API keys, tokens, cloud credentials, private keys, passwords
  - Obfuscation / scrambled code designed to hide its true purpose
    (huge base64 blobs, hex-encoded strings, eval(atob(...)), \\x escapes, etc.)

Deterministic evidence collector. Only inspects the diff deltas (added lines).
"""

import re
import math

# (name, severity, compiled regex) — high-signal secret patterns.
SECRET_PATTERNS = [
    ("AWS Access Key ID", "critical", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Access Key", "critical", re.compile(r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("GitHub Personal Access Token", "critical", re.compile(r"ghp_[0-9A-Za-z]{36}")),
    ("GitHub OAuth Token", "critical", re.compile(r"gho_[0-9A-Za-z]{36}")),
    ("GitHub App Token", "high", re.compile(r"(ghu|ghs)_[0-9A-Za-z]{36}")),
    ("Slack Token", "high", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("Google API Key", "high", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Stripe Secret Key", "critical", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Restricted Key", "high", re.compile(r"rk_live_[0-9a-zA-Z]{24,}")),
    ("OpenAI API Key", "critical", re.compile(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}")),
    ("Anthropic API Key", "critical", re.compile(r"sk-ant-[0-9A-Za-z\-_]{20,}")),
    ("Private Key Block", "critical", re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----")),
    ("Generic API Key Assignment", "medium", re.compile(r"(?i)(api[_-]?key|apikey|secret|token|passwd|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("JWT Token", "medium", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Slack Webhook", "high", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    ("Database Connection URI", "high", re.compile(r"(?i)(mongodb|postgres|postgresql|mysql|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+")),
]

# Obfuscation indicators.
OBFUSCATION_PATTERNS = [
    ("eval(atob(...)) — base64 eval", "critical", re.compile(r"eval\s*\(\s*atob\s*\(")),
    ("eval(Buffer.from(...)) — encoded eval", "critical", re.compile(r"eval\s*\(\s*Buffer\.from\s*\(")),
    ("Function constructor with decode", "high", re.compile(r"new\s+Function\s*\(\s*atob")),
    ("Python exec(base64 decode)", "critical", re.compile(r"exec\s*\(\s*(base64|__import__\(['\"]base64)")),
    ("Hex-escaped string blob", "medium", re.compile(r"(\\x[0-9a-fA-F]{2}){12,}")),
    ("Unicode-escaped string blob", "medium", re.compile(r"(\\u[0-9a-fA-F]{4}){10,}")),
    ("child_process exec", "high", re.compile(r"child_process|require\(['\"]child_process['\"]\)")),
    ("Python os.system / subprocess shell", "medium", re.compile(r"os\.system\(|subprocess\.(call|Popen|run)\(.*shell\s*=\s*True")),
]

LONG_B64 = re.compile(r"['\"][A-Za-z0-9+/]{120,}={0,2}['\"]")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _finding(severity, title, detail, filename, evidence, kind):
    return {
        "agent": "Agent 2 — Scrambled Code & Secret Leak Scanner",
        "pillar": "Integrity",
        "severity": severity,
        "title": title,
        "detail": detail,
        "filename": filename,
        "evidence": (evidence[:160] + "...") if len(evidence) > 160 else evidence,
        "kind": kind,
    }


def scan(deltas: dict) -> list:
    findings = []
    for commit in deltas.get("commits", []):
        for f in commit.get("files", []):
            if f.get("status") == "removed":
                continue
            filename = f.get("filename", "")
            for line in f.get("added_lines", []):
                if not line.strip():
                    continue

                # Secret detection
                for name, sev, pat in SECRET_PATTERNS:
                    if pat.search(line):
                        fd = _finding(
                            sev, f"Exposed secret: {name}",
                            f"A {name} was committed into the repository. Once a secret is in git history, "
                            "it must be treated as compromised — attackers scrape public repos for exactly these.",
                            filename, line.strip(), "secret",
                        )
                        fd["commit"] = commit["short_sha"]
                        findings.append(fd)

                # Obfuscation detection
                for name, sev, pat in OBFUSCATION_PATTERNS:
                    if pat.search(line):
                        fd = _finding(
                            sev, f"Obfuscated / scrambled code: {name}",
                            "Code that decodes-then-executes hidden payloads (or escapes large encoded blobs) "
                            "is a hallmark of supply-chain malware trying to hide its true behavior.",
                            filename, line.strip(), "obfuscation",
                        )
                        fd["commit"] = commit["short_sha"]
                        findings.append(fd)

                # High-entropy base64 blob
                for m in LONG_B64.finditer(line):
                    blob = m.group(0)
                    if _shannon_entropy(blob) > 4.5:
                        fd = _finding(
                            "medium", "High-entropy encoded blob",
                            "A long, high-entropy base64-like string was added. These blobs frequently hide "
                            "encoded payloads, exfiltrated data, or embedded credentials.",
                            filename, blob, "obfuscation",
                        )
                        fd["commit"] = commit["short_sha"]
                        findings.append(fd)
    return findings
