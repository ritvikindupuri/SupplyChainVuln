"""
Agent 3 — Hacker Connection Tracer  (Pillar: NETWORK — "Where is the code sending data?")
========================================================================================
Checks new / modified code for where it tries to send data:
  - Suspicious outbound URLs / hardcoded IPs
  - Raw socket connections to external hosts
  - Rogue API endpoints / webhooks (pastebin, discord, telegram, ngrok, etc.)
  - Data exfiltration patterns (read file -> POST to external host)

Deterministic evidence collector. Only inspects diff deltas (added lines).
"""

import re

# Hosts/services commonly abused for exfiltration or C2.
SUSPICIOUS_HOSTS = [
    "pastebin.com", "hastebin.com", "ngrok.io", "ngrok-free.app", "discord.com/api/webhooks",
    "discordapp.com/api/webhooks", "api.telegram.org", "transfer.sh", "0x0.st",
    "requestbin", "webhook.site", "burpcollaborator", "interactsh", "oast.fun",
    "anonfiles.com", "file.io", "termbin.com", "glot.io",
]

URL_RE = re.compile(r"https?://[^\s'\"<>)]+", re.I)
IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
SOCKET_RE = re.compile(r"(socket\.(connect|create_connection)|net\.connect|new\s+WebSocket|net\.Socket)", re.I)
EXFIL_HINT_RE = re.compile(r"(?i)(process\.env|os\.environ|readFileSync|open\(['\"].*(\.env|id_rsa|passwd)|child_process|require\(['\"]os)")
OUTBOUND_CALL_RE = re.compile(r"(?i)(requests\.(post|get|put)|fetch\(|axios\.|http\.request|urllib|XMLHttpRequest|curl\s|wget\s)")

# Well-known benign hosts to reduce noise.
BENIGN_HOSTS = {
    "github.com", "raw.githubusercontent.com", "registry.npmjs.org", "pypi.org",
    "files.pythonhosted.org", "googleapis.com", "schema.org", "www.w3.org",
    "localhost", "127.0.0.1", "example.com", "npmjs.com", "nodejs.org",
}

PRIVATE_IP_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.2", "172.30.", "172.31.", "127.", "0.")


def _host_of(url: str) -> str:
    m = re.search(r"https?://([^/:\s'\"]+)", url, re.I)
    return m.group(1).lower() if m else ""


def _finding(severity, title, detail, filename, evidence, endpoint=None):
    return {
        "agent": "Agent 3 — Hacker Connection Tracer",
        "pillar": "Network",
        "severity": severity,
        "title": title,
        "detail": detail,
        "filename": filename,
        "evidence": (evidence[:160] + "...") if len(evidence) > 160 else evidence,
        "endpoint": endpoint,
    }


def scan(deltas: dict) -> list:
    findings = []
    for commit in deltas.get("commits", []):
        for f in commit.get("files", []):
            if f.get("status") == "removed":
                continue
            filename = f.get("filename", "")
            if f.get("category") not in ("source", "config", "other"):
                # Still scan dependency files for embedded URLs, but lower priority.
                pass
            for line in f.get("added_lines", []):
                s = line.strip()
                if not s:
                    continue

                # Suspicious outbound URLs
                for url in URL_RE.findall(line):
                    host = _host_of(url)
                    matched = next((h for h in SUSPICIOUS_HOSTS if h in url.lower()), None)
                    if matched:
                        fd = _finding(
                            "high", f"Suspicious outbound endpoint ({matched})",
                            f"Code references '{matched}', a service frequently abused for data exfiltration, "
                            "command-and-control, or anonymous payload hosting.",
                            filename, url, endpoint=url,
                        )
                        fd["commit"] = commit["short_sha"]
                        findings.append(fd)

                # Hardcoded public IP address in a URL or connection
                for m in IP_RE.finditer(line):
                    ip = m.group(0)
                    if not ip.startswith(PRIVATE_IP_PREFIXES) and not ip.endswith(".0") and ip != "0.0.0.0":
                        # Only flag if it looks network-related
                        if OUTBOUND_CALL_RE.search(line) or SOCKET_RE.search(line) or "http" in line.lower():
                            fd = _finding(
                                "medium", f"Hardcoded external IP address ({ip})",
                                f"A hardcoded public IP ({ip}) appears in network code. Hardcoded IPs are "
                                "common in malware C2 configuration and bypass DNS-based monitoring.",
                                filename, s, endpoint=ip,
                            )
                            fd["commit"] = commit["short_sha"]
                            findings.append(fd)

                # Raw socket connections
                if SOCKET_RE.search(line):
                    fd = _finding(
                        "medium", "Raw socket / WebSocket connection",
                        "Direct socket connections can establish covert channels that bypass HTTP-layer "
                        "monitoring. Combined with environment access this is a classic exfiltration pattern.",
                        filename, s,
                    )
                    fd["commit"] = commit["short_sha"]
                    findings.append(fd)

                # Exfiltration combo: reads secrets/env AND makes an outbound call on same line
                if EXFIL_HINT_RE.search(line) and OUTBOUND_CALL_RE.search(line):
                    fd = _finding(
                        "critical", "Potential data exfiltration pattern",
                        "This line reads sensitive data (environment variables, key files, or process info) "
                        "AND issues an outbound network call — a direct indicator of data exfiltration.",
                        filename, s,
                    )
                    fd["commit"] = commit["short_sha"]
                    findings.append(fd)
    return findings
