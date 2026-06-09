"""
IOC Matcher  (Pillar: INDICATORS — "Does this commit match a known bad indicator?")
==================================================================================
Checks each commit's added lines against curated Indicator-of-Compromise lists:
  - Known-malicious npm / PyPI package names (documented campaigns)
  - Known C2 / exfiltration / anonymous-hosting infrastructure
  - High-risk / abused TLDs
  - Download-and-execute / reverse-shell command patterns

Every match is emitted as an evidence finding tagged with ioc=True so the
dashboard and report can present a dedicated "Indicators of Compromise" view.

Deterministic and offline (no tokens). The AI consensus later validates whether
each IOC is a genuine compromise indicator in context.
"""

import re

from .ioc_indicators import (
    MALICIOUS_NPM_PACKAGES, MALICIOUS_PYPI_PACKAGES, C2_EXFIL_HOSTS,
    SUSPICIOUS_TLDS, MALICIOUS_PATTERNS,
)

URL_RE = re.compile(r"https?://[^\s'\"<>)]+", re.I)
_COMPILED_PATTERNS = [(name, re.compile(rx)) for name, rx in MALICIOUS_PATTERNS]
# Match dependency-style name tokens: "name": ... / name==ver / name>=ver
NAME_TOKEN_RE = re.compile(r"""['"]?([A-Za-z0-9._-]{2,})['"]?\s*(?::|==|>=|<=|~=|@|\s)""")


def _finding(severity, ioc_type, title, detail, filename, evidence, indicator):
    return {
        "agent": "IOC Matcher",
        "pillar": "Indicators",
        "ioc": True,
        "ioc_type": ioc_type,        # malicious_package | c2_exfil_host | suspicious_tld | malicious_pattern
        "indicator": indicator,      # the concrete matched indicator value
        "severity": severity,
        "title": title,
        "detail": detail,
        "filename": filename,
        "evidence": (evidence[:160] + "...") if len(evidence) > 160 else evidence,
    }


def _host_of(url: str) -> str:
    m = re.search(r"https?://([^/:\s'\"]+)", url, re.I)
    return m.group(1).lower() if m else ""


def scan(deltas: dict) -> list:
    findings = []
    for commit in deltas.get("commits", []):
        for f in commit.get("files", []):
            if f.get("status") == "removed":
                continue
            filename = f.get("filename", "")
            base = filename.rsplit("/", 1)[-1].lower()
            is_npm = base in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml")
            is_pypi = base in ("requirements.txt", "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml")

            for line in f.get("added_lines", []):
                s = line.strip()
                if not s:
                    continue
                low = s.lower()

                # 1. Known-malicious package names (only in dependency files)
                if is_npm or is_pypi:
                    pkgset = MALICIOUS_NPM_PACKAGES if is_npm else MALICIOUS_PYPI_PACKAGES
                    eco = "npm" if is_npm else "PyPI"
                    for m in NAME_TOKEN_RE.finditer(s):
                        token = m.group(1).lower()
                        if token in pkgset:
                            fd = _finding(
                                "critical", "malicious_package",
                                f"Known-malicious {eco} package: {token}",
                                f"'{token}' matches a documented malicious {eco} supply-chain campaign. "
                                "Its presence in a dependency file is a strong compromise indicator.",
                                filename, s, token,
                            )
                            fd["commit"] = commit["short_sha"]
                            findings.append(fd)

                # 2. C2 / exfil / anonymous-hosting infrastructure
                for host in C2_EXFIL_HOSTS:
                    if host in low:
                        fd = _finding(
                            "high", "c2_exfil_host",
                            f"Known C2 / exfil infrastructure: {host}",
                            f"The commit references '{host}', infrastructure commonly used for command-and-control, "
                            "data exfiltration, or anonymous payload hosting.",
                            filename, s, host,
                        )
                        fd["commit"] = commit["short_sha"]
                        findings.append(fd)
                        break  # one host hit per line is enough

                # 3. Suspicious TLD in a URL
                for url in URL_RE.findall(line):
                    host = _host_of(url)
                    for tld in SUSPICIOUS_TLDS:
                        if host.endswith(tld):
                            fd = _finding(
                                "medium", "suspicious_tld",
                                f"URL on high-risk TLD ({tld})",
                                f"Outbound URL '{url}' uses '{tld}', a free/abused TLD heavily associated with "
                                "malware C2 and phishing infrastructure.",
                                filename, url, host,
                            )
                            fd["commit"] = commit["short_sha"]
                            findings.append(fd)
                            break

                # 4. Download-and-execute / reverse-shell command patterns
                for name, pat in _COMPILED_PATTERNS:
                    if pat.search(line):
                        fd = _finding(
                            "critical", "malicious_pattern",
                            f"Malicious execution pattern: {name}",
                            "This line matches a known download-and-execute or reverse-shell pattern -- a direct "
                            "indicator of compromise / malicious staging code.",
                            filename, s, name,
                        )
                        fd["commit"] = commit["short_sha"]
                        findings.append(fd)
    return findings
