"""
Agent 1 — Package & Name Checker  (Pillar: IDENTITY — "Who is this package?")
============================================================================
Checks new/modified dependency & configuration files (package.json, lock files,
requirements.txt, etc.) for:
  - Typosquatting (names that look almost identical to popular libraries)
  - Dependency confusion (public packages shadowing private/internal names)
  - Suspicious install hooks / scripts
  - Non-registry sources (git URLs, http tarballs)

This is a deterministic, evidence-collecting scanner. It does NOT guess — it
produces concrete findings that the AI consensus layer later reviews.
"""

import re
import json

# A small registry of very popular packages used for typosquatting distance checks.
POPULAR_NPM = {
    "react", "react-dom", "lodash", "axios", "express", "chalk", "commander",
    "request", "moment", "vue", "webpack", "babel", "typescript", "jest",
    "eslint", "prettier", "next", "redux", "dotenv", "uuid", "debug", "async",
    "colors", "node-fetch", "cross-env", "rimraf", "yargs", "bluebird",
}
POPULAR_PYPI = {
    "requests", "numpy", "pandas", "flask", "django", "scipy", "pillow",
    "urllib3", "setuptools", "pytest", "click", "jinja2", "boto3", "certifi",
    "cryptography", "sqlalchemy", "pyyaml", "matplotlib", "beautifulsoup4",
    "selenium", "tensorflow", "torch", "fastapi", "pydantic", "colorama",
}

# Install-time script hooks that can run arbitrary code on install.
DANGEROUS_NPM_SCRIPTS = {"preinstall", "install", "postinstall", "prepare"}

# Patterns indicating a non-standard / risky dependency source.
NON_REGISTRY_SRC = re.compile(r"(git\+|https?://|file:|github:|git://|\.tar\.gz|ssh://)", re.I)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _typosquat_match(name: str, popular: set):
    """Return the popular package this name is suspiciously close to, or None."""
    name = name.lower()
    if name in popular:
        return None
    for p in popular:
        d = _levenshtein(name, p)
        # Close but not equal — and similar length (avoids matching short names).
        if 0 < d <= 2 and abs(len(name) - len(p)) <= 2 and len(name) >= 3:
            return p
    return None


def _finding(severity, title, detail, filename, evidence, package=None):
    return {
        "agent": "Agent 1 — Package & Name Checker",
        "pillar": "Identity",
        "severity": severity,
        "title": title,
        "detail": detail,
        "filename": filename,
        "evidence": evidence,
        "package": package,
    }


def _scan_package_json(content: str, filename: str):
    findings = []
    try:
        data = json.loads(content)
    except Exception:
        return findings

    # Install-script hooks
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        for hook in DANGEROUS_NPM_SCRIPTS:
            if hook in scripts:
                findings.append(_finding(
                    "high",
                    f"Install-time script hook '{hook}'",
                    f"The '{hook}' script runs automatically during installation and can execute arbitrary code. "
                    "Supply-chain attackers commonly abuse this to run payloads the moment a package is installed.",
                    filename,
                    f'"{hook}": "{scripts[hook]}"',
                ))

    # Dependency name + source checks
    for dep_key in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(dep_key, {})
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            squat = _typosquat_match(name, POPULAR_NPM)
            if squat:
                findings.append(_finding(
                    "high",
                    f"Possible typosquat: '{name}' resembles '{squat}'",
                    f"The dependency '{name}' is one or two characters away from the popular package '{squat}'. "
                    "This is a classic typosquatting pattern that tricks developers into installing malicious look-alikes.",
                    filename,
                    f'"{name}": "{version}"',
                    package=name,
                ))
            if isinstance(version, str) and NON_REGISTRY_SRC.search(version):
                findings.append(_finding(
                    "medium",
                    f"Non-registry dependency source for '{name}'",
                    f"'{name}' is installed from a non-standard source ({version}). "
                    "Pulling code directly from a URL or git ref bypasses registry integrity checks and "
                    "is a vector for dependency confusion / hijacking.",
                    filename,
                    f'"{name}": "{version}"',
                    package=name,
                ))
    return findings


def _scan_requirements(content: str, filename: str):
    findings = []
    for raw in content.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Direct URL / git installs
        if NON_REGISTRY_SRC.search(line):
            findings.append(_finding(
                "medium",
                "Non-registry Python dependency source",
                "A dependency is installed from a direct URL/git source, bypassing PyPI integrity checks. "
                "This is a known dependency-confusion / hijacking vector.",
                filename,
                line[:120],
            ))
            continue
        name = re.split(r"[=<>!~\[ ]", line)[0].strip().lower()
        squat = _typosquat_match(name, POPULAR_PYPI)
        if squat:
            findings.append(_finding(
                "high",
                f"Possible typosquat: '{name}' resembles '{squat}'",
                f"The dependency '{name}' is one or two characters away from the popular PyPI package '{squat}'. "
                "Typosquatting attacks rely on exactly this kind of near-miss name.",
                filename,
                line[:120],
                package=name,
            ))
    return findings


def scan(deltas: dict) -> list:
    """
    Scan all dependency/config files across all commits.
    `deltas` is the GitHub Core Stream output.
    Returns a list of evidence findings.
    """
    findings = []
    for commit in deltas.get("commits", []):
        for f in commit.get("files", []):
            if f.get("status") == "removed":
                continue
            filename = f.get("filename", "")
            base = filename.rsplit("/", 1)[-1]
            # Only inspect the ADDED lines (the diff delta) to stay diff-scoped,
            # but for structured files we need the full added content joined.
            added = "\n".join(f.get("added_lines", []))
            if not added:
                continue

            if base == "package.json":
                for fd in _scan_package_json(added, filename):
                    fd["commit"] = commit["short_sha"]
                    findings.append(fd)
            elif base in ("requirements.txt", "Pipfile") or base.endswith(".txt") and "require" in base:
                for fd in _scan_requirements(added, filename):
                    fd["commit"] = commit["short_sha"]
                    findings.append(fd)
            elif f.get("category") == "dependency":
                # Generic lockfile / manifest: run typosquat over token-like names.
                for fd in _scan_requirements(added, filename):
                    fd["commit"] = commit["short_sha"]
                    findings.append(fd)
    return findings
