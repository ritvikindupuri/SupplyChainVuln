"""
GitHub Core Stream
==================
Connects to public GitHub repositories and fetches only the COMMIT DIFF DELTAS
(added / modified / staged lines) instead of the entire repository.

Per the architecture: "Instead of reading every single line of the repository
every time, it fetches only the commit diff deltas." This keeps scanning fast
and cost-effective.

Public repositories only — uses the unauthenticated GitHub REST API.
"""

import re
import httpx

GITHUB_API = "https://api.github.com"

# File extensions / names the scanners care about. We still send the full diff
# delta downstream, but this helps classify which files matter.
DEPENDENCY_FILES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml",
    "Gemfile", "Gemfile.lock", "go.mod", "go.sum", "composer.json", "composer.lock",
    "pom.xml", "build.gradle", "Cargo.toml", "Cargo.lock",
}


class GitHubStreamError(Exception):
    pass


def parse_repo_url(url: str):
    """Extract (owner, repo) from a GitHub URL or 'owner/repo' string."""
    url = url.strip()
    # Plain owner/repo
    m = re.match(r"^([\w.-]+)/([\w.-]+?)(?:\.git)?$", url)
    if m and "github.com" not in url:
        return m.group(1), m.group(2)
    # Full URL
    m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/.*)?$", url)
    if m:
        return m.group(1), m.group(2)
    raise GitHubStreamError(f"Could not parse GitHub repo from: {url}")


async def _get(client: httpx.AsyncClient, path: str, **kwargs):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "SecureChain-Scanner",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    resp = await client.get(f"{GITHUB_API}{path}", headers=headers, timeout=30, **kwargs)
    if resp.status_code == 404:
        raise GitHubStreamError("Repository not found or is private. SecureChain scans public repos only.")
    if resp.status_code == 403:
        raise GitHubStreamError("GitHub API rate limit reached. Wait a few minutes and try again.")
    if resp.status_code >= 400:
        raise GitHubStreamError(f"GitHub API error {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def _classify_file(filename: str) -> str:
    base = filename.rsplit("/", 1)[-1]
    if base in DEPENDENCY_FILES:
        return "dependency"
    if re.search(r"\.(env|pem|key|cfg|conf|yml|yaml|json|toml|ini)$", filename, re.I):
        return "config"
    if re.search(r"\.(js|ts|jsx|tsx|py|rb|go|java|php|sh|ps1|c|cpp|rs)$", filename, re.I):
        return "source"
    return "other"


def _extract_added_lines(patch: str):
    """From a unified diff patch, return only the added (+) lines."""
    if not patch:
        return []
    added = []
    for line in patch.split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    return added


async def suggest_commit_window(repo_url: str) -> dict:
    """
    Deterministically pick how many recent commits to scan, based on repo
    activity. No AI / no tokens — just one cheap metadata page (commit list
    without diffs).

    Heuristic:
      - Look at the timestamps of the last ~30 commits.
      - High recent activity (many commits in the last 7 days) -> tighter window
        of the freshest commits (the risk, if any, was just introduced).
      - Low activity -> a slightly larger window so the time coverage is useful.
      - Always clamped to [DEFAULT_MIN, DEFAULT_MAX] around a default of 8.
    """
    from datetime import datetime, timezone

    DEFAULT, MIN_W, MAX_W = 8, 3, 15
    owner, repo = parse_repo_url(repo_url)
    async with httpx.AsyncClient() as client:
        commits = await _get(
            client, f"/repos/{owner}/{repo}/commits", params={"per_page": 30}
        )

    if not commits:
        return {"window": MIN_W, "reason": "Repository has very few commits.", "recent_7d": 0}

    now = datetime.now(timezone.utc)
    recent_7d = 0
    for c in commits:
        ds = ((c.get("commit", {}) or {}).get("author", {}) or {}).get("date", "")
        if not ds:
            continue
        try:
            dt = datetime.fromisoformat(ds.replace("Z", "+00:00"))
            if (now - dt).days <= 7:
                recent_7d += 1
        except Exception:
            pass

    # Active repo: concentrate on the freshest commits (where new risk lands).
    # Quiet repo: widen a bit so the window spans more history.
    if recent_7d >= 20:
        window = 6
        reason = f"High activity ({recent_7d} commits in the last 7 days) -- focusing on the freshest changes."
    elif recent_7d >= 8:
        window = DEFAULT
        reason = f"Moderate activity ({recent_7d} commits in the last 7 days) -- standard window."
    elif recent_7d >= 1:
        window = 12
        reason = f"Low recent activity ({recent_7d} commits in the last 7 days) -- widening the window for useful coverage."
    else:
        window = 12
        reason = "No commits in the last 7 days -- widening the window to cover older recent changes."

    window = max(MIN_W, min(MAX_W, window))
    return {"window": window, "reason": reason, "recent_7d": recent_7d, "sampled": len(commits)}


async def fetch_commit_deltas(repo_url: str, max_commits: int = 5):
    """
    Fetch the most recent commit diff deltas from a public repo.

    Returns a dict:
    {
      "repo": "owner/repo",
      "default_branch": "main",
      "commits": [
        {
          "sha": "...", "message": "...", "author": "...", "date": "...",
          "files": [
            {
              "filename": "...", "status": "added|modified|removed",
              "category": "dependency|config|source|other",
              "additions": N, "deletions": N,
              "added_lines": ["line1", "line2", ...],
              "patch": "<unified diff>"
            }, ...
          ]
        }, ...
      ]
    }
    """
    owner, repo = parse_repo_url(repo_url)
    async with httpx.AsyncClient() as client:
        meta = await _get(client, f"/repos/{owner}/{repo}")
        default_branch = meta.get("default_branch", "main")

        commit_list = await _get(
            client, f"/repos/{owner}/{repo}/commits",
            params={"sha": default_branch, "per_page": max_commits},
        )

        commits = []
        for c in commit_list[:max_commits]:
            sha = c["sha"]
            detail = await _get(client, f"/repos/{owner}/{repo}/commits/{sha}")
            files = []
            for f in detail.get("files", []):
                filename = f.get("filename", "")
                patch = f.get("patch", "")
                files.append({
                    "filename": filename,
                    "status": f.get("status", ""),
                    "category": _classify_file(filename),
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                    "added_lines": _extract_added_lines(patch),
                    "patch": patch,
                })
            commit_info = detail.get("commit", {})
            commits.append({
                "sha": sha,
                "short_sha": sha[:8],
                "message": commit_info.get("message", "").split("\n")[0][:200],
                "author": (commit_info.get("author", {}) or {}).get("name", "unknown"),
                "date": (commit_info.get("author", {}) or {}).get("date", ""),
                "url": detail.get("html_url", ""),
                "files": files,
            })

        return {
            "repo": f"{owner}/{repo}",
            "owner": owner,
            "name": repo,
            "url": meta.get("html_url", ""),
            "description": meta.get("description", "") or "",
            "default_branch": default_branch,
            "stars": meta.get("stargazers_count", 0),
            "language": meta.get("language", "") or "Unknown",
            "commits": commits,
        }
