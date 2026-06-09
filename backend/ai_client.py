"""
AI Consensus Client
==================
Thin HTTP client the core server uses to reach the ISOLATED ai-consensus
container over the internal Docker network. The core server itself never holds
AI keys and never talks to external AI providers directly.
"""

import os
import httpx

AI_SERVICE_URL = os.getenv("AI_SERVICE_URL", "http://ai-consensus:9100")


class AIClientError(Exception):
    pass


async def review_commit(commit: dict, evidence: list) -> dict:
    """Send ONE flagged commit's evidence to the isolated AI service for review."""
    try:
        async with httpx.AsyncClient(timeout=180) as client:
            resp = await client.post(
                f"{AI_SERVICE_URL}/review",
                json={"commit": commit, "evidence": evidence},
            )
        if resp.status_code >= 400:
            detail = resp.json().get("detail", resp.text) if resp.headers.get("content-type", "").startswith("application/json") else resp.text
            raise AIClientError(f"AI service {resp.status_code}: {detail}")
        return resp.json()
    except httpx.RequestError as e:
        raise AIClientError(f"could not reach AI consensus service: {e}")


async def health() -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{AI_SERVICE_URL}/health")
            return resp.json()
    except Exception:
        return {"status": "unreachable", "gemini_configured": False, "claude_configured": False}
