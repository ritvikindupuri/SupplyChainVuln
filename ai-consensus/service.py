"""
Isolated AI Consensus Service
=============================
A minimal FastAPI service that exposes the Gemini->Claude consensus over an
INTERNAL Docker network only. The core server calls this; it is never exposed
to the host. This container is the only place the AI API keys live.
"""

import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

load_dotenv()

from consensus import review_commit, ConsensusError

app = FastAPI(title="SecureChain AI Consensus", version="1.0")


class ReviewRequest(BaseModel):
    commit: dict
    evidence: list


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "gemini_configured": bool(os.getenv("GEMINI_API_KEY")),
        "claude_configured": bool(os.getenv("ANTHROPIC_API_KEY")),
    }


@app.post("/review")
async def review(req: ReviewRequest):
    if not req.evidence:
        raise HTTPException(400, "no evidence supplied; clean commits should not be sent to the AI service")
    try:
        verdict = await review_commit(req.commit, req.evidence)
        return verdict
    except ConsensusError as e:
        raise HTTPException(502, f"consensus error: {e}")
    except Exception as e:
        raise HTTPException(500, f"AI service error: {type(e).__name__}: {e}")
