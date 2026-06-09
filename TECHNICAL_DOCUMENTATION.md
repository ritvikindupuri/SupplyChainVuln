# SecureChain Multi-Agent Security Pipeline: Technical Documentation

**Author:** Ritvik Indupuri
**Date:** June 09, 2026

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [System Architecture](#system-architecture)
3. [Architecture Diagram](#architecture-diagram)
4. [Detailed Flow-by-Flow Explanation](#detailed-flow-by-flow-explanation)
5. [Container Hardening and Security Features](#container-hardening-and-security-features)

---

## Executive Summary

The SecureChain Multi-Agent Security Pipeline is a robust, containerized application designed to continuously monitor and analyze target GitHub repositories for security vulnerabilities. Utilizing a parallel prescan security team and an AI-driven consensus validation engine, SecureChain identifies potential threats such as dependency issues, secret leaks, obfuscated code, and unauthorized network endpoints. The system emphasizes deep analysis and cross-validation between multiple AI models (Google Gemini and Anthropic Claude) to ensure high-fidelity security findings while maintaining strict security isolation within its deployment environment.

---

## System Architecture

The architecture of the SecureChain pipeline relies on a secure, multi-container Docker Compose deployment featuring two isolated but synergistic services: the **core service** (SecureChain-core) and the **ai-consensus service** (SecureChain-ai). This split-service model ensures that external-facing components are separated from highly sensitive, AI-processing components.

### Architecture Diagram

<div align="center">
  <img src="https://i.imgur.com/aUcKuaZ.png" alt="SecureChain System Architecture">
  <br>
  <em>Figure 1: SecureChain Multi-Agent Security Pipeline Architecture</em>
</div>

---

## Detailed Flow-by-Flow Explanation

The operational flow of the SecureChain application is carefully orchestrated to process code changes, detect vulnerabilities, and validate findings through AI consensus. The step-by-step breakdown is as follows:

1. **Analyst Access & Setup:**
   - An Analyst (or end user) interfaces with the system via a web browser.
   - Access is facilitated through **Port 8000**, which is exposed from the core service to the host machine.
   - Static assets for the frontend are mounted as a read-only bind mount (`./frontend -> /frontend (ro)`).

2. **Fetching Repository Diffs:**
   - Within the **core service**, the *GitHub Core Stream* actively monitors target repositories.
   - It fetches commit diff deltas (the exact changes made to the codebase) and pushes them to the backend for processing.

3. **Dispatching Parallel Scans:**
   - The *Core Express Server* acts as a Git Diff Delta Compiler.
   - Upon receiving a new diff, the compiler immediately dispatches parallel analysis tasks to the *Parallel Prescan Security Team*.

4. **Parallel Prescan Execution:**
   - The security team consists of three specialized sub-agents working simultaneously:
     - **Agent 1 (Package & Name Checker) [Pillar: Identity]:** Ingests and analyzes package dependencies and configuration files (e.g., `package.json`, `requirements.txt`).
       - *Features Assessed:*
         - **Typosquatting Detection:** Calculates Levenshtein distance against registries of popular packages (e.g., React, Lodash, Requests, Django) to flag malicious look-alikes.
         - **Dependency Confusion / Non-Registry Sources:** Flags packages pulled from non-standard or direct URLs (e.g., `git+`, `http tarballs`) rather than verified registries.
         - **Suspicious Install Hooks:** Detects dangerous install-time scripts (e.g., `preinstall`, `postinstall`, `prepare` in npm) commonly abused to execute arbitrary code.
     - **Agent 2 (Scrambled Code & Secret Leak Scanner) [Pillar: Integrity]:** Scans code deltas for intentionally obscured logic or accidentally committed credentials.
       - *Features Assessed:*
         - **Exposed Secrets:** Detects AWS Access/Secret Keys, GitHub Personal/OAuth/App Tokens, Slack Tokens, Google API Keys, Stripe Keys, OpenAI/Anthropic Keys, Private Key Blocks, JWT Tokens, and Database Connection URIs.
         - **Code Obfuscation:** Flags scrambled payloads designed to hide intent, including base64 `eval(atob(...))`, encoded buffers, hex/unicode-escaped string blobs, high-entropy base64 blobs, and `child_process`/`os.system` executions.
     - **Agent 3 (Hacker Connection Tracer) [Pillar: Network]:** Traces code execution pathways to identify where the application is sending data.
       - *Features Assessed:*
         - **Suspicious Outbound Endpoints:** Flags hardcoded references to domains frequently abused for C2 or exfiltration (e.g., `pastebin`, `ngrok`, `discord webhooks`, `telegram API`, `requestbin`).
         - **Hardcoded External IPs:** Identifies raw, public IP addresses integrated into network calls or socket connections.
         - **Raw Sockets/WebSockets:** Detects direct, lower-level socket connections that might bypass standard HTTP monitoring.
         - **Data Exfiltration Combinations:** Flags critical lines of code that simultaneously read sensitive data (e.g., `process.env`, `id_rsa`) and make an outbound network call (`requests.post`, `fetch`).
     - **IOC Matcher [Pillar: Indicators]:** Operates deterministically to match code against curated Lists of Indicators of Compromise.
       - *Features Assessed:*
         - **Malicious Packages:** Cross-references dependencies against documented malicious npm/PyPI supply-chain campaigns (e.g., `crossenv`, `colourama`).
         - **C2/Exfil Infrastructure:** Flags immediate matches for known anonymous-hosting or command-and-control infrastructure.
         - **Suspicious TLDs:** Identifies outbound URLs utilizing high-risk top-level domains (e.g., `.tk`, `.xyz`, `.top`).
         - **Malicious Patterns:** Detects known download-and-execute or reverse-shell command patterns (e.g., `curl-pipe-shell`, `powershell-download`, `nc -e`).

5. **Evidence Collection:**
   - All findings from the three prescan agents are aggregated into the **Evidence Store (SES)**.
   - The system categorizes these security findings and logs them as preliminary proof/evidence for further review.

6. **AI Consensus & Validation (Detailed Engine Workflow):**
   - The core service packages the preliminary evidence and forwards it across a highly restrictive, internal bridge network to the **ai-consensus service** (`http://ai-consensus:9100`).
   - This architecture is highly token-efficient: the core server only routes a commit to the AI service if the deterministic agents and IOC Matcher previously flagged risk within the diff. Clean commits are bypassed entirely.
   - Inside the consensus service, the *Consensus Validation Engine* initializes the secondary, per-commit review.
   - **Dual-Model Consensus Dynamics:**
     - **Primary Orchestrator (Google Gemini):** Gemini takes the raw evidence and the commit digest. It assesses the findings (including verifying whether IOC matches are genuine indicators or benign occurrences like test fixtures/allowlists) and returns an initial JSON verdict structure defining the overarching commit risk, a summary, and specific remediations.
     - **Peer Validator (Anthropic Claude):** Claude subsequently acts as a strict secondary reviewer. It takes both the original raw evidence and Gemini's initial verdict as input. Claude validates each finding, actively downgrading or removing false positives (such as placeholder values or documentation links), confirms the true nature of IOCs, and finalizes the JSON verdict. This ensures a high-confidence alert meant directly for a security analyst.
   - *Security Note:* The ai-consensus service container is strictly isolated. It contains the highly sensitive API keys required for AI communication and exposes **no ports** to the host.

7. **Review and Reporting:**
   - The finalized verdict JSON details are streamed back to the **Analyst Workspace Portal** within the core service.
   - The portal features a D3.js topology and alerts dashboard, allowing the analyst to intuitively review the confirmed proof and evidence.
   - Finally, comprehensive reports are generated and persisted into a named volume (`report_storage -> /app/reports`) ensuring findings are durably saved.

---

## Container Hardening and Security Features

Given its role in security analysis, the SecureChain architecture strictly adheres to zero-trust container hardening practices. These measures apply equally to both the core and ai-consensus services:
- **Read-Only Root Filesystem:** Prevents malicious actors or compromised dependencies from altering the container's base file system.
- **Dropping All Capabilities (`cap_drop: ALL`):** Strips the containers of unnecessary Linux kernel privileges, minimizing the potential impact of a container breakout.
- **No New Privileges (`no-new-privileges:true`):** Prevents processes within the container from gaining additional privileges through `setuid` or `setgid` bits.
- **Ephemeral Storage:** Any required temporary file writing is directed to `/tmp`, which is securely mounted as an in-memory `tmpfs`.
- **Restart Policy:** Defined as `unless-stopped` to maintain high availability and self-healing for the pipeline.
