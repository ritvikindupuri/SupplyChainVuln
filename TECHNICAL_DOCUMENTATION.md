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

4. **Parallel Prescan Execution (Deterministic Python Agents):**
   - The security team consists of three specialized sub-agents working simultaneously. **Important Note:** These three prescan agents are *not* powered by LLMs (neither Gemini nor Claude). They are deterministic Python scripts that utilize regular expressions, entropy analysis, and curated IOC lists to ensure fast, low-cost, and rule-based initial detection.
     - **Agent 1 (Package & Name Checker):** Ingests and analyzes package dependencies to identify known vulnerable libraries or malicious typosquatting attempts.
     - **Agent 2 (Scrambled Code & Secret Leak):** Scans the code deltas for accidentally committed cryptographic keys, passwords, and deliberately obfuscated logic.
     - **Agent 3 (Hacker Connection Tracer):** Traces and evaluates network endpoints defined in the code to identify hardcoded, suspicious, or unverified outbound connections.

5. **Evidence Collection:**
   - All findings from the three prescan agents are aggregated into the **Evidence Store (SES)**.
   - The system categorizes these security findings and logs them as preliminary proof/evidence for further review.

6. **AI Consensus & Validation (Consensus Validation Engine):**
   - The core service packages the preliminary evidence and forwards it across a highly restrictive, internal bridge network to the **ai-consensus service**.
   - *Token-Efficient Design:* The core server only sends a commit digest to the AI service if the deterministic prescanners found concrete evidence. Clean commits never reach the AI, saving API tokens.
   - **Model Consensus Peer Review:** A dual-model approach is used to drastically reduce false positives:
     - **Google Gemini (Primary Orchestrator):** Gemini ingests the commit digest, evaluates the raw evidence, and produces an initial strict JSON verdict deciding if the commit is worth an analyst's attention.
     - **Anthropic Claude (Peer Validator):** Claude takes Gemini's initial verdict and cross-references it with the raw evidence. It is strictly prompted to remove or downgrade noise (e.g., test fixtures, documentation links, safe placeholder values), validate the truthfulness of IOC matches, and verify that the suggested remediations are safe.
   - *Security Note:* The ai-consensus service container is strictly isolated. It is the **only** component that holds the Gemini/Claude API keys. It does not use mock data; actual API keys are strictly required or the pipeline throws a `ConsensusError`. It exposes **no ports** to the host.

7. **Review and Reporting:**
   - The finalized verdict JSON details are streamed back to the **Analyst Workspace Portal** within the core service.
   - The portal features a D3.js topology and alerts dashboard, allowing the analyst to intuitively review the confirmed proof and evidence.
   - Finally, comprehensive reports are generated and persisted into a named volume (`report_storage -> /app/reports`) ensuring findings are durably saved.

---

## Detailed Features & Assessed Risks

SecureChain does not solely rely on AI for initial detection; instead, it uses a deterministic Indicator of Compromise (IOC) matching system. The parallel prescan agents evaluate specific, vetted security risks. *(Note again: Agents 1, 2, and 3 are standard Python evidence collectors. Gemini and Claude are strictly reserved for the Consensus Validation Engine).*

### 1. Package Checker (Agent 1)
- **Risk Assessed:** Malicious supply-chain campaigns, dependency confusion, and typosquatting.
- **Mechanism:** Scans new `package.json` and `requirements.txt` additions against a curated list of known malicious npm/PyPI packages (e.g., `crossenv`, `babelcli`, `shadow-deno`). It focuses on known indicators to keep false positives low.

### 2. Secret & Obfuscation Scanner (Agent 2)
- **Risk Assessed:** Hardcoded secrets, credential leaks, and intentionally obfuscated code.
- **Mechanism:** Utilizes regex and entropy-based scanning to detect AWS keys, GitHub tokens, generic API keys, and Base64 encoded payloads indicative of malicious payloads or accidental credential leaks.

### 3. Network Tracer (Agent 3)
- **Risk Assessed:** Unauthorized outbound connections, Command and Control (C2) communication, and data exfiltration.
- **Mechanism:** Traces hardcoded IPs, suspicious domains, and high-risk Top-Level Domains (TLDs) like `.top`, `.xyz`, or `.pw`. It also flags known abused free-hosting and paste sites (e.g., `pastebin.com`, `ngrok.io`).

---

## PDF Report Generation & API

Once the AI Consensus Engine finalizes a verdict, the system persists the data and allows for structured retrieval.

- **PDF Generation:** A dedicated `report_generator.py` utility transforms the finalized JSON consensus data into a formatted, downloadable PDF report using `fpdf2`. This ensures findings are easily distributable to stakeholders.
- **RESTful API:** The backend FastAPI server exposes several endpoints for integration and automation:
  - `POST /api/scan`: Initiates a new GitHub repository scan.
  - `GET /api/scan/{scan_id}`: Polls the current status of the scan (e.g., `running`, `completed`).
  - `POST /api/scan/{scan_id}/report`: Generates and retrieves the final JSON verdict report.
  - `GET /api/scan/{scan_id}/report/download`: Downloads the generated PDF summary report.
  - `GET /api/health`: Healthcheck endpoint for the core service.

---

## Container Hardening and Security Features

Given its role in security analysis, the SecureChain architecture strictly adheres to zero-trust container hardening practices. These measures apply equally to both the core and ai-consensus services:
- **Read-Only Root Filesystem:** Prevents malicious actors or compromised dependencies from altering the container's base file system.
- **Dropping All Capabilities (`cap_drop: ALL`):** Strips the containers of unnecessary Linux kernel privileges, minimizing the potential impact of a container breakout.
- **No New Privileges (`no-new-privileges:true`):** Prevents processes within the container from gaining additional privileges through `setuid` or `setgid` bits.
- **Ephemeral Storage:** Any required temporary file writing is directed to `/tmp`, which is securely mounted as an in-memory `tmpfs`.
- **Restart Policy:** Defined as `unless-stopped` to maintain high availability and self-healing for the pipeline.
