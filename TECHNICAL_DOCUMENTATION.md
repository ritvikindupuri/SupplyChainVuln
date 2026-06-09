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
     - **Agent 1 (Package & Name Checker):** Ingests and analyzes package dependencies to identify known vulnerable libraries or malicious typosquatting attempts.
     - **Agent 2 (Scrambled Code & Secret Leak):** Scans the code deltas for accidentally committed cryptographic keys, passwords, and deliberately obfuscated logic.
     - **Agent 3 (Hacker Connection Tracer):** Traces and evaluates network endpoints defined in the code to identify hardcoded, suspicious, or unverified outbound connections.

5. **Evidence Collection:**
   - All findings from the three prescan agents are aggregated into the **Evidence Store (SES)**.
   - The system categorizes these security findings and logs them as preliminary proof/evidence for further review.

6. **AI Consensus & Validation:**
   - The core service packages the preliminary evidence and forwards it across a highly restrictive, internal bridge network to the **ai-consensus service** (`http://ai-consensus:9100`).
   - Inside the consensus service, the *Consensus Validation Engine* initializes the secondary review.
   - **Model Consensus Peer Review:** The primary orchestrator, powered by **Google Gemini**, evaluates the findings and consults the Joint/Peer Validator, powered by **Anthropic Claude**. The models debate and validate the evidence until a consensus verdict on the true severity and nature of the vulnerability is reached.
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
