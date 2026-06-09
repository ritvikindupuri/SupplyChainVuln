# SecureChain - Software Supply-Chain Recon

SecureChain is an automated security analysis tool that proactively scans target GitHub repositories for supply chain vulnerabilities. By continuously analyzing commit diffs, it acts as a robust early-warning system capable of identifying malicious packages, hardcoded secrets, obfuscated code, and suspicious network endpoints before they are deployed.

> 📖 **For a comprehensive look at the system design, container hardening, and agent orchestration, please read our [Technical Documentation](TECHNICAL_DOCUMENTATION.md).**

## System Architecture

<div align="center">
  <img src="https://i.imgur.com/7QTasX3.png" alt="SecureChain Architecture Diagram">
  <br>
  <br>
  <i>Figure 1: SecureChain Architecture and Data Flow</i>
</div>

## Flow by Flow Explanation

The SecureChain system operates through a structured pipeline:

1. **Fetch commit diff deltas:** The system begins by monitoring target repositories via the **GitHub Core Stream**. When changes occur, it fetches the precise commit diff deltas.
2. **Dispatch parallel scans:** The **Core Express Server** (Git Diff Delta Compiler) compiles the fetched diffs and dispatches them as parallel scanning jobs to dedicated security agents.
3. **Ingest dependencies (Deterministic):** The Parallel Prescan Security Team gets to work. **Agent 1 (Package & Name Checker)** specifically ingests and inspects newly introduced package dependencies for malicious intent or typosquatting. *(Note: Agents 1, 2, and 3 are standard, non-LLM Python scripts).*
4. **Scan keys & obfuscation (Deterministic):** Concurrently, **Agent 2 (Scrambled Code & Secret Leak)** scans the raw code looking for inadvertently exposed secrets, hardcoded API keys, or intentionally obfuscated code.
5. **Trace network endpoints (Deterministic):** At the same time, **Agent 3 (Hacker Connection Tracer)** analyzes the code to trace any suspicious outbound network endpoints or unexpected connections.
6. **Review proof & evidence:** The combined security findings from these three non-AI prescan agents are funneled into the **Evidence Store (SES)**, acting as a central repository for all identified proof and evidence.
7. **Model consensus peer review:** The collected evidence is forwarded to the **Consensus Validation Engine**, where a dual-LLM approach takes place. **Google Gemini (Primary Orchestrator)** and **Anthropic Claude (Joint / Peer Validator)** perform a consensus-based peer review to reduce false positives and deliver high-confidence vulnerability verdicts.
8. **Stream verdict JSON details:** Finally, the finalized security verdicts are streamed as structured JSON details to the **Analyst Workspace Portal**, which visually maps out D3.js topologies and alerts for security analysts.

## Tech Stack

*   **Backend:** Python, FastAPI
*   **Version Control Integration:** GitHub REST API
*   **Security Agents:** Deterministic Python evidence collectors
*   **AI Consensus Engine:** Google Gemini (Primary), Anthropic Claude (Validator)
*   **Reporting:** fpdf2 (PDF Generation)
*   **Frontend:** Vanilla JavaScript, D3.js (Topology visualization), HTML/CSS
*   **Infrastructure:** Docker, Docker Compose

## Detailed Setup Instructions

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-org/securechain.git
    cd securechain
    ```

2.  **Environment Variables:**
    Copy the `.env.example` file to `.env` in the root directory:
    ```bash
    cp .env.example .env
    ```
    Open the `.env` file and configure your API keys:
    *   `GITHUB_TOKEN`: Your GitHub Personal Access Token (for fetching repositories).
    *   `GEMINI_API_KEY`: Your Google Gemini API key.
    *   `ANTHROPIC_API_KEY`: Your Anthropic Claude API key.

3.  **Run with Docker Compose:**
    The easiest way to run the entire application stack is using Docker Compose. Ensure Docker and Docker Compose are installed on your system.
    ```bash
    docker-compose up -d --build
    ```
    This command will build the necessary Docker images and start the backend service on port 8000 and the frontend service on port 80.

## How to Use the App

Once the application is running, you can interact with it using its REST API or by accessing the frontend dashboard.

**Frontend Dashboard:**
Open your web browser and navigate to `http://localhost`. This provides a visual Analyst Workspace Portal where you can input GitHub repository URLs to scan and view D3.js topology alerts.

**API Endpoints:**

1.  **Initiate a Scan:**
    Submit a GitHub repository URL to the scanner.
    ```bash
    curl -X POST http://localhost:8000/api/scan \
         -H "Content-Type: application/json" \
         -d '{"repo_url": "https://github.com/owner/repo"}'
    ```
    *Response:* Returns a JSON object containing a `scan_id`.

2.  **Check Scan Status:**
    Use the `scan_id` to poll for the current status of the scan (e.g., `running`, `completed`, `failed`).
    ```bash
    curl http://localhost:8000/api/scan/<scan_id>
    ```

3.  **Retrieve Security Report:**
    Once the scan is marked as `completed`, you can retrieve the detailed consensus findings.
    ```bash
    curl -X POST http://localhost:8000/api/scan/<scan_id>/report
    ```
    *Response:* Returns the structured JSON verdict details containing the identified vulnerabilities, evidence, and AI consensus summaries.
