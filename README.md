# DockerFalco — AI-Powered Container Attack & Defense Lab

A fully containerized security lab where a **Claude-powered AI agent** systematically attacks a vulnerable web application using **10 realistic container escape and exploitation techniques**, while **Falco** runtime security monitors every syscall and forwards alerts through **Falcosidekick** to **Elasticsearch** for analysis in **Kibana** and a custom **Security Dashboard** with downloadable reports and an interactive AI remediation agent.

---

## System Architecture

```mermaid
graph TD
  subgraph "docker-compose.yml"
    A["Attacker<br/>(Claude AI)"]
    B["Vulnerable<br/>Web App"]
    C["Falco"]
    D["Falcosidekick"]
    E["Elasticsearch"]
    F["Kibana"]
    G["Security<br/>Dashboard"]
    H["Auto Setup<br/>(init-setup)"]
  end

  A -->|"① live events"| B
  B -->|"② syscalls"| C
  C -->|"③ alerts"| D
  D -->|"④ index"| E
  E -->|"⑥ visualize"| F
  E -->|"⑦ query"| G
  A -->|"⑤ attack logs"| E
  H -.->|"index templates + data views"| E
  H -.->|"data views"| F

  style A fill:#ff3355,color:#fff
  style B fill:#ffaa00,color:#000
  style C fill:#8b5cf6,color:#fff
  style D fill:#8b5cf6,color:#fff
  style E fill:#00d4ff,color:#000
  style F fill:#00d4ff,color:#000
  style G fill:#00ff88,color:#000
  style H fill:#6a8fa8,color:#fff
```

<figure align="center">
  <figcaption><strong>Figure 1:</strong> DockerFalco System Architecture — Service Interactions and Data Flow</figcaption>
</figure>

### Flow-by-Flow Explanation

**1. AI Attacker → Vulnerable Web App**
The Claude-powered attacker container executes 10 different container attack scenarios against the vulnerable Flask web application. Each attack targets a specific container security weakness (Docker socket abuse, capability exploitation, cgroup escapes, etc.). The attacker sends real-time attack events to the vulnerable app's `/api/attack-event` endpoint so the live dashboard updates in real-time.

**2. Vulnerable Web App → Falco**
As the vulnerable app processes requests (including malicious ones), it makes system calls (syscalls) at the kernel level — spawning processes, opening files, making network connections. Falco, running with kernel-level visibility, monitors every syscall against its rule set.

**3. Falco → Falcosidekick**
When Falco detects a syscall matching a rule (e.g., "Mount syscall from container" or "Docker socket accessed"), it creates an alert and forwards it to Falcosidekick via HTTP webhook.

**4. Falcosidekick → Elasticsearch**
Falcosidekick receives the alert and indexes it into Elasticsearch under the `falco-events-*` index pattern. Every alert contains: rule name, priority, container context (name, image, ID), process details (PID, command line), file descriptor info, and user context.

**5. Attacker → Elasticsearch (side channel)**
After executing each attack, the attacker sends the attack result *and* the Claude-generated AI analysis directly to Elasticsearch under the `attack-logs-*` index pattern. This creates two parallel data streams — raw syscall events from Falco and AI-analyzed attack records from the attacker.

**6. Kibana ← Elasticsearch**
Kibana reads from both `falco-events-*` and `attack-logs-*` indices, providing pre-built data views so you can search, filter, and visualize everything. The "Falco Events" view shows raw syscall detections; the "Attack Logs" view shows the attacker's AI-analyzed perspective.

**7. Security Dashboard ← Elasticsearch**
The custom Flask dashboard queries Elasticsearch for attack records, displays them with severity color-coding, and provides:
- **Download Reports**: Professional-grade HTML security report with executive summary, attack timeline, detailed findings, MITRE mapping, affected infrastructure matrix, and remediation plan.
- **AI Remediation Agent**: Select an attack technique, click "Execute Remediation", and watch the AI agent stream security hardening commands in real-time with thinking, command output, and status for each step.

---

## Attack Scenarios

The AI attacker executes **10 realistic container attack techniques** against the vulnerable web app. Each attack maps to a known real-world container security weakness:

### 1. Docker Socket Abuse
Mounts the Docker socket (`/var/run/docker.sock`) exposed inside the vulnerable container and uses the Docker API to create a privileged container, escaping to the host. *Real-world: CI/CD runners, monitoring tools like Portainer commonly mount docker.sock for management, creating this exact escape vector.*

### 2. CAP_SYS_ADMIN Capability Exploit
Detects the `CAP_SYS_ADMIN` Linux capability and uses it to mount the host filesystem inside the container, gaining read/write access to host files. *Real-world: System monitoring, hardware-access, and network tools often run with extra capabilities like SYS_ADMIN.*

### 3. Cgroup notify_on_release Escape
Exploits the classic cgroup escape technique by writing to a cgroup's `release_agent` file. When the cgroup is emptied, the kernel executes the release agent on the host as root. *Real-world: CVE-2022-0492 — this exact bug affected Android and BuildKit containers using cgroup v1.*

### 4. Procfs /proc/1/root Host Read
Reads host files through the `/proc/1/root` symlink, which points to the host's root filesystem when PID namespace sharing is enabled. Accesses `/etc/shadow`, SSH keys, and Docker credentials. *Real-world: Monitoring and debug containers frequently share the host PID namespace to see host processes.*

### 5. Privileged Container Full Escape
When running in `--privileged` mode, the attacker has all capabilities, full device access, and can perform arbitrary kernel operations — effectively running as root on the host. *Real-world: Debug containers, CI runners, and some orchestrator agents run privileged "because it's easier."*

### 6. Volume Mount Traversal
Exploits host-path volume mounts (e.g., `/etc/shadow` mounted into the container) to read sensitive host files. Enumerates all mount points and checks for bind-mounted host paths. *Real-world: Config mounts, log directories, and secret injection often use bind mounts from host paths.*

### 7. Container Network Namespace Escape
Scans the host's internal network, discovers services running on the host (Docker API, Kubernetes API, Elasticsearch), and probes for open ports. Tries to access host-only services from within the container. *Real-world: Containers with `--network=host` or `CAP_NET_ADMIN` can access the host's full network namespace.*

### 8. Docker API Abuse via SSRF
Uses Server-Side Request Forgery (SSRF) vulnerabilities in the web app to reach the Docker API on TCP port 2375/2376 or uses the app's Docker proxy endpoint. *Real-world: Docker API exposed on TCP is a common dev-environment misconfiguration, and SSRF in web apps is the top cloud security vulnerability.*

### 9. Sidecar Container Attack
Discovers other containers on the same Docker network (Elasticsearch, Kibana, etc.) and probes them for unauthenticated access. Tries to read Elasticsearch indices or access Kibana without credentials. *Real-world: In Kubernetes pods, sidecar containers share a network namespace and can attack each other's localhost services.*

### 10. Seccomp/AppArmor Profile Bypass
Checks if seccomp is disabled (`seccomp=unconfined`) or if AppArmor is not enforced. When security profiles are missing, the attacker has access to all 300+ Linux syscalls, including dangerous ones like `mount`, `unshare`, and `ptrace`. *Real-world: seccomp=unconfined is common in dev/staging and even some production setups "to avoid compatibility issues."*

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Attacker** | Python 3.11 + Anthropic Claude SDK | AI-powered attack execution and analysis |
| **Vulnerable App** | Flask 3.0 (Python) | Intentionally vulnerable web application |
| **Security Dashboard** | Flask 3.0 + Server-Sent Events | Report generation + streaming remediation agent |
| **Runtime Security** | Falco (falcosecurity/falco-no-driver) | Kernel-level syscall monitoring |
| **Event Forwarding** | Falcosidekick | Routes Falco alerts to Elasticsearch |
| **Log Storage** | Elasticsearch 8.12.0 | Stores falco-events and attack-logs indices |
| **Visualization** | Kibana 8.12.0 | Dashboards for Falco events + attack logs |
| **Container Runtime** | Docker + docker-compose | Orchestrates all services |
| **AI Model** | Claude Sonnet 4 (via Anthropic API) | Attack analysis and remediation planning |

---

## Setup Instructions

### ⚠️ Platform Requirements

**This project runs on Linux only.** Here is why:

| Issue | Windows | macOS |
|-------|---------|-------|
| **Falco kernel module** | Falco needs kernel-level eBPF or kernel module access. Docker Desktop on Windows runs containers in a Hyper-V VM that does not expose kernel events to the Falco driver. | macOS uses a Hypervisor.framework VM — same limitation. Falco cannot access the Darwin kernel. |
| **`/proc` and `/boot` mounts** | Falco requires read-only access to host `/proc`, `/boot`, and `/lib/modules`. Windows has no equivalent. | macOS has no Linux `/proc` filesystem. |
| **Docker socket** | The docker.sock path differs and behavior changes between WSL2 and Hyper-V backends. | Docker socket exists but the Linux VM layer breaks Falco. |
| **eBPF probes** | Falco's eBPF probe cannot load on the Windows kernel. | No eBPF support on Darwin. |
| **Container escape attacks** | Several attacks (cgroup escape, mount escape, namespace manipulation) require Linux kernel features. | Same limitation — macOS kernel is not Linux. |

> **If you are on Windows**, install [WSL2](https://learn.microsoft.com/en-us/windows/wsl/install) with an Ubuntu distribution, then follow the Ubuntu instructions below from within WSL2. Docker Desktop must be configured to use the WSL2 backend.

> **If you are on macOS**, provision a Linux VM (Ubuntu recommended) using Multipass, Parallels, or UTM, and run the project inside the VM.

### Prerequisites

A fresh **Ubuntu 22.04 or 24.04** machine with:

- Git installed
- Internet access (to pull Docker images and clone repos)
- At least **4 GB RAM** (8 GB recommended)
- At least **10 GB free disk space**
- **Anthropic API key** — get one free at https://console.anthropic.com

### Step 1: Install Docker

```bash
# Update package index
sudo apt update

# Install prerequisites
sudo apt install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Set up the Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine and docker-compose plugin
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start Docker and enable on boot
sudo systemctl start docker
sudo systemctl enable docker

# Add your user to the docker group (so you don't need sudo)
sudo usermod -aG docker $USER

# IMPORTANT: Log out and back in for group changes to take effect
echo "=== RUN THIS COMMAND NOW ==="
echo "newgrp docker"
echo "=== THEN CONTINUE WITH STEP 2 ==="
```

After running `newgrp docker`, verify Docker works:

```bash
docker --version
docker compose version
```

### Step 2: Clone the Repository

```bash
# Clone the project
git clone https://github.com/ritvikindupuri/dockerfalco.git

# Enter the project directory
cd dockerfalco
```

### Step 3: Configure Your API Key

```bash
# Create your .env file from the example
cp .env.example .env

# Edit the .env file with your API key
nano .env
```

Change the line to:

```
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Replace the `sk-ant-...` with your actual Anthropic API key. Save and exit (`Ctrl+X`, then `Y`, then `Enter` in nano).

### Step 4: Phase 1 — Start All Infrastructure Services

This starts everything **except the attacker** — you get blank dashboards, the vulnerable web app, Falco monitoring, Elasticsearch, and Kibana with pre-configured data views.

```bash
# Pull all images and build containers
docker compose up -d

# Also run the auto-setup (creates ES index templates + Kibana data views)
docker compose --profile setup up init-setup
```

The `init-setup` service waits for Elasticsearch and Kibana to finish starting, then:
- Creates the `attack-logs-*` index template in Elasticsearch
- Creates the `falco-events-*` index template in Elasticsearch  
- Creates the **Attack Logs** data view in Kibana
- Creates the **Falco Events** data view in Kibana
- Prints a summary of all URLs

You do **not** need to manually configure anything in Kibana.

### Step 5: Verify Phase 1 is Running

```bash
# Check that all services are running
docker compose ps
```

You should see output like:

```
NAME                IMAGE                                          STATUS
elasticsearch       docker.elastic.co/elasticsearch/elasticsearch:8.12.0   Up (healthy)
falco               falcosecurity/falco-no-driver:latest           Up
falcosidekick       falcosecurity/falcosidekick:latest             Up
init-setup          curlimages/curl:latest                         Exited (0)
kibana              docker.elastic.co/kibana/kibana:8.12.0        Up (healthy)
sec-dashboard       dockerfalco-dashboard                          Up
vuln-app            dockerfalco-vulnerable-app                     Up
```

Note: `ai-attacker` is **not running** yet — it only starts in Phase 2. `init-setup` has `Exited (0)` which means it ran successfully and finished.

Now open these URLs in your browser to see the **blank** state:

| URL | What You See |
|-----|-------------|
| http://localhost:5000 | Security Dashboard — "No attacks recorded yet" with the Phase 2 command shown |
| http://localhost:8080 | Vulnerable Web App — live feed says "Waiting for Phase 2 attacks..." |
| http://localhost:5601 | Kibana — Data views exist but indices are empty (no documents yet) |
| http://localhost:2802 | Falcosidekick UI — Event counters at 0 |
| http://localhost:9200 | Elasticsearch API — Cluster is healthy, no `attack-logs` or `falco-events` indices yet |

All UIs will auto-populate in real-time once Phase 2 starts — no manual refreshing needed.

### Step 6: Phase 2 — Launch the AI Attacker

Phase 2 starts the Claude-powered attacker container which immediately begins executing attacks against the vulnerable app. As attacks run:

1. **Security Dashboard** fills with attack entries in real-time (auto-refreshes every 10 seconds)
2. **Vulnerable Web App** shows live system metrics spiking (CPU, memory, processes) and a live attack feed
3. **Elasticsearch** receives `attack-logs-*` and `falco-events-*` documents
4. **Kibana** data views become populated — you can immediately search and filter
5. **Falcosidekick UI** counters start incrementing

```bash
# Start the attacker container (in the 'attack' profile)
docker compose --profile attack up -d attacker

# Watch the attacker's logs in real-time
docker compose logs -f attacker
```

You will see output like:

```
[INIT] Anthropic API: CONFIGURED
[INIT] Elasticsearch: http://elasticsearch:9200
[INIT] Attack interval: 30s
[INIT] Loaded 10 attack scenarios

############################################################
#  ATTACK ROUND 1
############################################################

============================================================
[ATTACK] Executing: Docker Socket Abuse - Container Escape
============================================================
[RESULT] Success: True
[RESULT] Detail: Privileged container escape via docker socket...
```

After ~2 minutes, a full round of all 10 attacks will have completed. Switch between your browser tabs to see each dashboard populate in real-time.

### Stopping & Cleanup

#### Stop Phase 2 only (pause attacks, keep all UIs and data)

```bash
# Stop the attacker but keep everything else running
docker compose --profile attack stop attacker

# Verify: attacker is stopped, infra stays up
docker compose ps

# (Optional) Resume attacks later:
docker compose --profile attack start attacker
```

All dashboards, logs, and Elasticsearch data are preserved. You can browse past attacks, download reports, and run remediation against the existing data.

#### Stop everything (full shutdown, keep data)

```bash
# Stop all containers but keep Elasticsearch volumes
docker compose down

# To restart later:
docker compose up -d
docker compose --profile setup up init-setup
docker compose --profile attack up -d attacker
```

#### Full cleanup (destroy all data)

```bash
# 1. Stop the attacker
docker compose --profile attack stop attacker

# 2. Stop everything and delete Elasticsearch data volumes
docker compose down -v

# 3. Remove any leftover containers/networks
docker compose down --volumes --remove-orphans

# 4. Verify nothing is left
docker compose ps
docker ps -a | grep dockerfalco  # should show no results
```

After full cleanup, to start fresh:

```bash
docker compose up -d
docker compose --profile setup up init-setup
docker compose --profile attack up -d attacker
```

You should see the attacker initializing, checking the target, and beginning to execute attacks:

```
[INIT] Anthropic API: CONFIGURED
[INIT] Elasticsearch: http://elasticsearch:9200
[INIT] Attack interval: 30s
[INIT] Loaded 10 attack scenarios

############################################################
#  ATTACK ROUND 1
#  2026-05-25T16:30:00.123456
############################################################

============================================================
[ATTACK] Executing: Docker Socket Abuse - Container Escape
[ATTACK] Technique: docker_socket_abuse
============================================================
[RESULT] Success: True
[RESULT] Detail: Privileged container escape via docker socket...
```

Let the attacker run through at least one full round of attacks (about 2 minutes) before proceeding to the usage guides.

---

## Usage Guides

### 1. Security Dashboard (`http://<your-ubuntu-ip>:5000`)

The Security Dashboard is the main interface for reviewing attack results, downloading reports, and running remediation.

#### Viewing Attack History

1. Open your browser and go to `http://<your-ubuntu-ip>:5000`
2. The **Attacks** tab is selected by default
3. You will see a table with columns: Time, Attack Name, Technique, Severity, Status, MITRE, Actions
4. **Filter attacks** using the search bar (type any keyword) or the Severity/Status dropdowns
5. The stats bar at the top shows: Total Attacks, Critical, High, Successful counts

#### Reading a Detailed Attack Analysis

1. In the Attacks table, **click any row** to open the detail panel below the table
2. The detail panel shows:
   - **Attack metadata**: Time, Technique, Severity, Status, MITRE ATT&CK ID, Detail description
   - **AI Analysis section**: Claude's expert assessment of the attack including:
     - What was attempted
     - Why it succeeded or failed
     - Real-world impact in production
     - MITRE ATT&CK mapping
     - Detection and prevention recommendations
   - **Raw Output section**: The full terminal output from the attack execution
3. Click the **Execute Remediation for This Attack** button to jump directly to the remediation agent

#### Downloading a Security Report

1. Click the **Reports** tab in the navigation bar
2. You will see three report options:
   - **Detailed HTML Report** — Professional-grade security assessment report. Click **Download HTML** to get a complete report with:
     - Cover page with classification marking
     - Table of contents
     - Executive summary with attack statistics
     - Attack timeline table
     - Detailed findings for every attack (with AI analysis)
     - Prioritized remediation plan (Critical > High > Medium)
     - Affected infrastructure matrix
     - Security recommendations (10 items)
     - MITRE ATT&CK mapping table
   - **Attack Data Export** — Raw JSON of all attack records with AI analysis for SIEM integration
   - **Falco Events Report** — Link to view raw Falco events

#### Running AI Remediation

1. Click the **Remediation** tab
2. From the dropdown, select a specific attack technique (e.g., "Docker Socket Abuse") or leave it as "Full Security Remediation"
3. Click **Execute Remediation** button
4. Watch the AI agent work in real-time:
   - **Progress bar** shows overall completion
   - **Each step card** shows:
     - **Agent Thinking**: What the agent is analyzing before running the command
     - **Command**: The exact command being executed
     - **Output**: The live command output (green for success, red for failure)
     - **Status tag**: RUNNING → SUCCESS / FAILED
5. When complete, a green banner shows the summary
6. Scroll through each step to review what commands were executed and their results

#### Generating Claude Remediation Analysis

1. In the **Remediation** tab, scroll to the "Claude AI Remediation Analysis" section
2. Click **Generate AI Analysis**
3. Wait a few seconds while Claude analyzes the latest attacks
4. A detailed remediation strategy appears with Claude's recommendations

### 2. Vulnerable Web App (`http://<your-ubuntu-ip>:8080`)

The vulnerable web app is the target that the AI attacker exploits. It also serves as a real-time attack visualization dashboard.

#### Real-Time Attack Effects

As the attacker runs, the vulnerable app's UI updates in real-time:

| Indicator | What to Watch | What It Means |
|-----------|--------------|---------------|
| **CPU Meter** (top-left) | Bar fills up and percentage rises | The attacker is executing commands, spawning processes |
| **Memory Meter** | Bar rises | Processes are consuming memory |
| **Process Count** | Number increases | New processes spawned by command injection |
| **Net Connections** | Number increases | Network connections made by the attacker |
| **Status Indicator** | Changes from "SECURE" → "COMPROMISED" with red pulsing animation | A container escape or privilege escalation succeeded |
| **Compromise Banner** | Red pulsing banner appears at top | Security breach detected |
| **Live Attack Feed** | New entries appear with severity color-coding | Each attack event in real time |

#### Accessing Vulnerable Endpoints

The app exposes intentional vulnerabilities for the attacker to exploit. You can also try them manually:

1. **Command Injection**: `http://<your-ubuntu-ip>:8080/shell?cmd=cat /etc/passwd`
2. **File Read**: `http://<your-ubuntu-ip>:8080/readfile?path=/etc/host-shadow`
3. **Docker API Proxy**: `http://<your-ubuntu-ip>:8080/docker/containers/json`
4. **Environment Dump**: `http://<your-ubuntu-ip>:8080/env`
5. **Event Log**: `http://<your-ubuntu-ip>:8080/logs`

#### Understanding the Vulnerability Context

The app is intentionally misconfigured to simulate real-world container security gaps:
- `CAP_SYS_ADMIN` capability added (too permissive)
- `/var/run/docker.sock` mounted inside the container (critical misconfiguration)
- `/etc/shadow` mounted at `/etc/host-shadow` (credential exposure)
- `seccomp=unconfined` (no syscall filtering)

### 3. Kibana (Falco UI) (`http://<your-ubuntu-ip>:5601`)

Kibana provides the Falco event visualization and attack log analysis dashboards.

#### Creating the Data Views (First-Time Setup)

The init script should auto-create these, but if they don't appear, create them manually:

**Creating the Falco Events data view:**

1. Open `http://<your-ubuntu-ip>:5601` in your browser
2. In the left sidebar, click the **☰ (hamburger) menu** → **Stack Management**
3. In the left panel, click **Data Views**
4. Click **Create data view**
5. In the **Name** field, enter: `Falco Events`
6. In the **Index pattern** field, enter: `falco-events-*`
7. In the **Timestamp field** dropdown, select `@timestamp`
8. Click **Save data view to Kibana**

**Creating the Attack Logs data view:**

1. Follow steps 1-4 above
2. **Name**: `Attack Logs`
3. **Index pattern**: `attack-logs-*`
4. **Timestamp field**: `@timestamp`
5. Click **Save**

#### Exploring Falco Events

1. In the left sidebar, click **☰ menu** → **Discover**
2. From the data view dropdown (top-left), select **Falco Events**
3. You will see a timeline histogram and a list of events

**What to look for:**

| Field | What It Contains | Example Value |
|-------|-----------------|---------------|
| `rule` | Name of the Falco rule that triggered | `Docker Socket Mounted in Container` |
| `priority` | Severity level | `CRITICAL`, `HIGH`, `WARNING` |
| `output` | Human-readable alert message with context | `DOCKER SOCKET ACCESSED (user=root container=vuln-app...)` |
| `container.name` | Which container triggered the alert | `vuln-app`, `ai-attacker` |
| `container.image` | Container image | `dockerfalco-vulnerable-app` |
| `proc.name` | Process name that made the syscall | `python3`, `docker` |
| `proc.cmdline` | Full command line | `python3 app.py` |
| `evt.type` | System call type | `open`, `mount`, `connect` |
| `fd.name` | File descriptor path | `/var/run/docker.sock` |

**How to filter:**
- To see only critical events: Click the `priority` field → click the **+** (plus) icon next to `CRITICAL`
- To see events for a specific container: In the search bar, type `container.name : "vuln-app"`
- To see mount syscalls: Type `evt.type : "mount"`
- To filter by time: Use the time picker (top-right) and select **Last 15 minutes**

**Interesting event types to look for:**

1. **DOCKER SOCKET ACCESSED** (CRITICAL) — Someone accessed the Docker socket from a container
2. **MOUNT SYSCALL IN CONTAINER** (CRITICAL) — Container tried to mount a filesystem (potential escape)
3. **HOST FILE READ VIA PROCFS** (CRITICAL) — Container read host files via /proc/1/root
4. **CGROUP RELEASE_AGENT MODIFICATION** (CRITICAL) — Cgroup escape attempt detected
5. **CAP_SYS_ADMIN DETECTED IN CONTAINER** (HIGH) — Container with dangerous capability
6. **SENSITIVE HOST FILE ACCESS** (CRITICAL) — Direct access to shadow/SSH keys

#### Exploring Attack Logs

1. In Discover, switch the data view to **Attack Logs**
2. You will see the attacker's records with AI analysis

**Key fields:**

| Field | What It Contains |
|-------|-----------------|
| `attack_name` | Friendly name of the attack |
| `technique` | Internal technique identifier |
| `mitre_technique` | MITRE ATT&CK mapping |
| `status` | `success`, `failed`, or `error` |
| `detail` | Human-readable description of what happened |
| `analysis` | Full Claude AI analysis (scroll to read) |
| `raw_output` | Complete command output from the attack |

**How to analyze attack patterns:**
- Sort by `@timestamp` to see the chronological attack sequence
- Filter `status : "success"` to see which attacks successfully breached the container
- Filter `technique : "docker_socket_abuse"` to see all Docker socket attacks
- Use the **Dashboard** feature to create visualizations like a pie chart of successful vs. failed attacks

### 4. Falcosidekick UI (`http://<your-ubuntu-ip>:2802`)

Falcosidekick provides a real-time view of all Falco events being forwarded.

1. Open `http://<your-ubuntu-ip>:2802` in your browser
2. You will see a live dashboard showing:
   - **Total events received** counter
   - **Events by priority** breakdown (Critical, High, Warning, etc.)
   - **Events by rule** distribution
   - **Outputs status** — shows if Elasticsearch is receiving events
3. As attacks run, watch the counter increment in real-time
4. Check the **Elasticsearch output** section to confirm events are being indexed successfully

### 5. Elasticsearch (`http://<your-ubuntu-ip>:9200`)

Elasticsearch stores all the data. You can query it directly via the REST API.

#### Verify Indices Exist

```bash
# List all indices
curl http://localhost:9200/_cat/indices?v

# You should see:
# health status index              uuid ... pri rep docs.count ...
# yellow open   attack-logs-...    ...      1   0         10
# yellow open   falco-events-...   ...      1   0         85
```

#### Search Attack Logs

```bash
# Get all attack logs (last 10)
curl -s "http://localhost:9200/attack-logs-*/_search?sort=@timestamp:desc&size=10" | python3 -m json.tool

# Get only successful attacks
curl -s "http://localhost:9200/attack-logs-*/_search" -H "Content-Type: application/json" -d '{
  "query": { "term": { "status": "success" } },
  "sort": [ { "@timestamp": "desc" } ],
  "size": 50
}' | python3 -m json.tool

# Get attacks by technique
curl -s "http://localhost:9200/attack-logs-*/_search" -H "Content-Type: application/json" -d '{
  "query": { "term": { "technique": "docker_socket_abuse" } },
  "sort": [ { "@timestamp": "desc" } ]
}' | python3 -m json.tool

# Count attacks by status
curl -s "http://localhost:9200/attack-logs-*/_search" -H "Content-Type: application/json" -d '{
  "size": 0,
  "aggs": {
    "by_status": {
      "terms": { "field": "status" }
    }
  }
}' | python3 -m json.tool
```

#### Search Falco Events

```bash
# Get all Falco events
curl -s "http://localhost:9200/falco-events-*/_search?sort=@timestamp:desc&size=5" | python3 -m json.tool

# Get only CRITICAL events
curl -s "http://localhost:9200/falco-events-*/_search" -H "Content-Type: application/json" -d '{
  "query": { "term": { "priority": "CRITICAL" } },
  "sort": [ { "@timestamp": "desc" } ],
  "size": 20
}' | python3 -m json.tool

# Get events by rule name
curl -s "http://localhost:9200/falco-events-*/_search" -H "Content-Type: application/json" -d '{
  "query": { "term": { "rule.keyword": "Docker Socket Mounted in Container" } },
  "sort": [ { "@timestamp": "desc" } ],
  "size": 20
}' | python3 -m json.tool

# Count events by priority
curl -s "http://localhost:9200/falco-events-*/_search" -H "Content-Type: application/json" -d '{
  "size": 0,
  "aggs": {
    "by_priority": {
      "terms": { "field": "priority" }
    }
  }
}' | python3 -m json.tool
```

#### Check Elasticsearch Cluster Health

```bash
curl -s "http://localhost:9200/_cluster/health?pretty"
```

---

## Troubleshooting

### 1. Docker Services Won't Start

```bash
# Check all container logs at once
docker compose logs --tail=50

# Check individual service logs
docker compose logs elasticsearch --tail=100
docker compose logs falco --tail=100
docker compose logs kibana --tail=100

# Restart everything
docker compose down
docker compose up -d

# Rebuild and restart (if you changed code)
docker compose down
docker compose build --no-cache
docker compose up -d
```

### 2. Elasticsearch Fails to Start

```bash
# Check Elasticsearch logs
docker compose logs elasticsearch

# Check if port 9200 is already in use
sudo lsof -i :9200

# Increase memory limits (if vm.max_map_count is too low)
sudo sysctl -w vm.max_map_count=262144
# Make permanent
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# Check disk space (ES needs at least 10% free)
df -h

# If ES keeps restarting, give it more time
sleep 120 && curl http://localhost:9200
```

### 3. Kibana Shows "No data views"

```bash
# Check if indices exist in Elasticsearch
curl http://localhost:9200/_cat/indices?v

# If indices exist but Kibana can't see them:
# 1. Wait 30 seconds for Kibana to sync
# 2. Go to http://localhost:5601 → ☰ → Stack Management → Data Views
# 3. Click "Create data view"
# 4. Pattern: falco-events-* (or attack-logs-*)
# 5. Time field: @timestamp
# 6. Click "Save data view to Kibana"

# Or check that Kibana can reach Elasticsearch
curl http://localhost:5601/api/status
```

### 4. Attacker Container Exits Immediately

```bash
# Check logs
docker compose logs attacker

# Most common cause: ANTHROPIC_API_KEY not set
# Fix:
nano .env
# Make sure your key is set correctly

# Restart the attacker
docker compose --profile attack up -d attacker
docker compose logs -f attacker
```

### 5. Attacker Runs But All Attacks Fail

```bash
# Check if the target is reachable
docker exec ai-attacker curl -s http://vulnerable-app:8080/health

# Check if Anthropic API is configured
docker exec ai-attacker env | grep ANTHROPIC

# Verify Elasticsearch is receiving data
docker exec ai-attacker curl -s http://elasticsearch:9200/_cat/indices

# Check actual HTTP responses from attacks
docker compose logs attacker --tail=200

# Common cause: Invalid or expired Anthropic API key
# Test your key manually:
curl -s https://api.anthropic.com/v1/messages \
  -H "x-api-key: sk-ant-..." \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}'
```

### 6. Falco Shows No Events

```bash
# Check if Falco is running
docker compose ps falco

# Check Falco logs
docker compose logs falco --tail=50

# Check Falco configuration
docker exec falco cat /etc/falco/falco.yaml

# Check if Falcosidekick is receiving events
curl http://localhost:2801/ping

# Check Falcosidekick UI at http://localhost:2802 for event counters

# If Falco has no events, try:
docker compose restart falco
docker compose logs -f falco
```

### 7. Dashboard Shows No Attacks

```bash
# Check if Phase 2 has been started
docker compose ps attacker

# If the attacker is not running, start Phase 2:
docker compose --profile attack up -d attacker

# Check if any attack data exists in Elasticsearch
curl "http://localhost:9200/attack-logs-*/_search?size=1&ignore_unavailable=true"

# If Elasticsearch returns "index_not_found_exception", the attacker
# hasn't run yet — wait for Phase 2 attacks to complete

# Check if the dashboard can reach Elasticsearch
docker exec sec-dashboard curl -s http://elasticsearch:9200/_cluster/health

# Check dashboard logs
docker compose logs dashboard --tail=30

# Restart dashboard
docker compose restart dashboard
```

### 8. Kibana Shows "No data views" (init-setup failed)

```bash
# Check if init-setup ran
docker compose ps init-setup

# If it shows "Exited (0)", it succeeded — wait 30s and refresh Kibana
# If it shows anything else, check its logs:
docker compose logs init-setup

# Manually re-run the setup:
docker compose --profile setup run --rm init-setup

# If that fails, create data views manually:
# 1. Go to http://localhost:5601
# 2. ☰ menu → Stack Management → Data Views
# 3. Click "Create data view"
# 4. Name: "Falco Events", Index pattern: "falco-events-*", Time: @timestamp
# 5. Click "Save data view to Kibana"
# 6. Repeat with Name: "Attack Logs", Index pattern: "attack-logs-*"
```

### 8. Port Already in Use

```bash
# Check which service is using a port
sudo lsof -i :8080
sudo lsof -i :5000
sudo lsof -i :5601
sudo lsof -i :9200

# If needed, stop the conflicting service
sudo systemctl stop <service-name>

# Or change ports in docker-compose.yml and restart
```

### 9. Permission Denied for Docker Socket

```bash
# If you see "Permission denied" when accessing docker.sock
sudo chmod 666 /var/run/docker.sock

# Or add your user to the docker group (more secure)
sudo usermod -aG docker $USER
newgrp docker
```

### 10. Container Logs Show "Out of Memory"

```bash
# Check memory usage
docker stats --no-stream

# Increase Docker memory limit (if using Docker Desktop)
# Go to Settings → Resources → Advanced → Increase RAM

# Or reduce Elasticsearch memory in docker-compose.yml:
# Change: ES_JAVA_OPTS=-Xms512m -Xmx512m
# To:     ES_JAVA_OPTS=-Xms256m -Xmx256m
# Then restart:
docker compose down
docker compose up -d
```

### 11. WSL2-specific Issues (Windows Users)

```bash
# If Docker Desktop in WSL2 fails to start
wsl --shutdown
# Restart Docker Desktop from Windows

# If Falco cannot load in WSL2
# Falco does not work in WSL2! Use a native Linux VM or cloud instance.

# If you see "The command 'docker' could not be found" in WSL2
# Install Docker Desktop for Windows and enable WSL2 integration
# Then in WSL2:
sudo ln -s /mnt/c/Program\ Files/Docker/Docker/resources/bin/docker /usr/local/bin/docker
sudo ln -s /mnt/c/Program\ Files/Docker/Docker/resources/bin/docker-compose /usr/local/bin/docker-compose
```

### 12. Complete Reset

See the **[Stopping & Cleanup](#stopping--cleanup)** section above for the full cleanup command sequence. Quick reset:

```bash
# Nuke everything and start fresh
docker compose --profile attack stop attacker
docker compose down -v --remove-orphans
docker compose build --no-cache
docker compose up -d
docker compose --profile setup up init-setup
docker compose --profile attack up -d attacker
```
