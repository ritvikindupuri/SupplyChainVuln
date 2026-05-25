import json
import os
import time
import requests
from datetime import datetime

REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>%TITLE%</title>
<style>
  @page { margin: 2.5cm 2cm; @bottom-center { content: "Page " counter(page) " of " counter(pages); font-size: 9pt; color: #666; } }
  body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 11pt; line-height: 1.6; color: #1a1a1a; }
  .cover { text-align: center; padding: 80px 0 40px 0; page-break-after: always; }
  .cover h1 { font-size: 28pt; color: #c00; margin-bottom: 10px; letter-spacing: 1px; }
  .cover .subtitle { font-size: 14pt; color: #555; margin-bottom: 30px; }
  .cover .meta { font-size: 10pt; color: #888; margin-top: 60px; }
  .cover .classification { display: inline-block; border: 2px solid #c00; color: #c00; padding: 8px 24px; font-weight: bold; font-size: 10pt; letter-spacing: 3px; margin-top: 20px; }
  h2 { font-size: 16pt; color: #c00; border-bottom: 2px solid #c00; padding-bottom: 5px; margin: 30px 0 15px 0; }
  h3 { font-size: 13pt; color: #333; margin: 20px 0 10px 0; }
  .finding { border: 1px solid #ddd; border-left: 4px solid; margin: 15px 0; padding: 15px; page-break-inside: avoid; }
  .finding.critical { border-left-color: #c00; }
  .finding.high { border-left-color: #f80; }
  .finding.medium { border-left-color: #e5a000; }
  .finding.low { border-left-color: #6a0; }
  .finding .header { font-weight: bold; font-size: 12pt; margin-bottom: 8px; }
  .finding .meta { font-size: 9pt; color: #888; margin-bottom: 8px; }
  .finding .body { font-size: 10pt; }
  .tag { display: inline-block; background: #eee; padding: 2px 8px; font-size: 8pt; border-radius: 3px; margin: 2px; }
  table { width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 10pt; }
  th { background: #f5f5f5; text-align: left; padding: 8px; border: 1px solid #ddd; }
  td { padding: 8px; border: 1px solid #ddd; }
  .severity-critical { background: #ffe8e8; }
  .severity-high { background: #fff0e0; }
  .severity-medium { background: #fff8e0; }
  .severity-low { background: #f0f8e8; }
  .remediation { background: #f0f4f8; border: 1px solid #c8d8e8; padding: 12px; margin: 10px 0; page-break-inside: avoid; }
  .remediation h4 { color: #2a5a8a; margin: 0 0 8px 0; font-size: 11pt; }
  .remediation ol { margin: 0; padding-left: 20px; font-size: 10pt; }
  .exec-summary { background: #fafafa; border: 1px solid #ddd; padding: 20px; margin: 15px 0; }
  .exec-summary .stat { display: inline-block; text-align: center; padding: 10px 20px; margin: 5px; }
  .exec-summary .stat .num { font-size: 24pt; font-weight: bold; }
  .exec-summary .stat .label { font-size: 9pt; color: #888; }
  code { background: #f4f4f4; padding: 1px 4px; font-size: 9pt; border: 1px solid #e0e0e0; border-radius: 2px; }
  pre { background: #1a1a2e; color: #00ff88; padding: 12px; font-size: 9pt; overflow-x: auto; border-radius: 4px; }
  .toc { page-break-after: always; }
  .toc ul { list-style: none; padding: 0; }
  .toc li { padding: 6px 0; border-bottom: 1px dotted #ddd; font-size: 11pt; }
  .toc li span { float: right; color: #888; }
  .footer { text-align: center; font-size: 8pt; color: #aaa; margin-top: 40px; border-top: 1px solid #eee; padding-top: 10px; }
</style>
</head>
<body>

<div class="cover">
  <div class="classification">%CLASSIFICATION%</div>
  <h1>%TITLE%</h1>
  <div class="subtitle">%SUBTITLE%</div>
  <div class="meta">
    <strong>Report ID:</strong> %REPORT_ID%<br>
    <strong>Date:</strong> %DATE%<br>
    <strong>Target:</strong> %TARGET%<br>
    <strong>Engine:</strong> %ENGINE%<br>
    <strong>Analyst:</strong> %ANALYST%
  </div>
</div>

<div class="toc">
  <h2>Table of Contents</h2>
  <ul>
    <li>1. Executive Summary <span>3</span></li>
    <li>2. Attack Timeline <span>4</span></li>
    <li>3. Detailed Findings <span>5</span></li>
    <li>4. Remediation Plan <span>%REMED_PAGE%</span></li>
    <li>5. Affected Infrastructure <span>%AFFECTED_PAGE%</span></li>
    <li>6. Security Recommendations <span>%RECOMMEND_PAGE%</span></li>
    <li>7. MITRE ATT&CK Mapping <span>%MITRE_PAGE%</span></li>
  </ul>
</div>

<h2>1. Executive Summary</h2>
<div class="exec-summary">
  <p>%EXEC_SUMMARY%</p>
  <div>
    <div class="stat"><div class="num">%TOTAL_ATTACKS%</div><div class="label">Total Attacks</div></div>
    <div class="stat"><div class="num" style="color:#c00">%CRITICAL%</div><div class="label">Critical</div></div>
    <div class="stat"><div class="num" style="color:#f80">%HIGH%</div><div class="label">High</div></div>
    <div class="stat"><div class="num" style="color:#e5a000">%MEDIUM%</div><div class="label">Medium</div></div>
    <div class="stat"><div class="num">%SUCCESSFUL%</div><div class="label">Successful</div></div>
    <div class="stat"><div class="num">%MITIGATED%</div><div class="label">Mitigated</div></div>
  </div>
</div>

<h2>2. Attack Timeline</h2>
<table>
  <tr><th>Time</th><th>Attack</th><th>Technique</th><th>Severity</th><th>Status</th></tr>
  %TIMELINE_ROWS%
</table>

<h2>3. Detailed Findings</h2>
%DETAILED_FINDINGS%

<h2>4. Remediation Plan</h2>
%REMEDIATION_SECTION%

<h2>5. Affected Infrastructure</h2>
%AFFECTED_INFRA%

<h2>6. Security Recommendations</h2>
%RECOMMENDATIONS%

<h2>7. MITRE ATT&CK Mapping</h2>
<table>
  <tr><th>Technique</th><th>Attack</th><th>MITRE ID</th><th>Tactic</th></tr>
  %MITRE_ROWS%
</table>

<div class="footer">
  %TITLE% — Report ID: %REPORT_ID% — Generated %DATE%<br>
  Confidential — For authorized security personnel only
</div>

</body>
</html>"""


def severity_class(sev):
    sev = sev or "medium"
    sev = sev.lower()
    if sev in ("critical", "high", "medium", "low"):
        return sev
    return "medium"


def get_affected_infra_html():
    return """
<table>
  <tr><th>Component</th><th>Container</th><th>Image</th><th>Risk</th><th>Exposure</th></tr>
  <tr class="severity-critical">
    <td>Web Application</td><td>vuln-app</td><td>python:3.11-slim</td><td>CRITICAL</td>
    <td>Public port 8080, CAP_SYS_ADMIN, docker.sock mounted, seccomp unconfined</td>
  </tr>
  <tr class="severity-high">
    <td>Docker Socket</td><td>vuln-app / ai-attacker</td><td>host</td><td>HIGH</td>
    <td>/var/run/docker.sock mounted read-write — full host control</td>
  </tr>
  <tr class="severity-critical">
    <td>Host Shadow File</td><td>vuln-app</td><td>host file</td><td>CRITICAL</td>
    <td>/etc/shadow mounted at /etc/host-shadow:ro — credential exposure</td>
  </tr>
  <tr class="severity-high">
    <td>Elasticsearch</td><td>elasticsearch</td><td>elasticsearch:8.12.0</td><td>HIGH</td>
    <td>No authentication, exposed on container network (port 9200)</td>
  </tr>
  <tr class="severity-high">
    <td>Kibana</td><td>kibana</td><td>kibana:8.12.0</td><td>HIGH</td>
    <td>No authentication, exposed on container network (port 5601)</td>
  </tr>
  <tr class="severity-high">
    <td>Network</td><td>all containers</td><td>pentest-net bridge</td><td>HIGH</td>
    <td>No network policies — all containers can reach each other</td>
  </tr>
  <tr class="severity-medium">
    <td>AI Attacker</td><td>ai-attacker</td><td>python:3.11-slim</td><td>MEDIUM</td>
    <td>docker.sock mounted, NET_ADMIN + NET_RAW capabilities</td>
  </tr>
</table>
"""


def get_recommendations_html():
    return """
<ol>
  <li><strong>Immediate: Remove Docker socket mounts</strong> — Unmount /var/run/docker.sock from all containers. Use Docker API proxies with authentication if remote access is needed.</li>
  <li><strong>Immediate: Drop unnecessary capabilities</strong> — Remove CAP_SYS_ADMIN, NET_ADMIN, NET_RAW, SYS_PTRACE from all containers. Use --cap-drop ALL and add back only what's needed.</li>
  <li><strong>Immediate: Enable seccomp and AppArmor</strong> — Never use seccomp=unconfined. Apply Docker's default seccomp profile which blocks 44+ dangerous syscalls.</li>
  <li><strong>Short-term: Network segmentation</strong> — Use separate Docker networks per application tier. Disable inter-container communication where not needed.</li>
  <li><strong>Short-term: Enable authentication</strong> — Add authentication to Elasticsearch and Kibana. Use Docker secrets for credential management.</li>
  <li><strong>Short-term: Read-only filesystems</strong> — Mount container filesystems as read-only where possible. Use --read-only flag.</li>
  <li><strong>Long-term: User namespace remapping</strong> — Enable userns-remap in Docker daemon to add an extra isolation layer.</li>
  <li><strong>Long-term: Runtime security monitoring</strong> — Deploy Falco in production with alerting to detect container escape attempts in real-time.</li>
  <li><strong>Long-term: Image scanning</strong> — Scan all container images for vulnerabilities before deployment. Use tools like Trivy or Snyk.</li>
  <li><strong>Long-term: Principle of least privilege</strong> — Review all container configurations. Every capability, mount, and network setting should be justified.</li>
</ol>
"""


def generate_report(attack_logs, output_format="html"):
    now = datetime.utcnow().isoformat()
    report_id = "CR-%s-%s" % (now[:10].replace("-", ""), str(int(time.time()))[-6:])

    total = len(attack_logs)
    critical = sum(1 for a in attack_logs if a.get("severity") == "critical")
    high = sum(1 for a in attack_logs if a.get("severity") == "high")
    medium = sum(1 for a in attack_logs if a.get("severity") == "medium")
    successful = sum(1 for a in attack_logs if a.get("status") == "success")

    # Build timeline rows
    timeline = ""
    for a in attack_logs:
        ts = a.get("@timestamp", a.get("timestamp", "unknown"))[:19]
        name = a.get("attack_name", "Unknown")
        tech = a.get("technique", "Unknown")
        sev = a.get("severity", "medium")
        status = a.get("status", "unknown")
        timeline += '<tr class="severity-%s"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' % (
            severity_class(sev), ts, name, tech, sev.upper(), status)

    # Build detailed findings
    findings = ""
    for a in attack_logs:
        sev = a.get("severity", "medium")
        findings += '''
<div class="finding %s">
  <div class="header">%s</div>
  <div class="meta">Technique: %s | MITRE: %s | Status: %s | Severity: %s</div>
  <div class="body">
    <p><strong>Detail:</strong> %s</p>
    <p><strong>AI Analysis:</strong></p>
    <pre>%s</pre>
  </div>
</div>''' % (severity_class(sev),
             a.get("attack_name", "Unknown"),
             a.get("technique", "Unknown"),
             a.get("mitre_technique", "Unknown"),
             a.get("status", "Unknown"),
             sev.upper(),
             a.get("detail", "N/A"),
             a.get("analysis", "No AI analysis available")[:2000])

    # Build MITRE rows
    mitre_rows = ""
    seen_mitre = set()
    for a in attack_logs:
        mt = a.get("mitre_technique", "")
        if mt and mt not in seen_mitre:
            seen_mitre.add(mt)
            parts = mt.split(" - ", 1)
            mitre_id = parts[0] if len(parts) > 1 else mt
            tactic = parts[1] if len(parts) > 1 else ""
            mitre_rows += "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (
                mt, a.get("attack_name", ""), mitre_id, tactic)

    # Exec summary
    exec_summary = (
        "This report presents the findings from an automated container security assessment conducted by the "
        "ContainerSec AI Agent against the target environment. A total of <strong>%d</strong> attack scenarios "
        "were executed, targeting container escape techniques, privilege escalation vectors, and inter-container "
        "attack patterns commonly observed in production containerized environments. "
        "<strong>%d</strong> attacks were successful, with <strong>%d critical</strong> and "
        "<strong>%d high</strong> severity findings identified. "
        "The assessment reveals significant container security gaps including exposed Docker sockets, "
        "excessive capabilities, missing security profiles, and inadequate network segmentation.") % (
        total, successful, critical, high)

    affected_infra = get_affected_infra_html()
    recommendations = get_recommendations_html()

    remediation_section = """
<div class="remediation">
  <h4>Priority 1: Critical (Immediate Action Required)</h4>
  <ol>
    <li><strong>Remove Docker socket mounts</strong> — All containers with /var/run/docker.sock mounts must be reconfigured immediately.</li>
    <li><strong>Drop CAP_SYS_ADMIN</strong> — Remove this capability from all containers. Replace with granular capabilities.</li>
    <li><strong>Apply seccomp profile</strong> — Remove seccomp=unconfined and apply default Docker seccomp profile.</li>
    <li><strong>Restrict volume mounts</strong> — Remove sensitive host path mounts (especially /etc/shadow, /root/.ssh).</li>
  </ol>
</div>
<div class="remediation">
  <h4>Priority 2: High (Action Required Within 48 Hours)</h4>
  <ol>
    <li><strong>Network segmentation</strong> — Separate containers into different networks based on trust levels.</li>
    <li><strong>Enable authentication</strong> — Add auth to Elasticsearch, Kibana, and all data stores.</li>
    <li><strong>Drop NET_ADMIN/NET_RAW</strong> — Remove network-related capabilities from non-network containers.</li>
    <li><strong>Read-only filesystems</strong> — Use --read-only flag for all stateless containers.</li>
  </ol>
</div>
<div class="remediation">
  <h4>Priority 3: Medium (Schedule Within 2 Weeks)</h4>
  <ol>
    <li><strong>User namespace remapping</strong> — Enable userns-remap in Docker daemon configuration.</li>
    <li><strong>Image scanning</strong> — Integrate container image scanning into CI/CD pipeline.</li>
    <li><strong>Audit logging</strong> — Enable Docker audit logging and ship to centralized logging.</li>
    <li><strong>Runtime detection</strong> — Deploy Falco or similar runtime security tool with alerting.</li>
  </ol>
</div>
"""

    html = REPORT_TEMPLATE
    replacements = {
        "%TITLE%": "Container Security Assessment Report",
        "%SUBTITLE%": "AI-Powered Automated Penetration Testing — Detailed Findings & Remediation",
        "%CLASSIFICATION%": "CONFIDENTIAL",
        "%REPORT_ID%": report_id,
        "%DATE%": now[:19],
        "%TARGET%": "Containerized Web Application Stack",
        "%ENGINE%": "ContainerSec AI Agent v1.0 (Claude Sonnet 4)",
        "%ANALYST%": "AI Security Agent (Claude-powered)",
        "%EXEC_SUMMARY%": exec_summary,
        "%TOTAL_ATTACKS%": str(total),
        "%CRITICAL%": str(critical),
        "%HIGH%": str(high),
        "%MEDIUM%": str(medium),
        "%SUCCESSFUL%": str(successful),
        "%MITIGATED%": str(len(attack_logs) - successful),
        "%TIMELINE_ROWS%": timeline,
        "%DETAILED_FINDINGS%": findings,
        "%REMEDIATION_SECTION%": remediation_section,
        "%AFFECTED_INFRA%": affected_infra,
        "%RECOMMENDATIONS%": recommendations,
        "%MITRE_ROWS%": mitre_rows,
        "%REMED_PAGE%": "5",
        "%AFFECTED_PAGE%": "6",
        "%RECOMMEND_PAGE%": "7",
        "%MITRE_PAGE%": "8",
    }
    for k, v in replacements.items():
        html = html.replace(k, v)

    return html, report_id
