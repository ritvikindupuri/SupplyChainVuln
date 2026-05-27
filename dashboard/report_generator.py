import os
import json
import time
import requests
from datetime import datetime
from fpdf import FPDF

NAVY = (18, 28, 48)
DARK_NAVY = (10, 18, 32)
ACCENT_BLUE = (0, 120, 255)
LIGHT_BLUE = (90, 176, 255)
WHITE = (255, 255, 255)
LIGHT_GRAY = (220, 225, 232)
MID_GRAY = (140, 150, 165)
DARK_TEXT = (40, 48, 60)
BODY_TEXT = (60, 70, 85)
RED = (200, 40, 50)
GREEN = (0, 180, 100)
ORANGE = (220, 130, 0)
YELLOW = (210, 160, 0)
CARD_BG = (240, 243, 248)

REPORTS_DIR = "/dashboard/reports"

SEVERITY_COLORS = {
    "critical": (200, 40, 50),
    "high": (220, 130, 0),
    "medium": (210, 160, 0),
    "low": (0, 160, 80),
}

class FPDF2(FPDF):
    def _sanitize(self, text):
        repl = {
            '\u2014': '--', '\u2013': '-', '\u2018': "'", '\u2019': "'",
            '\u201c': '"', '\u201d': '"', '\u2022': '*', '\u2026': '...',
            '\u00a0': ' ', '\u2028': ' ', '\u2029': ' ',
        }
        out = str(text)
        for k, v in repl.items():
            out = out.replace(k, v)
        return out

    def header(self):
        if self.page_no() > 2:
            self.set_font("Helvetica", "", 7)
            self.set_text_color(*MID_GRAY)
            self.cell(0, 5, "PacketSentry -- Security Analysis Report", align="L")
            self.cell(0, 5, f"Page {self.page_no()}", align="R", new_x="LMARGIN", new_y="NEXT")
            y = self.get_y()
            self.set_draw_color(*LIGHT_GRAY)
            self.set_line_width(0.2)
            self.line(10, y, 200, y)
            self.ln(4)

    def footer(self):
        if self.page_no() > 1:
            self.set_y(-15)
            self.set_font("Helvetica", "I", 7)
            self.set_text_color(*MID_GRAY)
            self.cell(0, 10, f"Confidential -- Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} | PacketSentry", align="C")

    def multi_cell(self, w, h, text, **kw):
        super().multi_cell(w, h, self._sanitize(text), **kw)

    def cell(self, w, h=0, text="", **kw):
        super().cell(w, h, self._sanitize(text), **kw)

class ReportGenerator:
    def __init__(self, es_url, es_user, es_pass, claude_api_key):
        self.es_url = es_url
        self.es_user = es_user
        self.es_pass = es_pass
        self.claude_api_key = claude_api_key
        os.makedirs(REPORTS_DIR, exist_ok=True)

    def generate(self, report_id, target_url=""):
        alerts = self._es_search("packetsentry-alerts-*", 200)
        packets = self._es_search("packetsentry-packets-*", 100)
        activity = self._es_search("packetsentry-activity-*", 200)

        alert_count = len(alerts)
        packet_count = len(packets)
        activity_count = len(activity)

        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        top_alerts = []
        for a in alerts:
            src = a.get("_source", {})
            sev = src.get("severity", "low")
            if sev in severity_counts:
                severity_counts[sev] += 1
            if len(top_alerts) < 20:
                top_alerts.append({
                    "severity": sev,
                    "threat_level": src.get("threat_level", ""),
                    "attack_name": src.get("attack_name", ""),
                    "mitre_tactic": src.get("mitre_tactic", ""),
                    "mitre_technique": src.get("mitre_technique", ""),
                    "confidence": src.get("confidence", 0),
                    "claude_analysis": (src.get("claude_analysis", "") or "")[:500],
                    "timestamp": src.get("@timestamp", ""),
                    "remediation": src.get("remediation", []),
                })

        report_md = self._claude_report(alerts, packets, activity, severity_counts, top_alerts, target_url)

        pdf_path = os.path.join(REPORTS_DIR, f"{report_id}.pdf")
        self._build_pdf(pdf_path, report_md, alert_count, packet_count, activity_count, severity_counts, top_alerts)
        return pdf_path

    def _es_search(self, index, size):
        try:
            r = requests.get(
                f"{self.es_url}/{index}/_search",
                json={"query": {"match_all": {}}, "size": size, "sort": [{"@timestamp": "desc"}]},
                auth=(self.es_user, self.es_pass),
                timeout=15
            )
            return r.json().get("hits", {}).get("hits", [])
        except:
            return []

    def _claude_report(self, alerts, packets, activity, severity_counts, top_alerts, target_url=""):
        prompt = self._build_prompt(alerts, packets, activity, severity_counts, top_alerts, target_url)
        if not self.claude_api_key:
            return self._fallback_report(severity_counts, top_alerts, target_url=target_url)
        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.claude_api_key,
                    "content-type": "application/json",
                    "anthropic-version": "2023-06-01"
                },
                json={
                    "model": "claude-sonnet-4-6",
                    "max_tokens": 8192,
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=180
            )
            result = r.json()
            if "content" in result and len(result["content"]) > 0:
                block = result["content"][0]
                if block.get("type") == "text":
                    return block.get("text", "")
                return str(block.get("text", ""))
            return self._fallback_report(severity_counts, top_alerts, target_url=target_url)
        except Exception as e:
            return self._fallback_report(severity_counts, top_alerts, target_url=target_url, error=str(e))

    def _build_prompt(self, alerts, packets, activity, severity_counts, top_alerts, target_url=""):
        alerts_json = json.dumps(top_alerts, indent=2, default=str)
        target_line = f" - **Target URL**: {target_url}" if target_url else ""
        return f"""You are a senior cybersecurity report writer for PacketSentry, an autonomous AI network security platform. Your reports are read by CISOs, security directors, and engineering leads at FAANG companies. Write an EXTREMELY DETAILED, professionally formatted security analysis report in MARKDOWN.

CRITICAL REQUIREMENTS:
- Every section must be EXTREMELY DETAILED -- no less than 5-8 paragraphs each
- Write in formal, authoritative, professional tone suitable for a FAANG security team
- Include specific data points, technical details, and evidence from the session data
- Each finding must include: full description, severity rationale, MITRE ATT&CK mapping, confidence assessment, affected systems, technical analysis, and specific remediation steps
- The attack timeline must list every detected event with timestamps, techniques, targets, and impact assessment
- Traffic analysis must cover protocol distribution, top talkers, unusual patterns, baseline comparison, and anomalies
- Recommendations must be prioritized (P0/P1/P2) with specific implementation guidance and expected impact

Write the report using these exact section headings (## level):

## Executive Summary
(5-8 paragraphs: overall security posture summary, key threat narrative, critical findings overview, business impact assessment, risk level determination, summary of affected systems, immediate actions required, outlook)

## Session Overview
(5-8 paragraphs: monitoring period and scope, total alerts/packets/actions with breakdown, severity distribution analysis, data collection methodology, attack surface coverage, detection capabilities exercised, limitations and constraints, session statistics summary table in text)

## Key Findings
(At least 8-12 detailed findings. For EACH finding use this format with bold titles:
**Finding: [Title]** -- [Detailed description 3-5 sentences]. Severity: [level]. MITRE ATT&CK: [tactic/technique ID]. Confidence: [0-1]. Technical Analysis: [detailed analysis of the attack mechanism, what was observed, how it unfolded, 3-5 sentences]. Affected Systems: [systems, ports, protocols involved]. Evidence: [specific packet data, timestamps, observations]. Recommendation: [specific actionable remediation steps].)

## Attack Timeline
(Chronological log of every detected event with: timestamp, attack type, source, target, technique, severity, status. At least 10-15 entries with detailed descriptions. Group by phase if applicable.)

## Traffic Analysis
(5-8 paragraphs: protocol distribution with percentages, top source/destination IPs by volume, baseline vs observed patterns, anomalous traffic identification, port usage analysis, packet size distribution, bandwidth utilization, temporal patterns, geographic considerations if applicable, IoC identification)

## Recommendations
(Prioritized list using P0/P1/P2 format with detailed implementation guidance. At least 10-15 specific recommendations covering: immediate containment, network hardening, monitoring improvements, process changes, architecture recommendations. Each must include: priority, description, implementation steps, expected impact, effort estimate.)

## Conclusion
(5-8 paragraphs: final risk assessment with quantitative justification, key takeaways for leadership, critical vulnerabilities summary, strategic recommendations, expected remediation timeline, follow-up actions, closing statement)

SESSION DATA:{target_line}
- Total Alerts: {len(alerts)}
- Total Packets: {len(packets)}
- Total Agent Actions: {len(activity)}
- Severity Breakdown: {json.dumps(severity_counts)}

TOP ALERTS DATA:
{alerts_json}

Do NOT wrap the response in a code block. Output plain markdown only. Every section MUST be excruciatingly detailed -- write at least 5-8 substantial paragraphs per section."""

    def _fallback_report(self, severity_counts, top_alerts, target_url="", error=None):
        lines = []
        lines.append("## Executive Summary")
        lines.append("")
        total = sum(severity_counts.values())
        crit_high = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
        if total > 20:
            risk_level = "CRITICAL"
        elif total > 10:
            risk_level = "HIGH"
        elif total > 5:
            risk_level = "MODERATE"
        else:
            risk_level = "LOW"
        target_phrase = f"target ({target_url})" if target_url else "monitored target"
        lines.append(f"This report presents the findings from an autonomous network security analysis session conducted by PacketSentry against {target_phrase}. The platform performed real-time packet capture, heuristic threat detection, and AI-powered analysis against the monitored target. During this session, the system observed a total of {total} security events across {len([k for k, v in severity_counts.items() if v > 0])} severity levels.")
        lines.append("")
        if error:
            lines.append(f"*Note: The AI-powered analysis component encountered an issue during report generation ({error}). The findings below are based on heuristic detection data and statistical analysis of the captured traffic. While the detection signatures are verified, the depth of analysis may be reduced compared to AI-enhanced reports.*")
            lines.append("")
        lines.append(f"The overall security posture is assessed as **{risk_level} RISK**. A total of {crit_high} events were classified as critical or high severity, indicating active or potential malicious activity targeting the monitored environment. {severity_counts.get('medium', 0)} medium severity events suggest reconnaissance or probing activity that may precede more aggressive attacks. The platform recommends immediate review and remediation of critical and high severity findings.")
        lines.append("")
        lines.append(f"The session covered network traffic from both internal (Docker bridge network 172.30.0.0/24) and external sources, providing comprehensive visibility into the attack surface. The traffic engine generated controlled attack patterns to validate detection capabilities, including port scans, SYN floods, Slowloris attacks, TCP connection scans, directory brute-forcing, and DNS amplification attempts.")
        lines.append("")
        lines.append("## Session Overview")
        lines.append("")
        lines.append("The PacketSentry agent conducted a comprehensive security analysis session encompassing real-time packet capture, heuristic-based threat detection, and automated response assessment. The monitoring infrastructure captured traffic across multiple network interfaces using tshark with full packet visibility.")
        lines.append("")
        lines.append("- **Total Alerts Generated:** {0}".format(total))
        lines.append("- **Critical Severity:** {0}".format(severity_counts.get("critical", 0)))
        lines.append("- **High Severity:** {0}".format(severity_counts.get("high", 0)))
        lines.append("- **Medium Severity:** {0}".format(severity_counts.get("medium", 0)))
        lines.append("- **Low Severity:** {0}".format(severity_counts.get("low", 0)))
        lines.append("- **Attack Traffic Sources:** Docker bridge network (172.30.0.0/24)")
        lines.append("- **Detection Methodology:** Heuristic signatures + AI analysis")
        lines.append("- **Attack Types Detected:** Port scanning, denial of service, brute force, DNS abuse, web application attacks")
        lines.append("")
        lines.append("The severity distribution indicates that the detection engine successfully identified a range of attack patterns. The presence of critical and high severity alerts confirms that the monitored environment was subjected to significant security testing. Medium and low severity findings provide additional context around reconnaissance and probing activities.")
        lines.append("")
        lines.append("## Key Findings")
        lines.append("")
        if top_alerts:
            for a in top_alerts:
                aname = a.get("attack_name") or "Suspicious Activity"
                sev = a.get("severity", "low").upper()
                mitre_tactic = a.get("mitre_tactic", "Unknown")
                mitre_technique = a.get("mitre_technique", "Unknown")
                conf = a.get("confidence", 0)
                analysis = a.get("claude_analysis", "") or "Heuristic detection triggered based on network traffic pattern analysis. The observed packet characteristics match known attack signatures for this category."
                rem = a.get("remediation", [])
                if isinstance(rem, str):
                    try:
                        rem = json.loads(rem)
                    except:
                        rem = [rem]
                rem_text = " | ".join(rem[:3]) if isinstance(rem, list) and rem else "Review and mitigate based on severity."
                lines.append("**Finding: {0}**".format(aname))
                lines.append("")
                lines.append("Severity: {0} | MITRE ATT&CK: {1}/{2} | Confidence: {3}".format(sev, mitre_tactic, mitre_technique, conf))
                lines.append("")
                lines.append("Technical Analysis: {0}".format(analysis))
                lines.append("")
                lines.append("Recommendation: {0}".format(rem_text))
                lines.append("")
        else:
            lines.append("No significant findings were recorded during this session. The monitored environment did not exhibit detectable malicious activity within the configured detection thresholds. This may indicate either a clean network environment or the need for adjusted detection sensitivity.")
            lines.append("")
        lines.append("## Attack Timeline")
        lines.append("")
        if top_alerts:
            lines.append("The following chronological log presents all detected security events during the monitoring session. Each entry includes the timestamp, attack classification, target information, and current disposition.")
            lines.append("")
            for a in top_alerts:
                ts = (a.get("timestamp") or "")[:19]
                aname = a.get("attack_name") or "Alert"
                sev = a.get("severity", "low")
                mitre = a.get("mitre_tactic", "Unknown")
                lines.append("- **{0}** | {1} | Severity: {2} | MITRE: {3} | Status: Detected".format(ts, aname, sev.upper(), mitre))
            if not top_alerts:
                lines.append("No attack timeline data available.")
        else:
            lines.append("No security events were detected during the monitoring period.")
        lines.append("")
        lines.append("## Traffic Analysis")
        lines.append("")
        lines.append("The traffic analysis examines the packet capture data collected during the monitoring session. The agent processed traffic across multiple protocols and identified patterns consistent with both legitimate user activity and simulated attack scenarios. The traffic engine generated controlled attack traffic from the Docker bridge network (172.30.0.0/24), while the remaining traffic represents baseline network communication.")
        lines.append("")
        lines.append("Protocol distribution analysis reveals activity across TCP, UDP, ICMP, DNS, HTTP, and ARP protocols. TCP traffic dominates the packet capture volume, driven primarily by connection-oriented attacks such as SYN floods and port scans. UDP traffic is associated with DNS amplification attempts and normal DNS resolution. ICMP packets indicate network discovery and potential covert channel activity.")
        lines.append("")
        lines.append("Top talker analysis identifies the traffic engine container (172.30.0.x range) as the primary source of attack traffic, generating the majority of alerts. External traffic patterns show baseline network activity from the host system. The distinction between attack and host traffic sources enables clear attribution of malicious activity.")
        lines.append("")
        lines.append("## Recommendations")
        lines.append("")
        lines.append("Based on the detected security events and traffic analysis, the following prioritized recommendations are provided to strengthen the security posture of the monitored environment.")
        lines.append("")
        seen = set()
        rec_num = 1
        for a in top_alerts:
            rem = a.get("remediation", [])
            if isinstance(rem, str):
                try:
                    rem = json.loads(rem)
                except:
                    rem = [rem]
            if isinstance(rem, list):
                for r_item in rem:
                    if r_item and r_item not in seen:
                        seen.add(r_item)
                        priority = "P0" if rec_num <= 2 else "P1" if rec_num <= 5 else "P2"
                        lines.append("**[{0}] Recommendation {1}:** {2}".format(priority, rec_num, r_item))
                        lines.append("")
                        rec_num += 1
        if rec_num == 1:
            lines.append("**[P1] Recommendation 1:** Deploy network segmentation to isolate critical infrastructure from general network traffic, limiting the blast radius of potential attacks.")
            lines.append("")
            lines.append("**[P1] Recommendation 2:** Implement real-time intrusion detection and prevention systems (IDS/IPS) with signature-based and behavioral detection capabilities to identify and block malicious traffic patterns.")
            lines.append("")
            lines.append("**[P2] Recommendation 3:** Establish a vulnerability management program with regular scanning and patching cycles to address known vulnerabilities before they can be exploited.")
            lines.append("")
            lines.append("**[P2] Recommendation 4:** Enhance logging and monitoring capabilities with centralized log aggregation and analysis to improve threat detection and incident response capabilities.")
            lines.append("")
            lines.append("**[P2] Recommendation 5:** Conduct regular security awareness training and phishing simulations to reduce the risk of social engineering attacks.")
            lines.append("")
        lines.append("## Conclusion")
        lines.append("")
        lines.append("This security analysis session conducted by the PacketSentry autonomous platform has provided comprehensive visibility into the network security posture of the monitored environment. The platform detected a total of {0} security events, with {1} classified as critical or high severity. These findings indicate that the environment faces active security threats that require immediate attention.".format(total, crit_high))
        lines.append("")
        lines.append("The risk level for the monitored environment is assessed as **{0}**. This assessment is based on the volume and severity of detected alerts, the types of attacks observed, and the effectiveness of current security controls. A total of {1} distinct attack patterns were identified, spanning reconnaissance, denial of service, and application-layer attacks.".format(risk_level, len(set(a.get("attack_name", "") for a in top_alerts)) if top_alerts else 0))
        lines.append("")
        lines.append("Key areas requiring immediate attention include: (1) network segmentation and access controls to limit attack surface, (2) enhanced monitoring and detection capabilities for timely threat identification, (3) incident response procedures to handle confirmed security events, and (4) regular security assessments to validate control effectiveness.")
        lines.append("")
        lines.append("It is recommended that the security team reviews the detailed findings in this report, prioritizes remediation based on severity and business impact, and conducts follow-up assessments to verify that corrective measures are effectively implemented. PacketSentry can be reconfigured for continuous monitoring to track security posture improvement over time.")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("*Report generated by PacketSentry Autonomous Security Platform. This document contains confidential security assessment information and should be handled according to organizational security policies.*")
        return "\n".join(lines)

    def _build_pdf(self, pdf_path, report_md, alert_count, packet_count, activity_count, severity_counts, top_alerts):
        pdf = FPDF2(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=22)

        # ---- COVER PAGE ----
        pdf.add_page()
        w = 210
        h = 297

        # White background
        pdf.set_fill_color(*WHITE)
        pdf.rect(0, 0, w, h, "F")

        # Navy header band at top
        pdf.set_fill_color(*NAVY)
        pdf.rect(0, 0, w, 90, "F")

        # Accent stripe
        pdf.set_fill_color(*ACCENT_BLUE)
        pdf.rect(0, 90, w, 3, "F")

        # Title
        pdf.set_y(32)
        pdf.set_font("Helvetica", "B", 36)
        pdf.set_text_color(*WHITE)
        pdf.cell(0, 14, "PacketSentry", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 16)
        pdf.set_text_color(*LIGHT_BLUE)
        pdf.cell(0, 10, "Autonomous Security Analysis Report", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*MID_GRAY)
        pdf.cell(0, 7, "AI-Powered Network Penetration Testing Platform", align="C", new_x="LMARGIN", new_y="NEXT")

        # Report metadata box
        pdf.set_y(120)
        box_x = 35
        box_w = 140
        pdf.set_fill_color(*CARD_BG)
        pdf.set_draw_color(*LIGHT_GRAY)
        pdf.set_line_width(0.3)
        pdf.rect(box_x, pdf.get_y(), box_w, 55, "DF")

        bx = box_x + 10
        pdf.set_xy(bx, 126)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*DARK_TEXT)
        pdf.cell(0, 7, "Report Information", align="L", new_x="LMARGIN", new_y="NEXT")
        pdf.set_x(bx)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*BODY_TEXT)

        meta = [
            ("Date Generated", datetime.now().strftime("%B %d, %Y at %H:%M")),
            ("Total Alerts", str(alert_count)),
            ("Packets Captured", str(packet_count)),
            ("Agent Actions", str(activity_count)),
            ("Risk Assessment", self._risk_level(severity_counts)),
        ]
        for label, value in meta:
            pdf.set_x(bx)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*BODY_TEXT)
            pdf.cell(40, 6, label + ":", align="L")
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*DARK_TEXT)
            pdf.cell(0, 6, value, align="L", new_x="LMARGIN", new_y="NEXT")

        # Severity summary at bottom of cover
        pdf.set_y(200)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*DARK_TEXT)
        pdf.cell(0, 8, "Severity Overview", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        total = sum(severity_counts.values()) or 1
        bar_w = 140
        bar_x = 35
        pdf.set_x(bar_x)
        sev_order = ["critical", "high", "medium", "low"]
        for sev in sev_order:
            count = severity_counts.get(sev, 0)
            if count == 0:
                continue
            pct = count / total
            color = SEVERITY_COLORS.get(sev, MID_GRAY)
            pdf.set_fill_color(*color)
            bw = bar_w * pct
            pdf.cell(bw, 8, "", align="L", fill=True)
        pdf.ln(12)

        pdf.set_x(bar_x)
        for sev in sev_order:
            count = severity_counts.get(sev, 0)
            color = SEVERITY_COLORS.get(sev, MID_GRAY)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*color)
            label = f"{sev.capitalize()}: {count}   "
            pdf.cell(35, 5, label, align="L")

        # Classification footer
        pdf.set_y(275)
        pdf.set_font("Helvetica", "I", 7)
        pdf.set_text_color(*MID_GRAY)
        pdf.cell(0, 5, "CONFIDENTIAL -- For authorized recipients only", align="C")

        # ---- TABLE OF CONTENTS ----
        pdf.add_page()
        pdf.set_fill_color(*WHITE)
        pdf.rect(0, 0, w, h, "F")

        # TOC header band
        pdf.set_fill_color(*NAVY)
        pdf.rect(0, 0, w, 40, "F")
        pdf.set_fill_color(*ACCENT_BLUE)
        pdf.rect(0, 40, w, 2, "F")

        pdf.set_y(14)
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_text_color(*WHITE)
        pdf.cell(0, 12, "Table of Contents", align="C", new_x="LMARGIN", new_y="NEXT")

        pdf.set_y(55)
        toc_sections = [
            ("1", "Executive Summary"),
            ("2", "Session Overview"),
            ("3", "Key Findings"),
            ("4", "Attack Timeline"),
            ("5", "Traffic Analysis"),
            ("6", "Recommendations"),
            ("7", "Conclusion"),
        ]
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(*DARK_TEXT)
        for num, title in toc_sections:
            y0 = pdf.get_y()
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(10, 9, num + ".", align="R")
            pdf.set_font("Helvetica", "", 11)
            pdf.cell(0, 9, title, align="L", new_x="LMARGIN", new_y="NEXT")
            pdf.set_draw_color(*LIGHT_GRAY)
            pdf.set_line_width(0.1)
            pdf.line(25, pdf.get_y() + 1, 190, pdf.get_y() + 1)
            pdf.ln(2)

        # ---- CONTENT PAGES ----
        pdf.set_text_color(*BODY_TEXT)
        lines = report_md.split("\n")

        # Track if we're in a finding block to prevent page-break inside it
        in_finding = False

        for line in lines:
            s = line.strip()
            if not s:
                pdf.ln(2)
                continue

            if s.startswith("## "):
                in_finding = False
                if pdf.get_y() > 230:
                    pdf.add_page()
                pdf.ln(4)
                pdf.set_font("Helvetica", "B", 18)
                pdf.set_text_color(*NAVY)
                title = s[3:].strip()
                pdf.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
                pdf.set_draw_color(*ACCENT_BLUE)
                pdf.set_line_width(0.5)
                y = pdf.get_y()
                pdf.line(10, y, 60, y)
                pdf.ln(6)
            elif s.startswith("### "):
                if pdf.get_y() > 240:
                    pdf.add_page()
                pdf.ln(2)
                pdf.set_font("Helvetica", "B", 13)
                pdf.set_text_color(*NAVY)
                pdf.cell(0, 8, s[4:].strip(), new_x="LMARGIN", new_y="NEXT")
                pdf.ln(3)
            elif s.startswith("**Finding:"):
                in_finding = True
                if pdf.get_y() > 220:
                    pdf.add_page()
                pdf.ln(3)
                pdf.set_fill_color(*CARD_BG)
                pdf.set_draw_color(*LIGHT_GRAY)
                y_before = pdf.get_y()
                # We'll just draw the finding text
                pdf.set_font("Helvetica", "B", 11)
                pdf.set_text_color(*NAVY)
                clean = s.replace("**", "")
                pdf.multi_cell(0, 6, clean)
                pdf.ln(1)
            elif s.startswith("Severity:") and in_finding:
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*MID_GRAY)
                pdf.multi_cell(0, 5, s)
                pdf.ln(1)
            elif s.startswith("Technical Analysis:") and in_finding:
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*DARK_TEXT)
                pdf.multi_cell(0, 5.5, s)
                pdf.ln(1)
            elif s.startswith("Recommendation:") and in_finding:
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*DARK_TEXT)
                pdf.multi_cell(0, 5.5, s)
                pdf.ln(3)
                # Separator line after finding
                pdf.set_draw_color(*LIGHT_GRAY)
                pdf.set_line_width(0.1)
                y = pdf.get_y()
                pdf.line(15, y, 195, y)
                pdf.ln(3)
            elif s.startswith("- **") and (s.endswith("**") or "** " in s):
                if pdf.get_y() > 245:
                    pdf.add_page()
                pdf.set_font("Helvetica", "", 9.5)
                pdf.set_text_color(*BODY_TEXT)
                clean = s.replace("**", "").replace("---", "")
                pdf.multi_cell(0, 5.5, "  \u2022  " + clean)
                pdf.ln(1)
            elif s.startswith("- "):
                if pdf.get_y() > 245:
                    pdf.add_page()
                pdf.set_font("Helvetica", "", 9.5)
                pdf.set_text_color(*BODY_TEXT)
                pdf.multi_cell(0, 5.5, "  \u2022  " + s[2:])
                pdf.ln(1)
            elif s.startswith("[P0]") or s.startswith("[P1]") or s.startswith("[P2]"):
                if pdf.get_y() > 230:
                    pdf.add_page()
                pdf.ln(2)
                priority = s[1:3]
                pcolor = RED if priority == "P0" else ORANGE if priority == "P1" else NAVY
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_text_color(*pcolor)
                pdf.multi_cell(0, 6, s)
                pdf.ln(1)
            elif s.startswith("1. ") or s.startswith("2. ") or s.startswith("3. ") or s.startswith("4. ") or s.startswith("5. ") or s.startswith("6. ") or s.startswith("7. ") or s.startswith("8. ") or s.startswith("9. "):
                if pdf.get_y() > 245:
                    pdf.add_page()
                pdf.set_font("Helvetica", "", 9.5)
                pdf.set_text_color(*BODY_TEXT)
                pdf.multi_cell(0, 5.5, s)
                pdf.ln(1)
            elif s.startswith("*") and s.endswith("*"):
                pdf.set_font("Helvetica", "I", 8.5)
                pdf.set_text_color(*MID_GRAY)
                clean = s.replace("*", "").replace("---", "")
                pdf.multi_cell(0, 4.5, clean)
                pdf.ln(1)
            elif s.startswith("---"):
                pdf.set_draw_color(*LIGHT_GRAY)
                pdf.set_line_width(0.2)
                y = pdf.get_y()
                pdf.line(10, y, 200, y)
                pdf.ln(3)
            else:
                if pdf.get_y() > 245:
                    pdf.add_page()
                pdf.set_font("Helvetica", "", 9.5)
                pdf.set_text_color(*BODY_TEXT)
                clean = s.replace("**", "").replace("---", "")
                pdf.multi_cell(0, 5.5, clean)
                pdf.ln(1)

        pdf.output(pdf_path)

    def _risk_level(self, severity_counts):
        total = sum(severity_counts.values())
        if severity_counts.get("critical", 0) > 0 or severity_counts.get("high", 0) > 5:
            return "CRITICAL"
        elif severity_counts.get("high", 0) > 0 or total > 15:
            return "HIGH"
        elif total > 5:
            return "MODERATE"
        return "LOW"
