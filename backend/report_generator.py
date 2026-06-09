"""
SecureChain Analyst Report Generator
====================================
Produces a concise, analyst-focused PDF an analyst can act on:

  - Alert banner (overall risk + whether this repo warrants customer notification)
  - Customer Alert Summary (ready-to-send wording for the specific repo)
  - Per-Commit Findings Timeline (which commit introduced what, with evidence)
  - Scan coverage footnote (commits walked, clean commits skipped / tokens saved)

Built from real scan data only — no mock content.
"""

import re
from datetime import datetime
from fpdf import FPDF

NAVY = (17, 28, 51)
ACCENT = (0, 102, 204)
LIGHT = (224, 230, 240)
MIDGRAY = (120, 130, 145)
DARK = (38, 46, 60)
BODY = (55, 64, 80)
WHITE = (255, 255, 255)
CARD = (243, 246, 251)

SEV_COLOR = {
    "critical": (192, 38, 50),
    "high": (214, 122, 0),
    "medium": (200, 160, 0),
    "low": (0, 150, 80),
    "clean": (0, 150, 80),
    "noise": (120, 130, 145),
}


def _clean(text) -> str:
    if text is None:
        return ""
    out = str(text)
    repl = {
        "\u2014": "--", "\u2013": "-", "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"', "\u2022": "*", "\u2026": "...",
        "\u00a0": " ", "\u2028": " ", "\u2029": " ",
    }
    for k, v in repl.items():
        out = out.replace(k, v)
    return re.sub(r"[^\x00-\xff]", "", out)


class Report(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*MIDGRAY)
        self.cell(0, 5, "SecureChain -- Supply-Chain Recon Report (Analyst)", align="L")
        self.cell(0, 5, f"Page {self.page_no()}", align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*LIGHT)
        self.set_line_width(0.2)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-14)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*MIDGRAY)
        self.cell(0, 10, f"Confidential -- Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} | SecureChain", align="C")

    def cell(self, w, h=0, text="", **kw):
        super().cell(w, h, _clean(text), **kw)

    def multi_cell(self, w, h, text="", **kw):
        if w == 0 and (self.w - self.r_margin - self.get_x()) < 20:
            self.set_x(self.l_margin)
        super().multi_cell(w, h, _clean(text), **kw)


def _section(pdf: Report, title: str):
    if pdf.get_y() > 250:
        pdf.add_page()
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 9, title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(*ACCENT)
    pdf.set_line_width(0.5)
    y = pdf.get_y()
    pdf.line(10, y, 52, y)
    pdf.ln(4)


def _para(pdf: Report, text: str, size=10):
    pdf.set_font("Helvetica", "", size)
    pdf.set_text_color(*BODY)
    pdf.multi_cell(0, 5.4, text)
    pdf.ln(2)


def build_report(path: str, scan: dict, agg: dict):
    repo = scan.get("repo") or {}
    commits = scan.get("commits", [])
    overall = (agg.get("overall_risk") or "clean").lower()
    counts = agg.get("counts", {})
    flagged = agg.get("flagged_commits", [])
    iocs = agg.get("iocs", [])
    tokens_saved = scan.get("tokens_saved_commits", 0)
    repo_name = repo.get("repo", scan.get("repo_url", "n/a"))

    pdf = Report(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)

    # ---------------- Cover ----------------
    pdf.add_page()
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, 210, 70, "F")
    pdf.set_fill_color(*ACCENT)
    pdf.rect(0, 70, 210, 2.5, "F")
    pdf.set_y(20)
    pdf.set_font("Helvetica", "B", 30)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 13, "SecureChain", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 13)
    pdf.set_text_color(*LIGHT)
    pdf.cell(0, 8, "Software Supply-Chain Recon -- Analyst Report", align="C", new_x="LMARGIN", new_y="NEXT")

    # Alert banner
    pdf.set_y(86)
    risk_col = SEV_COLOR.get(overall, MIDGRAY)
    pdf.set_fill_color(*risk_col)
    pdf.rect(20, 86, 170, 20, "F")
    pdf.set_xy(20, 90)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*WHITE)
    alert_word = "CUSTOMER ALERT RECOMMENDED" if flagged else "NO ALERT REQUIRED"
    pdf.cell(170, 12, f"{overall.upper()} -- {alert_word}", align="C")

    # Details box
    pdf.set_y(116)
    pdf.set_fill_color(*CARD)
    pdf.set_draw_color(*LIGHT)
    pdf.rect(20, 116, 170, 72, "DF")
    pdf.set_xy(28, 121)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*DARK)
    pdf.cell(0, 7, "Scan Summary", new_x="LMARGIN", new_y="NEXT")
    meta = [
        ("Repository", repo_name),
        ("Repository URL", scan.get("repo_url", "n/a")),
        ("Commits Walked", str(len(commits))),
        ("Commits That Introduced Risk", str(len(flagged))),
        ("Clean Commits (AI Skipped)", f"{tokens_saved}  (token-efficient)"),
        ("Findings (C/H/M/L)", f"{counts.get('critical',0)} / {counts.get('high',0)} / {counts.get('medium',0)} / {counts.get('low',0)}"),
        ("Confirmed IOCs", str(len(iocs))),
        ("Date Generated", datetime.now().strftime("%B %d, %Y at %H:%M")),
    ]
    for label, value in meta:
        pdf.set_x(28)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*BODY)
        pdf.cell(58, 6, label + ":")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*DARK)
        pdf.cell(0, 6, str(value)[:60], new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(272)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(*MIDGRAY)
    pdf.cell(0, 5, "CONFIDENTIAL -- For authorized analysts only", align="C")

    # ---------------- Customer Alert Summary ----------------
    pdf.add_page()
    _section(pdf, "Customer Alert Summary")
    if flagged:
        crit = counts.get("critical", 0)
        high = counts.get("high", 0)
        lead = (
            f"During monitoring of the public repository {repo_name}, SecureChain detected that "
            f"{len(flagged)} recent commit(s) introduced potential supply-chain risk "
            f"({crit} critical and {high} high-severity finding(s) after AI consensus validation). "
            "We recommend notifying the customer and reviewing the specific commits listed in the timeline below."
        )
        _para(pdf, lead)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*NAVY)
        pdf.cell(0, 6, "Ready-to-send summary:", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        pdf.set_fill_color(*CARD)
        pdf.set_draw_color(*LIGHT)
        start_y = pdf.get_y()
        pdf.set_xy(14, start_y + 3)
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(*BODY)
        for c in flagged[:6]:
            v = c.get("verdict") or {}
            pdf.set_x(16)
            pdf.multi_cell(0, 5,
                f"* Commit {c['short_sha']} ({c.get('author','')}) -- {v.get('commit_risk','').upper()}: "
                f"{v.get('summary','')}")
            pdf.ln(0.5)
    else:
        _para(pdf,
              f"SecureChain walked the {len(commits)} most recent commit(s) of {repo_name} and found that none of them "
              "introduced new supply-chain risk. No customer notification is required at this time. Continued monitoring "
              "is recommended, since the value of this tooling is catching risk introduced by future commits.")

    # ---------------- Indicators of Compromise (IOCs) ----------------
    _section(pdf, f"Indicators of Compromise (IOCs) -- {len(iocs)}")
    _para(pdf,
          "IOCs are matches against curated lists of known-bad indicators (malicious package names, "
          "C2 / exfiltration infrastructure, high-risk TLDs, and download-execute command patterns), each "
          "validated in context by the AI consensus. Note: SecureChain does not claim to detect zero-day "
          "(previously-unknown) vulnerabilities; its novel-risk capability is AI consensus reasoning about "
          "newly-introduced suspicious code in a commit.")
    if not iocs:
        _para(pdf, "No known IOCs were matched in the scanned commit diffs.")
    else:
        IOC_LABEL = {
            "malicious_package": "Malicious package",
            "c2_exfil_host": "C2 / exfil host",
            "suspicious_tld": "High-risk TLD",
            "malicious_pattern": "Execution pattern",
        }
        for ind in iocs:
            if pdf.get_y() > 255:
                pdf.add_page()
            sev = (ind.get("severity") or "low").lower()
            pdf.set_x(12)
            pdf.set_font("Helvetica", "B", 9.2)
            pdf.set_text_color(*SEV_COLOR.get(sev, MIDGRAY))
            label = IOC_LABEL.get(ind.get("ioc_type"), "Indicator")
            pdf.multi_cell(0, 4.8, f"[{sev.upper()}] {label}: {ind.get('indicator', ind.get('title',''))}")
            pdf.set_x(14)
            pdf.set_font("Courier", "", 8)
            pdf.set_text_color(*DARK)
            pdf.multi_cell(0, 4.4, f"{ind.get('filename','')} (commit {ind.get('commit','')}): {ind.get('evidence','')}")
            if ind.get("explanation"):
                pdf.set_x(14)
                pdf.set_font("Helvetica", "", 8.8)
                pdf.set_text_color(*BODY)
                pdf.multi_cell(0, 4.6, ind.get("explanation"))
            pdf.ln(1.5)

    # ---------------- Per-Commit Findings Timeline ----------------
    _section(pdf, "Per-Commit Findings Timeline")
    _para(pdf,
          "Commits are listed newest to oldest. Only commits whose diff INTRODUCED risk were sent to the "
          "Gemini + Claude consensus; clean commits were skipped to save tokens.")

    for c in commits:
        if pdf.get_y() > 255:
            pdf.add_page()
        v = c.get("verdict") or {}
        flagged_c = c.get("flagged") and v.get("worth_alerting")
        risk = (v.get("commit_risk") or ("clean" if not c.get("flagged") else "noise")).lower()
        dot = SEV_COLOR.get(risk, MIDGRAY)

        pdf.ln(1)
        pdf.set_fill_color(*dot)
        cy = pdf.get_y()
        pdf.rect(12, cy + 1, 3, 3, "F")
        pdf.set_xy(18, cy)
        pdf.set_font("Helvetica", "B", 10.5)
        pdf.set_text_color(*NAVY)
        pdf.multi_cell(0, 5.5, f"{c['short_sha']}  --  {c.get('message','')[:80]}")
        pdf.set_x(18)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*MIDGRAY)
        pdf.multi_cell(0, 4.6,
            f"{c.get('author','')}  |  {(c.get('date','') or '')[:10]}  |  {c.get('files_changed',0)} file(s) changed  |  "
            f"status: {risk.upper()}")

        if not c.get("flagged"):
            pdf.set_x(18)
            pdf.set_font("Helvetica", "I", 8.5)
            pdf.set_text_color(*SEV_COLOR['low'])
            pdf.multi_cell(0, 4.6, "Clean -- no new risk introduced (AI review skipped, 0 tokens).")
        elif flagged_c:
            pdf.set_x(18)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*BODY)
            pdf.multi_cell(0, 4.8, v.get("summary", ""))
            for f in v.get("findings", []):
                if pdf.get_y() > 262:
                    pdf.add_page()
                sev = (f.get("severity") or "low").lower()
                pdf.set_x(22)
                pdf.set_font("Helvetica", "B", 8.8)
                pdf.set_text_color(*SEV_COLOR.get(sev, MIDGRAY))
                pdf.multi_cell(0, 4.6, f"[{sev.upper()}] {f.get('title','')} ({f.get('category','')})")
                if f.get("filename"):
                    pdf.set_x(22)
                    pdf.set_font("Courier", "", 8)
                    pdf.set_text_color(*DARK)
                    pdf.multi_cell(0, 4.3, f"{f.get('filename','')}: {f.get('evidence','')}")
                pdf.set_x(22)
                pdf.set_font("Helvetica", "", 8.8)
                pdf.set_text_color(*BODY)
                if f.get("explanation"):
                    pdf.multi_cell(0, 4.6, f.get("explanation"))
                if f.get("remediation"):
                    pdf.set_x(22)
                    pdf.set_font("Helvetica", "B", 8.8)
                    pdf.set_text_color(*SEV_COLOR['low'])
                    pdf.multi_cell(0, 4.6, f"Fix: {f.get('remediation')}")
        else:
            pdf.set_x(18)
            pdf.set_font("Helvetica", "I", 8.5)
            pdf.set_text_color(*MIDGRAY)
            note = v.get("summary") or "Scanner flagged this commit, but AI consensus classified it as noise / not worth alerting."
            pdf.multi_cell(0, 4.6, note)
        pdf.ln(1)
        pdf.set_draw_color(*LIGHT)
        pdf.line(14, pdf.get_y(), 196, pdf.get_y())

    pdf.output(path)
    return path
