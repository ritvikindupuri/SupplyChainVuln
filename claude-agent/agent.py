import os
import json
import re
import time
import uuid
import threading
import requests
import subprocess
from datetime import datetime
from collections import deque
from dotenv import load_dotenv
from flask import Flask, request, jsonify

load_dotenv("/agent/.env")
load_dotenv("/agent/.env.example")

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://127.0.0.1:5000")
MAX_CYCLES = int(os.getenv("MAX_CYCLES", "8"))
NO_ALERT_STOP = int(os.getenv("NO_ALERT_STOP", "3"))
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")
SESSION_ID = str(uuid.uuid4())[:8]

from capture import PacketCapture, packet_queue, PCAP_DIR
from attack_detector import AttackDetector

capture = PacketCapture(interface="any")
detector = AttackDetector()

analysis_active = False
console_buffer = deque(maxlen=500)
activity_log = deque(maxlen=1000)
CUSTOM_TARGET = None

# Guardrail: require real investigative steps before Claude can claim completion.
# This makes "analysis_complete" behave like a human pentester: verify with evidence, don't just infer from silence.
MIN_TOOL_CALLS_FOR_COMPLETE = int(os.getenv("MIN_TOOL_CALLS_FOR_COMPLETE", "2"))

def push_to_dashboard(event_type, data):
    try:
        requests.post(
            f"{DASHBOARD_URL}/api/events",
            json={"type": event_type, "data": data, "timestamp": datetime.utcnow().isoformat(), "session": SESSION_ID},
            timeout=2
        )
    except requests.exceptions.ConnectionError:
        pass
    except:
        pass

def log_activity(event_type, data):
    entry = {
        "@timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "session": SESSION_ID,
        "data": data
    }
    activity_log.append(entry)

def execute_tshark(args):
    cmd = ["tshark"] + args
    log_activity("command_execution", {"command": " ".join(cmd)})
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout if result.stdout else result.stderr
        log_activity("command_output", {"command": " ".join(cmd), "output": output[:5000]})
        return output
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Command exceeded 30 seconds"
    except Exception as e:
        return f"[ERROR] {e}"

def capture_fresh_packets(count=30, bpf_filter=""):
    return capture.capture_once(count=count, filter_expr=bpf_filter)

def get_statistics(stat_type="io"):
    cmd = ["tshark", "-i", "any", "-c", "200", "-q", "-z"]
    stat_map = {
        "io": "io,stat,1",
        "conv_ip": "conv,ip",
        "conv_tcp": "conv,tcp",
        "endpoints": "endpoints,ip",
        "io_phy": "io,phs"
    }
    cmd.append(stat_map.get(stat_type, "io,stat,1"))
    log_activity("command_execution", {"command": f"tshark statistics: {stat_type}"})
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout if result.stdout else result.stderr
        log_activity("command_output", {"command": f"statistics {stat_type}", "output": output[:5000]})
        return output
    except:
        return "[ERROR] Statistics unavailable"

TOOL_MAP = {
    "run_tshark": lambda args: execute_tshark(args.get("args", [])),
    "capture_packets": lambda args: capture_fresh_packets(
        args.get("count", 20),
        args.get("filter", "")
    ),
    "get_statistics": lambda args: get_statistics(args.get("stat_type", "io")),
}

TOOLS = [
    {
        "name": "run_tshark",
        "description": "Execute a tshark command for deep packet inspection. Use display filters like 'tcp.port==80', 'http', 'dns', 'ip.addr==X.X.X.X'",
        "input_schema": {
            "type": "object",
            "properties": {
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "tshark arguments as a list (e.g. ['-i', 'any', '-c', '15', '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', 'tcp.port==80'])"
                }
            },
            "required": ["args"]
        }
    },
    {
        "name": "capture_packets",
        "description": "Capture a fresh batch of packets for analysis. Use a BPF filter to focus on specific traffic types.",
        "input_schema": {
            "type": "object",
            "properties": {
                "count": {"type": "integer", "description": "Number of packets to capture (1-100)"},
                "filter": {"type": "string", "description": "BPF filter expression (e.g. 'tcp port 80', 'host 192.168.1.100', 'udp port 53')"}
            },
            "required": ["count"]
        }
    },
    {
        "name": "get_statistics",
        "description": "Get network traffic statistics from tshark (conversations, endpoints, IO rates)",
        "input_schema": {
            "type": "object",
            "properties": {
                "stat_type": {
                    "type": "string",
                    "enum": ["io", "conv_ip", "conv_tcp", "endpoints"],
                    "description": "Type of statistics: io=IO rates, conv_ip=IP conversations, conv_tcp=TCP conversations, endpoints=IP endpoints"
                }
            },
            "required": ["stat_type"]
        }
    }
]

def build_system_prompt():
    target_info = ""
    if CUSTOM_TARGET:
        from urllib.parse import urlparse
        parsed = urlparse(CUSTOM_TARGET)
        host = parsed.hostname or CUSTOM_TARGET
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        target_info = f"""
CURRENT TARGET: {CUSTOM_TARGET} ({host}:{port})
- This is the custom web application you have been asked to analyze and penetration test.
- All traffic to/from this target should be closely inspected for vulnerabilities.
- Look for exposed endpoints, authentication issues, injection flaws, misconfigurations, and other security weaknesses.
- Run tshark commands to investigate traffic patterns targeting this host.
"""
    else:
        target_info = "\nNo target application configured yet. Wait for a target URL to be provided before starting analysis.\n"

    return f"""You are PacketSentry, an autonomous AI network security analyst with live Wireshark (tshark) access.
{target_info}
CAPABILITIES:
- You can run ANY tshark command live against real network traffic
- You can capture specific packets with BPF filters
- You can analyze traffic patterns, detect anomalies, and identify attacks
- You can view network statistics (conversations, endpoints, IO rates)
- 172.30.0.x range = Docker internal bridge traffic
- 127.0.0.1 = localhost (agent itself)

YOUR ANALYSIS CYCLE:
1. Review the packet summaries and alerts provided to you
2. Think step-by-step about what the traffic indicates
3. Run tshark commands to investigate anything suspicious
4. Analyze the command output to confirm or rule out threats
5. Determine if there is malicious activity and what kind
6. Provide threat level, MITRE mapping, and remediation steps

RESPONSE FORMAT (CRITICAL):
At the end of your analysis, return ONLY a valid JSON object (no markdown, no code fences, no extra text) with exactly these fields:
{{
  "analysis": "detailed analysis text",
  "threat_level": "low|medium|high|critical",
  "attack_name": "name of attack or null",
  "mitre_mapping": {{"tactic": "TAxxxx - Name", "technique": "Txxxx - Name"}},
  "recommendations": ["rec1", "rec2", ...],
  "confidence": 0.0-1.0,
  "analysis_complete": true or false
}}

analysis_complete:
Set to true ONLY if you have thoroughly analyzed the target and found no remaining attack surface to investigate.
Set to false if you need more cycles to probe further, test additional endpoints, or wait for more attack traffic.

CRITICAL RULE — ALWAYS EXPLAIN BEFORE TOOL USE:
Before using any tool, you MUST write 1-3 sentences explaining what you are about to do and why. Never run a tool silently. Your reasoning is the only way the user can follow your analysis."""

    + f"""

COMPLETION STANDARD (HUMAN-LIKE, STRICT):
- You are acting like a penetration tester / network security engineer.
- You may ONLY set analysis_complete=true if you have performed ACTIVE verification, not just observed "no alerts".
- Before setting analysis_complete=true, you MUST have executed multiple investigative checks using the available tools
  (run_tshark / capture_packets / get_statistics) to validate that:
  - traffic to/from the target is understood (protocols, ports, directionality)
  - no clear scanning/flooding/exfil patterns exist for the target
  - you have no remaining high-value hypotheses to test with the available tools
- If you cannot complete active verification (e.g., insufficient traffic), set analysis_complete=false and say exactly what evidence is missing and what you are waiting for.

WHEN analysis_complete=true, the "analysis" field MUST include a clearly labeled section:
"Completion rationale:" followed by bullet points of:
- checks performed (tool commands executed + what they proved)
- why remaining hypotheses are low value / out of scope for network-only visibility
- what new evidence would make you resume analysis
"""

def extract_json_analysis(text):
    """
    Claude outputs a JSON object (required). This helper makes parsing resilient to minor formatting issues.
    """
    defaults = {
        "analysis": "",
        "threat_level": "low",
        "attack_name": None,
        "mitre_mapping": {"tactic": "", "technique": ""},
        "recommendations": [],
        "confidence": 0.0,
        "analysis_complete": False,
    }
    if not text:
        return defaults

    candidate = None
    # Prefer a fenced JSON block if Claude includes one (we still asked for no fences, but be tolerant).
    m = re.search(r"```(?:json)?\s*({.*?})\s*```", text, flags=re.DOTALL)
    if m:
        candidate = m.group(1)
    else:
        # Fallback: take the first {...} occurrence.
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = text[start:end + 1]

    if not candidate:
        defaults["analysis"] = text.strip()[:5000]
        return defaults

    try:
        data = json.loads(candidate)
    except Exception:
        defaults["analysis"] = text.strip()[:5000]
        return defaults

    # Normalize expected fields/types.
    normalized = defaults.copy()
    if isinstance(data, dict):
        normalized["analysis"] = str(data.get("analysis", normalized["analysis"]))
        normalized["threat_level"] = str(data.get("threat_level", normalized["threat_level"]))
        normalized["attack_name"] = data.get("attack_name", normalized["attack_name"])
        mm = data.get("mitre_mapping", {}) or {}
        normalized["mitre_mapping"] = {
            "tactic": str(mm.get("tactic", "")) if isinstance(mm, dict) else "",
            "technique": str(mm.get("technique", "")) if isinstance(mm, dict) else "",
        }
        recs = data.get("recommendations", []) or []
        normalized["recommendations"] = recs if isinstance(recs, list) else [str(recs)]
        try:
            normalized["confidence"] = float(data.get("confidence", normalized["confidence"]))
        except Exception:
            pass
        normalized["analysis_complete"] = bool(data.get("analysis_complete", False))
    return normalized


def generate_fallback_analysis(packets, alerts):
    """
    Used when Claude is unavailable. Must still return analysis_complete so the agent can stop.
    """
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    worst_sev = "low"
    for a in alerts:
        sev = (a.get("severity") or "low").lower()
        if sev in severity_order and severity_order[sev] > severity_order.get(worst_sev, 0):
            worst_sev = sev

    top_attack = alerts[0].get("attack_name") if alerts else None
    mm = {"tactic": "", "technique": ""}
    if alerts:
        mm["tactic"] = alerts[0].get("mitre_tactic") or ""
        mm["technique"] = alerts[0].get("mitre_technique") or ""

    confidence = 0.0
    if alerts:
        confs = []
        for a in alerts[:10]:
            try:
                confs.append(float(a.get("confidence", 0.5)))
            except Exception:
                pass
        confidence = sum(confs) / len(confs) if confs else 0.5
    else:
        confidence = 0.3

    analysis = (
        f"Heuristic fallback analysis only (Claude disabled/unavailable).\n"
        f"- Packets analyzed (window): {len(packets)}\n"
        f"- Heuristic alerts: {len(alerts)}\n"
        f"- Worst severity observed: {worst_sev.upper()}\n\n"
        "Because this is offline/heuristic mode, the system cannot guarantee full attack-surface enumeration. "
        "However, if no alerts are present, we can conservatively treat the current window as having no detected malicious activity."
    )

    # In fallback mode, completion is based on whether the detector sees anything.
    analysis_complete = (len(alerts) == 0)

    recommendations = []
    if alerts:
        recommendations.append("Review the top alert evidence and implement targeted mitigations for the observed behavior.")
        recommendations.append("Harden exposed services, validate input handling, and add detection rules for the relevant MITRE mappings.")
    else:
        recommendations.append("Maintain baseline monitoring and consider expanding probes if new traffic patterns appear.")

    return {
        "analysis": analysis,
        "threat_level": worst_sev,
        "attack_name": top_attack,
        "mitre_mapping": mm,
        "recommendations": recommendations,
        "confidence": confidence,
        "analysis_complete": analysis_complete,
    }

def ask_claude_question(question):
    """
    Used by the dashboard "Ask Agent" feature. This is separate from the analysis/cycle lifecycle.
    """
    if not ANTHROPIC_API_KEY or not ANTHROPIC_API_KEY.startswith("sk-ant-"):
        return "Claude API key not configured — cannot answer queries."

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        recent_packets = capture.get_recent_packets(10)

        pkt_lines = []
        for p in recent_packets[-10:]:
            proto = p.get("protocol") or p.get("ip_proto") or "unknown"
            src = p.get("ip_src") or ""
            dst = p.get("ip_dst") or ""
            info = p.get("info") or ""
            ln = p.get("frame_len") or ""
            pkt_lines.append(f"- {proto} {src} -> {dst} len={ln} info={info}".strip())

        pkt_context = "\n".join(pkt_lines) if pkt_lines else "- (no packet context available)"

        system = (
            "You are PacketSentry, a senior network security engineer. "
            "Answer the user's question using the provided packet context. "
            "Be concrete and practical: call out likely causes, what to verify next, and any relevant security controls."
        )
        user = f"Target: {CUSTOM_TARGET or 'not set'}\n\nUser question: {question}\n\nRecent packet samples:\n{pkt_context}\n\nAnswer:"

        resp = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=900,
            system=system,
            messages=[{"role": "user", "content": user}],
        )

        text_parts = [b.text for b in resp.content if getattr(b, "type", None) == "text" and getattr(b, "text", None)]
        return ("".join(text_parts) or "").strip() or "No response generated."
    except Exception as e:
        return f"Query error: {e}"

def analyze_with_claude_streaming(packets, alerts):
    global analysis_active
    analysis_active = True
    cycle_id = f"cycle_{int(time.time())}"

    pkt_summary = f"Captured {len(packets)} packets in the current window (last ~15s). "
    if packets:
        proto_counts = {}
        for p in packets:
            proto = p.get("protocol", "unknown") or "unknown"
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
        pkt_summary += f"Protocol distribution: {json.dumps(proto_counts)}. "
        top_srcs = list(set(p.get("ip_src", "") for p in packets if p.get("ip_src")))[:6]
        top_dsts = list(set(p.get("ip_dst", "") for p in packets if p.get("ip_dst")))[:6]
        if top_srcs:
            pkt_summary += f"Active sources: {', '.join(top_srcs)}. "
        if top_dsts:
            pkt_summary += f"Active destinations: {', '.join(top_dsts)}. "
        flagged = [p for p in packets if int(p.get("frame_len", 0) or 0) > 1000]
        if flagged:
            pkt_summary += f"Large packets (>1KB): {len(flagged)}. "

    alert_summary = f"Automatic alerts triggered: {len(alerts)}"
    if alerts:
        for a in alerts[:5]:
            alert_summary += f"\n- [{a['severity'].upper()}] {a['event_type']}: {a['description']} (confidence: {a.get('confidence', 0.5):.2f})"
    else:
        alert_summary += "\n- No automatic alerts triggered by pattern matching."

    prompt = f"""=== ANALYSIS CYCLE {SESSION_ID}:{cycle_id} ===

PACKET DATA:
{pkt_summary}

ALERTS:
{alert_summary}

TASK:
1. Analyze the current network traffic
2. Run tshark commands to investigate any suspicious activity
3. Determine if there are security threats
4. Provide your final analysis in the required JSON format"""

    push_to_dashboard("agent_cycle_start", {"cycle_id": cycle_id, "packet_count": len(packets), "alert_count": len(alerts)})
    log_activity("cycle_start", {"cycle_id": cycle_id, "packet_count": len(packets), "alert_count": len(alerts)})

    if not ANTHROPIC_API_KEY or not ANTHROPIC_API_KEY.startswith("sk-ant-"):
        fallback = generate_fallback_analysis(packets, alerts)
        push_to_dashboard(
            "agent_think",
            {"text": "[Claude API key not configured — running in fallback mode]", "cycle_id": cycle_id, "final": True}
        )
        push_to_dashboard(
            "agent_cycle_complete",
            {"cycle_id": cycle_id, "analysis": fallback, "thinking": ["Fallback mode"], "commands": []}
        )
        analysis_active = False
        return fallback

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        system = build_system_prompt()

        # Messages history (we append assistant tool requests + user tool results).
        messages = [{"role": "user", "content": prompt}]

        max_tool_rounds = 8
        last_text = ""
        tool_calls_executed = 0

        # Show initial "starting up" message so the user sees something immediately
        push_to_dashboard(
            "agent_status",
            {"status": "thinking", "message": "Starting analysis — contacting Claude AI...", "cycle_id": cycle_id}
        )

        # Tool-use loop: ONE TOOL PER ROUND so Claude's thinking appears between each command.
        for _round in range(max_tool_rounds + 1):
            push_to_dashboard(
                "agent_status",
                {"status": "thinking", "message": f"Analysis round {_round + 1}", "cycle_id": cycle_id}
            )

            response = client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=2048,
                system=system,
                messages=messages,
                tools=TOOLS
            )

            text_parts = []
            tool_calls = []
            for block in response.content:
                if getattr(block, "type", None) == "text" and getattr(block, "text", None):
                    text_parts.append(block.text)
                elif getattr(block, "type", None) == "tool_use":
                    tool_calls.append(block)

            combined_text = "".join(text_parts).strip()
            if combined_text:
                last_text = combined_text
                push_to_dashboard("agent_think", {"text": combined_text, "cycle_id": cycle_id, "final": False})

            # ALWAYS record the assistant response, even if no text.
            messages.append({"role": "assistant", "content": [block.model_dump(mode="json", exclude_none=True) for block in response.content]})

            if not tool_calls:
                # No more tools — parse final JSON.
                analysis = extract_json_analysis(combined_text or last_text)

                # Enforce "human-like stop": require active verification + explicit completion rationale.
                if analysis.get("analysis_complete") is True:
                    has_rationale = "completion rationale" in (analysis.get("analysis") or "").lower()
                    if tool_calls_executed < MIN_TOOL_CALLS_FOR_COMPLETE or not has_rationale:
                        needed = max(0, MIN_TOOL_CALLS_FOR_COMPLETE - tool_calls_executed)
                        messages.append({
                            "role": "user",
                            "content": "".join([
                                "You set analysis_complete=true, but the completion standard was not met.\n",
                                f"- Tool calls executed this cycle: {tool_calls_executed} (minimum required: {MIN_TOOL_CALLS_FOR_COMPLETE})\n",
                                f"- Missing completion rationale section: {not has_rationale}\n\n",
                                "Continue investigating like a human pentester:\n",
                                (f"- Execute at least {needed} more investigative tool checks, and interpret the output.\n" if needed > 0 else ""),
                                "- Then return ONLY the final JSON again. If evidence is still insufficient, set analysis_complete=false and state what evidence is missing.\n",
                            ])
                        })
                        continue

                push_to_dashboard("agent_think", {"text": "", "cycle_id": cycle_id, "final": True})
                push_to_dashboard(
                    "agent_cycle_complete",
                    {"cycle_id": cycle_id, "analysis": analysis, "thinking": ["Claude finished turn"], "commands": []},
                )
                analysis_active = False
                return analysis

            # Execute only ONE tool per round so Claude thinks between commands.
            call = tool_calls[0]
            tool_id = getattr(call, "id", None)
            tool_name = getattr(call, "name", None)
            tool_input = getattr(call, "input", None) or {}

            push_to_dashboard(
                "agent_command",
                {
                    "cycle_id": cycle_id,
                    "tool_id": tool_id,
                    "command": tool_name,
                    "args": tool_input,
                    "executing": True,
                },
            )

            try:
                handler = TOOL_MAP.get(tool_name)
                if not handler:
                    result = f"[ERROR] Unknown tool: {tool_name}"
                else:
                    result = handler(tool_input)
            except Exception as e:
                result = f"[ERROR] Tool execution failed: {e}"

            result_str = str(result)
            tool_calls_executed += 1
            push_to_dashboard(
                "agent_command_output",
                {"cycle_id": cycle_id, "tool_id": tool_id, "command": tool_name, "output": result_str}
            )

            # Send tool result back. If Claude had asked for more tools in this response,
            # tell it to analyze the result first before proceeding.
            tool_result_block = {"type": "tool_result", "tool_use_id": tool_id, "content": result_str}
            if len(tool_calls) > 1:
                remaining = [c.name for c in tool_calls[1:]]
                messages.append({
                    "role": "user",
                    "content": [
                        tool_result_block,
                        {"type": "text", "text": f"That tool finished. You also requested: {remaining}. Analyze this result carefully, then proceed with the next tool if still needed."}
                    ]
                })
            else:
                messages.append({"role": "user", "content": [tool_result_block]})

            # Loop back — Claude will respond with thinking + next tool

        # Tool loop limit hit.
        analysis = extract_json_analysis(last_text) if last_text else generate_fallback_analysis(packets, alerts)
        push_to_dashboard("agent_think", {"text": "", "cycle_id": cycle_id, "final": True})
        push_to_dashboard(
            "agent_cycle_complete",
            {"cycle_id": cycle_id, "analysis": analysis, "thinking": ["Tool loop limit reached"], "commands": []},
        )
        analysis_active = False
        return analysis
    except Exception as e:
        fallback = generate_fallback_analysis(packets, alerts)
        push_to_dashboard(
            "agent_think",
            {"text": f"[Claude error — fallback mode: {str(e)[:120]}]", "cycle_id": cycle_id, "final": True},
        )
        push_to_dashboard("agent_cycle_complete", {"cycle_id": cycle_id, "analysis": fallback, "thinking": ["Claude error fallback"], "commands": []})
        analysis_active = False
        return fallback

def agent_loop():
    global analysis_active, CUSTOM_TARGET
    print(f"[+] PacketSentry Agent starting (session: {SESSION_ID})")
    push_to_dashboard("agent_status", {"status": "starting", "message": "PacketSentry agent initializing — starting packet capture via tshark..."})

    time.sleep(3)
    interfaces = capture.get_interfaces()
    print(f"[+] Available interfaces: {len(interfaces)}")
    capture.start_continuous()

    while True:
        # Reset session state and wait for a target
        CUSTOM_TARGET = None
        push_to_dashboard("agent_status", {"status": "waiting", "message": "Agent ready — waiting for target URL to be configured via the dashboard setup screen."})
        print("[+] Agent ready — waiting for target URL")

        while not CUSTOM_TARGET:
            time.sleep(4)
            push_to_dashboard("agent_status", {"status": "waiting", "message": "Awaiting target URL — configure it from the dashboard (setup screen) to begin analysis."})

        # New session starts
        session_id = str(uuid.uuid4())[:8]
        cycle_count = 0
        no_alert_streak = 0
        stop_reason = None
        print(f"[+] New session {session_id} starting — target: {CUSTOM_TARGET}")

        while True:
            try:
                time.sleep(4)
                if not CUSTOM_TARGET:
                    push_to_dashboard("agent_status", {"status": "waiting", "message": "Target cleared — awaiting a new target URL."})
                    break

                if analysis_active:
                    continue

                cycle_count += 1
                packets = capture.get_recent_packets(60)
                alerts = detector.analyze_packets(packets)

                print(f"[Cycle {cycle_count}] {len(packets)} packets, {len(alerts)} alerts — analyzing {CUSTOM_TARGET}")
                push_to_dashboard("agent_status", {"status": "analyzing", "message": f"Cycle {cycle_count}: analyzing {CUSTOM_TARGET} — {len(packets)} packets, {len(alerts)} alerts", "cycle": cycle_count})

                push_to_dashboard("analysis_cycle", {"sample_packets": [{
                    "ip_src": p.get("ip_src",""), "ip_dst": p.get("ip_dst",""),
                    "protocol": p.get("protocol",""), "frame_len": p.get("frame_len",""),
                    "info": p.get("info",""), "src_port": p.get("src_port",""),
                    "dst_port": p.get("dst_port",""), "timestamp": p.get("timestamp","")
                } for p in packets[-10:]], "cycle": cycle_count, "packet_count": len(packets), "alert_count": len(alerts)})

                analysis = analyze_with_claude_streaming(packets, alerts)

                threat = analysis.get("threat_level", "low")
                attack = analysis.get("attack_name", "")
                print(f"[Cycle {cycle_count}] Complete — threat: {threat}{f', attack: {attack}' if attack else ''}")

                if alerts:
                    severity_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                    worst = max(alerts, key=lambda a: severity_map.get(a.get("severity", "low"), 0))
                    push_to_dashboard("alert", {
                        "severity": worst["severity"],
                        "event_type": worst["event_type"],
                        "description": worst["description"],
                        "timestamp": datetime.utcnow().isoformat(),
                        "cycle": cycle_count,
                        "claude_verdict": analysis.get("analysis", "")[:200]
                    })

                if not alerts:
                    no_alert_streak += 1
                else:
                    no_alert_streak = 0

                analysis_complete = analysis.get("analysis_complete", False)

                if analysis_complete:
                    stop_reason = f"Claude determined analysis is complete — all attack surfaces investigated"
                elif cycle_count >= MAX_CYCLES:
                    stop_reason = f"Reached maximum of {MAX_CYCLES} analysis cycles"
                elif no_alert_streak >= NO_ALERT_STOP:
                    stop_reason = f"No threats detected for {NO_ALERT_STOP} consecutive cycles"

                if stop_reason:
                    push_to_dashboard("session_complete", {
                        "total_cycles": cycle_count,
                        "message": f"{stop_reason}. Final threat level: {threat}.",
                        "final_threat": threat,
                        "stop_reason": stop_reason
                    })
                    push_to_dashboard("agent_status", {"status": "complete", "message": f"Session complete — {cycle_count} cycles, final threat: {threat}. {stop_reason}"})
                    print(f"[+] Session complete after {cycle_count} cycles: {stop_reason}")
                    print("[+] === STOP POINT: PacketSentry agent session finished ===")
                    break
            except Exception as e:
                print(f"[!] Agent error: {e}")
                push_to_dashboard("agent_status", {"status": "error", "message": f"Error: {str(e)[:100]}"})
                time.sleep(15)

        push_to_dashboard("agent_status", {"status": "idle", "message": "Session complete. Waiting for a new target URL to start the next session."})

query_app = Flask(__name__)

@query_app.route("/api/query", methods=["POST"])
def handle_query():
    data = request.json or {}
    question = data.get("question", "")
    if not question:
        return jsonify({"answer": "No question provided"})
    answer = ask_claude_question(question)
    return jsonify({"answer": answer, "packets": capture.get_recent_packets(10)})

@query_app.route("/api/status")
def agent_query_status():
    return jsonify({
        "session": SESSION_ID,
        "analyzing": analysis_active,
        "activity_count": len(activity_log),
        "uptime": int(time.time()),
        "target": CUSTOM_TARGET
    })

@query_app.route("/api/reset", methods=["POST"])
def handle_reset():
    global CUSTOM_TARGET
    CUSTOM_TARGET = None
    print(f"[+] Target cleared — agent ready for new session")
    return jsonify({"ok": True, "message": "Target cleared"})

@query_app.route("/api/setup/target", methods=["POST"])
def handle_setup_target():
    global CUSTOM_TARGET
    data = request.json or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"ok": False, "error": "No URL provided"})
    CUSTOM_TARGET = url
    print(f"[+] Target configured: {CUSTOM_TARGET}")
    push_to_dashboard("agent_status", {"status": "running", "message": f"Target set: {CUSTOM_TARGET}. Beginning analysis cycles."})
    return jsonify({"ok": True, "target": CUSTOM_TARGET})

@query_app.route("/api/target")
def get_target():
    return jsonify({"url": CUSTOM_TARGET or ""})

def run_http_server():
    query_app.run(host="0.0.0.0", port=8000, debug=False, use_reloader=False)

if __name__ == "__main__":
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    http_thread.start()
    agent_loop()
