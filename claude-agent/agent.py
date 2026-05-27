import os
import json
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
ES_URL = os.getenv("ES_URL", "http://127.0.0.1:9200")
ES_USER = os.getenv("ELASTIC_USER", "elastic")
ES_PASS = os.getenv("ELASTIC_PASSWORD", "packetsentry")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://127.0.0.1:5000")
MAX_CYCLES = int(os.getenv("MAX_CYCLES", "8"))
NO_ALERT_STOP = int(os.getenv("NO_ALERT_STOP", "3"))
SESSION_ID = str(uuid.uuid4())[:8]

from capture import PacketCapture, packet_queue, PCAP_DIR
from attack_detector import AttackDetector

capture = PacketCapture(interface="any")
detector = AttackDetector()

analysis_active = False
console_buffer = deque(maxlen=500)
activity_log = deque(maxlen=1000)
CUSTOM_TARGET = None

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

def push_to_elasticsearch(index, doc):
    try:
        doc["@timestamp"] = doc.get("@timestamp", datetime.utcnow().isoformat())
        doc["session"] = SESSION_ID
        url = f"{ES_URL}/{index}/_doc"
        requests.post(url, json=doc, auth=(ES_USER, ES_PASS), timeout=2)
    except:
        pass

def log_activity(event_type, data, index="packetsentry-activity-000001"):
    entry = {
        "@timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "session": SESSION_ID,
        "data": data
    }
    activity_log.append(entry)
    push_to_elasticsearch(index, entry)

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

RESPONSE FORMAT:
At the end of your analysis, provide a JSON block with:
```json
{{
  "analysis": "detailed analysis text",
  "threat_level": "low|medium|high|critical",
  "attack_name": "name of attack or null",
  "mitre_mapping": {{"tactic": "TAxxxx - Name", "technique": "Txxxx - Name"}},
  "recommendations": ["rec1", "rec2", ...],
  "confidence": 0.0-1.0,
  "analysis_complete": true or false
}}
```

analysis_complete: Set to true ONLY if you have thoroughly analyzed the target and found no remaining attack surface to investigate. Set to false if you need more cycles to probe further, test additional endpoints, or wait for more attack traffic. Be honest — if there's more to discover, set this to false."""

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

    thinking_blocks = []
    tool_calls_made = []

    if not ANTHROPIC_API_KEY or not ANTHROPIC_API_KEY.startswith("sk-ant-"):
        fallback = generate_fallback_analysis(packets, alerts)
        push_to_dashboard("agent_think", {"text": "[Claude API key not configured — running in offline detection mode]", "cycle_id": cycle_id, "final": True})
        push_to_dashboard("agent_cycle_complete", {"cycle_id": cycle_id, "analysis": fallback, "thinking": ["Offline mode"], "commands": []})
        analysis_active = False
        return fallback

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        messages = [{"role": "user", "content": prompt}]

        max_tool_rounds = 5
        tool_round = 0

        while tool_round < max_tool_rounds:
            tool_round += 1
            accumulated_text = ""
            current_tool_block = None

            push_to_dashboard("agent_status", {"status": "thinking", "message": f"Analysis round {tool_round}", "cycle_id": cycle_id})

            with client.messages.stream(
                model="claude-sonnet-4-6",
                max_tokens=4096,
                system=build_system_prompt(),
                messages=messages,
                tools=TOOLS
            ) as stream:
                for event in stream:
                    if event.type == "content_block_start":
                        if event.content_block.type == "tool_use":
                            current_tool_block = {
                                "id": event.content_block.id,
                                "name": event.content_block.name,
                                "input": event.content_block.input or {}
                            }
                            log_activity("tool_use_start", current_tool_block)

                    elif event.type == "content_block_delta":
                        if event.delta.type == "text_delta":
                            accumulated_text += event.delta.text
                            push_to_dashboard("agent_think", {
                                "text": event.delta.text,
                                "cycle_id": cycle_id,
                                "accumulated": accumulated_text
                            })

                    elif event.type == "message_delta":
                        pass

                    elif event.type == "message_stop":
                        pass

            final_message = stream.get_final_message()

            if accumulated_text:
                thinking_blocks.append(accumulated_text)
                push_to_dashboard("agent_think", {
                    "text": "",
                    "cycle_id": cycle_id,
                    "final": True,
                    "block_text": accumulated_text
                })
                log_activity("thinking_block", {"text": accumulated_text[:2000], "cycle_id": cycle_id})

            if final_message.stop_reason == "tool_use":
                for content_block in final_message.content:
                    if content_block.type == "tool_use":
                        tool_name = content_block.name
                        tool_input = content_block.input
                        tool_id = content_block.id

                        push_to_dashboard("agent_command", {
                            "command": tool_name,
                            "args": tool_input,
                            "cycle_id": cycle_id,
                            "tool_id": tool_id,
                            "executing": True
                        })
                        log_activity("tool_execution", {"tool": tool_name, "input": tool_input})

                        handler = TOOL_MAP.get(tool_name)
                        if handler:
                            output = handler(tool_input)
                            if isinstance(output, list):
                                output = json.dumps(output[:20], indent=2)
                            if not isinstance(output, str):
                                output = str(output)
                        else:
                            output = f"[ERROR] Unknown tool: {tool_name}"

                        tool_calls_made.append({"tool": tool_name, "input": tool_input, "output": output[:2000]})

                        push_to_dashboard("agent_command_output", {
                            "command": tool_name,
                            "output": output[:2000],
                            "cycle_id": cycle_id,
                            "tool_id": tool_id
                        })
                        log_activity("tool_output", {"tool": tool_name, "output": output[:2000]})

                        tool_result_content = []
                        for block in final_message.content:
                            if block.type == "text":
                                tool_result_content.append({"type": "text", "text": block.text})
                            elif block.type == "tool_use":
                                tool_result_content.append({
                                    "type": "tool_result",
                                    "tool_use_id": block.id,
                                    "content": output[:10000]
                                })

                        messages.append({"role": "assistant", "content": tool_result_content})
                        messages.append({"role": "user", "content": "Continue with your analysis using the tool output above."})
            else:
                break

        accumulated_text = ""
        if messages and messages[-1]["role"] == "assistant":
            for block in messages[-1]["content"]:
                if isinstance(block, dict) and block.get("type") == "text":
                    accumulated_text += block["text"]

        final_analysis = extract_json_analysis(accumulated_text or thinking_blocks[-1] if thinking_blocks else "")

        final_analysis["thinking_blocks"] = thinking_blocks
        final_analysis["tool_calls"] = tool_calls_made

        push_to_dashboard("agent_cycle_complete", {
            "cycle_id": cycle_id,
            "analysis": final_analysis,
            "thinking": thinking_blocks,
            "commands": tool_calls_made
        })

        push_to_elasticsearch("packetsentry-alerts-000001", {
            "event_type": "analysis_cycle",
            "cycle_id": cycle_id,
            "packet_count": len(packets),
            "alert_count": len(alerts),
            "threat_level": final_analysis.get("threat_level", "low"),
            "claude_analysis": final_analysis.get("analysis", ""),
            "attack_name": final_analysis.get("attack_name", ""),
            "mitre_tactic": final_analysis.get("mitre_mapping", {}).get("tactic", ""),
            "mitre_technique": final_analysis.get("mitre_mapping", {}).get("technique", ""),
            "remediation": json.dumps(final_analysis.get("recommendations", [])),
            "confidence": final_analysis.get("confidence", 0.0),
            "thinking_blocks": json.dumps(thinking_blocks),
            "tool_calls": json.dumps(tool_calls_made),
            "session": SESSION_ID
        })

        log_activity("cycle_complete", {"cycle_id": cycle_id, "threat_level": final_analysis.get("threat_level")})

        analysis_active = False
        return final_analysis

    except ImportError:
        push_to_dashboard("agent_think", {"text": "[anthropic SDK not installed]", "cycle_id": cycle_id, "final": True})
    except Exception as e:
        push_to_dashboard("agent_think", {"text": f"[Claude API Error: {e}]", "cycle_id": cycle_id, "final": True})
        log_activity("error", {"error": str(e), "cycle_id": cycle_id})

    analysis_active = False
    fallback = generate_fallback_analysis(packets, alerts)
    push_to_dashboard("agent_cycle_complete", {"cycle_id": cycle_id, "analysis": fallback, "thinking": thinking_blocks, "commands": tool_calls_made})
    return fallback

def generate_fallback_analysis(packets, alerts):
    summary = f"Captured {len(packets)} packets, detected {len(alerts)} alerts. "
    if alerts:
        for a in alerts[:3]:
            summary += f"[{a['severity'].upper()}] {a['event_type']}: {a['description']}. "
    else:
        summary += "No suspicious patterns detected by heuristics."
    return {
        "analysis": summary,
        "threat_level": "medium" if alerts else "low",
        "attack_name": alerts[0].get("event_type") if alerts else None,
        "mitre_mapping": {
            "tactic": alerts[0].get("mitre_tactic", "") if alerts else "",
            "technique": alerts[0].get("mitre_technique", "") if alerts else ""
        },
        "recommendations": ["Investigate suspicious hosts", "Review firewall rules"] if alerts else ["Continue monitoring"],
        "confidence": max((a.get("confidence", 0) for a in alerts), default=0.0) if alerts else 0.0,
        "llm_available": False,
        "analysis_complete": True
    }

def extract_json_analysis(text):
    try:
        start = text.rfind("```json")
        if start != -1:
            end = text.find("```", start + 7)
            if end != -1:
                return json.loads(text[start+7:end].strip())
        start = text.rfind("{")
        if start != -1:
            end = text.rfind("}")
            if end != -1 and end > start:
                return json.loads(text[start:end+1].strip())
    except:
        pass
    return generate_fallback_analysis([], [])

def ask_claude_question(question):
    packets = capture.get_recent_packets(30)
    alerts = detector.analyze_packets(packets)
    pkt_text = json.dumps(packets[-10:], indent=2) if packets else "No packets"
    alert_text = json.dumps(alerts[:3], indent=2) if alerts else "No alerts"

    if not ANTHROPIC_API_KEY or not ANTHROPIC_API_KEY.startswith("sk-ant-"):
        return f"[Offline] {len(packets)} packets. {len(alerts)} alerts. Question: {question}"

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        accumulated = ""
        push_to_dashboard("agent_think", {"text": f"[Answering query: {question[:80]}...]\n", "cycle_id": "query", "query": True})
        with client.messages.stream(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=f"You are PacketSentry, an AI network security analyst. Target: {CUSTOM_TARGET or 'not set'}. Answer the user's question about current network traffic based on live packet captures.",
            messages=[{"role": "user", "content": f"Recent packets:\n{pkt_text}\n\nAlerts:\n{alert_text}\n\nQuestion: {question}"}]
        ) as stream:
            for event in stream:
                if event.type == "content_block_delta" and event.delta.type == "text_delta":
                    accumulated += event.delta.text
                    push_to_dashboard("agent_think", {"text": event.delta.text, "cycle_id": "query", "query": True})
        push_to_dashboard("agent_think", {"text": "", "cycle_id": "query", "final": True, "query": True, "block_text": accumulated})
        return accumulated
    except Exception as e:
        return f"Error: {e}"

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
                    for a in alerts[:5]:
                        push_to_elasticsearch("packetsentry-alerts-000001", {
                            "@timestamp": datetime.utcnow().isoformat(),
                            "event_type": a.get("event_type"),
                            "severity": a.get("severity"),
                            "protocol": a.get("protocol"),
                            "src_ip": a.get("src_ip"),
                            "src_port": a.get("src_port"),
                            "dst_ip": a.get("dst_ip"),
                            "dst_port": a.get("dst_port"),
                            "packet_count": a.get("packet_count"),
                            "threat_level": a.get("threat_level"),
                            "attack_name": a.get("attack_name"),
                            "mitre_tactic": a.get("mitre_tactic"),
                            "mitre_technique": a.get("mitre_technique"),
                            "confidence": a.get("confidence"),
                            "description": a.get("description"),
                            "claude_analysis": analysis.get("analysis", "")[:500],
                            "cycle": cycle_count
                        })

                if packets:
                    for p in packets[-5:]:
                        push_to_elasticsearch("packetsentry-packets-000001", {
                            "frame_len": p.get("frame_len"),
                            "ip_src": p.get("ip_src"),
                            "ip_dst": p.get("ip_dst"),
                            "ip_proto": p.get("ip_proto"),
                            "src_port": p.get("src_port"),
                            "dst_port": p.get("dst_port"),
                            "protocol": p.get("protocol"),
                            "info": p.get("info"),
                            "cycle": cycle_count
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
