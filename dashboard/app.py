import os
import json
import time
import queue
import uuid
import threading
import socket
import ipaddress
import requests
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, render_template, Response, request, jsonify, stream_with_context, send_file
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

AGENT_URL = os.getenv("AGENT_URL", "http://172.30.0.1:8000")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY", "")

CUSTOM_TARGET = ""

BLOCKED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "reddit.com", "amazon.com", "apple.com", "microsoft.com",
    "netflix.com", "spotify.com", "whatsapp.com", "telegram.org", "discord.com",
    "slack.com", "stackoverflow.com", "wikipedia.org", "github.com", "gitlab.com",
    "docker.com", "nginx.org", "apache.org", "python.org", "nodejs.org",
}

def resolve_to_private_ip(hostname):
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback, False
    except ValueError:
        pass
    try:
        addrs = socket.getaddrinfo(hostname, None)
        for addr in addrs:
            try:
                ip = ipaddress.ip_address(addr[4][0])
                if ip.is_private or ip.is_loopback:
                    return True, False
            except:
                continue
        return False, True
    except:
        return False, False

def generate_allow_reason(url, hostname, is_private):
    if is_private:
        try:
            ip = ipaddress.ip_address(hostname)
            return f"Target resolves to private IP ({hostname}) — this is a local/custom application on your network."
        except:
            return f"Target ({hostname}) is on a private/local network — confirmed as a custom application."
    stripped = hostname.lower().removeprefix("www.")
    domain_parts = stripped.split(".")
    if len(domain_parts) >= 2:
        domain = ".".join(domain_parts[-2:])
    else:
        domain = hostname
    platforms = {"netlify.app": "Netlify", "vercel.app": "Vercel", "pages.dev": "Cloudflare Pages",
                 "github.io": "GitHub Pages", "render.com": "Render", "fly.dev": "Fly.io",
                 "railway.app": "Railway", "cyclic.app": "Cyclic", "replit.app": "Replit"}
    platform = next((v for k, v in platforms.items() if hostname.endswith(k) or hostname.endswith("." + k)), None)
    if platform:
        return f"Domain ({stripped}) is hosted on {platform} — a custom application hosting platform. Not on the blocked sites list."
    return f"Domain ({stripped}) is not on the blocked sites list. Appears to be a custom application you own."

def validate_target_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "URL must use HTTP or HTTPS scheme", ""
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "Invalid URL: no hostname", ""

    is_private, resolved = resolve_to_private_ip(hostname)
    if is_private:
        return True, generate_allow_reason(url, hostname, True), ""

    stripped = hostname.removeprefix("www.")
    if stripped in BLOCKED_DOMAINS:
        return False, f"Public website blocked ({stripped}). Only custom/internal applications are allowed.", ""

    domain_parts = stripped.split(".")
    if len(domain_parts) >= 2:
        domain = ".".join(domain_parts[-2:])
        if domain in BLOCKED_DOMAINS:
            return False, f"Public website blocked ({domain}). Only custom/internal applications are allowed.", ""

    return True, generate_allow_reason(url, hostname, False), ""

from report_generator import ReportGenerator, REPORTS_DIR
report_gen = ReportGenerator(ANTHROPIC_KEY)

def _report_status_path(report_id):
    return os.path.join(REPORTS_DIR, f"{report_id}.status.json")

def _write_report_status(report_id, data):
    try:
        with open(_report_status_path(report_id), "w") as f:
            json.dump(data, f)
    except:
        pass

def _read_report_status(report_id):
    try:
        with open(_report_status_path(report_id), "r") as f:
            return json.load(f)
    except:
        return None

event_queue = queue.Queue(maxsize=2000)
agent_status = {"status": "starting", "message": "Waiting for agent connection..."}

alerts = []
analysis_history = []
packet_buffer = []
thinking_buffer = []
command_history = []
activity_feed = []

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/setup/target", methods=["POST"])
def setup_target():
    global CUSTOM_TARGET
    data = request.json or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"ok": False, "error": "No URL provided"}), 400
    valid, message, _ = validate_target_url(url)
    if not valid:
        return jsonify({"ok": False, "error": message}), 400
    CUSTOM_TARGET = url
    try:
        requests.post(f"{AGENT_URL}/api/setup/target", json={"url": url}, timeout=3)
    except:
        pass
    return jsonify({"ok": True, "target": url, "reason": message})

@app.route("/api/reset", methods=["POST"])
def reset_data():
    global alerts, packet_buffer, thinking_buffer, command_history, analysis_history, activity_feed
    alerts.clear()
    packet_buffer.clear()
    thinking_buffer.clear()
    command_history.clear()
    analysis_history.clear()
    activity_feed.clear()
    agent_status["status"] = "waiting"
    agent_status["message"] = "Dashboard reset — awaiting new data"
    try:
        requests.post(f"{AGENT_URL}/api/reset", timeout=3)
    except:
        pass
    try:
        while not event_queue.empty():
            event_queue.get_nowait()
    except:
        pass
    return jsonify({"ok": True})

@app.route("/api/target")
def get_target():
    return jsonify({"url": CUSTOM_TARGET or ""})

@app.route("/api/events", methods=["POST"])
def receive_event():
    data = request.json
    if not data:
        return jsonify({"ok": False, "error": "no data"}), 400

    event_type = data.get("type", "unknown")
    event_data = data.get("data", {})
    ts = data.get("timestamp", datetime.utcnow().isoformat())

    try:
        event_queue.put_nowait(data)
    except queue.Full:
        pass

    if event_type == "agent_status":
        agent_status.update(event_data)
        agent_status["last_seen"] = ts
        add_activity("agent_status", event_data, ts)

    elif event_type == "alert":
        event_data["timestamp"] = ts
        alerts.insert(0, event_data)
        if len(alerts) > 200:
            alerts.pop()
        add_activity("alert", event_data, ts)

    elif event_type == "agent_think":
        thinking_buffer.append({**event_data, "timestamp": ts})
        if len(thinking_buffer) > 500:
            thinking_buffer.pop(0)

    elif event_type == "agent_command":
        command_history.append({**event_data, "timestamp": ts, "status": "executing", "output": ""})
        if len(command_history) > 100:
            command_history.pop(0)
        add_activity("command", event_data, ts)

    elif event_type == "agent_command_output":
        if command_history:
            for c in command_history:
                if c.get("tool_id") == event_data.get("tool_id") or c.get("command") == event_data.get("command"):
                    c["output"] = event_data.get("output", "")
                    c["status"] = "complete"
                    break
        add_activity("command_output", event_data, ts)

    elif event_type == "agent_cycle_start":
        add_activity("cycle_start", event_data, ts)

    elif event_type == "agent_cycle_complete":
        analysis_history.insert(0, {"data": event_data, "timestamp": ts})
        if len(analysis_history) > 100:
            analysis_history.pop()
        add_activity("cycle_complete", event_data, ts)

    elif event_type == "analysis_cycle":
        analysis_history.insert(0, {"data": event_data, "timestamp": ts})
        if len(analysis_history) > 100:
            analysis_history.pop()
        if event_data.get("sample_packets"):
            for p in event_data["sample_packets"][-5:]:
                packet_buffer.append({**p, "arrived": ts})
        if len(packet_buffer) > 500:
            packet_buffer = packet_buffer[-500:]

    elif event_type == "heartbeat":
        pass

    return jsonify({"ok": True})

def add_activity(atype, data, ts):
    activity_feed.insert(0, {"type": atype, "data": data, "timestamp": ts})
    if len(activity_feed) > 200:
        activity_feed.pop()

@app.route("/api/events/stream")
def event_stream():
    def generate():
        while True:
            try:
                event = event_queue.get(timeout=25)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': datetime.utcnow().isoformat()})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")

@app.route("/api/status")
def get_status():
    return jsonify({
        "agent": agent_status,
        "alert_count": len(alerts),
        "analysis_count": len(analysis_history),
        "thinking_buffer_size": len(thinking_buffer),
        "command_count": len(command_history),
        "recent_alerts": alerts[:10],
        "last_updated": datetime.utcnow().isoformat()
    })

@app.route("/api/alerts")
def get_alerts():
    severity = request.args.get("severity", "")
    limit = int(request.args.get("limit", 50))
    if severity:
        filtered = [a for a in alerts if a.get("severity") == severity]
        return jsonify(filtered[:limit])
    return jsonify(alerts[:limit])

@app.route("/api/thinking")
def get_thinking():
    cycle_id = request.args.get("cycle_id", "")
    if cycle_id:
        filtered = [t for t in thinking_buffer if t.get("cycle_id") == cycle_id]
        return jsonify(filtered)
    return jsonify(thinking_buffer[-100:])

@app.route("/api/commands")
def get_commands():
    limit = int(request.args.get("limit", 50))
    return jsonify(command_history[:limit])

@app.route("/api/analyses")
def get_analyses():
    return jsonify(analysis_history[:20])

@app.route("/api/activity")
def get_activity():
    limit = int(request.args.get("limit", 50))
    return jsonify(activity_feed[:limit])

@app.route("/api/packets/recent")
def recent_packets():
    limit = min(int(request.args.get("limit", 100)), 500)
    return jsonify(packet_buffer[:limit])

@app.route("/api/search/packets")
def search_packets():
    ip = request.args.get("ip", "").lower()
    protocol = request.args.get("protocol", "").lower()
    port = request.args.get("port", "")
    results = packet_buffer
    if ip:
        results = [p for p in results if ip in p.get("ip_src", "").lower() or ip in p.get("ip_dst", "").lower()]
    if protocol:
        results = [p for p in results if p.get("protocol", "").lower() == protocol]
    if port:
        results = [p for p in results if p.get("src_port", "") == port or p.get("dst_port", "") == port]
    return jsonify(results[:50])

@app.route("/api/stats")
def get_stats():
    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for a in alerts:
        sev = a.get("severity", "low")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return jsonify({
        "total_alerts": len(alerts),
        "total_packets": len(packet_buffer),
        "total_activities": len(activity_feed),
        "session_alerts": len(alerts),
        "severity_breakdown": severity_counts,
        "agent_status": agent_status.get("status", "unknown"),
        "agent_message": agent_status.get("message", ""),
        "thinking_blocks": len(thinking_buffer),
        "commands_executed": len(command_history),
        "target_url": CUSTOM_TARGET,
    })

@app.route("/api/ask", methods=["POST"])
def ask_agent():
    question = request.json.get("question", "")
    if not question:
        return jsonify({"error": "No question provided"}), 400

    try:
        r = requests.post(
            f"{AGENT_URL}/api/query",
            json={"question": question},
            timeout=45
        )
        return jsonify(r.json())
    except requests.exceptions.ConnectionError:
        return jsonify({
            "answer": "Agent is running on host network. Analysis continues autonomously. Your question will be queued for the next analysis cycle."
        })
    except requests.exceptions.Timeout:
        return jsonify({"answer": "Agent is busy analyzing traffic. Please try again shortly."})
    except Exception as e:
        return jsonify({"answer": f"Query error: {str(e)[:100]}"})

@app.route("/api/report/generate", methods=["POST"])
def generate_report():
    report_id = uuid.uuid4().hex[:12]
    _write_report_status(report_id, {"status": "generating", "progress": 0})

    def gen_task():
        try:
            _write_report_status(report_id, {"status": "generating", "progress": 10})
            time.sleep(1)
            _write_report_status(report_id, {"status": "generating", "progress": 30})
            path = report_gen.generate(
                report_id,
                target_url=CUSTOM_TARGET,
                alerts=alerts,
                packets=packet_buffer,
                activity=activity_feed
            )
            if path and os.path.exists(path):
                _write_report_status(report_id, {"status": "complete", "progress": 100, "path": path})
            else:
                _write_report_status(report_id, {"status": "error", "progress": 0, "error": "Report file was not created"})
        except Exception as e:
            _write_report_status(report_id, {"status": "error", "progress": 0, "error": str(e)})

    t = threading.Thread(target=gen_task, daemon=True)
    t.start()

    return jsonify({"report_id": report_id, "status": "generating"})

@app.route("/api/report/status/<report_id>")
def report_status(report_id):
    r = _read_report_status(report_id)
    if not r:
        return jsonify({"status": "not_found"}), 404
    return jsonify(r)

@app.route("/api/report/download/<report_id>")
def download_report(report_id):
    r = _read_report_status(report_id)
    if not r or r.get("status") != "complete":
        return jsonify({"error": "Report not ready"}), 404
    path = r.get("path")
    if not path or not os.path.exists(path):
        return jsonify({"error": "File not found"}), 404
    return send_file(path, as_attachment=True, download_name=f"packetsentry-report-{report_id}.pdf", mimetype="application/pdf")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
