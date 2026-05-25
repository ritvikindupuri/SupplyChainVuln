import os
import json
import time
import uuid
import threading
import requests
from flask import Flask, render_template, jsonify, request, Response, stream_with_context

app = Flask(__name__)

ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

remediation_sessions = {}
attack_cache = []


def fetch_attack_logs():
    try:
        r = requests.get("%s/attack-logs-*/_search?sort=@timestamp:desc&size=100&ignore_unavailable=true" % ELASTICSEARCH_URL, timeout=10)
        if r.status_code in (200, 404):
            data = r.json() if r.status_code == 200 else {"hits": {"hits": []}}
            hits = data.get("hits", {}).get("hits", [])
            return [h["_source"] for h in hits]
    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass
    return []


def enrich_severity(attack_name, technique, status):
    critical_keywords = ["docker_socket_abuse", "cap_sys_admin_escape", "cgroup_escape", "privileged_container"]
    high_keywords = ["procfs_host_read", "volume_mount_traversal", "seccomp_bypass"]
    if technique in critical_keywords or "escape" in (attack_name or "").lower():
        return "critical"
    if technique in high_keywords:
        return "high"
    if status == "success":
        return "high"
    return "medium"


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/attacks")
def api_attacks():
    logs = fetch_attack_logs()
    for log in logs:
        if "severity" not in log:
            log["severity"] = enrich_severity(log.get("attack_name"), log.get("technique"), log.get("status"))
    return jsonify(logs)


@app.route("/api/attacks/<attack_id>")
def api_attack_detail(attack_id):
    try:
        r = requests.get("%s/attack-logs-*/_search?q=attack_id:%s" % (ELASTICSEARCH_URL, attack_id), timeout=10)
        if r.status_code == 200:
            hits = r.json().get("hits", {}).get("hits", [])
            if hits:
                return jsonify(hits[0]["_source"])
    except:
        pass
    return jsonify({"error": "not found"}), 404


@app.route("/api/report/download")
def download_report():
    from report_generator import generate_report
    logs = fetch_attack_logs()
    for log in logs:
        if "severity" not in log:
            log["severity"] = enrich_severity(log.get("attack_name"), log.get("technique"), log.get("status"))
    html, report_id = generate_report(logs)
    return Response(html, mimetype="text/html",
                    headers={"Content-Disposition": "attachment; filename=security-report-%s.html" % report_id})


@app.route("/api/report/json")
def download_report_json():
    logs = fetch_attack_logs()
    report = {
        "report_id": "CR-%s" % int(time.time()),
        "generated_at": time.time(),
        "total_attacks": len(logs),
        "attacks": logs
    }
    return jsonify(report)


@app.route("/api/remediation/plan", methods=["POST"])
def remediation_plan():
    from remediation_agent import generate_remediation_plan
    data = request.get_json(silent=True) or {}
    technique = data.get("technique", "all")
    plan = generate_remediation_plan(technique)
    if plan:
        return jsonify(plan)
    return jsonify({"error": "Unknown technique"}), 400


@app.route("/api/remediation/execute", methods=["POST"])
def remediation_execute():
    from remediation_agent import execute_command, generate_remediation_plan
    data = request.get_json(silent=True) or {}
    technique = data.get("technique", "all")
    session_id = str(uuid.uuid4())

    plan = generate_remediation_plan(technique)
    if not plan:
        return jsonify({"error": "Unknown technique"}), 400

    steps = plan["steps"]
    if not steps:
        return jsonify({"error": "No steps in plan"}), 400

    def run_remediation():
        session = remediation_sessions.get(session_id, {"status": "running", "steps": []})
        for i, step in enumerate(steps):
            cmd = step["command"]
            desc = step["description"]

            thinking = "Analyzing step %d/%d: %s\nChecking current state with: %s" % (i+1, len(steps), desc, cmd)
            session["steps"].append({
                "step": i+1,
                "total": len(steps),
                "description": desc,
                "thinking": thinking,
                "command": cmd,
                "output": "",
                "status": "running"
            })
            remediation_sessions[session_id] = session

            result = execute_command(cmd)
            session["steps"][-1]["output"] = result.get("output", "")
            session["steps"][-1]["exit_code"] = result.get("exit_code", -1)
            session["steps"][-1]["status"] = "success" if result.get("exit_code") == 0 else "failed"

            if result.get("error"):
                session["steps"][-1]["error"] = result["error"]

            remediation_sessions[session_id] = session
            time.sleep(0.5)

        session["status"] = "completed"
        remediation_sessions[session_id] = session

    thread = threading.Thread(target=run_remediation, daemon=True)
    thread.start()

    return jsonify({"session_id": session_id, "total_steps": len(steps)})


@app.route("/api/remediation/stream/<session_id>")
def remediation_stream(session_id):
    def generate():
        last_count = 0
        while True:
            session = remediation_sessions.get(session_id, {})
            if not session:
                yield "data: %s\n\n" % json.dumps({"error": "Session not found"})
                break

            steps = session.get("steps", [])
            if len(steps) > last_count:
                new_steps = steps[last_count:]
                for s in new_steps:
                    yield "data: %s\n\n" % json.dumps(s)
                last_count = len(steps)

            if session.get("status") == "completed" and len(steps) == last_count:
                yield "data: %s\n\n" % json.dumps({"status": "completed", "step": -1})
                break

            time.sleep(0.3)

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/api/remediation/session/<session_id>")
def remediation_session(session_id):
    session = remediation_sessions.get(session_id, {"error": "not found"})
    return jsonify(session)


@app.route("/api/remediation/claude", methods=["POST"])
def remediation_claude():
    from remediation_agent import call_claude_remediation
    data = request.get_json(silent=True) or {}
    attack_data = data.get("attack_data", {})
    context = data.get("context", "")
    analysis = call_claude_remediation(attack_data, context)
    return jsonify({"analysis": analysis or "Claude remediation unavailable"})


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
