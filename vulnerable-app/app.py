from flask import Flask, request, jsonify, render_template_string, render_template, Response
import subprocess
import os
import socket
import json
import uuid
import time
import threading
import queue

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "default-dev-secret")

EXEC_LOG = []
LIVE_EVENTS = queue.Queue(maxsize=200)
SYSTEM_METRICS = {
    "cpu": 12.0, "memory": 45.0, "processes": 8,
    "network_connections": 3, "open_files": 42,
    "disk_io": "2.3 MB/s", "compromised": False,
    "alerts": [], "attack_active": False,
    "current_attacker_ip": ""
}

def log_event(event_type, detail, severity="info"):
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "type": event_type,
        "detail": detail,
        "severity": severity,
        "container": os.uname().nodename
    }
    EXEC_LOG.append(entry)
    if len(EXEC_LOG) > 500:
        EXEC_LOG.pop(0)
    return entry

def push_live_event(attack_name, technique, severity, detail, status):
    event = {
        "type": "attack",
        "attack_name": attack_name,
        "technique": technique,
        "severity": severity,
        "detail": detail,
        "status": status,
        "timestamp": time.time(),
        "time_str": time.strftime("%H:%M:%S")
    }
    try:
        LIVE_EVENTS.put_nowait(event)
    except queue.Full:
        try:
            LIVE_EVENTS.get_nowait()
            LIVE_EVENTS.put_nowait(event)
        except:
            pass

    if severity in ("critical", "high"):
        SYSTEM_METRICS["alerts"].append(event)
        if len(SYSTEM_METRICS["alerts"]) > 20:
            SYSTEM_METRICS["alerts"] = SYSTEM_METRICS["alerts"][-20:]
        SYSTEM_METRICS["compromised"] = True
        SYSTEM_METRICS["attack_active"] = True

    SYSTEM_METRICS["cpu"] = min(100, SYSTEM_METRICS["cpu"] + 5 + (15 if severity == "critical" else 0))
    SYSTEM_METRICS["memory"] = min(100, SYSTEM_METRICS["memory"] + 3 + (8 if severity == "critical" else 0))
    SYSTEM_METRICS["processes"] += 1


@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head><title>ContainerCorp - Internal Dashboard</title>
    <script>
    let attackActive = false;
    let compromised = false;
    function pollSystem() {
        fetch('/api/system/status').then(r=>r.json()).then(d => {
            document.getElementById('cpuBar').style.width = d.cpu + '%';
            document.getElementById('cpuVal').textContent = d.cpu.toFixed(1) + '%';
            document.getElementById('memBar').style.width = d.memory + '%';
            document.getElementById('memVal').textContent = d.memory.toFixed(1) + '%';
            document.getElementById('procCount').textContent = d.processes;
            document.getElementById('netConn').textContent = d.network_connections;
            document.getElementById('diskIO').textContent = d.disk_io;

            if (d.compromised && !compromised) {
                compromised = true;
                document.getElementById('compromiseBanner').style.display = 'block';
                document.getElementById('statusIndicator').className = 'status compromised';
                document.getElementById('statusIndicator').textContent = 'COMPROMISED';
                document.body.classList.add('compromised');
            }
            if (d.attack_active) {
                attackActive = true;
                document.getElementById('attackIndicator').style.display = 'block';
            }
        }).catch(()=>{});
    }
    function pollEvents() {
        fetch('/api/live-events').then(r=>r.json()).then(events => {
            const feed = document.getElementById('liveFeed');
            if (events.length > 0) {
                document.getElementById('feedPlaceholder').style.display = 'none';
                events.forEach(e => {
                    const div = document.createElement('div');
                    div.className = 'event ' + (e.severity || 'info');
                    div.innerHTML = '<span class="evt-time">'+e.time_str+'</span> ' +
                        '<span class="evt-sev">['+(e.severity||'info').toUpperCase()+']</span> ' +
                        '<span class="evt-name">'+(e.attack_name||e.detail||'')+'</span>';
                    feed.insertBefore(div, feed.firstChild);
                    if (feed.children.length > 50) feed.removeChild(feed.lastChild);
                });
            }
        }).catch(()=>{});
    }
    setInterval(pollSystem, 1500);
    setInterval(pollEvents, 2000);
    pollSystem();
    pollEvents();
    </script>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family: 'Segoe UI', monospace; background: #0a0e17; color: #00ff88; padding: 20px; transition: all 0.3s; }
        body.compromised { background: #0a0a0a; }
        body.compromised::before { content: ''; position: fixed; inset:0; pointer-events:none; background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,0,0,0.03) 2px, rgba(255,0,0,0.03) 4px); z-index:9999; }
        h1 { color: #00ffcc; border-bottom: 1px solid #00ff88; padding-bottom: 10px; font-size: 20px; }
        .container { display:grid; grid-template-columns: 1fr 1fr; gap:16px; margin-top:16px; }
        .card { background: #111827; border: 1px solid #1f2937; padding: 14px; border-radius: 6px; }
        .card h3 { font-size: 12px; color: #6a8fa8; text-transform: uppercase; letter-spacing:1px; margin-bottom:8px; }
        .full { grid-column: 1 / -1; }
        .nav-links { display:flex; gap:8px; flex-wrap:wrap; margin:12px 0; }
        .nav-links a { color: #00ff88; text-decoration:none; font-size:12px; padding:4px 10px; border:1px solid #1f2937; border-radius:4px; }
        .nav-links a:hover { background:#1f2937; }
        .meter { height:20px; background:#1a1a2e; border-radius:10px; overflow:hidden; margin:4px 0; }
        .meter .fill { height:100%; transition: width 1s; border-radius:10px; }
        .fill.cpu { background: linear-gradient(90deg, #00ff88, #ffaa00); }
        .fill.mem { background: linear-gradient(90deg, #00ff88, #00ccff); }
        .meter-text { display:flex; justify-content:space-between; font-size:11px; }
        .stat-row { display:grid; grid-template-columns:repeat(3,1fr); gap:8px; margin:8px 0; }
        .stat { text-align:center; padding:8px; background:#0a0e17; border-radius:4px; }
        .stat .val { font-size:18px; font-weight:bold; color:#00ffcc; }
        .stat .lbl { font-size:10px; color:#6a8fa8; }
        .compromise-banner { display:none; background:rgba(255,0,0,0.15); border:1px solid #ff4444; color:#ff4444; padding:10px 16px; border-radius:6px; margin:8px 0; font-weight:bold; animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity:0.7; } 50% { opacity:1; } 100% { opacity:0.7; } }
        .status { display:inline-block; padding:3px 10px; border-radius:4px; font-size:10px; font-weight:bold; }
        .status.secure { background:rgba(0,255,136,0.15); color:#00ff88; }
        .status.compromised { background:rgba(255,0,0,0.15); color:#ff4444; animation:pulse 1s infinite; }
        .attack-indicator { display:none; background:rgba(255,170,0,0.1); border:1px solid #ffaa00; padding:8px 12px; border-radius:4px; margin:4px 0; font-size:11px; }
        .live-feed { max-height:300px; overflow-y:auto; font-size:11px; }
        .live-feed .event { padding:3px 0; border-bottom:1px solid #1a1a2e; }
        .live-feed .event.critical { color:#ff4444; }
        .live-feed .event.high { color:#ffaa00; }
        .live-feed .event.medium { color:#00ccff; }
        .evt-time { color:#6a8fa8; margin-right:6px; }
        .evt-sev { font-weight:bold; margin-right:6px; }
    </style>
    </head>
    <body>
        <div style="display:flex;justify-content:space-between;align-items:center;">
            <h1>ContainerCorp Internal Dashboard</h1>
            <span class="status secure" id="statusIndicator">SECURE</span>
        </div>

        <div class="compromise-banner" id="compromiseBanner">
            &#x26a0; SECURITY BREACH DETECTED — Container escape attempt in progress
        </div>
        <div class="attack-indicator" id="attackIndicator">
            &#x26a1; Active attack detected — System security may be compromised
        </div>

        <div class="nav-links">
            <a href="/">Dashboard</a>
            <a href="/health">Health</a>
            <a href="/env">Environment</a>
            <a href="/shell?cmd=id">Command Runner</a>
            <a href="/readfile?path=/etc/passwd">File Reader</a>
            <a href="/docker/info">Docker API</a>
            <a href="/logs">Event Log</a>
        </div>

        <div class="container">
            <div class="card full">
                <h3>System Status</h3>
                <div class="stat-row">
                    <div class="stat"><div class="val" id="cpuVal">12.0%</div><div class="lbl">CPU</div><div class="meter"><div class="fill cpu" id="cpuBar" style="width:12%"></div></div></div>
                    <div class="stat"><div class="val" id="memVal">45.0%</div><div class="lbl">Memory</div><div class="meter"><div class="fill mem" id="memBar" style="width:45%"></div></div></div>
                    <div class="stat"><div class="val" id="procCount">8</div><div class="lbl">Processes</div></div>
                    <div class="stat"><div class="val" id="netConn">3</div><div class="lbl">Net Connections</div></div>
                    <div class="stat"><div class="val" id="diskIO">2.3 MB/s</div><div class="lbl">Disk I/O</div></div>
                    <div class="stat"><div class="val" id="openFiles">42</div><div class="lbl">Open Files</div></div>
                </div>
            </div>

            <div class="card full">
                <h3>Live Attack Feed</h3>
                <div class="live-feed" id="liveFeed">
                    <div id="feedPlaceholder" style="color:#6a8fa8;padding:10px">Waiting for Phase 2 attacks...<br><span style="font-size:10px">Run: docker compose --profile attack up -d attacker</span></div>
                </div>
            </div>

            <div class="card full">
                <h3>Vulnerable Endpoints (for testing)</h3>
                <div style="font-size:11px;display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px">
                    <div style="background:#0a0e17;padding:8px;border-radius:4px">
                        <strong>GET /shell?cmd=</strong><br>
                        <span style="color:#6a8fa8">Command injection — no input sanitization</span>
                    </div>
                    <div style="background:#0a0e17;padding:8px;border-radius:4px">
                        <strong>GET /readfile?path=</strong><br>
                        <span style="color:#6a8fa8">Path traversal — no path restrictions</span>
                    </div>
                    <div style="background:#0a0e17;padding:8px;border-radius:4px">
                        <strong>POST /api/exec</strong><br>
                        <span style="color:#6a8fa8">Remote command execution API</span>
                    </div>
                    <div style="background:#0a0e17;padding:8px;border-radius:4px">
                        <strong>POST /api/fetch</strong><br>
                        <span style="color:#6a8fa8">SSRF — no URL restrictions</span>
                    </div>
                    <div style="background:#0a0e17;padding:8px;border-radius:4px">
                        <strong>POST /api/deserialize</strong><br>
                        <span style="color:#6a8fa8">Insecure deserialization via eval()</span>
                    </div>
                    <div style="background:#0a0e17;padding:8px;border-radius:4px">
                        <strong>GET /docker/*</strong><br>
                        <span style="color:#6a8fa8">Docker API proxy via mounted socket</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>Container Info</h3>
                <div style="font-size:11px">
                    <div><strong>Hostname:</strong> {{ hostname }}</div>
                    <div><strong>Container:</strong> vuln-app</div>
                    <div><strong>Capabilities:</strong> SYS_ADMIN, DAC_OVERRIDE</div>
                    <div><strong>Seccomp:</strong> unconfined</div>
                    <div><strong>Docker Socket:</strong> /var/run/docker.sock (rw)</div>
                    <div><strong>Host Shadow:</strong> /etc/host-shadow (ro)</div>
                </div>
            </div>

            <div class="card">
                <h3>Events This Session</h3>
                <div style="font-size:11px" id="eventCount">{{ event_count }}</div>
            </div>
        </div>
    </body>
    </html>
    """, hostname=socket.gethostname(), event_count=len(EXEC_LOG))


@app.route("/api/system/status")
def system_status():
    return jsonify(SYSTEM_METRICS)


@app.route("/api/live-events")
def live_events():
    events = []
    try:
        while not LIVE_EVENTS.empty():
            events.append(LIVE_EVENTS.get_nowait())
    except:
        pass
    return jsonify(events)


@app.route("/api/attack-event", methods=["POST"])
def receive_attack_event():
    data = request.get_json(silent=True) or {}
    attack_name = data.get("attack_name", "Unknown")
    technique = data.get("technique", "unknown")
    severity = data.get("severity", "medium")
    detail = data.get("detail", "")
    status = data.get("status", "unknown")
    push_live_event(attack_name, technique, severity, detail, status)
    log_event("attack_%s" % technique, detail, severity)
    return jsonify({"received": True})


@app.route("/api/system/metrics", methods=["POST"])
def update_metrics():
    data = request.get_json(silent=True) or {}
    if "cpu" in data:
        SYSTEM_METRICS["cpu"] = min(100, data["cpu"])
    if "memory" in data:
        SYSTEM_METRICS["memory"] = min(100, data["memory"])
    if "processes" in data:
        SYSTEM_METRICS["processes"] = data["processes"]
    if "network_connections" in data:
        SYSTEM_METRICS["network_connections"] = data["network_connections"]
    if "compromised" in data:
        SYSTEM_METRICS["compromised"] = data["compromised"]
    if "attack_active" in data:
        SYSTEM_METRICS["attack_active"] = data["attack_active"]
    return jsonify({"ok": True})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "hostname": socket.gethostname()})


@app.route("/env")
def env_dump():
    return jsonify({k: v for k, v in sorted(os.environ.items())})


@app.route("/debug/network")
def debug_network():
    host = request.args.get("host", "localhost")
    try:
        result = subprocess.check_output(["ping", "-c", "1", "-W", "2", host], stderr=subprocess.STDOUT, timeout=5)
        return render_template_string("<pre>{{ output }}</pre><a href='/'>Back</a>", output=result.decode())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/debug/processes")
def debug_processes():
    try:
        result = subprocess.check_output(["ps", "aux"], stderr=subprocess.STDOUT, timeout=5)
        return render_template_string("<pre>{{ output }}</pre><a href='/'>Back</a>", output=result.decode())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/shell")
def shell_injection():
    cmd = request.args.get("cmd", "id")
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        log_event("command_execution", "Executed via shell: %s" % cmd, "medium")
        push_live_event("Shell Command Executed", "command_injection", "high", "Command: %s" % cmd, "success")
        SYSTEM_METRICS["cpu"] = min(100, SYSTEM_METRICS["cpu"] + 10)
        SYSTEM_METRICS["processes"] += 1
        return render_template_string("""
        <h2>Command Output</h2>
        <pre>{{ output }}</pre>
        <form><input name="cmd" placeholder="Enter command"><button>Run</button></form>
        <a href="/">Back</a>
        """, output=result.decode())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/readfile")
def read_file():
    path = request.args.get("path", "/etc/passwd")
    try:
        with open(path, "r") as f:
            content = f.read()
        log_event("file_read", "Read file: %s" % path, "medium")
        push_live_event("File Read", "path_traversal", "medium", "Path: %s" % path, "success")
        return render_template_string("""
        <h2>File: {{ path }}</h2>
        <pre>{{ content }}</pre>
        <form><input name="path" placeholder="/etc/passwd"><button>Read</button></form>
        <a href="/">Back</a>
        """, path=path, content=content[:5000])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/docker/info")
@app.route("/docker/<path:docker_path>")
def docker_proxy(docker_path="info"):
    sock_path = "/var/run/docker.sock"
    if not os.path.exists(sock_path):
        return jsonify({"error": "Docker socket not available"}), 503
    try:
        import http.client
        conn = http.client.HTTPConnection("localhost", 80, timeout=5)
        conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.sock.connect(sock_path)
        conn.request("GET", "/%s" % docker_path)
        resp = conn.getresponse()
        data = resp.read().decode()
        log_event("docker_api", "Docker API call: /%s" % docker_path, "high")
        push_live_event("Docker API Access", "docker_socket", "critical", "Endpoint: /%s" % docker_path, "success")
        SYSTEM_METRICS["compromised"] = True
        SYSTEM_METRICS["attack_active"] = True
        return jsonify({"status": resp.status, "data": json.loads(data) if data else {}})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/exec", methods=["POST"])
def api_exec():
    data = request.get_json(silent=True) or {}
    cmd = data.get("cmd", "id")
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
        log_event("api_command_execution", "API exec: %s" % cmd, "high")
        push_live_event("API Command Execution", "api_exec", "critical", "Command: %s" % cmd, "success")
        SYSTEM_METRICS["cpu"] = min(100, SYSTEM_METRICS["cpu"] + 20)
        SYSTEM_METRICS["processes"] += 2
        SYSTEM_METRICS["attack_active"] = True
        return jsonify({"output": result.decode(), "exit_code": 0})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "timeout", "exit_code": -1}), 408
    except subprocess.CalledProcessError as e:
        return jsonify({"output": e.output.decode(), "exit_code": e.returncode})
    except Exception as e:
        return jsonify({"error": str(e), "exit_code": -1}), 500


@app.route("/api/readfile", methods=["POST"])
def api_readfile():
    data = request.get_json(silent=True) or {}
    path = data.get("path", "/etc/passwd")
    try:
        with open(path, "r") as f:
            content = f.read()
        log_event("api_file_read", "API read file: %s" % path, "high")
        push_live_event("API File Read", "file_read", "high", "Path: %s" % path, "success")
        return jsonify({"content": content, "path": path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/fetch", methods=["POST"])
def api_fetch():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=10) as resp:
            content = resp.read().decode()
        log_event("ssrf_request", "SSRF fetch: %s" % url, "critical")
        push_live_event("SSRF Request", "ssrf", "critical", "URL: %s" % url, "success")
        SYSTEM_METRICS["attack_active"] = True
        return jsonify({"status": resp.status, "content": content[:5000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/deserialize", methods=["POST"])
def api_deserialize():
    data = request.get_json(silent=True) or {}
    raw = data.get("data", "")
    try:
        import base64
        decoded = base64.b64decode(raw)
        obj = eval(decoded)
        log_event("unsafe_deserialization", "Unsafe eval deserialization triggered", "critical")
        push_live_event("Insecure Deserialization", "unsafe_deserialize", "critical", "eval() executed on user input", "success")
        SYSTEM_METRICS["compromised"] = True
        return jsonify({"result": str(obj)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/logs")
def view_logs():
    html = "<h2>Event Log</h2><table border='1' style='color:#00ff88'><tr><th>Time</th><th>Type</th><th>Severity</th><th>Detail</th></tr>"
    for entry in reversed(EXEC_LOG[-100:]):
        html += "<tr><td>%.1f</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            entry['timestamp'], entry['type'], entry['severity'], entry['detail'][:100])
    html += "</table><a href='/'>Back</a>"
    return render_template_string(html)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True, threaded=True)
