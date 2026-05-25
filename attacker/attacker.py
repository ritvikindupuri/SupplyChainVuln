import os
import json
import time
import uuid
import requests
import traceback
from datetime import datetime

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
TARGET_URL = os.environ.get("TARGET_URL", "http://vulnerable-app:8080")
ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")
ATTACK_INTERVAL = int(os.environ.get("ATTACK_INTERVAL", "30"))
VULNERABLE_APP_URL = os.environ.get("VULNERABLE_APP_URL", "http://vulnerable-app:8080")


def push_to_elasticsearch(index, doc_type, body):
    url = f"{ELASTICSEARCH_URL}/{index}/_doc"
    try:
        resp = requests.post(url, json=body, timeout=10)
        if resp.status_code not in (200, 201):
            print(f"[ES] Failed to index: {resp.status_code} {resp.text[:200]}")
    except requests.exceptions.ConnectionError:
        print(f"[ES] Connection refused (Elasticsearch not ready)")


def create_attack_record(attack_name, technique, status, detail, analysis, raw_output=""):
    return {
        "@timestamp": datetime.utcnow().isoformat(),
        "attack_id": str(uuid.uuid4()),
        "attack_name": attack_name,
        "technique": technique,
        "mitre_technique": map_technique_to_mitre(technique),
        "status": status,
        "detail": detail,
        "analysis": analysis,
        "raw_output": raw_output[:50000],
        "target": TARGET_URL,
        "agent": "claude-attacker-v1",
        "source": "ai-attacker-container"
    }


def map_technique_to_mitre(technique):
    mapping = {
        "docker_socket_abuse": "T1610 - Deploy Container",
        "cap_sys_admin_escape": "T1611 - Escape to Host",
        "cgroup_escape": "T1611 - Escape to Host",
        "procfs_host_read": "T1611 - Escape to Host",
        "privileged_container": "T1611 - Escape to Host",
        "volume_mount_traversal": "T1611 - Escape to Host",
        "container_network_escape": "T1610 - Deploy Container",
        "docker_api_abuse": "T1610 - Deploy Container",
        "sidecar_attack": "T1552 - Unsecured Credentials",
        "seccomp_bypass": "T1611 - Escape to Host"
    }
    return mapping.get(technique, "TA0004 - Privilege Escalation")


def check_target_healthy():
    try:
        r = requests.get(f"{TARGET_URL}/health", timeout=10)
        return r.status_code == 200
    except:
        return False


def call_claude_analyze(system_prompt, user_prompt):
    if not ANTHROPIC_API_KEY:
        return {"error": "No API key configured"}

    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=ANTHROPIC_API_KEY)
        msg = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}]
        )
        return {"response": msg.content[0].text}
    except Exception as e:
        return {"error": str(e), "traceback": traceback.format_exc()}


def format_claude_analysis(attack_name, technique, result_data, success):
    sys_prompt = """You are a container security expert. Analyze the following attack attempt against a containerized application. 
Provide:
1. A brief summary of what was attempted
2. Whether it succeeded and why
3. The real-world impact if this were a production environment
4. MITRE ATT&CK mapping
5. Recommendations for detection/prevention
Be concise but thorough."""

    user_prompt = f"""Attack Name: {attack_name}
Technique: {technique}
Target: {TARGET_URL}
Success: {success}
Result Data: {json.dumps(result_data, indent=2)[:3000]}

Analyze this attack attempt and provide your expert assessment."""

    analysis = call_claude_analyze(sys_prompt, user_prompt)
    return analysis.get("response", json.dumps(analysis))


def push_live_event(attack_name, technique, severity, detail, status):
    try:
        requests.post("%s/api/attack-event" % VULNERABLE_APP_URL, json={
            "attack_name": attack_name,
            "technique": technique,
            "severity": severity,
            "detail": detail,
            "status": status
        }, timeout=5)
    except:
        pass


from attack_scenarios import ATTACK_SCENARIOS

def execute_attack(scenario):
    name = scenario["name"]
    technique = scenario["technique"]
    print(f"\n{'='*60}")
    print(f"[ATTACK] Executing: {name}")
    print(f"[ATTACK] Technique: {technique}")
    print(f"[ATTACK] Description: {scenario['description']}")
    print(f"{'='*60}")

    try:
        result = scenario["handler"](TARGET_URL)
        success = result.get("success", False)
        detail = result.get("detail", "No detail provided")
        raw_output = result.get("raw_output", "")

        push_live_event(name, technique, "critical" if success else "high", detail, "success" if success else "failed")
        print(f"[RESULT] Success: {success}")
        print(f"[RESULT] Detail: {detail[:200]}")

        analysis = format_claude_analysis(name, technique, result, success)
        print(f"[CLAUDE] Analysis: {analysis[:200]}...")

        record = create_attack_record(name, technique, "success" if success else "failed", detail, analysis, raw_output)

        push_to_elasticsearch("attack-logs", "attack", record)

        return record

    except Exception as e:
        print(f"[ERROR] Attack failed with exception: {e}")
        traceback.print_exc()

        analysis = format_claude_analysis(name, technique, {"error": str(e)}, False)
        record = create_attack_record(name, technique, "error", str(e), analysis)

        push_to_elasticsearch("attack-logs", "attack", record)
        return record


def main():
    print(f"""
    ╔══════════════════════════════════════════════════╗
    ║   AI Container Attacker - Claude Powered         ║
    ║   Target: {TARGET_URL:<35} ║
    ║   Attacks: {len(ATTACK_SCENARIOS):<35} ║
    ║   Interval: {ATTACK_INTERVAL}s                                        ║
    ╚══════════════════════════════════════════════════╝
    """)

    api_key_status = "CONFIGURED" if ANTHROPIC_API_KEY else "NOT SET (running in mock mode)"
    es_status = ELASTICSEARCH_URL
    print(f"[INIT] Anthropic API: {api_key_status}")
    print(f"[INIT] Elasticsearch: {es_status}")
    print(f"[INIT] Attack interval: {ATTACK_INTERVAL}s")
    print(f"[INIT] Loaded {len(ATTACK_SCENARIOS)} attack scenarios")

    round_num = 1
    while True:
        print(f"\n{'#'*60}")
        print(f"#  ATTACK ROUND {round_num}")
        print(f"#  {datetime.utcnow().isoformat()}")
        print(f"{'#'*60}")

        if not check_target_healthy():
            print(f"[WAIT] Target not ready at {TARGET_URL}, retrying in 10s...")
            time.sleep(10)
            continue

        for scenario in ATTACK_SCENARIOS:
            execute_attack(scenario)
            time.sleep(5)

        print(f"\n[DONE] Round {round_num} complete. Next round in {ATTACK_INTERVAL}s...")
        round_num += 1
        time.sleep(ATTACK_INTERVAL)


if __name__ == "__main__":
    main()
