import os
import json
import time
import subprocess
import shlex
import traceback

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

REMEDIATION_PLANS = {
    "docker_socket_abuse": {
        "title": "Docker Socket Exposure Remediation",
        "steps": [
            {
                "command": 'docker inspect $(docker ps -q) --format "{{.Name}}: {{.HostConfig.Binds}}" 2>/dev/null',
                "description": "Identify all containers with Docker socket mounts",
                "check": "docker.sock",
                "fix": "Remove docker.sock mounts from containers that don't need them"
            },
            {
                "command": 'docker inspect $(docker ps -q) --format "{{.Name}}: privileged={{.HostConfig.Privileged}}" 2>/dev/null',
                "description": "Identify privileged containers",
                "check": "privileged=true",
                "fix": "Remove --privileged flag and use granular capabilities instead"
            },
            {
                "command": 'docker info --format "{{.SecurityOptions}}" 2>/dev/null',
                "description": "Check Docker daemon security options",
                "check": "",
                "fix": "Enable userns-remap, live-restore, and other security options"
            },
            {
                "command": 'iptables -L DOCKER-USER -n 2>/dev/null || echo "No DOCKER-USER chain"',
                "description": "Check for Docker firewall restrictions",
                "check": "",
                "fix": "Add iptables rules to restrict container access to docker.sock"
            }
        ],
    },
    "cap_sys_admin_escape": {
        "title": "CAP_SYS_ADMIN Capability Remediation",
        "steps": [
            {
                "command": 'docker inspect $(docker ps -q) --format "{{.Name}}: {{range $k,$v := .HostConfig.CapAdd}}{{if eq $k \"SysAdmin\"}}{{$v}}{{end}}{{end}}" 2>/dev/null',
                "description": "Find containers with CAP_SYS_ADMIN",
                "check": "SysAdmin",
                "fix": "Drop CAP_SYS_ADMIN from all containers; use granular caps instead"
            },
            {
                "command": 'docker run --rm --security-opt no-new-privileges alpine echo "no-new-privileges test" 2>/dev/null',
                "description": "Test no-new-privileges security option",
                "check": "",
                "fix": "Add --security-opt=no-new-privileges to all container run commands"
            },
            {
                "command": 'docker inspect $(docker ps -q) --format "{{.Name}}: Seccomp={{.HostConfig.SecurityOpt}}" 2>/dev/null',
                "description": "Check seccomp profiles on running containers",
                "check": "unconfined",
                "fix": "Apply default seccomp profile; do not use seccomp=unconfined"
            }
        ],
    },
    "cgroup_escape": {
        "title": "Cgroup Escape Remediation",
        "steps": [
            {
                "command": 'mount | grep cgroup 2>/dev/null',
                "description": "Check cgroup mount configurations",
                "check": "cgroup",
                "fix": "Use cgroup v2 with unified hierarchy which mitigates notify_on_release escape"
            },
            {
                "command": 'cat /proc/self/cgroup 2>/dev/null',
                "description": "Check current cgroup version and hierarchy",
                "check": "",
                "fix": "Migrate to cgroup v2 and ensure cgroup filesystems are read-only in containers"
            },
            {
                "command": 'docker info --format "{{.CgroupDriver}} {{.CgroupVersion}}" 2>/dev/null',
                "description": "Check Docker cgroup configuration",
                "check": "",
                "fix": "Use cgroupfs or systemd cgroup driver with cgroup v2"
            }
        ],
    },
    "procfs_host_read": {
        "title": "Procfs /proc/1/root Access Remediation",
        "steps": [
            {
                "command": 'docker inspect $(docker ps -q) --format "{{.Name}}: PidMode={{.HostConfig.PidMode}}" 2>/dev/null',
                "description": "Find containers sharing host PID namespace",
                "check": "host",
                "fix": "Do not use --pid=host; use --pid=container: for sidecar patterns instead"
            },
            {
                "command": 'sysctl kernel.pid_max 2>/dev/null',
                "description": "Check system PID limits",
                "check": "",
                "fix": "Ensure containers run with default (isolated) PID namespace"
            },
            {
                "command": 'docker run --rm alpine cat /proc/1/cmdline 2>/dev/null || echo "Isolated"',
                "description": "Verify PID namespace isolation by default",
                "check": "",
                "fix": "Never share host PID namespace with untrusted containers"
            }
        ],
    },
    "privileged_container": {
        "title": "Privileged Container Remediation",
        "steps": [
            {
                "command": 'docker ps --filter "status=running" --format "{{.ID}} {{.Names}}" 2>/dev/null',
                "description": "List all running containers for audit",
                "check": "",
                "fix": "Audit every container and remove --privileged flag where unnecessary"
            },
            {
                "command": 'docker inspect $(docker ps -q) --format "{{.Name}}: Privileged={{.HostConfig.Privileged}}" 2>/dev/null | grep "Privileged=true"',
                "description": "Find all privileged containers",
                "check": "true",
                "fix": "Replace --privileged with specific --cap-add and --device flags"
            },
            {
                "command": 'docker run --rm --cap-drop ALL alpine echo "All caps dropped" 2>/dev/null',
                "description": "Test running with all capabilities dropped",
                "check": "",
                "fix": "Use --cap-drop ALL then --cap-add only what's needed"
            }
        ],
    },
    "volume_mount_traversal": {
        "title": "Volume Mount Traversal Remediation",
        "steps": [
            {
                "command": 'docker inspect $(docker ps -q) --format "{{.Name}}: {{.Mounts}}" 2>/dev/null',
                "description": "List all volume mounts on running containers",
                "check": "",
                "fix": "Audit all host path mounts; remove unnecessary ones"
            },
            {
                "command": 'docker inspect $(docker ps -q) --format "{{.Name}}: {{range .Mounts}}{{if eq .Type \"bind\"}}{{.Source}}->{{.Destination}}{{end}}{{end}}" 2>/dev/null',
                "description": "List bind mounts specifically",
                "check": "",
                "fix": "Mount volumes read-only (:ro) whenever possible"
            },
            {
                "command": 'docker run --rm -v /etc:/etc:ro alpine ls /etc/shadow 2>/dev/null && echo "Readable" || echo "Protected"',
                "description": "Verify read-only mount enforcement",
                "check": "",
                "fix": "Always append :ro to bind mounts; never mount sensitive host paths"
            }
        ],
    },
    "container_network_escape": {
        "title": "Container Network Namespace Remediation",
        "steps": [
            {
                "command": 'docker inspect $(docker ps -q) --format "{{.Name}}: NetworkMode={{.HostConfig.NetworkMode}}" 2>/dev/null',
                "description": "Check container network modes",
                "check": "host",
                "fix": "Do not use --network=host; use bridge or overlay networks with port mapping"
            },
            {
                "command": 'docker inspect $(docker ps -q) --format "{{.Name}}: CapAdd={{.HostConfig.CapAdd}}" 2>/dev/null | grep -i net',
                "description": "Find containers with NET_ADMIN or NET_RAW capability",
                "check": "",
                "fix": "Drop NET_ADMIN and NET_RAW capabilities unless absolutely required"
            },
            {
                "command": 'iptables -L DOCKER-USER -n -v 2>/dev/null | head -20',
                "description": "Check Docker user-defined firewall rules",
                "check": "",
                "fix": "Implement iptables DOCKER-USER chain rules to restrict container networking"
            }
        ],
    },
    "docker_api_abuse": {
        "title": "Docker API SSRF Remediation",
        "steps": [
            {
                "command": 'ss -tlnp 2>/dev/null | grep -E "2375|2376"',
                "description": "Check for exposed Docker TCP API ports",
                "check": "2375",
                "fix": "Never expose Docker TCP API on 0.0.0.0; use Unix socket or TLS"
            },
            {
                "command": 'docker context ls 2>/dev/null',
                "description": "Check Docker contexts for remote endpoints",
                "check": "",
                "fix": "Use TLS client/server certs for remote Docker API access"
            },
            {
                "command": 'curl -s http://127.0.0.1:2375/version 2>/dev/null || echo "Not exposed on localhost"',
                "description": "Verify Docker API is not exposed on localhost TCP",
                "check": "",
                "fix": "Disable TCP port in docker.service; use only Unix socket"
            }
        ],
    },
    "sidecar_attack": {
        "title": "Sidecar/Inter-Container Attack Remediation",
        "steps": [
            {
                "command": 'docker network ls 2>/dev/null',
                "description": "List Docker networks to understand connectivity",
                "check": "",
                "fix": "Implement network segmentation; isolate sensitive containers"
            },
            {
                "command": 'docker network inspect bridge --format "{{range .Containers}}{{.Name}} {{end}}" 2>/dev/null',
                "description": "Check which containers share the default bridge network",
                "check": "",
                "fix": "Use separate networks per application tier; avoid default bridge"
            },
            {
                "command": 'curl -s http://elasticsearch:9200/_cluster/health 2>/dev/null | head -1',
                "description": "Check if Elasticsearch is accessible without auth",
                "check": "",
                "fix": "Enable authentication on all data stores; use network policies"
            }
        ],
    },
    "seccomp_bypass": {
        "title": "Seccomp/AppArmor Profile Remediation",
        "steps": [
            {
                "command": 'docker inspect $(docker ps -q) --format "{{.Name}}: SecurityOpt={{.HostConfig.SecurityOpt}}" 2>/dev/null',
                "description": "Check security options on all running containers",
                "check": "unconfined",
                "fix": "Never use --security-opt seccomp=unconfined or apparmor=unconfined"
            },
            {
                "command": 'cat /proc/self/status | grep Seccomp 2>/dev/null',
                "description": "Check current container seccomp status",
                "check": "0",
                "fix": "Apply Docker's default seccomp profile which blocks 44+ dangerous syscalls"
            },
            {
                "command": 'cat /proc/self/attr/current 2>/dev/null',
                "description": "Check AppArmor status",
                "check": "unconfined",
                "fix": "Apply Docker's default AppArmor profile (docker-default) or a custom restrictive profile"
            }
        ],
    }
}


REMEDIATE_ALL_EXTRA = [
    {
        "command": 'docker system df 2>/dev/null',
        "description": "Check Docker disk usage and cleanup opportunities",
        "check": "",
        "fix": "Run docker system prune to clean up unused resources"
    },
    {
        "command": 'docker info 2>/dev/null | grep -i "security\|userns\|live-restore"',
        "description": "Check Docker daemon-level security configuration",
        "check": "",
        "fix": "Enable user namespace remapping (userns-remap) to add an extra isolation layer"
    },
    {
        "command": 'sysctl kernel.unprivileged_userns_clone 2>/dev/null',
        "description": "Check unprivileged user namespace clone setting",
        "check": "",
        "fix": "Disable unprivileged user namespace clone if not needed"
    }
]


def generate_remediation_plan(attack_technique=None):
    if attack_technique and attack_technique in REMEDIATION_PLANS:
        plan = REMEDIATION_PLANS[attack_technique]
        return {
            "title": plan["title"],
            "technique": attack_technique,
            "steps": plan["steps"]
        }
    elif attack_technique is None or attack_technique == "all":
        all_steps = []
        for tech, plan in REMEDIATION_PLANS.items():
            for step in plan["steps"]:
                all_steps.append({**step, "technique": tech, "plan_title": plan["title"]})
        return {
            "title": "Full Security Remediation",
            "technique": "all",
            "steps": all_steps + REMEDIATE_ALL_EXTRA
        }
    return None


def execute_command(cmd, timeout=30):
    """Execute a remediation command and return structured output."""
    result = {"command": cmd, "output": "", "exit_code": -1, "error": None}
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        result["output"] = (proc.stdout + "\n" + proc.stderr).strip()[:10000]
        result["exit_code"] = proc.returncode
    except subprocess.TimeoutExpired:
        result["error"] = "Command timed out after %ds" % timeout
        result["output"] = "TIMEOUT"
    except Exception as e:
        result["error"] = str(e)
        result["output"] = str(e)
    return result


def call_claude_remediation(attack_data, analysis_context):
    """Use Claude to generate a sophisticated remediation plan."""
    if not ANTHROPIC_API_KEY:
        return None

    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=ANTHROPIC_API_KEY)

        prompt = f"""You are a senior container security engineer performing incident response.

Attack Data:
{json.dumps(attack_data, indent=2)[:3000]}

Analysis Context:
{analysis_context[:3000]}

Generate a detailed remediation plan for this container security incident. Include:
1. Immediate containment steps
2. Root cause analysis
3. Specific commands to execute
4. Configuration changes needed
5. Long-term prevention measures

Format your response as structured remediation steps with clear commands."""

        msg = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system="You are a senior container security engineer. Provide concise, actionable remediation commands.",
            messages=[{"role": "user", "content": prompt}]
        )
        return msg.content[0].text
    except Exception as e:
        return "Claude analysis unavailable: %s" % str(e)
