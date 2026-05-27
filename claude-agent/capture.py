import subprocess
import json
import re
import os
import signal
import threading
from collections import deque
from datetime import datetime

PCAP_DIR = "/pcaps"
os.makedirs(PCAP_DIR, exist_ok=True)

packet_queue = deque(maxlen=500)

class PacketCapture:
    def __init__(self, interface="any", bpf_filter=""):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.process = None
        self.running = False
        self._thread = None

    def get_interfaces(self):
        try:
            result = subprocess.run(
                ["tshark", "-D"],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip().split("\n")
        except:
            return ["any"]

    def capture_once(self, count=50, filter_expr=""):
        cmd = ["tshark", "-i", self.interface, "-c", str(count), "-T", "fields"]
        fields = [
            "-e", "frame.time_epoch",
            "-e", "frame.len",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ip.proto",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info",
        ]
        cmd.extend(fields)
        cmd.extend(["-E", "separator=|", "-E", "occurrence=f"])
        if filter_expr:
            cmd.extend(["-f", filter_expr])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return self._parse_output(result.stdout)
        except subprocess.TimeoutExpired:
            return []
        except Exception as e:
            return []

    def _parse_output(self, output):
        packets = []
        for line in output.strip().split("\n"):
            if not line or line.startswith("tshark:"):
                continue
            parts = line.split("|")
            if len(parts) < 6:
                continue
            pkt = {
                "timestamp": parts[0] if parts[0] else datetime.utcnow().isoformat(),
                "frame_len": parts[1] if len(parts) > 1 else "",
                "ip_src": parts[2] if len(parts) > 2 else "",
                "ip_dst": parts[3] if len(parts) > 3 else "",
                "ip_proto": parts[4] if len(parts) > 4 else "",
                "src_port": (parts[5] or parts[7]) if len(parts) > 7 else "",
                "dst_port": (parts[6] or parts[8]) if len(parts) > 8 else "",
                "protocol": parts[9] if len(parts) > 9 else "",
                "info": parts[10] if len(parts) > 10 else "",
            }
            packets.append(pkt)
        return packets

    def write_pcap(self, count=200, filter_expr="", output_name=None):
        if not output_name:
            output_name = f"capture_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pcap"
        output_path = os.path.join(PCAP_DIR, output_name)
        cmd = ["tshark", "-i", self.interface, "-c", str(count),
               "-w", output_path, "-F", "pcap"]
        if filter_expr:
            cmd.extend(["-f", filter_expr])
        try:
            subprocess.run(cmd, timeout=60)
            return output_path
        except:
            return None

    def start_continuous(self, filter_expr=""):
        self.running = True
        self._thread = threading.Thread(target=self._capture_loop, args=(filter_expr,), daemon=True)
        self._thread.start()

    def stop_continuous(self):
        self.running = False

    def _capture_loop(self, filter_expr=""):
        while self.running:
            packets = self.capture_once(count=20, filter_expr=filter_expr)
            for p in packets:
                if p["ip_src"]:
                    packet_queue.append(p)
            threading.Event().wait(0.5)

    def get_recent_packets(self, n=20):
        return list(packet_queue)[-n:]

    def run_tshark_command(self, args):
        cmd = ["tshark"] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"

    def get_statistics(self, stat_type="io"):
        cmd = ["tshark", "-i", self.interface, "-c", "1000", "-q", "-z"]
        if stat_type == "io":
            cmd.append("io,stat,1")
        elif stat_type == "conv_ip":
            cmd.append("conv,ip")
        elif stat_type == "conv_tcp":
            cmd.append("conv,tcp")
        elif stat_type == "endpoints":
            cmd.append("endpoints,ip")
        else:
            cmd.append("io,stat,1")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout
        except:
            return ""
