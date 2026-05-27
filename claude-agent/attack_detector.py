import re
from collections import defaultdict

class AttackDetector:
    def __init__(self):
        self.connection_tracker = defaultdict(list)
        self.port_scan_threshold = 15
        self.syn_flood_threshold = 100
        self.dns_tunnel_threshold = 50

    def analyze_packets(self, packets):
        alerts = []
        src_dst_pairs = defaultdict(int)
        syn_packets = defaultdict(int)
        dns_queries = defaultdict(int)
        large_packets = []

        for pkt in packets:
            src = pkt.get("ip_src", "")
            dst = pkt.get("ip_dst", "")
            proto = pkt.get("protocol", "")
            info = pkt.get("info", "")
            length = pkt.get("frame_len", "0")

            try:
                length = int(length) if length else 0
            except:
                length = 0

            key = f"{src}->{dst}"
            src_dst_pairs[key] += 1

            if "SYN" in info and "ACK" not in info:
                syn_packets[dst] += 1

            if proto == "DNS" or "dns" in info.lower():
                src_ip = src
                dns_queries[src_ip] += 1

            if length > 1000:
                large_packets.append(pkt)

        for pair, count in src_dst_pairs.items():
            if count >= self.port_scan_threshold:
                src_ip = pair.split("->")[0]
                dst_ip = pair.split("->")[1]
                alerts.append({
                    "event_type": "port_scan",
                    "severity": "medium",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "confidence": min(count / self.port_scan_threshold, 1.0),
                    "description": f"Possible port scan: {count} connections from {src_ip} to {dst_ip}",
                    "mitre_tactic": "Discovery",
                    "mitre_technique": "T1046 - Network Service Discovery"
                })

        for dst, count in syn_packets.items():
            if count >= self.syn_flood_threshold:
                alerts.append({
                    "event_type": "syn_flood",
                    "severity": "high",
                    "src_ip": "multiple",
                    "dst_ip": dst,
                    "confidence": min(count / self.syn_flood_threshold, 1.0),
                    "description": f"Possible SYN flood: {count} SYN packets to {dst}",
                    "mitre_tactic": "Impact",
                    "mitre_technique": "T1498 - Network Denial of Service"
                })

        for src_ip, count in dns_queries.items():
            if count >= self.dns_tunnel_threshold:
                alerts.append({
                    "event_type": "dns_tunneling",
                    "severity": "medium",
                    "src_ip": src_ip,
                    "dst_ip": "dns_server",
                    "confidence": min(count / self.dns_tunnel_threshold, 1.0),
                    "description": f"Possible DNS tunneling: {count} DNS queries from {src_ip}",
                    "mitre_tactic": "Exfiltration",
                    "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol"
                })

        if len(large_packets) > 10:
            avg_size = sum(int(p.get("frame_len", 0) or 0) for p in large_packets) / len(large_packets)
            if avg_size > 1400:
                alerts.append({
                    "event_type": "data_exfiltration",
                    "severity": "high",
                    "src_ip": large_packets[0].get("ip_src", ""),
                    "dst_ip": large_packets[0].get("ip_dst", ""),
                    "confidence": 0.5,
                    "description": f"Large packet exfiltration: {len(large_packets)} packets > 1000 bytes (avg {avg_size:.0f}B)",
                    "mitre_tactic": "Exfiltration",
                    "mitre_technique": "T1041 - Exfiltration Over C2 Channel"
                })

        return alerts

    def analyze_pcap_statistics(self, stats_text):
        alerts = []
        conv_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)")
        matches = conv_pattern.findall(stats_text)
        for src, dst, pkts, bytes_ in matches[:20]:
            if int(pkts) > 500:
                alerts.append({
                    "event_type": "high_volume_traffic",
                    "severity": "medium",
                    "src_ip": src,
                    "dst_ip": dst,
                    "confidence": 0.6,
                    "description": f"High traffic volume: {pkts} packets between {src} and {dst}"
                })
        return alerts
