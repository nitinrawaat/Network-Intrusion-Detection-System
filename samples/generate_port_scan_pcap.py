"""
Utility to generate synthetic port scan attack PCAPs for Phase 6 validation.
"""

import os
import time
from scapy.all import Ether, IP, TCP, UDP, ICMP, wrpcap


def generate_port_scan_pcap(output_path="samples/port_scan.pcap"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    attacker_ip = "192.168.1.150"
    target_ip = "192.168.1.50"
    base_time = time.time()

    packets = []

    # 1. Normal baseline background traffic
    p1 = Ether() / IP(src="192.168.1.20", dst=target_ip) / TCP(sport=54321, dport=80, flags="S")
    p1.time = base_time + 0.1
    packets.append(p1)

    p2 = Ether() / IP(src=target_ip, dst="192.168.1.20") / TCP(sport=80, dport=54321, flags="SA")
    p2.time = base_time + 0.12
    packets.append(p2)

    p3 = Ether() / IP(src="192.168.1.20", dst="192.168.1.1") / ICMP(type=8, code=0)
    p3.time = base_time + 0.2
    packets.append(p3)

    # 2. Port scan simulation from attacker (15 distinct destination ports within 2 seconds)
    probed_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 8080]
    for idx, dport in enumerate(probed_ports):
        pkt = Ether() / IP(src=attacker_ip, dst=target_ip) / TCP(sport=40000 + idx, dport=dport, flags="S")
        pkt.time = base_time + 1.0 + (idx * 0.1)
        packets.append(pkt)

    wrpcap(output_path, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {output_path} (Scan ports: {len(probed_ports)})")


if __name__ == "__main__":
    generate_port_scan_pcap()
