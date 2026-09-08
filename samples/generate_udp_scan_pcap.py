"""
Utility to generate synthetic UDP scan attack PCAPs for Phase 7 validation.
"""

import os
import time
from scapy.all import Ether, IP, TCP, UDP, ICMP, wrpcap


def generate_udp_scan_pcap(output_path="samples/udp_scan.pcap"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    attacker_ip = "192.168.1.160"
    target_ip = "192.168.1.50"
    base_time = time.time()

    packets = []

    # 1. Normal baseline background traffic
    p1 = Ether() / IP(src="192.168.1.20", dst=target_ip) / TCP(sport=54321, dport=80, flags="S")
    p1.time = base_time + 0.1
    packets.append(p1)

    p2 = Ether() / IP(src="192.168.1.20", dst="8.8.8.8") / UDP(sport=53000, dport=53)
    p2.time = base_time + 0.15
    packets.append(p2)

    p3 = Ether() / IP(src="192.168.1.20", dst="192.168.1.1") / ICMP(type=8, code=0)
    p3.time = base_time + 0.2
    packets.append(p3)

    # 2. UDP port sweep from attacker (15 distinct UDP destination ports within 2 seconds)
    udp_ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1900, 5353]
    for idx, dport in enumerate(udp_ports):
        pkt = Ether() / IP(src=attacker_ip, dst=target_ip) / UDP(sport=30000 + idx, dport=dport)
        pkt.time = base_time + 1.0 + (idx * 0.1)
        packets.append(pkt)

    wrpcap(output_path, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {output_path} (Scan ports: {len(udp_ports)})")


if __name__ == "__main__":
    generate_udp_scan_pcap()
