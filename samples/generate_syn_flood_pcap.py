"""
Utility to generate synthetic TCP SYN flood attack PCAPs for Phase 8 validation.
"""

import os
import time
from scapy.all import Ether, IP, TCP, UDP, ICMP, wrpcap


def generate_syn_flood_pcap(output_path="samples/syn_flood.pcap", count=220):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    target_ip = "192.168.1.50"
    target_port = 80
    base_time = time.time()

    packets = []

    # 1. Normal baseline background traffic
    eth_src_norm = "00:50:56:c0:00:01"
    eth_dst_target = "00:0c:29:1a:2b:3c"
    p1 = Ether(src=eth_src_norm, dst=eth_dst_target) / IP(src="192.168.1.20", dst=target_ip) / TCP(sport=54321, dport=443, flags="S")
    p1.time = base_time + 0.1
    packets.append(p1)

    p2 = Ether(src=eth_src_norm, dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.20", dst="8.8.8.8") / UDP(sport=53000, dport=53)
    p2.time = base_time + 0.15
    packets.append(p2)

    p3 = Ether(src=eth_src_norm, dst=eth_dst_target) / IP(src="192.168.1.20", dst="192.168.1.1") / ICMP(type=8, code=0)
    p3.time = base_time + 0.2
    packets.append(p3)

    # 2. High-rate TCP SYN flood burst (count packets within 2 seconds)
    interval = 2.0 / count
    for idx in range(count):
        # Mix of single attacker and spoofed sources
        attacker_ip = f"192.168.1.{100 + (idx % 20)}"
        sport = 40000 + (idx % 20000)
        eth_attacker = f"00:50:56:c0:00:{(idx % 50):02x}"
        pkt = Ether(src=eth_attacker, dst=eth_dst_target) / IP(src=attacker_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S", seq=1000 + idx)
        pkt.time = base_time + 1.0 + (idx * interval)
        packets.append(pkt)

    wrpcap(output_path, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {output_path} ({count} SYN flood packets targeting {target_ip}:{target_port})")


if __name__ == "__main__":
    generate_syn_flood_pcap()
