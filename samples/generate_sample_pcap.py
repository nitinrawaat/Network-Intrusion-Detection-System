"""
Utility to generate synthetic baseline test PCAPs.
"""

import os
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, wrpcap

def generate_sample_pcap(output_path="samples/demo.pcap"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    packets = [
        Ether() / IP(src="192.168.1.20", dst="192.168.1.50") / TCP(sport=51234, dport=80, flags="S"),
        Ether() / IP(src="192.168.1.50", dst="192.168.1.20") / TCP(sport=80, dport=51234, flags="SA"),
        Ether() / IP(src="192.168.1.20", dst="192.168.1.50") / TCP(sport=51234, dport=80, flags="A"),
        Ether() / IP(src="192.168.1.20", dst="192.168.1.1") / ICMP(type=8, code=0),
        Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=53000, dport=53),
        Ether(src="aa:bb:cc:dd:ee:ff") / ARP(op=1, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.20", pdst="192.168.1.50"),
    ]
    wrpcap(output_path, packets)
    print(f"[+] Successfully wrote {len(packets)} synthetic packets to {output_path}")

if __name__ == "__main__":
    generate_sample_pcap()
