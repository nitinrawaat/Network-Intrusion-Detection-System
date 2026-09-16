"""
Utility to generate synthetic ARP spoofing / cache poisoning attack PCAPs for Phase 9 validation.
"""

import os
import time
from scapy.all import Ether, ARP, IP, TCP, UDP, wrpcap


def generate_arp_spoof_pcap(output_path="samples/arp_spoof.pcap"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    gateway_ip = "192.168.1.1"
    gateway_mac = "00:50:56:c0:00:01"

    victim_ip = "192.168.1.50"
    victim_mac = "00:0c:29:1a:2b:3c"

    attacker_ip = "192.168.1.166"
    attacker_mac = "de:ad:be:ef:ca:fe"

    base_time = time.time()
    packets = []

    # 1. Normal legitimate ARP resolution: Gateway is at gateway_mac
    p_arp_req = Ether(src=victim_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,  # who-has
        psrc=victim_ip,
        hwsrc=victim_mac,
        pdst=gateway_ip,
        hwdst="00:00:00:00:00:00",
    )
    p_arp_req.time = base_time + 0.1
    packets.append(p_arp_req)

    p_arp_rep = Ether(src=gateway_mac, dst=victim_mac) / ARP(
        op=2,  # is-at
        psrc=gateway_ip,
        hwsrc=gateway_mac,
        pdst=victim_ip,
        hwdst=victim_mac,
    )
    p_arp_rep.time = base_time + 0.15
    packets.append(p_arp_rep)

    # 2. Legitimate outbound web connection through gateway
    p_tcp = Ether(src=victim_mac, dst=gateway_mac) / IP(src=victim_ip, dst="93.184.216.34") / TCP(sport=51234, dport=80, flags="S")
    p_tcp.time = base_time + 0.3
    packets.append(p_tcp)

    # 3. Attacker launches ARP Poisoning / MITM attack:
    # Sends unsolicited ARP reply claiming gateway_ip is at attacker_mac
    for i in range(5):
        p_poison = Ether(src=attacker_mac, dst=victim_mac) / ARP(
            op=2,  # is-at
            psrc=gateway_ip,
            hwsrc=attacker_mac,
            pdst=victim_ip,
            hwdst=victim_mac,
        )
        p_poison.time = base_time + 1.0 + (i * 0.2)
        packets.append(p_poison)

    wrpcap(output_path, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {output_path} (ARP Poisoning: {gateway_ip} hijacked by {attacker_mac})")


if __name__ == "__main__":
    generate_arp_spoof_pcap()
