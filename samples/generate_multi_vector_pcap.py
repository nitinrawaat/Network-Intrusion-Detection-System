"""
Utility to generate a comprehensive Multi-Vector Attack PCAP for Phase 13 validation.

Combines background benign traffic with all 5 attack vectors:
1. TCP Port Scan
2. UDP Port Probing
3. TCP SYN Flood
4. ARP Cache Poisoning (MITM)
5. DNS Tunneling & NXDOMAIN Burst
"""

import os
import time
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, wrpcap


def generate_multi_vector_pcap(output_path="samples/multi_vector_attack.pcap"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Network topology endpoints
    gateway_ip = "192.168.1.1"
    gateway_mac = "00:50:56:c0:00:01"

    victim_ip = "192.168.1.50"
    victim_mac = "00:0c:29:1a:2b:3c"

    scanner_ip = "192.168.1.150"
    scanner_mac = "00:50:56:c0:00:10"

    udp_scanner_ip = "192.168.1.160"
    udp_scanner_mac = "00:50:56:c0:00:11"

    mitm_ip = "192.168.1.170"
    mitm_mac = "de:ad:be:ef:13:37"

    dns_server_ip = "8.8.8.8"
    dns_server_mac = "00:50:56:c0:00:02"

    base_time = time.time()
    packets = []

    # ==========================================
    # 1. Baseline Benign Traffic
    # ==========================================
    # ARP resolution for gateway
    p_arp_req = Ether(src=victim_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc=victim_ip, hwsrc=victim_mac, pdst=gateway_ip, hwdst="00:00:00:00:00:00"
    )
    p_arp_req.time = base_time + 0.05
    packets.append(p_arp_req)

    p_arp_rep = Ether(src=gateway_mac, dst=victim_mac) / ARP(
        op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=victim_ip, hwdst=victim_mac
    )
    p_arp_rep.time = base_time + 0.1
    packets.append(p_arp_rep)

    # Legitimate ICMP Echo (Ping)
    p_ping = Ether(src=victim_mac, dst=gateway_mac) / IP(src=victim_ip, dst=gateway_ip) / ICMP(type=8, code=0)
    p_ping.time = base_time + 0.2
    packets.append(p_ping)

    p_pong = Ether(src=gateway_mac, dst=victim_mac) / IP(src=gateway_ip, dst=victim_ip) / ICMP(type=0, code=0)
    p_pong.time = base_time + 0.22
    packets.append(p_pong)

    # ==========================================
    # 2. Vector 1: TCP Port Scan (12 ports)
    # ==========================================
    tcp_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]
    for idx, port in enumerate(tcp_ports):
        p_scan = Ether(src=scanner_mac, dst=victim_mac) / IP(src=scanner_ip, dst=victim_ip) / TCP(
            sport=40000 + idx, dport=port, flags="S"
        )
        p_scan.time = base_time + 0.5 + (idx * 0.08)
        packets.append(p_scan)

    # ==========================================
    # 3. Vector 2: UDP Scan (12 ports)
    # ==========================================
    udp_ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1194]
    for idx, port in enumerate(udp_ports):
        p_udp = Ether(src=udp_scanner_mac, dst=victim_mac) / IP(src=udp_scanner_ip, dst=victim_ip) / UDP(
            sport=35000 + idx, dport=port
        )
        p_udp.time = base_time + 1.8 + (idx * 0.08)
        packets.append(p_udp)

    # ==========================================
    # 4. Vector 3: TCP SYN Flood (210 SYNs)
    # ==========================================
    syn_count = 210
    interval = 1.5 / syn_count
    for idx in range(syn_count):
        spoofed_src = f"192.168.1.{100 + (idx % 20)}"
        sport = 42000 + (idx % 20000)
        p_syn = Ether(src=scanner_mac, dst=victim_mac) / IP(src=spoofed_src, dst=victim_ip) / TCP(
            sport=sport, dport=80, flags="S", seq=50000 + idx
        )
        p_syn.time = base_time + 3.0 + (idx * interval)
        packets.append(p_syn)

    # ==========================================
    # 5. Vector 4: ARP Spoofing / Poisoning
    # ==========================================
    for idx in range(4):
        p_arp_poison = Ether(src=mitm_mac, dst=victim_mac) / ARP(
            op=2, psrc=gateway_ip, hwsrc=mitm_mac, pdst=victim_ip, hwdst=victim_mac
        )
        p_arp_poison.time = base_time + 5.0 + (idx * 0.1)
        packets.append(p_arp_poison)

    # ==========================================
    # 6. Vector 5: DNS Tunneling & NXDOMAIN Burst
    # ==========================================
    # DNS Tunneling query (> 50 chars label)
    tunnel_label = "c2beacon99999exfiltratedsecretcredentialsdatapart01"
    p_tunnel = Ether(src=victim_mac, dst=dns_server_mac) / IP(src=victim_ip, dst=dns_server_ip) / UDP(
        sport=53888, dport=53
    ) / DNS(rd=1, qd=DNSQR(qname=f"{tunnel_label}.darknet.c2.org"))
    p_tunnel.time = base_time + 5.6
    packets.append(p_tunnel)

    # NXDOMAIN burst (22 queries & responses)
    for idx in range(22):
        fake_domain = f"dga-probe-{idx:03d}.nonexistent-tld.org"
        sport = 55000 + idx
        p_nx = Ether(src=dns_server_mac, dst=victim_mac) / IP(src=dns_server_ip, dst=victim_ip) / UDP(
            sport=53, dport=sport
        ) / DNS(qr=1, rcode=3, qd=DNSQR(qname=fake_domain))
        p_nx.time = base_time + 6.0 + (idx * 0.04)
        packets.append(p_nx)

    wrpcap(output_path, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {output_path}")
    print("    Vectors included: Benign baseline, TCP Port Scan, UDP Scan, SYN Flood, ARP Spoofing, DNS Tunneling & NXDOMAIN burst.")


if __name__ == "__main__":
    generate_multi_vector_pcap()
