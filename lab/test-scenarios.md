# 🧪 Lab Testing Scenarios

This document outlines the test validation plan across all project development phases.

---

## Phase 2 Test Matrix: Baseline Capture Verification

| ID | Test Scenario | Traffic Source | Command / Action | Expected IDS Output |
|---|---|---|---|---|
| **T2.1** | Interface Discovery | Kali IDS | `sudo .venv/bin/python3 -m ids.main -l` | List of system interfaces (e.g. `eth0`, `lo`) |
| **T2.2** | ICMP Echo (Ping) | Attacker Machine | `ping -c 4 <KALI_IP>` | IDS outputs 4 Echo Request & 4 Echo Reply packets |
| **T2.3** | Normal DNS Query | Kali or Attacker | `dig @8.8.8.8 example.com` | IDS logs UDP packet to port 53 and response |
| **T2.4** | Normal HTTP Connection | Attacker Machine | `curl -I http://<KALI_IP>` | TCP SYN, SYN-ACK, ACK handshake packets logged |
| **T2.5** | Graceful Shutdown | Kali IDS Terminal | `Ctrl + C` during active capture | Signal caught, sniffer stops, prints packet count |
| **T2.6** | Fixed Packet Count | Kali IDS Terminal | `sudo .venv/bin/python3 -m ids.main -i eth0 -c 10` | Captures exactly 10 packets and terminates cleanly |

---

## Future Detection Testing Roadmap (Phases 5+)

- **Scenario 1 — TCP Port Scan**: `nmap -sS -p 1-100 <KALI_IP>`
- **Scenario 2 — UDP Port Probing**: `nmap -sU -p 53,67,68,123,161 <KALI_IP>`
- **Scenario 3 — TCP SYN Flood**: `hping3 -S --flood -p 80 <KALI_IP>`
- **Scenario 4 — Controlled ARP Spoof**: `arpspoof -i eth0 -t <KALI_IP> <GATEWAY_IP>`
- **Scenario 5 — DNS Anomaly**: High-frequency script querying random nonexistent domains (NXDOMAIN)
