# 🔬 IDS Testing & Verification Guide

## Testing Layers

1. **Unit Testing with Synthetic Packets**:
   - Packets generated in memory using Scapy (`Ether() / IP() / TCP()`).
   - Validates parsers and detection rules deterministically without network access.
   - Fast, reproducible, automated.

2. **Offline PCAP Replay**:
   - Replay captured traffic files (`sample.pcap`) through the capture engine.
   - Allows regressions and edge case verification.

3. **Live Lab Verification**:
   - Real-time traffic exchanged between Attacker machine and Kali Linux VM sensor.
   - Validates live interface binding, promiscuous mode, OS buffer handling, and alert latency.

---

## Test Suites Matrix
- `tests/test_capture_sanity.py`: Packet capture engine, offline PCAP replay, signal termination.
- `tests/test_parser.py`: Layer-by-layer packet normalization (IP, TCP, UDP, ICMP, ARP, DNS).
- `tests/test_events.py`: SecurityEvent serialization, deserialization, and severity formatting.
- `tests/test_detection_engine.py`: Dynamic detector registry, fault isolation, and state cleanup.
- `tests/test_port_scan.py`: TCP SYN port scan reconnaissance detection.
- `tests/test_udp_scan.py`: UDP service sweep and port enumeration detection.
- `tests/test_syn_flood.py`: Volumetric TCP SYN flood detection (single and distributed sources).
- `tests/test_arp_spoof.py`: Conflicting IP-to-MAC resolution and static pinning violations.
- `tests/test_dns_anomaly.py`: DNS Tunneling, outbound query flood, and NXDOMAIN burst detection.
- `tests/test_alert_manager.py`: Severity triage, burst deduplication, rate limits, and output sinks.
- `tests/test_storage.py`: JSON append-only logging and SQLite relational querying.
- `tests/test_end_to_end.py`: Comprehensive multi-vector attack integration test.

---

## Offline Synthetic Attack PCAPs
Generate realistic threat scenarios using the built-in generator scripts:
```powershell
python samples/generate_port_scan_pcap.py      # TCP Port Scan
python samples/generate_udp_scan_pcap.py       # UDP Port Scan
python samples/generate_syn_flood_pcap.py      # TCP SYN Flood
python samples/generate_arp_spoof_pcap.py      # ARP Poisoning / MITM
python samples/generate_dns_anomaly_pcap.py    # DNS Tunneling & NXDOMAIN
python samples/generate_multi_vector_pcap.py   # Full Multi-Vector Scenario
```

---

## Running Test Suites

```powershell
# In Windows virtual environment:
.\.venv\Scripts\python -m unittest discover -s tests -v

# Replay comprehensive multi-vector attack PCAP:
.\.venv\Scripts\python -m ids.main --pcap samples/multi_vector_attack.pcap
```

```bash
# In Kali Linux VM:
.venv/bin/python3 -m unittest discover -s tests -v
sudo .venv/bin/python3 -m ids.main --pcap samples/multi_vector_attack.pcap
```
