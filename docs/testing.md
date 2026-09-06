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

## Running Test Suites

```powershell
# In Windows virtual environment:
.\.venv\Scripts\python -m unittest discover -s tests -v
```

```bash
# In Kali Linux VM:
.venv/bin/python3 -m unittest discover -s tests -v
```
