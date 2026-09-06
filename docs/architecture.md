# 🏛️ IDS Architecture Specification

## Overview

The Python Network Intrusion Detection System is built around a unidirectional pipeline that processes network packets with minimal memory overhead and bounded state tracking.

```text
       +-----------------------+
       |   Network Interface   |
       +-----------+-----------+
                   |
                   v
       +-----------------------+
       | Packet Capture Engine | (Scapy sniff with bounded buffer)
       +-----------+-----------+
                   |
                   v
       +-----------------------+
       |     Packet Parser     | (Extract normalized IP/TCP/UDP/ICMP/ARP)
       +-----------+-----------+
                   |
                   v
       +-----------------------+
       |   Detection Engine    | (Modular detector registry)
       +-----------+-----------+
                   |
                   v
       +-----------------------+
       |     Alert Manager     | (Severity triage & rate-limiting)
       +-----------+-----------+
                   |
         +---------+---------+
         |                   |
         v                   v
   +-----------+       +-----------+
   |  Console  |       | JSON / DB |
   +-----------+       +-----------+
```

## Subsystems

1. **Capture Engine (`ids.capture`)**:
   - Manages raw packet sockets via Scapy.
   - Supports live network sniffing and offline PCAP playback.
   - Handles OS signals (`SIGINT`, `SIGTERM`) for zero-loss clean termination.

2. **Parser (`ids.parser`)**:
   - Converts raw Scapy packets into clean, lightweight internal data structures.
   - Extracts standard network and transport layer headers safely.

3. **Detectors (`ids.detectors`)**:
   - Modular plugins implementing `BaseDetector`.
   - Track state internally using sliding time windows and bounded counters.

4. **Alert Manager (`ids.alerts`)**:
   - Receives events, normalizes alert formats, deduplicates bursts, and dispatches to sinks.

5. **Storage (`ids.storage`)**:
   - Structured append-only JSON logging (`logs/alerts.json`) and relational SQLite database.
