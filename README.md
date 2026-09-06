# 🔥 Python Network Intrusion Detection System (IDS)

A modular, learning-focused Network Intrusion Detection System built from scratch in Python using Scapy, designed to run inside a **Kali Linux virtual machine** on a Windows host with traffic generated from a separate physical attacker machine.

---

## 🚀 Project Overview

The objective of this project is to understand the inner workings of network security monitoring, packet inspection, rule-based threat classification, and incident logging without relying on monolithic engines like Snort or Suricata.

### Architecture Pipeline
```text
  Network Interface (eth0 / ens33)
                │
                ▼
         [Packet Capture]  ◄─── (Current Phase: Phase 2)
                │
                ▼
         [Packet Parser]
                │
                ▼
       [Feature Extraction]
                │
                ▼
        [Detection Engine]
    ┌───────────┼───────────┐
    ▼           ▼           ▼
Port Scan   SYN Flood   ARP Spoof ...
    │           │           │
    └───────────┼───────────┘
                ▼
         [Alert Manager]
         ┌──────┴──────┐
         ▼             ▼
      Console     JSON / SQLite
```

---

## 📁 Repository Structure

```text
python-network-ids/
├── README.md
├── requirements.txt
├── .gitignore
│
├── ids/
│   ├── __init__.py
│   ├── main.py                  # CLI entrypoint & banner
│   ├── capture/                 # Packet sniffing engine
│   │   ├── __init__.py
│   │   └── packet_capture.py
│   ├── parser/                  # Normalized layer parser
│   ├── models/                  # Security event dataclasses
│   ├── detectors/               # Threat detection rules
│   ├── alerts/                  # Alert manager
│   ├── storage/                 # JSON and SQLite persistence
│   └── config/
│       └── rules.json           # Configurable thresholds
│
├── tests/
│   ├── __init__.py
│   └── test_capture_sanity.py   # In-memory synthetic packet tests
│
├── lab/
│   ├── setup.md                 # Kali Linux VM VMware setup guide
│   ├── topology.md              # Network lab layout
│   └── test-scenarios.md        # Validation scenarios
│
├── docs/                        # Architecture & detection specs
└── logs/                        # Runtime logs and event exports
```

---

## ⚡ Quickstart

### 1. Local / Windows Development

```powershell
# Activate virtual environment
.\.venv\Scripts\activate

# Run tests
python -m unittest discover -s tests

# List available interfaces
python -m ids.main --list-interfaces
```

### 2. Kali Linux VM Deployment (IDS Sensor)

```bash
# 1. Clone or copy repo to Kali
cd ~/python-network-ids

# 2. Setup venv & install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. List network interfaces
sudo .venv/bin/python3 -m ids.main --list-interfaces

# 4. Start live packet capture (e.g. on eth0)
sudo .venv/bin/python3 -m ids.main --interface eth0
```

Press `Ctrl+C` at any time to gracefully terminate and view capture metrics.

---

## 🛡️ Security & Scope
This project is strictly for defensive cybersecurity education and lab research. All testing and attack traffic generation must be restricted to isolated lab machines and authorized test networks.
