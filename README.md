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
         [Packet Capture]
                │
                ▼
         [Packet Parser]
                │
                ▼
       [Feature Extraction]
                │
                ▼
          [Detection Engine] ◄─── (ACTIVE)
     ┌───────────┬───────────┼───────────┬───────────┐
     ▼           ▼           ▼           ▼           ▼
[Port Scan]  [UDP Scan]  [SYN Flood] [ARP Spoof] [DNS Anomaly]
 (ACTIVE)     (ACTIVE)    (ACTIVE)    (ACTIVE)     (ACTIVE)
     │           │           │           │           │
     └───────────┴───────────┼───────────┴───────────┘
                             ▼
                     [Alert Manager] ◄─── (ACTIVE)
                     ┌───────┴───────┐
                     ▼               ▼
              Console (ACTIVE) [Storage Engine] ◄─── (ACTIVE)
                               ┌──────┴──────┐
                               ▼             ▼
                          JSON (ACTIVE) SQLite (ACTIVE)
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

# Run complete test suite
python -m unittest discover -s tests

# List available network interfaces
python -m ids.main --list-interfaces

# Replay full multi-vector attack scenario through entire pipeline
python -m ids.main --pcap samples/multi_vector_attack.pcap

# Launch Cyber SOC Web Dashboard
python -m ids.main --web --port 8080
# Open http://localhost:8080 in your browser
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

# 4. Start live packet capture with Web Dashboard (e.g. on eth0)
sudo .venv/bin/python3 -m ids.main --interface eth0 --web --port 8080

# Or run Web Dashboard in standalone mode
python3 -m ids.main --web --port 8080
```

Access the Cyber SOC Dashboard at `http://<LINUX_OR_HOST_IP>:8080` to inspect live threats, telemetry charts, and packet forensics in real-time.
Press `Ctrl+C` at any time to gracefully terminate and view capture metrics.

---

## 🛡️ Security & Scope
This project is strictly for defensive cybersecurity education and lab research. All testing and attack traffic generation must be restricted to isolated lab machines and authorized test networks.
