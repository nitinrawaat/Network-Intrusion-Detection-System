# 🔥 AEGIS — Python Network Intrusion Detection & Prevention System (IDS/IPS)

A modular, production-grade Network Intrusion Detection & Prevention System built from scratch in Python using Scapy, backed by SQLite event storage and a modern web-based **Security Operations Center (SOC) Console**. Designed to run on Linux/Kali virtual machines, bare metal, or Windows development environments.

---

## 🚀 Project Overview

The objective of AEGIS is to provide transparent, high-visibility network security monitoring, packet inspection, sliding-window threat classification, MITRE ATT&CK correlation, and active IPS mitigation without relying on monolithic black-box engines like Snort or Suricata.

### Architecture Pipeline
```text
  Network Interface (eth0 / ens33 / Wi-Fi)
                │
                ▼
         [Packet Capture]  (Scapy Promiscuous Sniffer)
                │
                ▼
         [Packet Parser]   (Normalized Ethernet / IP / TCP / UDP / ARP / DNS)
                │
                ▼
       [Feature Extraction] (Flow Tracking & Sliding Time Windows)
                │
                ▼
          [Detection Engine]
     ┌───────────┬───────────┼───────────┬───────────┐
     ▼           ▼           ▼           ▼           ▼
[Port Scan]  [UDP Scan]  [SYN Flood] [ARP Spoof] [DNS Tunnel / DGA]
 (T1046)      (T1046)    (T1498.001) (T1557.002)   (T1071.004 / T1568.002)
     │           │           │           │           │
     └───────────┴───────────┼───────────┴───────────┘
                             │
                             ▼
                     [Alert Manager] (Deduplication, Rate Limiting & Sinks)
                     ┌───────┴───────┬─────────────────────────┐
                     ▼               ▼                         ▼
              Console Logs    [Storage Engine]        [Web Broadcast Sink]
                              ┌──────┴──────┐                  │ (SSE Stream)
                              ▼             ▼                  ▼
                         JSON File     SQLite (WAL)    [SOC Web Dashboard]
                                                               │
                                      ┌────────────────────────┴────────────────────────┐
                                      ▼                                                 ▼
                             [Dashboard Overview]                              [Dedicated Threat Logs]
                         - 4 Real-time Stat Cards                         - Filter by Severity (CRIT/HIGH/MED/LOW)
                         - Priority Threat Alert                          - Free-text IP / Protocol Search
                         - Top Threat Actors Leaderboard                  - Deep Forensic Inspection Modals
                         - MITRE ATT&CK Matrix Distribution               - Unseen / Unread Threat Badge
                         - Sensor Node Telemetry & Controls
```

---

## 🖥️ Modern Web SOC Dashboard

AEGIS includes a built-in, responsive **Security Operations Center Console** running on `http://localhost:8080/`:

* **Multi-View Tabbed Architecture**:
  * **Dashboard Overview (`#view-dashboard`)**:
    * **4 Live Stat Cards**: Total Threats Detected, Critical Alerts, High Severity, and Quarantined Hosts.
    * **Priority Threat Alert**: Immediate actionable mitigation banner for high-severity threats.
    * **Top Threat Actors Deck**: Adversary leaderboard showing offending IPs, attack vectors, hit counts, and one-click quarantine isolation.
    * **MITRE ATT&CK Breakdown**: Visual detection distribution progress bars across active tactical categories (`Impact`, `Discovery`, `Adversary-in-the-Middle`, `C2`).
    * **Sensor Node Telemetry**: Real-time packet inspection velocity, promiscuous sniffer interface status, SQLite engine mode, and live stream pause / attack burst controls.
  * **Dedicated Incident Logs View (`#view-logs`)**:
    * Full-page telemetry inspection table showing Timestamp, Source IP, Destination Target, Attack Vector, Severity Badge, and Forensic actions.
    * Real-time Severity Filter Pills (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and dynamic search filter.
    * **Unseen Threat Counter**: The sidebar badge dynamically tracks new, unreviewed threats that arrived since you last opened the logs, automatically clearing to 0 when viewed.
* **Active Defense (IPS Quarantine)**: Automated and manual host isolation with firewall drop rules.
* **Rule Tuner & Scenario Launcher**: Adjust sliding windows, port thresholds, and minimum severity levels on the fly, or simulate multi-vector attacks with a single click.

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
│   ├── main.py                  # CLI entrypoint & argument parser
│   ├── capture/                 # Packet sniffing engine
│   │   ├── __init__.py
│   │   └── packet_capture.py
│   ├── parser/                  # Normalized packet layer decoder
│   ├── models/                  # Security event dataclasses & Severity
│   ├── detectors/               # Sliding-window detection algorithms
│   │   ├── port_scan.py         # TCP Port Scan detector (T1046)
│   │   ├── udp_scan.py          # UDP Port Scan detector (T1046)
│   │   ├── syn_flood.py         # High-rate SYN Flood detector (T1498.001)
│   │   ├── arp_spoof.py         # ARP Cache Poisoning detector (T1557.002)
│   │   └── dns_anomaly.py       # DNS Tunneling & DGA detector (T1071.004)
│   ├── alerts/                  # Deduplication, rate limiting & sinks
│   ├── storage/                 # JSON and SQLite persistence engines
│   ├── config/
│   │   └── rules.json           # Configurable thresholds
│   └── web/                     # SOC Dashboard & REST API
│       ├── server.py            # HTTP Server, SSE broadcaster & REST API
│       └── static/
│           ├── index.html       # Single-Page SOC Dashboard Application
│           ├── css/style.css    # Clean responsive SOC styling
│           └── js/app.js        # Real-time state, SSE stream, and multi-view logic
│
├── tests/                       # Complete automated unit & integration test suite (97 tests)
│   ├── test_capture_sanity.py
│   ├── test_port_scan.py
│   ├── test_udp_scan.py
│   ├── test_syn_flood.py
│   ├── test_arp_spoof.py
│   ├── test_dns_anomaly.py
│   ├── test_sqlite_storage.py
│   └── test_web_api.py          # Web API & Dashboard integrity tests
│
├── lab/
│   ├── setup.md                 # Kali Linux VM VMware setup guide
│   ├── topology.md              # Network lab layout
│   └── test-scenarios.md        # Attack validation scenarios
│
├── docs/                        # Architecture & detection specs
└── logs/                        # Runtime SQLite database (events.db) & JSON exports
```

---

## ⚡ Quickstart

### 1. Local / Windows Development

```powershell
# Activate virtual environment
.\.venv\Scripts\activate

# Run complete test suite (97 passing tests)
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
# 1. Clone repo to Kali
cd ~/Network-Intrusion-Detection-System

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

Access the Cyber SOC Dashboard at `http://<LINUX_OR_HOST_IP>:8080` to inspect live threats, MITRE ATT&CK correlation, and packet forensics in real-time.
Press `Ctrl+C` at any time to gracefully terminate and view capture metrics.

---

## 🤖 Machine Learning Roadmap (Phase 15)

To complement the rule-based sliding-window detectors, AEGIS is evolving toward **hybrid AI-assisted intrusion detection**:

```
[Raw Packets] ──► [Flow Feature Extractor] ──► [Trained ML Model] ──► [MLAnomalyDetector] ──► [Dashboard & Alerts]
                   - Flow duration              - Random Forest /      - Emits SecurityEvent   - ML Confidence Score
                   - Packet size mean/std         Isolation Forest     - MITRE T1000/T1046     - Anomaly Heatmap
                   - Inter-arrival times        - ONNX / Joblib
                   - TCP flag distribution
```

1. **Flow Aggregator & Feature Extractor (`ids/features/`)**:
   - Groups raw packets into 5-tuple bidirectional flows (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`).
   - Computes statistical flow metrics: inter-arrival times (IAT), packet length variance, flag ratios (SYN/ACK/FIN/RST), and flow byte velocity.
2. **Model Training Pipeline (`ml/train.py`)**:
   - **Supervised Classification**: Random Forest / XGBoost trained on **CIC-IDS2017** benchmark dataset for multi-class attack identification (`PORT_SCAN`, `DOS_SYN_FLOOD`, `BOTNET`, `BRUTE_FORCE`).
   - **Unsupervised Anomaly Detection**: Isolation Forest / Autoencoder trained strictly on baseline benign network flows to detect zero-day anomalies without signature rules.
3. **Real-Time ML Detector Plugin (`ids/detectors/ml_detector.py`)**:
   - Ingests live flows, evaluates inference confidence, and emits standardized `SecurityEvent` alerts when confidence exceeds 85%.
4. **SOC Console AI Insights**:
   - Surfaces real-time ML confidence badges, model decision rationales, and anomaly heatmaps on the incident logs interface.

---

## 🛡️ Security & Scope
This project is strictly for defensive cybersecurity education and lab research. All testing and attack traffic generation must be restricted to isolated lab machines and authorized test networks.
