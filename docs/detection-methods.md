# 🎯 Detection Methods & Threat Models

This document details the threat models and detection criteria designed for the IDS engine.

---

## 1. TCP Port Scan (`PortScanDetector`)
- **What is detected**: Horizontal or vertical reconnaissance probing multiple TCP destination ports on one or more hosts.
- **Packet characteristics**: TCP SYN packets without established connections.
- **Metric**: Unique `dst_port` count per `src_ip` within `window_seconds`.
- **Threshold**: Default `10` unique ports within `5` seconds.
- **False Positives**: Multi-connection applications (e.g. web browsers opening parallel sockets to CDN ports, P2P clients).

---

## 2. UDP Scan (`UdpScanDetector`)
- **What is detected**: UDP port scanning or service enumeration across random or sequential ports.
- **Packet characteristics**: Unsolicited UDP datagrams targeting varying destination ports.
- **Metric**: Unique UDP `dst_port` count per `src_ip` within `window_seconds`.
- **Threshold**: Default `10` unique ports within `5` seconds.
- **False Positives**: Torrent clients, WebRTC streaming, gaming clients.

---

## 3. SYN Flood (`SynFloodDetector`)
- **What is detected**: High-rate transmission of TCP SYN packets aiming to exhaust TCP backlog queues.
- **Packet characteristics**: TCP packets with `SYN` flag set and without matching `ACK` responses.
- **Metric**: Total SYN count per destination service within `window_seconds`.
- **Threshold**: Default `200` SYNs within `5` seconds.
- **False Positives**: Flash crowds, heavy benchmark testing.

---

## 4. ARP Spoofing (`ArpSpoofDetector`)
- **What is detected**: Poisoning of the local ARP cache via unsolicited or altered ARP replies (MITM positioning).
- **Packet characteristics**: ARP reply (`op=2`) mapping an existing known IP to a conflicting MAC address.
- **Metric**: IP-to-MAC mapping transitions.
- **False Positives**: Legitimate NIC swaps, router redundancy protocols (VRRP/HSRP).

---

## 5. DNS Anomaly (`DnsAnomalyDetector`)
- **What is detected**: Abnormally high query volume, extremely long domain queries (potential DNS tunneling), or abnormal NXDOMAIN bursts.
- **Packet characteristics**: DNS query / response payloads over UDP port 53.
- **Metric**: Request rate, domain label length (> 50 chars), NXDOMAIN error counts.
- **False Positives**: DNS resolution benchmarking, CDNs using encoded subdomains.
