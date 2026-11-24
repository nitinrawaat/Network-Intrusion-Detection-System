"""
Web Dashboard Server and REST / SSE API for Python Network IDS.

Serves the Cyber SOC frontend, aggregates SQLite security alerts,
broadcasts live incidents via Server-Sent Events (SSE), and allows
rule tuning and attack simulation.
"""

import os
import sys
import io
import csv
import json
import time
import queue
import logging
import threading
from urllib.parse import urlparse, parse_qs
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import List, Dict, Any, Optional

from ids.models.events import SecurityEvent
from ids.alerts.alert_manager import AlertSink, AlertManager
from ids.storage.sqlite_storage import SqliteAlertStorage
from ids.parser.packet_parser import PacketParser
from ids.detectors.detection_engine import DetectionEngine
from ids.capture.packet_capture import PacketCaptureEngine

logger = logging.getLogger("ids.web")

# -----------------------------------------------------------------------------
# MITRE ATT&CK Framework Knowledge Base Mapping
# -----------------------------------------------------------------------------
MITRE_MAPPING = {
    "TCP_PORT_SCAN": {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "subtechnique": "TCP Port Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "UDP_PORT_SCAN": {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "subtechnique": "UDP Port Scan",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "TCP_SYN_FLOOD": {
        "technique_id": "T1498.001",
        "name": "Direct Network Flood",
        "tactic": "Impact",
        "subtechnique": "SYN Flood DoS",
        "url": "https://attack.mitre.org/techniques/T1498/001/",
    },
    "SYN_FLOOD": {
        "technique_id": "T1498.001",
        "name": "Direct Network Flood",
        "tactic": "Impact",
        "subtechnique": "SYN Flood DoS",
        "url": "https://attack.mitre.org/techniques/T1498/001/",
    },
    "ARP_SPOOFING": {
        "technique_id": "T1557.002",
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access, Collection",
        "subtechnique": "ARP Poisoning",
        "url": "https://attack.mitre.org/techniques/T1557/002/",
    },
    "ARP_SPOOF": {
        "technique_id": "T1557.002",
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access, Collection",
        "subtechnique": "ARP Poisoning",
        "url": "https://attack.mitre.org/techniques/T1557/002/",
    },
    "DNS_TUNNELING": {
        "technique_id": "T1071.004",
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control, Exfiltration",
        "subtechnique": "DNS Tunneling",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
    },
    "DNS_NXDOMAIN_BURST": {
        "technique_id": "T1568.002",
        "name": "Dynamic Resolution: DGA",
        "tactic": "Command and Control",
        "subtechnique": "Domain Generation Algorithms",
        "url": "https://attack.mitre.org/techniques/T1568/002/",
    },
    "DNS_ANOMALY": {
        "technique_id": "T1071.004",
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "subtechnique": "DNS Tunneling",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
    },
}


def enrich_event_with_mitre(event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Attach official MITRE ATT&CK metadata to a serialized event dict."""
    ev_type = event_dict.get("event_type", "")
    mitre_info = MITRE_MAPPING.get(ev_type)
    if not mitre_info:
        for k, v in MITRE_MAPPING.items():
            if k in ev_type:
                mitre_info = v
                break
    event_dict["mitre"] = mitre_info or {
        "technique_id": "T1000",
        "name": "Unclassified Network Threat",
        "tactic": "Initial Access",
        "subtechnique": None,
        "url": "https://attack.mitre.org/",
    }
    return event_dict


class WebBroadcastSink(AlertSink):
    """
    AlertSink that fans out real-time security events to active SSE client queues.
    """

    def __init__(self, max_queue_size: int = 100):
        self.subscribers: List[queue.Queue] = []
        self._lock = threading.Lock()
        self.max_queue_size = max_queue_size

    def subscribe(self) -> queue.Queue:
        """Register a new client queue for SSE stream."""
        q: queue.Queue = queue.Queue(maxsize=self.max_queue_size)
        with self._lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        """Remove a client queue when connection disconnects."""
        with self._lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def dispatch(self, event: SecurityEvent) -> None:
        """Push an alert to all active SSE queues."""
        if not event:
            return
        data = event.to_dict() if hasattr(event, "to_dict") else dict(event)
        with self._lock:
            dead_queues = []
            for q in self.subscribers:
                try:
                    q.put_nowait(data)
                except queue.Full:
                    dead_queues.append(q)
            for dq in dead_queues:
                if dq in self.subscribers:
                    self.subscribers.remove(dq)


class DashboardHandler(SimpleHTTPRequestHandler):
    """
    HTTP Request handler for dashboard static files and REST/SSE endpoints.
    """

    server_instance: "DashboardServer" = None

    def __init__(self, *args, **kwargs):
        static_dir = os.path.join(os.path.dirname(__file__), "static")
        super().__init__(*args, directory=static_dir, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # API Routes
        if path == "/api/summary":
            self._handle_api_summary()
        elif path == "/api/events":
            self._handle_api_events(query)
        elif path in ("/api/events/stream", "/api/stream"):
            self._handle_api_stream()
        elif path == "/api/config":
            self._handle_api_get_config()
        elif path == "/api/status":
            self._handle_api_status()
        elif path == "/api/interfaces":
            self._handle_api_interfaces()
        elif path == "/api/mitre":
            self._handle_api_mitre()
        elif path == "/api/quarantine":
            self._handle_api_get_quarantine()
        elif path == "/api/export/csv":
            self._handle_api_export_csv()
        elif path == "/api/telemetry":
            self._handle_api_telemetry()
        else:
            # Fall back to serving static files (index.html, style.css, app.js)
            if path in ("", "/"):
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/config":
            self._handle_api_post_config()
        elif path == "/api/simulate":
            self._handle_api_simulate()
        elif path.startswith("/api/scenario/"):
            scenario_name = path[len("/api/scenario/"):].strip("/")
            self._handle_api_simulate(scenario=scenario_name)
        elif path == "/api/clear":
            self._handle_api_clear()
        elif path == "/api/quarantine":
            self._handle_api_post_quarantine()
        elif path == "/api/quarantine/unblock":
            self._handle_api_unblock_quarantine()
        else:
            self.send_error(404, "Endpoint not found")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/quarantine":
            self._handle_api_unblock_quarantine()
        else:
            self.send_error(404, "Endpoint not found")

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # -------------------------------------------------------------------------
    # API Endpoints
    # -------------------------------------------------------------------------

    def _send_json(self, data: Any, status_code: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Dict[str, Any]:
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len > 0:
                raw_body = self.rfile.read(content_len).decode("utf-8")
                try:
                    return json.loads(raw_body)
                except json.JSONDecodeError:
                    sanitized = raw_body.replace("\\", "\\\\")
                    return json.loads(sanitized)
        except Exception as e:
            logger.warning(f"Error reading JSON request body: {e}")
        return {}

    def _handle_api_summary(self):
        storage = self.server_instance.sqlite_storage
        summary = storage.get_summary() if storage else {
            "total_events": 0,
            "by_severity": {},
            "by_type": {},
            "top_sources": [],
        }
        # Add live status info
        summary["sensor_status"] = self.server_instance.get_sensor_status()

        # MITRE ATT&CK Matrix Aggregation
        mitre_matrix: Dict[str, Dict[str, Any]] = {}
        for ev_type, count in summary.get("by_type", {}).items():
            meta = MITRE_MAPPING.get(ev_type)
            if not meta:
                for k, v in MITRE_MAPPING.items():
                    if k in ev_type:
                        meta = v
                        break
            if meta:
                tid = meta["technique_id"]
                if tid not in mitre_matrix:
                    mitre_matrix[tid] = {
                        "technique_id": tid,
                        "name": meta["name"],
                        "tactic": meta["tactic"],
                        "url": meta["url"],
                        "count": 0,
                    }
                mitre_matrix[tid]["count"] += count
        summary["mitre_matrix"] = mitre_matrix

        # IPS Active Defense Quarantine Stats
        quarantined = self.server_instance.quarantined_ips
        summary["quarantine_count"] = len(quarantined)
        summary["active_quarantine_list"] = list(quarantined.values())

        # Determine overall threat level
        by_sev = summary.get("by_severity", {})
        if by_sev.get("CRITICAL", 0) > 0:
            summary["threat_level"] = "CRITICAL"
        elif by_sev.get("HIGH", 0) > 0:
            summary["threat_level"] = "HIGH"
        elif by_sev.get("MEDIUM", 0) > 0:
            summary["threat_level"] = "ELEVATED"
        else:
            summary["threat_level"] = "NORMAL"

        self._send_json(summary)

    def _handle_api_events(self, query: Dict[str, List[str]]):
        storage = self.server_instance.sqlite_storage
        if not storage:
            self._send_json({"events": [], "total": 0})
            return

        limit = int(query.get("limit", ["50"])[0])
        offset = int(query.get("offset", ["0"])[0])
        severity = query.get("severity", [None])[0]
        event_type = query.get("event_type", [None])[0]
        source_ip = query.get("source_ip", [None])[0]

        raw_events = storage.get_events(
            limit=limit,
            offset=offset,
            severity=severity,
            event_type=event_type,
            source_ip=source_ip,
        )
        total = storage.count()

        # Enrich events with MITRE ATT&CK framework data
        enriched_events = [enrich_event_with_mitre(dict(ev)) for ev in raw_events]

        self._send_json({"events": enriched_events, "total": total, "limit": limit, "offset": offset})

    def _handle_api_stream(self):
        """Server-Sent Events (SSE) live alert stream."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        sink = self.server_instance.broadcast_sink
        q = sink.subscribe()

        # Send initial connection comment
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()

            while self.server_instance.is_running:
                try:
                    event_data = q.get(timeout=2.0)
                    if isinstance(event_data, dict):
                        enrich_event_with_mitre(event_data)
                    payload = f"data: {json.dumps(event_data)}\n\n".encode("utf-8")
                    self.wfile.write(payload)
                    self.wfile.flush()
                except queue.Empty:
                    # Heartbeat comment to keep connection alive
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            sink.unsubscribe(q)

    def _handle_api_mitre(self):
        """Return MITRE ATT&CK knowledge base mapping."""
        self._send_json({"mitre_techniques": MITRE_MAPPING})

    def _handle_api_get_quarantine(self):
        """Retrieve list of currently banned/quarantined IP addresses."""
        ips = list(self.server_instance.quarantined_ips.values())
        self._send_json({
            "quarantined_ips": ips,
            "quarantined_hosts": ips,
            "count": len(ips),
            "firewall_status": "ACTIVE (SIMULATED_IPS_BLOCKLIST)",
        })

    def _handle_api_post_quarantine(self):
        """Block an attacker IP address (Intrusion Prevention action)."""
        body = self._read_json_body()
        ip = body.get("ip")
        if not ip:
            self._send_json({"error": "Missing 'ip' field"}, 400)
            return

        reason = body.get("reason", "Manual SOC Analyst Quarantine")
        severity = body.get("severity", "HIGH")
        duration = body.get("duration_minutes", 30)

        entry = {
            "ip": ip,
            "reason": reason,
            "severity": severity,
            "duration_minutes": duration,
            "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "status": "ENFORCED (PACKETS_DROPPED)",
        }
        self.server_instance.quarantined_ips[ip] = entry
        logger.info(f"[IPS] Quarantined IP {ip}: {reason}")
        self._send_json({"status": "quarantined", "entry": entry})

    def _handle_api_unblock_quarantine(self):
        """Unblock / release an IP from quarantine."""
        body = self._read_json_body()
        ip = body.get("ip")
        if not ip:
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            ip = query.get("ip", [None])[0]

        if not ip or ip not in self.server_instance.quarantined_ips:
            self._send_json({"error": f"IP '{ip}' is not quarantined"}, 404)
            return

        del self.server_instance.quarantined_ips[ip]
        logger.info(f"[IPS] Unblocked IP {ip}")
        self._send_json({"status": "unblocked", "ip": ip})

    def _handle_api_export_csv(self):
        """Export all recorded security events as an incident forensic CSV file."""
        storage = self.server_instance.sqlite_storage
        events = storage.get_events(limit=10000, offset=0) if storage else []

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Incident_ID",
            "Timestamp_UTC",
            "Severity",
            "Threat_Vector",
            "MITRE_Technique_ID",
            "MITRE_Technique_Name",
            "MITRE_Tactic",
            "Attacker_Source_IP",
            "Target_Destination_IP",
            "Detector",
            "Description",
            "Forensic_Evidence",
        ])

        for ev in events:
            ev_dict = dict(ev)
            enrich_event_with_mitre(ev_dict)
            mitre = ev_dict.get("mitre", {})
            writer.writerow([
                ev_dict.get("id", ""),
                ev_dict.get("timestamp", ""),
                ev_dict.get("severity", ""),
                ev_dict.get("event_type", ""),
                mitre.get("technique_id", "N/A"),
                mitre.get("name", "N/A"),
                mitre.get("tactic", "N/A"),
                ev_dict.get("source_ip", ""),
                ev_dict.get("destination_ip", ""),
                ev_dict.get("detector", ""),
                ev_dict.get("description", ""),
                json.dumps(ev_dict.get("evidence", {})),
            ])

        body = output.getvalue().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="aegis_soc_incident_report.csv"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _handle_api_telemetry(self):
        """Provide real-time telemetry metrics for live canvas timeline."""
        storage = self.server_instance.sqlite_storage
        count = storage.count() if storage else 0
        uptime = int(time.time() - self.server_instance.start_time)
        pps = self.server_instance.recent_packet_rate
        self._send_json({
            "uptime_seconds": uptime,
            "packets_per_second": pps,
            "total_incidents": count,
            "quarantined_count": len(self.server_instance.quarantined_ips),
            "threat_level": "CRITICAL" if count > 20 else ("ELEVATED" if count > 0 else "NORMAL"),
        })

    def _handle_api_get_config(self):
        config_path = self.server_instance.config_path
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._send_json(data)
        else:
            self._send_json({}, 404)

    def _handle_api_post_config(self):
        new_config = self._read_json_body()
        config_path = self.server_instance.config_path
        if not new_config:
            self._send_json({"error": "Invalid or empty JSON body"}, 400)
            return

        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(new_config, f, indent=2)
            self._send_json({"status": "saved", "config": new_config})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_api_status(self):
        self._send_json(self.server_instance.get_sensor_status())

    def _handle_api_interfaces(self):
        interfaces = []
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
        except Exception:
            interfaces = ["eth0", "lo"]
        self._send_json({"interfaces": interfaces})

    def _handle_api_simulate(self, scenario: Optional[str] = None):
        """Trigger asynchronous replay of sample attack scenarios."""
        body = self._read_json_body()
        if not scenario:
            scenario = body.get("scenario") or body.get("type") or "all"
        pcap_file = body.get("pcap")

        # Map scenario name to sample pcap
        scenario_map = {
            "all": "samples/multi_vector_attack.pcap",
            "multi_vector": "samples/multi_vector_attack.pcap",
            "port_scan": "samples/port_scan.pcap",
            "syn_flood": "samples/syn_flood.pcap",
            "arp_spoof": "samples/arp_spoof.pcap",
            "dns_anomaly": "samples/dns_anomaly.pcap",
            "udp_scan": "samples/udp_scan.pcap",
        }

        if not pcap_file:
            pcap_file = scenario_map.get(scenario, "samples/multi_vector_attack.pcap")

        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        full_pcap_path = os.path.join(project_root, pcap_file)

        # Auto-generate if missing
        if not os.path.exists(full_pcap_path):
            try:
                if "multi_vector" in pcap_file:
                    from samples.generate_multi_vector_pcap import generate_multi_vector_pcap
                    generate_multi_vector_pcap(full_pcap_path)
                elif "port_scan" in pcap_file:
                    from samples.generate_port_scan_pcap import generate_port_scan_pcap
                    generate_port_scan_pcap(full_pcap_path)
                elif "syn_flood" in pcap_file:
                    from samples.generate_syn_flood_pcap import generate_syn_flood_pcap
                    generate_syn_flood_pcap(full_pcap_path)
                elif "arp_spoof" in pcap_file:
                    from samples.generate_arp_spoof_pcap import generate_arp_spoof_pcap
                    generate_arp_spoof_pcap(full_pcap_path)
                elif "dns_anomaly" in pcap_file:
                    from samples.generate_dns_anomaly_pcap import generate_dns_anomaly_pcap
                    generate_dns_anomaly_pcap(full_pcap_path)
                elif "udp_scan" in pcap_file:
                    from samples.generate_udp_scan_pcap import generate_udp_scan_pcap
                    generate_udp_scan_pcap(full_pcap_path)
            except Exception as e:
                self._send_json({"error": f"Failed to auto-generate PCAP: {e}"}, 500)
                return

        # Trigger simulation in background thread
        sim_thread = threading.Thread(
            target=self.server_instance.run_simulation,
            args=(full_pcap_path,),
            daemon=True,
        )
        sim_thread.start()

        self._send_json({
            "status": "simulation_started",
            "scenario": scenario,
            "pcap": pcap_file,
            "message": f"Scenario '{scenario}' executing; watch live SOC telemetry stream.",
        })

    def _handle_api_clear(self):
        storage = self.server_instance.sqlite_storage
        if storage:
            storage.clear()
        self.server_instance.quarantined_ips.clear()
        self._send_json({"status": "database_cleared", "total_events": 0})

    def log_message(self, format, *args):
        """Suppress noisy request logs for heartbeat SSE."""
        if "/api/events/stream" not in str(args):
            logger.debug(format % args)


class ThreadedHTTPServer(HTTPServer):
    """Multi-threaded HTTP Server so SSE streaming doesn't block other requests."""
    daemon_threads = True

    def process_request(self, request, client_address):
        t = threading.Thread(target=self.finish_request, args=(request, client_address))
        t.daemon = True
        t.start()


class DashboardServer:
    """
    Coordinates HTTP Server, SQLite storage, and Live Broadcast Sink.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        config_path: str = "ids/config/rules.json",
        sqlite_storage: Optional[SqliteAlertStorage] = None,
        alert_manager: Optional[AlertManager] = None,
        broadcast_sink: Optional[WebBroadcastSink] = None,
    ):
        self.host = host
        self.port = port
        self.config_path = config_path
        self.sqlite_storage = sqlite_storage or SqliteAlertStorage("logs/events.db")
        self.broadcast_sink = broadcast_sink or WebBroadcastSink()
        self.alert_manager = alert_manager

        if self.alert_manager and self.broadcast_sink not in self.alert_manager.sinks:
            self.alert_manager.register_sink(self.broadcast_sink)

        self.is_running = False
        self.httpd: Optional[ThreadedHTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.quarantined_ips: Dict[str, Dict[str, Any]] = {}
        self.start_time = time.time()
        self.recent_packet_rate: int = 128
        self.total_packets_seen: int = 0

        # Link server instance to handler
        DashboardHandler.server_instance = self

    def get_sensor_status(self) -> Dict[str, Any]:
        """Return operational state of sensor and active detectors."""
        detectors = ["TCP Port Scan", "UDP Port Scan", "SYN Flood", "ARP Spoofing", "DNS Anomaly"]
        return {
            "online": True,
            "dashboard_port": self.port,
            "active_detectors": detectors,
            "detector_count": len(detectors),
            "storage_db": getattr(self.sqlite_storage, "db_path", "logs/events.db"),
        }

    def run_simulation(self, pcap_path: str):
        """Run PCAP replay through pipeline and dispatch alerts."""
        logger.info(f"[*] Starting background attack simulation from {pcap_path}")
        try:
            # Instantiate pipeline components
            detection_engine = DetectionEngine(config_path=self.config_path)
            detection_engine.register_default_detectors()

            # Isolated alert manager for simulation to broadcast & persist
            sim_alert_manager = AlertManager(config={"min_severity": "LOW", "dedup_window_seconds": 1.0})
            if self.sqlite_storage:
                sim_alert_manager.register_sink(self.sqlite_storage)
            if self.broadcast_sink:
                sim_alert_manager.register_sink(self.broadcast_sink)

            parser = PacketParser()
            capture_engine = PacketCaptureEngine()

            def packet_handler(raw_pkt):
                self.total_packets_seen += 1
                now = time.time()
                raw_pkt.time = now
                normalized = parser.parse(raw_pkt)
                if normalized:
                    normalized.timestamp = now
                    events = detection_engine.process_packet(normalized)
                    for ev in events:
                        ev.timestamp = now
                        sim_alert_manager.dispatch(ev)
                        # Auto-quarantine on CRITICAL attack (Active Defense)
                        sev_str = str(getattr(ev, "severity", "")).upper()
                        if ("CRITICAL" in sev_str or "HIGH" in sev_str) and ev.source_ip:
                            if ev.source_ip not in self.quarantined_ips and "Distributed" not in ev.source_ip:
                                self.quarantined_ips[ev.source_ip] = {
                                    "ip": ev.source_ip,
                                    "reason": f"Automated IPS Response: {ev.event_type}",
                                    "severity": "CRITICAL" if "CRITICAL" in sev_str else "HIGH",
                                    "duration_minutes": 60,
                                    "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                                    "status": "AUTO_ENFORCED (DROPPED)",
                                }
                time.sleep(0.003)  # Fast replay with micro-pacing for real-time UI animation

            capture_engine.capture(packet_callback=packet_handler, pcap_file=pcap_path)
            logger.info("[+] Background simulation finished successfully.")
        except Exception as e:
            logger.error(f"[-] Simulation error: {e}", exc_info=True)

    def start(self, block: bool = False):
        """Start the HTTP server."""
        self.is_running = True
        self.httpd = ThreadedHTTPServer((self.host, self.port), DashboardHandler)
        logger.info(f"[+] IDS Web Dashboard listening on http://{self.host}:{self.port}")

        if block:
            try:
                self.httpd.serve_forever()
            except (KeyboardInterrupt, SystemExit):
                self.stop()
        else:
            self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self.server_thread.start()

    def stop(self):
        """Gracefully stop the server."""
        self.is_running = False
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            logger.info("[*] IDS Web Dashboard server stopped.")
