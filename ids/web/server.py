"""
Web Dashboard Server and REST / SSE API for Python Network IDS.

Serves the Cyber SOC frontend, aggregates SQLite security alerts,
broadcasts live incidents via Server-Sent Events (SSE), and allows
rule tuning and attack simulation.
"""

import os
import sys
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
        elif path == "/api/events/stream":
            self._handle_api_stream()
        elif path == "/api/config":
            self._handle_api_get_config()
        elif path == "/api/status":
            self._handle_api_status()
        elif path == "/api/interfaces":
            self._handle_api_interfaces()
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
        elif path == "/api/clear":
            self._handle_api_clear()
        else:
            self.send_error(404, "Endpoint not found")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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

        events = storage.get_events(
            limit=limit,
            offset=offset,
            severity=severity,
            event_type=event_type,
            source_ip=source_ip,
        )
        total = storage.count()
        self._send_json({"events": events, "total": total, "limit": limit, "offset": offset})

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

    def _handle_api_simulate(self):
        """Trigger asynchronous replay of sample attack PCAPs."""
        body = self._read_json_body()
        pcap_file = body.get("pcap", "samples/multi_vector_attack.pcap")

        # Resolve relative to project root
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        full_pcap_path = os.path.join(project_root, pcap_file)

        if not os.path.exists(full_pcap_path):
            # Check if we can auto-generate it
            if "multi_vector_attack.pcap" in pcap_file:
                try:
                    from samples.generate_multi_vector_pcap import generate_multi_vector_pcap
                    generate_multi_vector_pcap(full_pcap_path)
                except Exception as e:
                    self._send_json({"error": f"Failed to auto-generate PCAP: {e}"}, 500)
                    return
            else:
                self._send_json({"error": f"PCAP file not found: {pcap_file}"}, 404)
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
            "pcap": pcap_file,
            "message": "Attack simulation running in background; watch live alerts feed.",
        })

    def _handle_api_clear(self):
        storage = self.server_instance.sqlite_storage
        if storage:
            storage.clear()
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
                normalized = parser.parse(raw_pkt)
                if normalized:
                    events = detection_engine.process_packet(normalized)
                    for ev in events:
                        sim_alert_manager.dispatch(ev)
                time.sleep(0.015)  # Slight micro-delay so UI sees real-time animation

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
