"""
Unit and Integration Tests for IDS Web Dashboard & API (Phase 14).
"""

import os
import time
import json
import shutil
import tempfile
import unittest
from urllib.request import urlopen, Request
from urllib.error import HTTPError

from ids.models.events import SecurityEvent, Severity
from ids.storage.sqlite_storage import SqliteAlertStorage
from ids.alerts.alert_manager import AlertManager
from ids.web.server import DashboardServer, WebBroadcastSink


class TestWebDashboardApi(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_events.db")
        self.config_path = os.path.join(self.test_dir, "test_rules.json")

        # Initial test config
        sample_config = {
            "port_scan": {"enabled": True, "unique_ports": 15, "window_seconds": 5},
            "alerts": {"min_severity": "LOW", "dedup_window_seconds": 2.0, "max_rate_per_minute": 500},
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(sample_config, f)

        # Storage and test events
        self.storage = SqliteAlertStorage(self.db_path)
        self.broadcast_sink = WebBroadcastSink()

        # Insert 3 sample security events
        self.event1 = SecurityEvent(
            event_type="TCP_PORT_SCAN",
            severity=Severity.HIGH,
            detector="PortScanDetector",
            description="Port scan detected from 192.168.1.100",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.50",
            evidence={"scanned_ports": [22, 80, 443]},
        )
        self.event2 = SecurityEvent(
            event_type="SYN_FLOOD",
            severity=Severity.CRITICAL,
            detector="SynFloodDetector",
            description="SYN flood burst detected",
            source_ip="192.168.1.200",
            destination_ip="192.168.1.50",
            evidence={"syn_rate": 450},
        )
        self.storage.dispatch(self.event1)
        self.storage.dispatch(self.event2)

        # Pick a free high-range port for testing
        self.port = 18090
        self.server = DashboardServer(
            host="127.0.0.1",
            port=self.port,
            config_path=self.config_path,
            sqlite_storage=self.storage,
            broadcast_sink=self.broadcast_sink,
        )
        self.server.start(block=False)
        time.sleep(0.15)  # Allow socket to bind

    def tearDown(self):
        if self.server:
            self.server.stop()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _get(self, path: str):
        url = f"http://127.0.0.1:{self.port}{path}"
        req = Request(url)
        with urlopen(req, timeout=3.0) as resp:
            return resp.status, resp.read()

    def _post(self, path: str, payload: dict):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = Request(url, data=data, headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=3.0) as resp:
            return resp.status, resp.read()

    def test_static_index_html(self):
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"AEGIS", body)
        self.assertIn(b"CYBER THREAT DETECTION", body)

    def test_static_css_and_js(self):
        status, css = self._get("/css/style.css")
        self.assertEqual(status, 200)
        self.assertIn(b"--bg-base:", css)

        status, js = self._get("/js/app.js")
        self.assertEqual(status, 200)
        self.assertIn(b"inspectForensics", js)

    def test_api_status(self):
        status, body = self._get("/api/status")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data["online"])
        self.assertEqual(data["dashboard_port"], self.port)
        self.assertIn("TCP Port Scan", data["active_detectors"])

    def test_api_summary(self):
        status, body = self._get("/api/summary")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["total_events"], 2)
        self.assertEqual(data["by_severity"].get("HIGH"), 1)
        self.assertEqual(data["by_severity"].get("CRITICAL"), 1)
        self.assertEqual(len(data["top_sources"]), 2)

    def test_api_events_filtering(self):
        # All events
        status, body = self._get("/api/events")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(len(data["events"]), 2)

        # Filter by severity = CRITICAL
        status, body = self._get("/api/events?severity=CRITICAL")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(len(data["events"]), 1)
        self.assertEqual(data["events"][0]["severity"], "CRITICAL")
        self.assertEqual(data["events"][0]["event_type"], "SYN_FLOOD")

    def test_api_config_get_and_post(self):
        status, body = self._get("/api/config")
        self.assertEqual(status, 200)
        cfg = json.loads(body.decode("utf-8"))
        self.assertEqual(cfg["port_scan"]["unique_ports"], 15)

        # Update config via POST
        cfg["port_scan"]["unique_ports"] = 25
        status, body = self._post("/api/config", cfg)
        self.assertEqual(status, 200)

        # Verify change persisted
        status, body = self._get("/api/config")
        updated_cfg = json.loads(body.decode("utf-8"))
        self.assertEqual(updated_cfg["port_scan"]["unique_ports"], 25)

    def test_api_clear(self):
        self.assertEqual(self.storage.count(), 2)
        status, body = self._post("/api/clear", {})
        self.assertEqual(status, 200)
        self.assertEqual(self.storage.count(), 0)

    def test_web_broadcast_sink(self):
        q = self.broadcast_sink.subscribe()
        self.assertTrue(q.empty())

        event = SecurityEvent(
            event_type="ARP_SPOOF",
            severity=Severity.HIGH,
            detector="ArpSpoofDetector",
            description="ARP cache poison",
            source_ip="192.168.1.170",
            evidence={"spoofed_ip": "192.168.1.1"},
        )
        self.broadcast_sink.dispatch(event)

        item = q.get(timeout=1.0)
        self.assertEqual(item["event_type"], "ARP_SPOOF")
        self.assertEqual(item["source_ip"], "192.168.1.170")
        self.broadcast_sink.unsubscribe(q)


if __name__ == "__main__":
    unittest.main()
