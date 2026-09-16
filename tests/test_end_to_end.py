"""
End-to-End Integration Tests for Python Network IDS (Phase 13).

Tests the full capture -> parsing -> multi-threat detection -> alert management -> storage pipeline
against offline multi-vector attack PCAPs.
"""

import os
import shutil
import tempfile
import unittest

from ids.capture.packet_capture import PacketCaptureEngine
from ids.parser.packet_parser import PacketParser
from ids.detectors.detection_engine import DetectionEngine
from ids.alerts.alert_manager import AlertManager, AlertSink
from ids.storage.json_storage import JsonAlertStorage
from ids.storage.sqlite_storage import SqliteAlertStorage


class RecordingSink(AlertSink):
    def __init__(self):
        self.events = []

    def dispatch(self, event):
        self.events.append(event)


class TestEndToEndPipeline(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.json_path = os.path.join(self.test_dir, "alerts.json")
        self.sqlite_path = os.path.join(self.test_dir, "events.db")

        # 1. Detection Engine
        self.detection_engine = DetectionEngine()
        self.detection_engine.register_default_detectors()

        # 2. Storage Sinks
        self.json_storage = JsonAlertStorage(file_path=self.json_path)
        self.sqlite_storage = SqliteAlertStorage(db_path=self.sqlite_path)
        self.recording_sink = RecordingSink()

        # 3. Alert Manager
        self.alert_manager = AlertManager(
            config={
                "min_severity": "LOW",
                "dedup_window_seconds": 2.0,
                "max_rate_per_minute": 500,
            }
        )
        self.alert_manager.register_sink(self.recording_sink)
        self.alert_manager.register_sink(self.json_storage)
        self.alert_manager.register_sink(self.sqlite_storage)

        self.pcap_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "samples", "multi_vector_attack.pcap"
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_full_pipeline_multi_vector_playback(self):
        """Replay multi-vector attack PCAP through full pipeline and verify threat detections."""
        self.assertTrue(
            os.path.exists(self.pcap_path),
            f"Multi-vector PCAP missing at {self.pcap_path}",
        )

        capture_engine = PacketCaptureEngine()
        packets_parsed = 0

        def packet_handler(raw_pkt):
            nonlocal packets_parsed
            parsed = PacketParser.parse(raw_pkt)
            if parsed:
                packets_parsed += 1
                alerts = self.detection_engine.process_packet(parsed)
                for alert in alerts:
                    self.alert_manager.dispatch(alert)

        total_captured = capture_engine.capture(
            packet_callback=packet_handler,
            pcap_file=self.pcap_path,
        )

        # 1. Validate Capture & Parsing
        self.assertGreaterEqual(total_captured, 250)
        self.assertEqual(packets_parsed, total_captured)

        # 2. Validate Detection Engine
        self.assertGreater(self.detection_engine.stats["alerts_generated"], 0)
        self.assertEqual(self.detection_engine.stats["detector_errors"], 0)

        # 3. Validate Alert Manager
        dispatched_events = self.recording_sink.events
        self.assertGreaterEqual(len(dispatched_events), 4)

        event_types = {e.event_type for e in dispatched_events}

        # Expected attack vectors detected
        self.assertIn("TCP_PORT_SCAN", event_types)
        self.assertIn("TCP_SYN_FLOOD", event_types)
        self.assertIn("ARP_SPOOFING", event_types)

        # 4. Validate JSON Storage
        json_records = self.json_storage.read_all()
        self.assertEqual(len(json_records), len(dispatched_events))
        json_types = {r["event_type"] for r in json_records}
        self.assertEqual(json_types, event_types)

        # 5. Validate SQLite Relational Storage
        self.assertEqual(self.sqlite_storage.count(), len(dispatched_events))
        summary = self.sqlite_storage.get_summary()
        self.assertEqual(summary["total_events"], len(dispatched_events))
        self.assertIn("TCP_PORT_SCAN", summary["by_type"])
        self.assertIn("TCP_SYN_FLOOD", summary["by_type"])
        self.assertIn("ARP_SPOOFING", summary["by_type"])

        # Top sources query verification
        top_sources = summary["top_sources"]
        self.assertGreater(len(top_sources), 0)


if __name__ == "__main__":
    unittest.main()
