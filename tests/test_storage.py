"""
Unit tests for Persistent Storage Subsystem (Phase 12).
"""

import os
import shutil
import tempfile
import unittest

from ids.models.events import SecurityEvent, Severity
from ids.alerts.alert_manager import AlertManager
from ids.storage.json_storage import JsonAlertStorage
from ids.storage.sqlite_storage import SqliteAlertStorage


def make_test_event(
    event_type: str = "TCP_PORT_SCAN",
    severity: Severity = Severity.HIGH,
    source_ip: str = "192.168.1.100",
    destination_ip: str = "192.168.1.50",
    description: str = "Port scan detected",
) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type,
        severity=severity,
        source_ip=source_ip,
        destination_ip=destination_ip,
        detector="PortScanDetector",
        description=description,
        evidence={"ports": [80, 443, 8080]},
    )


class TestStorage(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.json_path = os.path.join(self.test_dir, "alerts.json")
        self.sqlite_path = os.path.join(self.test_dir, "events.db")

        self.json_storage = JsonAlertStorage(file_path=self.json_path)
        self.sqlite_storage = SqliteAlertStorage(db_path=self.sqlite_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # ------------------ JSON Storage Tests ------------------

    def test_json_storage_write_and_read(self):
        """Events are written as JSON lines and read back accurately."""
        ev1 = make_test_event(event_type="TCP_PORT_SCAN", source_ip="10.0.0.1")
        ev2 = make_test_event(event_type="UDP_SCAN", source_ip="10.0.0.2")

        self.json_storage.dispatch(ev1)
        self.json_storage.dispatch(ev2)

        self.assertEqual(self.json_storage.count(), 2)
        records = self.json_storage.read_all()
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["event_type"], "TCP_PORT_SCAN")
        self.assertEqual(records[0]["source_ip"], "10.0.0.1")
        self.assertEqual(records[1]["event_type"], "UDP_SCAN")

    def test_json_storage_clear(self):
        """clear() truncates the log file."""
        self.json_storage.dispatch(make_test_event())
        self.assertEqual(self.json_storage.count(), 1)
        self.json_storage.clear()
        self.assertEqual(self.json_storage.count(), 0)

    # ------------------ SQLite Storage Tests ------------------

    def test_sqlite_insert_and_count(self):
        """Events inserted into SQLite database can be counted and queried."""
        ev = make_test_event(severity=Severity.CRITICAL, event_type="ARP_SPOOFING")
        self.sqlite_storage.dispatch(ev)

        self.assertEqual(self.sqlite_storage.count(), 1)
        events = self.sqlite_storage.get_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "ARP_SPOOFING")
        self.assertEqual(events[0]["severity"], "CRITICAL")
        self.assertEqual(events[0]["evidence"]["ports"], [80, 443, 8080])

    def test_sqlite_filtered_queries(self):
        """Events can be filtered by severity, event_type, and source_ip."""
        self.sqlite_storage.dispatch(make_test_event(event_type="TCP_PORT_SCAN", severity=Severity.MEDIUM, source_ip="1.1.1.1"))
        self.sqlite_storage.dispatch(make_test_event(event_type="TCP_SYN_FLOOD", severity=Severity.HIGH, source_ip="2.2.2.2"))
        self.sqlite_storage.dispatch(make_test_event(event_type="DNS_TUNNELING", severity=Severity.HIGH, source_ip="1.1.1.1"))

        self.assertEqual(self.sqlite_storage.count(), 3)

        # Filter by severity
        high_events = self.sqlite_storage.get_events(severity="HIGH")
        self.assertEqual(len(high_events), 2)

        # Filter by event_type
        scan_events = self.sqlite_storage.get_events(event_type="TCP_PORT_SCAN")
        self.assertEqual(len(scan_events), 1)
        self.assertEqual(scan_events[0]["source_ip"], "1.1.1.1")

        # Filter by source_ip
        ip_events = self.sqlite_storage.get_events(source_ip="1.1.1.1")
        self.assertEqual(len(ip_events), 2)

    def test_sqlite_summary_metrics(self):
        """get_summary returns grouped event statistics."""
        self.sqlite_storage.dispatch(make_test_event(event_type="TCP_PORT_SCAN", severity=Severity.MEDIUM, source_ip="10.0.0.1"))
        self.sqlite_storage.dispatch(make_test_event(event_type="TCP_PORT_SCAN", severity=Severity.MEDIUM, source_ip="10.0.0.1"))
        self.sqlite_storage.dispatch(make_test_event(event_type="TCP_SYN_FLOOD", severity=Severity.HIGH, source_ip="10.0.0.2"))

        summary = self.sqlite_storage.get_summary()
        self.assertEqual(summary["total_events"], 3)
        self.assertEqual(summary["by_severity"]["MEDIUM"], 2)
        self.assertEqual(summary["by_severity"]["HIGH"], 1)
        self.assertEqual(summary["by_type"]["TCP_PORT_SCAN"], 2)
        self.assertEqual(summary["top_sources"][0]["source_ip"], "10.0.0.1")
        self.assertEqual(summary["top_sources"][0]["count"], 2)

    def test_sqlite_clear(self):
        """clear() removes all stored records."""
        self.sqlite_storage.dispatch(make_test_event())
        self.assertEqual(self.sqlite_storage.count(), 1)
        self.sqlite_storage.clear()
        self.assertEqual(self.sqlite_storage.count(), 0)

    # ------------------ Integration with AlertManager ------------------

    def test_alert_manager_storage_integration(self):
        """AlertManager dispatches alerts seamlessly into both storage sinks."""
        manager = AlertManager()
        manager.register_sink(self.json_storage)
        manager.register_sink(self.sqlite_storage)

        ev = make_test_event(event_type="DNS_TUNNELING", severity=Severity.HIGH)
        manager.dispatch(ev)

        self.assertEqual(self.json_storage.count(), 1)
        self.assertEqual(self.sqlite_storage.count(), 1)


if __name__ == "__main__":
    unittest.main()
