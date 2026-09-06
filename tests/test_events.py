"""
Unit tests for ids.models.events.
Tests SecurityEvent creation, serialization, deserialization, and severity handling.
"""

import json
import unittest

from ids.models.events import SecurityEvent, Severity


class TestSecurityEvent(unittest.TestCase):

    def test_create_event_defaults(self):
        """Verify event creation with defaults."""
        event = SecurityEvent(
            event_type="TEST_EVENT",
            severity=Severity.HIGH,
            detector="TestDetector",
            description="Test alert description",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.1",
            evidence={"probed": 5},
        )
        self.assertEqual(event.event_type, "TEST_EVENT")
        self.assertEqual(event.severity, Severity.HIGH)
        self.assertEqual(event.detector, "TestDetector")
        self.assertIsNotNone(event.timestamp)
        self.assertEqual(event.evidence["probed"], 5)

    def test_to_dict_and_json(self):
        """Verify dictionary and JSON conversions."""
        event = SecurityEvent(
            event_type="PORT_SCAN",
            severity=Severity.CRITICAL,
            detector="PortScanDetector",
            description="High rate scanning",
            source_ip="10.0.0.5",
            destination_ip="10.0.0.1",
            evidence={"unique_ports": 25},
        )
        d = event.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["event_type"], "PORT_SCAN")
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertEqual(d["evidence"]["unique_ports"], 25)

        raw_json = event.to_json()
        self.assertIsInstance(raw_json, str)
        parsed = json.loads(raw_json)
        self.assertEqual(parsed["source_ip"], "10.0.0.5")

    def test_from_dict_roundtrip(self):
        """Verify reconstruction from dictionary."""
        original = SecurityEvent(
            event_type="SYN_FLOOD",
            severity=Severity.HIGH,
            detector="SynFloodDetector",
            description="SYN flood threshold exceeded",
            source_ip="192.168.1.50",
            destination_ip="192.168.1.1",
            evidence={"syn_rate": 300},
        )
        data = original.to_dict()
        reconstructed = SecurityEvent.from_dict(data)

        self.assertEqual(reconstructed.event_type, original.event_type)
        self.assertEqual(reconstructed.severity, original.severity)
        self.assertEqual(reconstructed.source_ip, original.source_ip)
        self.assertEqual(reconstructed.evidence, original.evidence)

    def test_format_alert(self):
        """Verify format_alert produces readable text."""
        event = SecurityEvent(
            event_type="ARP_SPOOF",
            severity=Severity.HIGH,
            detector="ArpSpoofDetector",
            description="Conflict detected",
            source_ip="192.168.1.1",
        )
        alert_str = event.format_alert()
        self.assertIn("ALERT: [HIGH] ARP_SPOOF", alert_str)
        self.assertIn("Source:      192.168.1.1", alert_str)


if __name__ == "__main__":
    unittest.main()
