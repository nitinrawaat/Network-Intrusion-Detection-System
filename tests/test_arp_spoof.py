"""
Unit tests for ArpSpoofDetector (Phase 9).
"""

import unittest
import time

from ids.parser.packet_parser import ParsedPacket, ARPHeader
from ids.models.events import Severity
from ids.detectors.arp_spoof import ArpSpoofDetector
from ids.detectors.detection_engine import DetectionEngine


def make_arp_packet(
    src_ip: str = "192.168.1.1",
    src_mac: str = "00:50:56:c0:00:01",
    dst_ip: str = "192.168.1.50",
    dst_mac: str = "00:0c:29:1a:2b:3c",
    operation: str = "is-at",
    op_code: int = 2,
    timestamp: float = 1000.0,
) -> ParsedPacket:
    """Helper to synthesize a ParsedPacket with ARP header."""
    return ParsedPacket(
        timestamp=timestamp,
        raw_length=42,
        summary=f"ARP {operation} {src_ip} -> {dst_ip}",
        arp=ARPHeader(
            src_ip=src_ip,
            src_mac=src_mac,
            dst_ip=dst_ip,
            dst_mac=dst_mac,
            operation=operation,
            op_code=op_code,
        ),
    )


class TestArpSpoofDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ArpSpoofDetector(
            config={
                "enabled": True,
                "alert_cooldown": 5.0,
                "mac_ttl_seconds": 60.0,
                "static_mappings": {
                    "192.168.1.254": "00:aa:bb:cc:dd:ee"
                },
            }
        )

    def test_first_arp_packet_learned_no_alert(self):
        """Initial ARP packet establishes mapping without alerting."""
        pkt = make_arp_packet(src_ip="192.168.1.10", src_mac="00:11:22:33:44:55")
        alert = self.detector.process(pkt)
        self.assertIsNone(alert)
        self.assertEqual(self.detector.ip_mac_table["192.168.1.10"], "00:11:22:33:44:55")

    def test_consistent_arp_traffic_no_alert(self):
        """Subsequent packets matching known MAC should not alert."""
        pkt1 = make_arp_packet(src_ip="192.168.1.10", src_mac="00:11:22:33:44:55", timestamp=1000.0)
        pkt2 = make_arp_packet(src_ip="192.168.1.10", src_mac="00:11:22:33:44:55", timestamp=1001.0)
        self.assertIsNone(self.detector.process(pkt1))
        self.assertIsNone(self.detector.process(pkt2))

    def test_conflicting_mac_triggers_alert(self):
        """Conflicting MAC for an established dynamic mapping triggers alert."""
        # 1. Legitimate host announcement
        pkt1 = make_arp_packet(src_ip="192.168.1.1", src_mac="00:50:56:c0:00:01", timestamp=1000.0)
        self.assertIsNone(self.detector.process(pkt1))

        # 2. Attacker poisoning the gateway IP with their own MAC
        poison_pkt = make_arp_packet(
            src_ip="192.168.1.1",
            src_mac="de:ad:be:ef:13:37",
            timestamp=1001.0,
        )
        alert = self.detector.process(poison_pkt)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_type, "ARP_SPOOFING")
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertEqual(alert.source_ip, "192.168.1.1")
        self.assertEqual(alert.evidence["original_mac"], "00:50:56:c0:00:01")
        self.assertEqual(alert.evidence["spoofed_mac"], "de:ad:be:ef:13:37")
        self.assertFalse(alert.evidence["static_pinned"])

    def test_static_pinned_mapping_violation(self):
        """Violation of pre-configured static mapping triggers alert immediately."""
        # Configured static gateway 192.168.1.254 -> 00:aa:bb:cc:dd:ee
        pkt = make_arp_packet(
            src_ip="192.168.1.254",
            src_mac="de:ad:be:ef:00:01",
            timestamp=1000.0,
        )
        alert = self.detector.process(pkt)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_type, "ARP_SPOOFING")
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertTrue(alert.evidence["static_pinned"])
        self.assertIn("STATIC PINNING VIOLATION", alert.description)

    def test_alert_cooldown(self):
        """Repeated conflicting packets within alert_cooldown generate only 1 alert."""
        # Establish initial mapping
        self.detector.process(make_arp_packet(src_ip="192.168.1.1", src_mac="00:50:56:c0:00:01", timestamp=1000.0))

        # Send burst of poisoned ARPs
        alerts = []
        for i in range(10):
            pkt = make_arp_packet(
                src_ip="192.168.1.1",
                src_mac="de:ad:be:ef:13:37",
                timestamp=1000.5 + i * 0.1,
            )
            event = self.detector.process(pkt)
            if event:
                alerts.append(event)

        self.assertEqual(len(alerts), 1)

    def test_ignored_broadcast_and_invalid_macs(self):
        """Null and broadcast MACs must be ignored."""
        p1 = make_arp_packet(src_mac="00:00:00:00:00:00")
        p2 = make_arp_packet(src_mac="ff:ff:ff:ff:ff:ff")
        self.assertIsNone(self.detector.process(p1))
        self.assertIsNone(self.detector.process(p2))
        self.assertNotIn("192.168.1.1", self.detector.ip_mac_table)

    def test_ignored_probe_ips(self):
        """0.0.0.0 probe IP is ignored."""
        p = make_arp_packet(src_ip="0.0.0.0")
        self.assertIsNone(self.detector.process(p))
        self.assertNotIn("0.0.0.0", self.detector.ip_mac_table)

    def test_detector_disabled(self):
        """Disabled detector should not process or alert."""
        disabled = ArpSpoofDetector(config={"enabled": False})
        p1 = make_arp_packet(src_ip="192.168.1.1", src_mac="00:11:22:33:44:55")
        p2 = make_arp_packet(src_ip="192.168.1.1", src_mac="de:ad:be:ef:13:37")
        self.assertIsNone(disabled.process(p1))
        self.assertIsNone(disabled.process(p2))
        self.assertEqual(len(disabled.ip_mac_table), 0)

    def test_cleanup_expired_state(self):
        """Dynamic mappings older than mac_ttl_seconds are pruned, but static mappings persist."""
        base_time = 1000.0
        pkt = make_arp_packet(src_ip="192.168.1.5", src_mac="00:11:22:33:44:55", timestamp=base_time)
        self.detector.process(pkt)
        self.assertIn("192.168.1.5", self.detector.ip_mac_table)
        self.assertIn("192.168.1.254", self.detector.ip_mac_table)

        # Cleanup after TTL (60s)
        self.detector.cleanup_expired_state(current_time=base_time + 100.0)
        self.assertNotIn("192.168.1.5", self.detector.ip_mac_table)
        # Static mapping must remain
        self.assertIn("192.168.1.254", self.detector.ip_mac_table)

    def test_reset_state(self):
        """reset_state restores static mappings and clears learned entries."""
        pkt = make_arp_packet(src_ip="192.168.1.5", src_mac="00:11:22:33:44:55")
        self.detector.process(pkt)
        self.assertIn("192.168.1.5", self.detector.ip_mac_table)

        self.detector.reset_state()
        self.assertNotIn("192.168.1.5", self.detector.ip_mac_table)
        self.assertIn("192.168.1.254", self.detector.ip_mac_table)

    def test_engine_integration(self):
        """DetectionEngine integrates and triggers ArpSpoofDetector."""
        engine = DetectionEngine()
        detector = ArpSpoofDetector(config={"enabled": True})
        engine.register_detector(detector)

        pkt1 = make_arp_packet(src_ip="192.168.1.1", src_mac="00:50:56:c0:00:01", timestamp=1000.0)
        pkt2 = make_arp_packet(src_ip="192.168.1.1", src_mac="de:ad:be:ef:13:37", timestamp=1001.0)

        alerts1 = engine.process_packet(pkt1)
        self.assertEqual(len(alerts1), 0)

        alerts2 = engine.process_packet(pkt2)
        self.assertEqual(len(alerts2), 1)
        self.assertEqual(alerts2[0].event_type, "ARP_SPOOFING")


if __name__ == "__main__":
    unittest.main()
