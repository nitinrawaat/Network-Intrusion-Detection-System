"""
Unit tests for SynFloodDetector (Phase 8).
"""

import unittest
import time

from ids.parser.packet_parser import ParsedPacket, IPHeader, TCPHeader, UDPHeader
from ids.models.events import Severity
from ids.detectors.syn_flood import SynFloodDetector
from ids.detectors.detection_engine import DetectionEngine


def make_syn_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.50",
    src_port: int = 40000,
    dst_port: int = 80,
    timestamp: float = 1000.0,
    is_syn: bool = True,
    is_ack: bool = False,
) -> ParsedPacket:
    """Helper to synthesize a ParsedPacket with TCP SYN flags."""
    flags_list = []
    if is_syn:
        flags_list.append("SYN")
    if is_ack:
        flags_list.append("ACK")

    return ParsedPacket(
        timestamp=timestamp,
        raw_length=60,
        summary=f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} TCP SYN",
        ip=IPHeader(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=6,
            proto_name="TCP",
            ttl=64,
            length=60,
        ),
        tcp=TCPHeader(
            src_port=src_port,
            dst_port=dst_port,
            seq=123456,
            ack=0,
            flags=",".join(flags_list),
            is_syn=is_syn,
            is_ack=is_ack,
            is_fin=False,
            is_rst=False,
            is_psh=False,
            is_urg=False,
        ),
    )


class TestSynFloodDetector(unittest.TestCase):

    def setUp(self):
        # Set a low threshold (10 SYNs) and small window (3.0s) for testing
        self.detector = SynFloodDetector(
            config={
                "enabled": True,
                "syn_threshold": 10,
                "window_seconds": 3.0,
                "alert_cooldown": 5.0,
            }
        )

    def test_normal_traffic_no_alert(self):
        """SYN count below threshold should not trigger an alert."""
        base_time = 1000.0
        # Send 8 SYNs, threshold is 10
        for i in range(8):
            pkt = make_syn_packet(
                src_port=40000 + i,
                timestamp=base_time + i * 0.1,
            )
            event = self.detector.process(pkt)
            self.assertIsNone(event)

    def test_syn_flood_detected_single_source(self):
        """Single attacker exceeding threshold triggers HIGH severity alert."""
        base_time = 1000.0
        alert = None

        for i in range(10):
            pkt = make_syn_packet(
                src_ip="10.0.0.99",
                dst_ip="192.168.1.50",
                dst_port=80,
                src_port=50000 + i,
                timestamp=base_time + i * 0.05,
            )
            result = self.detector.process(pkt)
            if result:
                alert = result

        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_type, "TCP_SYN_FLOOD")
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertEqual(alert.source_ip, "10.0.0.99")
        self.assertEqual(alert.destination_ip, "192.168.1.50")
        self.assertEqual(alert.evidence["target_port"], 80)
        self.assertEqual(alert.evidence["syn_count"], 10)
        self.assertIn("10.0.0.99", alert.evidence["sample_sources"])

    def test_syn_flood_detected_distributed_spoofed(self):
        """Distributed/spoofed IPs targeting the victim service triggers alert."""
        base_time = 1000.0
        alert = None

        for i in range(10):
            pkt = make_syn_packet(
                src_ip=f"172.16.0.{i+1}",
                dst_ip="192.168.1.50",
                dst_port=443,
                src_port=40000 + i,
                timestamp=base_time + i * 0.05,
            )
            result = self.detector.process(pkt)
            if result:
                alert = result

        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_type, "TCP_SYN_FLOOD")
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertIn("Distributed", alert.source_ip)
        self.assertEqual(alert.evidence["unique_sources_count"], 10)
        self.assertEqual(alert.evidence["target_port"], 443)

    def test_syn_ack_and_ack_ignored(self):
        """Packets with ACK flag set (e.g. established traffic or SYN-ACK) must be ignored."""
        base_time = 1000.0

        for i in range(20):
            # SYN+ACK response
            pkt = make_syn_packet(
                src_port=40000 + i,
                timestamp=base_time + i * 0.05,
                is_syn=True,
                is_ack=True,
            )
            self.assertIsNone(self.detector.process(pkt))

            # Pure ACK packet
            ack_pkt = make_syn_packet(
                src_port=40000 + i,
                timestamp=base_time + i * 0.05,
                is_syn=False,
                is_ack=True,
            )
            self.assertIsNone(self.detector.process(ack_pkt))

    def test_sliding_window_pruning(self):
        """Packets arriving outside window_seconds are pruned."""
        base_time = 1000.0

        # Send 8 SYNs at t=1000.0
        for i in range(8):
            pkt = make_syn_packet(src_port=40000 + i, timestamp=base_time + i * 0.01)
            self.detector.process(pkt)

        # Jump forward past window_seconds (3.0s), send 3 more SYNs
        later_time = base_time + 4.0
        alert = None
        for i in range(3):
            pkt = make_syn_packet(src_port=50000 + i, timestamp=later_time + i * 0.01)
            result = self.detector.process(pkt)
            if result:
                alert = result

        # Total in current window is only 3, so no alert
        self.assertIsNone(alert)

    def test_alert_cooldown(self):
        """Alert cooldown prevents duplicate alert bursts for the same target."""
        base_time = 1000.0
        alerts = []

        # Send 25 consecutive SYNs
        for i in range(25):
            pkt = make_syn_packet(
                src_port=40000 + i,
                timestamp=base_time + i * 0.1,
            )
            event = self.detector.process(pkt)
            if event:
                alerts.append(event)

        # Only one alert should be triggered during the 5.0s cooldown window
        self.assertEqual(len(alerts), 1)

    def test_independent_target_endpoints(self):
        """Different destination target ports maintain independent state."""
        base_time = 1000.0

        # Send 8 SYNs to port 80 (below threshold of 10)
        for i in range(8):
            pkt = make_syn_packet(dst_port=80, src_port=40000 + i, timestamp=base_time + i * 0.05)
            self.assertIsNone(self.detector.process(pkt))

        # Send 8 SYNs to port 443 (below threshold of 10)
        for i in range(8):
            pkt = make_syn_packet(dst_port=443, src_port=40000 + i, timestamp=base_time + i * 0.05)
            self.assertIsNone(self.detector.process(pkt))

    def test_detector_disabled(self):
        """Disabled detector should immediately return None without recording state."""
        disabled_detector = SynFloodDetector(
            config={"enabled": False, "syn_threshold": 5, "window_seconds": 3.0}
        )
        for i in range(20):
            pkt = make_syn_packet(src_port=40000 + i, timestamp=1000.0 + i * 0.05)
            self.assertIsNone(disabled_detector.process(pkt))
        self.assertEqual(len(disabled_detector.trackers), 0)

    def test_cleanup_expired_state(self):
        """Expired target trackers should be removed to bound memory usage."""
        base_time = 1000.0
        pkt = make_syn_packet(timestamp=base_time)
        self.detector.process(pkt)
        self.assertIn("192.168.1.50:80", self.detector.trackers)

        # Cleanup after window + cooldown expired
        self.detector.cleanup_expired_state(current_time=base_time + 20.0)
        self.assertNotIn("192.168.1.50:80", self.detector.trackers)

    def test_reset_state(self):
        """reset_state clears all internal tracking queues."""
        pkt = make_syn_packet()
        self.detector.process(pkt)
        self.assertGreater(len(self.detector.trackers), 0)

        self.detector.reset_state()
        self.assertEqual(len(self.detector.trackers), 0)
        self.assertEqual(len(self.detector.last_alert_time), 0)

    def test_engine_integration(self):
        """DetectionEngine registers and triggers SynFloodDetector."""
        engine = DetectionEngine(
            config_path=None,
        )
        # Configure lower threshold for integration test
        detector = SynFloodDetector(
            config={"enabled": True, "syn_threshold": 5, "window_seconds": 3.0}
        )
        engine.register_detector(detector)

        all_alerts = []
        for i in range(6):
            pkt = make_syn_packet(src_port=40000 + i, timestamp=1000.0 + i * 0.05)
            alerts = engine.process_packet(pkt)
            all_alerts.extend(alerts)

        self.assertEqual(len(all_alerts), 1)
        self.assertEqual(all_alerts[0].event_type, "TCP_SYN_FLOOD")


if __name__ == "__main__":
    unittest.main()
