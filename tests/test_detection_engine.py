"""
Unit tests for ids.detectors.base_detector and ids.detectors.detection_engine.
Tests registration, fault-isolation, state cleanup, and sliding window management.
"""

import time
import unittest
from typing import Optional

from ids.parser.packet_parser import ParsedPacket, IPHeader, TCPHeader
from ids.models.events import SecurityEvent, Severity
from ids.detectors import BaseDetector, SlidingWindowTracker, DetectionEngine


class MockSuccessDetector(BaseDetector):
    """Generates an alert if destination port is 80."""

    def __init__(self, config=None):
        super().__init__(name="MockSuccessDetector", config=config)
        self.cleanup_called = False

    def process(self, packet: ParsedPacket) -> Optional[SecurityEvent]:
        if packet.tcp and packet.tcp.dst_port == 80:
            return SecurityEvent(
                event_type="HTTP_PROBE",
                severity=Severity.LOW,
                detector=self.name,
                description="Port 80 traffic observed",
                source_ip=packet.ip.src_ip if packet.ip else None,
                destination_ip=packet.ip.dst_ip if packet.ip else None,
            )
        return None

    def cleanup_expired_state(self, current_time: float) -> None:
        self.cleanup_called = True


class MockBrokenDetector(BaseDetector):
    """Always raises an unhandled exception during process()."""

    def __init__(self):
        super().__init__(name="MockBrokenDetector", config={"enabled": True})

    def process(self, packet: ParsedPacket) -> Optional[SecurityEvent]:
        raise RuntimeError("Simulated detector internal failure!")

    def cleanup_expired_state(self, current_time: float) -> None:
        pass


class TestDetectionEngine(unittest.TestCase):

    def setUp(self):
        self.engine = DetectionEngine(cleanup_interval_seconds=1.0)

    def test_sliding_window_tracker(self):
        """Verify SlidingWindowTracker prunes expired elements and counts items."""
        tracker = SlidingWindowTracker(window_seconds=5.0)
        base_time = 1000.0

        tracker.add("port_80", timestamp=base_time)
        tracker.add("port_443", timestamp=base_time + 2.0)
        tracker.add("port_22", timestamp=base_time + 4.0)

        # At base_time + 4.5s, all 3 are within the 5s window
        self.assertEqual(tracker.count(base_time + 4.5), 3)

        # At base_time + 6.0s, port_80 (at 1000.0) is expired (> 5s ago)
        active = tracker.prune(base_time + 6.0)
        self.assertEqual(len(active), 2)
        self.assertNotIn("port_80", active)
        self.assertIn("port_443", active)
        self.assertIn("port_22", active)

    def test_detector_registration_and_execution(self):
        """Verify detector registration and alert generation."""
        detector = MockSuccessDetector()
        self.engine.register_detector(detector)

        pkt = ParsedPacket(
            timestamp=time.time(),
            raw_length=60,
            summary="TCP test",
            ip=IPHeader(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol=6, proto_name="TCP", ttl=64, length=60),
            tcp=TCPHeader(
                src_port=12345, dst_port=80, flags="S", seq=1, ack=0,
                is_syn=True, is_ack=False, is_fin=False, is_rst=False, is_psh=False, is_urg=False
            ),
        )

        alerts = self.engine.process_packet(pkt)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_type, "HTTP_PROBE")
        self.assertEqual(alerts[0].source_ip, "1.1.1.1")

    def test_fault_isolation(self):
        """Ensure a broken detector does NOT crash the engine or block other detectors."""
        healthy_detector = MockSuccessDetector()
        broken_detector = MockBrokenDetector()

        self.engine.register_detector(broken_detector)
        self.engine.register_detector(healthy_detector)

        pkt = ParsedPacket(
            timestamp=time.time(),
            raw_length=60,
            summary="TCP test",
            ip=IPHeader(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol=6, proto_name="TCP", ttl=64, length=60),
            tcp=TCPHeader(
                src_port=12345, dst_port=80, flags="S", seq=1, ack=0,
                is_syn=True, is_ack=False, is_fin=False, is_rst=False, is_psh=False, is_urg=False
            ),
        )

        # Should process without throwing an exception!
        alerts = self.engine.process_packet(pkt)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_type, "HTTP_PROBE")
        self.assertEqual(self.engine.stats["detector_errors"], 1)

    def test_disabled_detector(self):
        """Disabled detector should not be invoked."""
        detector = MockSuccessDetector(config={"enabled": False})
        self.engine.register_detector(detector)

        pkt = ParsedPacket(
            timestamp=time.time(),
            raw_length=60,
            summary="TCP test",
            tcp=TCPHeader(
                src_port=12345, dst_port=80, flags="S", seq=1, ack=0,
                is_syn=True, is_ack=False, is_fin=False, is_rst=False, is_psh=False, is_urg=False
            ),
        )

        alerts = self.engine.process_packet(pkt)
        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
