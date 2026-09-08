"""
Unit tests for UdpScanDetector (Phase 7).
"""

import unittest
import time

from ids.parser.packet_parser import ParsedPacket, IPHeader, UDPHeader, TCPHeader
from ids.models.events import Severity
from ids.detectors.udp_scan import UdpScanDetector


def make_udp_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.50",
    src_port: int = 45678,
    dst_port: int = 53,
    timestamp: float = 1000.0,
) -> ParsedPacket:
    """Helper to synthesize a ParsedPacket with UDP header."""
    return ParsedPacket(
        timestamp=timestamp,
        raw_length=50,
        summary=f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} UDP",
        ip=IPHeader(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=17,
            proto_name="UDP",
            ttl=64,
            length=50,
        ),
        udp=UDPHeader(
            src_port=src_port,
            dst_port=dst_port,
            length=30,
        ),
    )


class TestUdpScanDetector(unittest.TestCase):

    def setUp(self):
        self.detector = UdpScanDetector(
            config={
                "enabled": True,
                "unique_ports": 5,        # Set to 5 for fast test cycles
                "window_seconds": 3.0,
                "alert_cooldown": 5.0,
            }
        )

    def test_normal_traffic_no_alert(self):
        """Repeated packets to the same port or below threshold should not alert."""
        base_time = 1000.0
        # 4 distinct ports, threshold is 5
        ports = [53, 123, 161, 67]
        for idx, port in enumerate(ports):
            pkt = make_udp_packet(dst_port=port, timestamp=base_time + idx * 0.1)
            alert = self.detector.process(pkt)
            self.assertIsNone(alert)

    def test_udp_scan_triggers_alert(self):
        """Crossing unique_ports threshold within window must trigger alert."""
        base_time = 1000.0
        ports = [53, 67, 68, 69, 123]
        alert = None
        for idx, port in enumerate(ports):
            pkt = make_udp_packet(
                src_ip="10.0.0.120",
                dst_ip="10.0.0.1",
                dst_port=port,
                timestamp=base_time + idx * 0.2,
            )
            alert = self.detector.process(pkt)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_type, "UDP_PORT_SCAN")
        self.assertEqual(alert.severity, Severity.LOW)
        self.assertEqual(alert.source_ip, "10.0.0.120")
        self.assertEqual(alert.destination_ip, "10.0.0.1")
        self.assertEqual(alert.evidence["port_count"], 5)
        self.assertListEqual(alert.evidence["probed_ports"], [53, 67, 68, 69, 123])

    def test_sliding_window_expiration(self):
        """UDP probes spread out beyond window_seconds should not accumulate."""
        base_time = 1000.0
        # 4 probes within window
        for idx, port in enumerate([53, 67, 68, 69]):
            pkt = make_udp_packet(dst_port=port, timestamp=base_time + idx * 0.2)
            self.assertIsNone(self.detector.process(pkt))

        # Advance time past window (window is 3.0s, advance to +4.0s)
        pkt = make_udp_packet(dst_port=123, timestamp=base_time + 4.0)
        alert = self.detector.process(pkt)
        self.assertIsNone(alert)

    def test_alert_cooldown(self):
        """Subsequent packets after alert must be suppressed until cooldown expires."""
        base_time = 1000.0
        # Trigger alert with 5 ports
        for idx, port in enumerate([10, 20, 30, 40, 50]):
            pkt = make_udp_packet(dst_port=port, timestamp=base_time + idx * 0.1)
            last_alert = self.detector.process(pkt)

        self.assertIsNotNone(last_alert)

        # 6th probe within cooldown window
        pkt6 = make_udp_packet(dst_port=60, timestamp=base_time + 1.0)
        suppressed_alert = self.detector.process(pkt6)
        self.assertIsNone(suppressed_alert)

        # After cooldown
        for idx, port in enumerate([100, 200, 300, 400, 500]):
            pkt = make_udp_packet(dst_port=port, timestamp=base_time + 6.0 + idx * 0.1)
            new_alert = self.detector.process(pkt)

        self.assertIsNotNone(new_alert)
        self.assertEqual(new_alert.event_type, "UDP_PORT_SCAN")

    def test_ignore_non_udp(self):
        """TCP and other non-UDP packets must be ignored."""
        base_time = 1000.0
        tcp_pkt = ParsedPacket(
            timestamp=base_time,
            raw_length=60,
            summary="TCP test",
            ip=IPHeader(src_ip="1.2.3.4", dst_ip="5.6.7.8", protocol=6, proto_name="TCP", ttl=64, length=60),
            tcp=TCPHeader(
                src_port=1234, dst_port=80, flags="S", seq=1, ack=0,
                is_syn=True, is_ack=False, is_fin=False, is_rst=False, is_psh=False, is_urg=False
            ),
        )
        self.assertIsNone(self.detector.process(tcp_pkt))

    def test_cleanup_expired_state(self):
        """Pruning should remove stale source IPs from memory."""
        base_time = 1000.0
        pkt = make_udp_packet(src_ip="1.2.3.4", dst_port=53, timestamp=base_time)
        self.detector.process(pkt)
        self.assertIn("1.2.3.4", self.detector.trackers)

        # Calling cleanup at time = base_time + 1.0
        self.detector.cleanup_expired_state(base_time + 1.0)
        self.assertIn("1.2.3.4", self.detector.trackers)

        # Calling cleanup after expiration + cooldown
        self.detector.cleanup_expired_state(base_time + 10.0)
        self.assertNotIn("1.2.3.4", self.detector.trackers)


if __name__ == "__main__":
    unittest.main()
