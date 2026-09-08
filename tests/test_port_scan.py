"""
Unit tests for PortScanDetector (Phase 6).
"""

import unittest
import time

from ids.parser.packet_parser import ParsedPacket, IPHeader, TCPHeader, UDPHeader
from ids.models.events import Severity
from ids.detectors.port_scan import PortScanDetector


def make_tcp_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.50",
    src_port: int = 45678,
    dst_port: int = 80,
    is_syn: bool = True,
    is_ack: bool = False,
    timestamp: float = 1000.0,
) -> ParsedPacket:
    """Helper to synthesize a ParsedPacket with TCP header."""
    return ParsedPacket(
        timestamp=timestamp,
        raw_length=60,
        summary=f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} TCP",
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
            flags="S" if is_syn and not is_ack else ("SA" if is_syn and is_ack else "A"),
            seq=100,
            ack=0,
            is_syn=is_syn,
            is_ack=is_ack,
            is_fin=False,
            is_rst=False,
            is_psh=False,
            is_urg=False,
        ),
    )


class TestPortScanDetector(unittest.TestCase):

    def setUp(self):
        self.detector = PortScanDetector(
            config={
                "enabled": True,
                "unique_ports": 5,        # Lowered to 5 for faster test cycles
                "window_seconds": 3.0,
                "alert_cooldown": 5.0,
            }
        )

    def test_normal_traffic_no_alert(self):
        """Repeated packets to the same port or below threshold should not alert."""
        # 4 distinct ports, threshold is 5
        base_time = 1000.0
        ports = [80, 443, 8080, 22]
        for idx, port in enumerate(ports):
            pkt = make_tcp_packet(dst_port=port, timestamp=base_time + idx * 0.1)
            alert = self.detector.process(pkt)
            self.assertIsNone(alert)

    def test_port_scan_triggers_alert(self):
        """Crossing the unique_ports threshold within the window must trigger an alert."""
        base_time = 1000.0
        # Send 5 probes to 5 distinct ports
        ports = [21, 22, 23, 25, 80]
        alert = None
        for idx, port in enumerate(ports):
            pkt = make_tcp_packet(
                src_ip="10.0.0.99",
                dst_ip="10.0.0.1",
                dst_port=port,
                timestamp=base_time + idx * 0.2,
            )
            alert = self.detector.process(pkt)

        # The 5th packet should have triggered an alert
        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_type, "TCP_PORT_SCAN")
        self.assertEqual(alert.severity, Severity.MEDIUM)
        self.assertEqual(alert.source_ip, "10.0.0.99")
        self.assertEqual(alert.destination_ip, "10.0.0.1")
        self.assertEqual(alert.evidence["port_count"], 5)
        self.assertListEqual(alert.evidence["probed_ports"], [21, 22, 23, 25, 80])

    def test_sliding_window_expiration(self):
        """Probes spread out beyond window_seconds should not accumulate to threshold."""
        base_time = 1000.0
        # Send 4 probes spread within window
        for idx, port in enumerate([21, 22, 23, 25]):
            pkt = make_tcp_packet(dst_port=port, timestamp=base_time + idx * 0.2)
            self.assertIsNone(self.detector.process(pkt))

        # Now advance time past window_seconds (window is 3.0s, advance to +4.0s)
        # Port 80 arrives at 1004.0s; ports 21, 22, 23, 25 arrived between 1000.0 and 1000.6, so they have expired.
        pkt = make_tcp_packet(dst_port=80, timestamp=base_time + 4.0)
        alert = self.detector.process(pkt)
        self.assertIsNone(alert)

    def test_alert_cooldown(self):
        """Subsequent packets after an alert must be suppressed until cooldown expires."""
        base_time = 1000.0
        # Trigger first alert with 5 ports
        for idx, port in enumerate([10, 20, 30, 40, 50]):
            pkt = make_tcp_packet(dst_port=port, timestamp=base_time + idx * 0.1)
            last_alert = self.detector.process(pkt)

        self.assertIsNotNone(last_alert)

        # Send a 6th probe at base_time + 1.0s (within alert_cooldown=5.0s)
        pkt6 = make_tcp_packet(dst_port=60, timestamp=base_time + 1.0)
        suppressed_alert = self.detector.process(pkt6)
        self.assertIsNone(suppressed_alert)

        # After cooldown (e.g. at base_time + 6.0s), sending new probes should be eligible to alert
        for idx, port in enumerate([100, 200, 300, 400, 500]):
            pkt = make_tcp_packet(dst_port=port, timestamp=base_time + 6.0 + idx * 0.1)
            new_alert = self.detector.process(pkt)

        self.assertIsNotNone(new_alert)
        self.assertEqual(new_alert.event_type, "TCP_PORT_SCAN")

    def test_ignore_non_syn_and_non_tcp(self):
        """Only TCP SYN packets without ACK should be tracked as scan probes."""
        base_time = 1000.0
        # TCP SYN-ACK should be ignored
        for p in range(1, 10):
            pkt = make_tcp_packet(dst_port=p, is_syn=True, is_ack=True, timestamp=base_time + p * 0.1)
            self.assertIsNone(self.detector.process(pkt))

        # TCP ACK (data) should be ignored
        for p in range(1, 10):
            pkt = make_tcp_packet(dst_port=p, is_syn=False, is_ack=True, timestamp=base_time + p * 0.1)
            self.assertIsNone(self.detector.process(pkt))

        # UDP packets should be ignored
        udp_pkt = ParsedPacket(
            timestamp=base_time,
            raw_length=50,
            summary="UDP test",
            ip=IPHeader(src_ip="1.2.3.4", dst_ip="5.6.7.8", protocol=17, proto_name="UDP", ttl=64, length=50),
            udp=UDPHeader(src_port=1234, dst_port=53, length=30),
        )
        self.assertIsNone(self.detector.process(udp_pkt))

    def test_cleanup_expired_state(self):
        """Pruning should remove stale source IPs from memory."""
        base_time = 1000.0
        # Add probe from IP 1.2.3.4
        pkt = make_tcp_packet(src_ip="1.2.3.4", dst_port=80, timestamp=base_time)
        self.detector.process(pkt)
        self.assertIn("1.2.3.4", self.detector.trackers)

        # Calling cleanup at time = base_time + 1.0 (tracker still has active entry)
        self.detector.cleanup_expired_state(base_time + 1.0)
        self.assertIn("1.2.3.4", self.detector.trackers)

        # Calling cleanup at time = base_time + 10.0 (tracker entry expired, cooldown elapsed)
        self.detector.cleanup_expired_state(base_time + 10.0)
        self.assertNotIn("1.2.3.4", self.detector.trackers)


if __name__ == "__main__":
    unittest.main()
