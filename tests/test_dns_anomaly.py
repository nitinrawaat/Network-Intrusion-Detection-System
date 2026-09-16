"""
Unit tests for DnsAnomalyDetector (Phase 10).
"""

import unittest
import time

from ids.parser.packet_parser import ParsedPacket, IPHeader, UDPHeader, DNSHeader
from ids.models.events import Severity
from ids.detectors.dns_anomaly import DnsAnomalyDetector
from ids.detectors.detection_engine import DetectionEngine


def make_dns_packet(
    query_name: str = "example.com",
    query_type: str = "A",
    is_response: bool = False,
    rcode: int = 0,
    client_ip: str = "192.168.1.100",
    server_ip: str = "8.8.8.8",
    timestamp: float = 1000.0,
) -> ParsedPacket:
    """Helper to synthesize a ParsedPacket with DNSHeader."""
    if not is_response:
        src_ip = client_ip
        dst_ip = server_ip
        sport = 54321
        dport = 53
    else:
        src_ip = server_ip
        dst_ip = client_ip
        sport = 53
        dport = 54321

    return ParsedPacket(
        timestamp=timestamp,
        raw_length=70,
        summary=f"DNS {'Resp' if is_response else 'Query'} {query_name} ({src_ip} -> {dst_ip})",
        ip=IPHeader(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=17,
            proto_name="UDP",
            ttl=64,
            length=70,
        ),
        udp=UDPHeader(
            src_port=sport,
            dst_port=dport,
            length=50,
        ),
        dns=DNSHeader(
            query_name=query_name,
            query_type=query_type,
            is_response=is_response,
            rcode=rcode,
            source_ip=src_ip,
            destination_ip=dst_ip,
        ),
    )


class TestDnsAnomalyDetector(unittest.TestCase):

    def setUp(self):
        self.detector = DnsAnomalyDetector(
            config={
                "enabled": True,
                "query_threshold": 10,       # Low for fast unit tests
                "window_seconds": 5.0,
                "max_label_length": 30,      # Low for testing
                "max_domain_length": 60,     # Low for testing
                "nxdomain_threshold": 5,     # Low for testing
                "alert_cooldown": 5.0,
            }
        )

    def test_normal_dns_query_no_alert(self):
        """Legitimate short query below flood threshold should not alert."""
        pkt = make_dns_packet(query_name="google.com")
        alert = self.detector.process(pkt)
        self.assertIsNone(alert)

    def test_normal_dns_response_no_alert(self):
        """Standard NOERROR response should not alert."""
        pkt = make_dns_packet(query_name="google.com", is_response=True, rcode=0)
        alert = self.detector.process(pkt)
        self.assertIsNone(alert)

    def test_dns_tunneling_long_label(self):
        """Subdomain label exceeding max_label_length triggers DNS_TUNNELING alert."""
        # 35-character label exceeds threshold of 30
        long_label = "a" * 35
        qname = f"{long_label}.attacker.com"
        pkt = make_dns_packet(query_name=qname, client_ip="192.168.1.150")
        alert = self.detector.process(pkt)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_type, "DNS_TUNNELING")
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertEqual(alert.source_ip, "192.168.1.150")
        self.assertGreaterEqual(alert.evidence["max_label_length"], 30)

    def test_dns_tunneling_long_domain(self):
        """Overall domain name exceeding max_domain_length triggers DNS_TUNNELING alert."""
        # 4 labels of 20 chars each = 80+ chars > 60 chars max_domain_length
        qname = "sub1111111111111111.sub2222222222222222.sub3333333333333333.example.com"
        pkt = make_dns_packet(query_name=qname)
        alert = self.detector.process(pkt)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.event_type, "DNS_TUNNELING")
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertGreaterEqual(alert.evidence["total_length"], 60)

    def test_dns_query_flood(self):
        """Bursts of outbound DNS queries exceeding threshold triggers DNS_QUERY_FLOOD."""
        base_time = 1000.0
        alerts = []

        # Send 10 queries, threshold is 10
        for i in range(10):
            pkt = make_dns_packet(
                query_name=f"host{i}.example.com",
                client_ip="192.168.1.75",
                timestamp=base_time + i * 0.1,
            )
            event = self.detector.process(pkt)
            if event:
                alerts.append(event)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_type, "DNS_QUERY_FLOOD")
        self.assertEqual(alerts[0].severity, Severity.MEDIUM)
        self.assertEqual(alerts[0].source_ip, "192.168.1.75")
        self.assertEqual(alerts[0].evidence["query_count"], 10)

    def test_nxdomain_burst(self):
        """Bursts of NXDOMAIN responses (rcode=3) trigger DNS_NXDOMAIN_BURST."""
        base_time = 1000.0
        alerts = []

        # 5 NXDOMAIN responses, threshold is 5
        for i in range(5):
            pkt = make_dns_packet(
                query_name=f"random-nonexistent-{i}.org",
                is_response=True,
                rcode=3,
                client_ip="192.168.1.80",
                timestamp=base_time + i * 0.1,
            )
            event = self.detector.process(pkt)
            if event:
                alerts.append(event)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_type, "DNS_NXDOMAIN_BURST")
        self.assertEqual(alerts[0].severity, Severity.MEDIUM)
        self.assertEqual(alerts[0].source_ip, "192.168.1.80")
        self.assertEqual(alerts[0].evidence["nxdomain_count"], 5)

    def test_alert_cooldown(self):
        """Repeated events of the same anomaly type within cooldown generate only 1 alert."""
        base_time = 1000.0
        alerts = []

        for i in range(25):
            pkt = make_dns_packet(
                query_name=f"bulk{i}.example.com",
                client_ip="192.168.1.75",
                timestamp=base_time + i * 0.05,
            )
            event = self.detector.process(pkt)
            if event:
                alerts.append(event)

        # Only one alert should fire during cooldown
        self.assertEqual(len(alerts), 1)

    def test_detector_disabled(self):
        """Disabled detector should not process or alert."""
        disabled = DnsAnomalyDetector(config={"enabled": False, "max_label_length": 10})
        pkt = make_dns_packet(query_name="a" * 20 + ".com")
        self.assertIsNone(disabled.process(pkt))
        self.assertEqual(len(disabled.query_trackers), 0)

    def test_cleanup_expired_state(self):
        """Expired client query trackers are cleaned up."""
        base_time = 1000.0
        pkt = make_dns_packet(client_ip="192.168.1.99", timestamp=base_time)
        self.detector.process(pkt)
        self.assertIn("192.168.1.99", self.detector.query_trackers)

        # Jump forward past window + cooldown
        self.detector.cleanup_expired_state(current_time=base_time + 30.0)
        self.assertNotIn("192.168.1.99", self.detector.query_trackers)

    def test_reset_state(self):
        """reset_state clears all internal tracking state."""
        pkt = make_dns_packet(client_ip="192.168.1.99")
        self.detector.process(pkt)
        self.assertGreater(len(self.detector.query_trackers), 0)

        self.detector.reset_state()
        self.assertEqual(len(self.detector.query_trackers), 0)
        self.assertEqual(len(self.detector.nxdomain_trackers), 0)
        self.assertEqual(len(self.detector.last_alert_time), 0)

    def test_engine_integration(self):
        """DetectionEngine registers and triggers DnsAnomalyDetector."""
        engine = DetectionEngine()
        detector = DnsAnomalyDetector(
            config={"enabled": True, "max_label_length": 20}
        )
        engine.register_detector(detector)

        long_qname = "a" * 25 + ".tunneling.net"
        pkt = make_dns_packet(query_name=long_qname)
        alerts = engine.process_packet(pkt)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_type, "DNS_TUNNELING")


if __name__ == "__main__":
    unittest.main()
