"""
Unit tests for PacketCaptureEngine and packet summary formatting.
Uses synthetic in-memory packets and temporary PCAPs.
"""

import os
import tempfile
import unittest

from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, wrpcap

from ids.capture.packet_capture import (
    PacketCaptureEngine,
    format_packet_summary,
)


class TestPacketCaptureEngine(unittest.TestCase):

    def test_format_packet_summary_tcp(self):
        """Test formatting of an IPv4 TCP SYN packet."""
        pkt = Ether() / IP(src="192.168.1.10", dst="192.168.1.50", ttl=64) / TCP(sport=44444, dport=80, flags="S")
        summary = format_packet_summary(pkt)
        self.assertIn("192.168.1.10:44444", summary)
        self.assertIn("192.168.1.50:80", summary)
        self.assertIn("TCP", summary)
        self.assertIn("S", summary)

    def test_format_packet_summary_udp(self):
        """Test formatting of an IPv4 UDP packet."""
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5353, dport=53)
        summary = format_packet_summary(pkt)
        self.assertIn("10.0.0.1:5353", summary)
        self.assertIn("10.0.0.2:53", summary)
        self.assertIn("UDP", summary)

    def test_format_packet_summary_icmp(self):
        """Test formatting of an ICMP echo request packet."""
        pkt = Ether() / IP(src="192.168.1.20", dst="192.168.1.1") / ICMP(type=8, code=0)
        summary = format_packet_summary(pkt)
        self.assertIn("192.168.1.20", summary)
        self.assertIn("192.168.1.1", summary)
        self.assertIn("ICMP type=8 code=0", summary)

    def test_format_packet_summary_arp(self):
        """Test formatting of an ARP request packet."""
        pkt = Ether(src="aa:bb:cc:dd:ee:ff") / ARP(
            op=1,
            hwsrc="aa:bb:cc:dd:ee:ff",
            psrc="192.168.1.100",
            hwdst="00:00:00:00:00:00",
            pdst="192.168.1.1",
        )
        summary = format_packet_summary(pkt)
        self.assertIn("ARP", summary)
        self.assertIn("192.168.1.100", summary)
        self.assertIn("192.168.1.1", summary)

    def test_list_interfaces_non_empty(self):
        """Ensure interface enumeration returns a list of interface dictionaries."""
        ifaces = PacketCaptureEngine.list_interfaces()
        self.assertIsInstance(ifaces, list)
        for iface in ifaces:
            self.assertIn("name", iface)
            self.assertIn("ip", iface)

    def test_pcap_replay_capture(self):
        """Test engine capture using a generated synthetic PCAP file."""
        packets = [
            Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1000, dport=80),
            Ether() / IP(src="192.168.1.3", dst="192.168.1.4") / UDP(sport=2000, dport=53),
            Ether() / IP(src="192.168.1.5", dst="192.168.1.6") / ICMP(),
        ]

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            temp_pcap = tf.name

        try:
            wrpcap(temp_pcap, packets)

            received = []
            engine = PacketCaptureEngine()
            count = engine.capture(
                packet_callback=lambda p: received.append(p),
                pcap_file=temp_pcap,
            )

            self.assertEqual(count, 3)
            self.assertEqual(len(received), 3)
            self.assertEqual(received[0][IP].src, "192.168.1.1")
            self.assertEqual(received[1][IP].src, "192.168.1.3")
            self.assertEqual(received[2][IP].src, "192.168.1.5")
        finally:
            if os.path.exists(temp_pcap):
                os.remove(temp_pcap)


if __name__ == "__main__":
    unittest.main()
