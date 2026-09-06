"""
Unit tests for ids.parser.packet_parser.
Tests normalized feature extraction for IPv4, IPv6, TCP, UDP, ICMP, ARP, and DNS.
"""

import unittest
from scapy.all import (
    Ether,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    Raw,
)

from ids.parser import (
    PacketParser,
    ParsedPacket,
    IPHeader,
    TCPHeader,
    UDPHeader,
    ICMPHeader,
    ARPHeader,
    DNSHeader,
)


class TestPacketParser(unittest.TestCase):

    def test_parse_none(self):
        """Passing None should safely return None without throwing."""
        self.assertIsNone(PacketParser.parse(None))

    def test_parse_tcp_syn(self):
        """Verify IPv4 and TCP SYN flag decoding."""
        pkt = Ether() / IP(src="192.168.1.10", dst="192.168.1.50", ttl=64) / TCP(
            sport=54321, dport=80, flags="S", seq=1000, ack=0
        )
        parsed = PacketParser.parse(pkt)
        self.assertIsNotNone(parsed)
        self.assertIsInstance(parsed, ParsedPacket)

        # IP Layer
        self.assertIsNotNone(parsed.ip)
        self.assertEqual(parsed.ip.src_ip, "192.168.1.10")
        self.assertEqual(parsed.ip.dst_ip, "192.168.1.50")
        self.assertEqual(parsed.ip.protocol, 6)
        self.assertEqual(parsed.ip.proto_name, "TCP")
        self.assertEqual(parsed.ip.ttl, 64)
        self.assertEqual(parsed.ip.version, 4)

        # TCP Layer
        self.assertIsNotNone(parsed.tcp)
        self.assertEqual(parsed.tcp.src_port, 54321)
        self.assertEqual(parsed.tcp.dst_port, 80)
        self.assertEqual(parsed.tcp.seq, 1000)
        self.assertEqual(parsed.tcp.ack, 0)
        self.assertTrue(parsed.tcp.is_syn)
        self.assertFalse(parsed.tcp.is_ack)
        self.assertFalse(parsed.tcp.is_rst)
        self.assertFalse(parsed.tcp.is_fin)

    def test_parse_tcp_syn_ack(self):
        """Verify TCP SYN-ACK flags decoding."""
        pkt = Ether() / IP(src="192.168.1.50", dst="192.168.1.10") / TCP(
            sport=80, dport=54321, flags="SA", seq=5000, ack=1001
        )
        parsed = PacketParser.parse(pkt)
        self.assertTrue(parsed.tcp.is_syn)
        self.assertTrue(parsed.tcp.is_ack)
        self.assertFalse(parsed.tcp.is_fin)

    def test_parse_udp(self):
        """Verify UDP layer extraction."""
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2", ttl=128) / UDP(sport=5353, dport=53)
        parsed = PacketParser.parse(pkt)
        self.assertIsNotNone(parsed.ip)
        self.assertEqual(parsed.ip.proto_name, "UDP")
        self.assertIsNotNone(parsed.udp)
        self.assertEqual(parsed.udp.src_port, 5353)
        self.assertEqual(parsed.udp.dst_port, 53)
        self.assertIsNone(parsed.tcp)

    def test_parse_icmp(self):
        """Verify ICMP Echo Request and Echo Reply."""
        req = Ether() / IP(src="192.168.1.20", dst="192.168.1.1") / ICMP(type=8, code=0)
        parsed_req = PacketParser.parse(req)
        self.assertIsNotNone(parsed_req.icmp)
        self.assertEqual(parsed_req.icmp.type, 8)
        self.assertEqual(parsed_req.icmp.code, 0)
        self.assertTrue(parsed_req.icmp.is_echo_request)
        self.assertFalse(parsed_req.icmp.is_echo_reply)

        rep = Ether() / IP(src="192.168.1.1", dst="192.168.1.20") / ICMP(type=0, code=0)
        parsed_rep = PacketParser.parse(rep)
        self.assertTrue(parsed_rep.icmp.is_echo_reply)
        self.assertFalse(parsed_rep.icmp.is_echo_request)

    def test_parse_arp(self):
        """Verify ARP request and response parsing."""
        who_has = Ether(src="aa:aa:aa:aa:aa:aa") / ARP(
            op=1,
            hwsrc="aa:aa:aa:aa:aa:aa",
            psrc="192.168.1.20",
            hwdst="00:00:00:00:00:00",
            pdst="192.168.1.1",
        )
        parsed_arp = PacketParser.parse(who_has)
        self.assertIsNotNone(parsed_arp.arp)
        self.assertEqual(parsed_arp.arp.src_ip, "192.168.1.20")
        self.assertEqual(parsed_arp.arp.src_mac, "aa:aa:aa:aa:aa:aa")
        self.assertEqual(parsed_arp.arp.operation, "who-has")
        self.assertEqual(parsed_arp.arp.op_code, 1)

        is_at = Ether(src="bb:bb:bb:bb:bb:bb") / ARP(
            op=2,
            hwsrc="bb:bb:bb:bb:bb:bb",
            psrc="192.168.1.1",
            hwdst="aa:aa:aa:aa:aa:aa",
            pdst="192.168.1.20",
        )
        parsed_reply = PacketParser.parse(is_at)
        self.assertEqual(parsed_reply.arp.operation, "is-at")
        self.assertEqual(parsed_reply.arp.op_code, 2)

    def test_parse_dns_query(self):
        """Verify DNS query parsing over UDP."""
        pkt = (
            Ether()
            / IP(src="192.168.1.20", dst="8.8.8.8")
            / UDP(sport=43210, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="malicious-domain.com", qtype="A"))
        )
        parsed = PacketParser.parse(pkt)
        self.assertIsNotNone(parsed.dns)
        self.assertEqual(parsed.dns.query_name, "malicious-domain.com")
        self.assertEqual(parsed.dns.query_type, "A")
        self.assertFalse(parsed.dns.is_response)
        self.assertEqual(parsed.dns.source_ip, "192.168.1.20")
        self.assertEqual(parsed.dns.destination_ip, "8.8.8.8")

    def test_parse_ipv6(self):
        """Verify IPv6 packet layer extraction."""
        pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=9999, dport=443, flags="S")
        parsed = PacketParser.parse(pkt)
        self.assertIsNotNone(parsed.ip)
        self.assertEqual(parsed.ip.version, 6)
        self.assertEqual(parsed.ip.src_ip, "2001:db8::1")
        self.assertEqual(parsed.ip.dst_ip, "2001:db8::2")
        self.assertEqual(parsed.ip.proto_name, "TCP")
        self.assertIsNotNone(parsed.tcp)
        self.assertEqual(parsed.tcp.dst_port, 443)


if __name__ == "__main__":
    unittest.main()
