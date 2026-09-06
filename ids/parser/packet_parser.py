"""
Normalized Packet Parser for Python Network IDS (Phase 3).

Transforms raw Scapy packets into clean, immutable, normalized dataclasses.
Safely handles missing layers, non-IP frames, malformed headers, and edge cases.
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Optional, Any

try:
    from scapy.all import (
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        ARP,
        DNS,
        DNSQR,
        DNSRR,
    )
except ImportError:
    IP = IPv6 = TCP = UDP = ICMP = ARP = DNS = DNSQR = DNSRR = None

logger = logging.getLogger("ids.parser")

PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    58: "ICMPv6",
}

DNS_QTYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    255: "ANY",
}


@dataclass(frozen=True)
class IPHeader:
    src_ip: str
    dst_ip: str
    protocol: int
    proto_name: str
    ttl: int
    length: int
    version: int = 4


@dataclass(frozen=True)
class TCPHeader:
    src_port: int
    dst_port: int
    flags: str
    seq: int
    ack: int
    is_syn: bool
    is_ack: bool
    is_fin: bool
    is_rst: bool
    is_psh: bool
    is_urg: bool


@dataclass(frozen=True)
class UDPHeader:
    src_port: int
    dst_port: int
    length: int


@dataclass(frozen=True)
class ICMPHeader:
    type: int
    code: int
    is_echo_request: bool
    is_echo_reply: bool


@dataclass(frozen=True)
class ARPHeader:
    src_ip: str
    src_mac: str
    dst_ip: str
    dst_mac: str
    operation: str
    op_code: int


@dataclass(frozen=True)
class DNSHeader:
    query_name: Optional[str]
    query_type: Optional[str]
    is_response: bool
    rcode: int
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None


@dataclass
class ParsedPacket:
    timestamp: float
    raw_length: int
    summary: str
    ip: Optional[IPHeader] = None
    tcp: Optional[TCPHeader] = None
    udp: Optional[UDPHeader] = None
    icmp: Optional[ICMPHeader] = None
    arp: Optional[ARPHeader] = None
    dns: Optional[DNSHeader] = None
    raw_packet: Any = field(default=None, repr=False)


class PacketParser:
    """
    Extracts normalized network structures from captured packets.
    Guarantees no unhandled exceptions on malformed or incomplete frames.
    """

    @classmethod
    def parse(cls, packet: Any) -> Optional[ParsedPacket]:
        """
        Parse a raw packet into a normalized ParsedPacket instance.
        Returns None if packet is None or completely unparsable.
        """
        if packet is None:
            return None

        try:
            timestamp = float(getattr(packet, "time", time.time()))
            raw_length = len(packet)
            summary = packet.summary() if hasattr(packet, "summary") else repr(packet)

            parsed = ParsedPacket(
                timestamp=timestamp,
                raw_length=raw_length,
                summary=summary,
                raw_packet=packet,
            )

            # 1. ARP Layer
            if ARP and packet.haslayer(ARP):
                parsed.arp = cls._parse_arp(packet[ARP])

            # 2. IPv4 / IPv6 Layer
            if IP and packet.haslayer(IP):
                parsed.ip = cls._parse_ipv4(packet[IP], raw_length)
            elif IPv6 and packet.haslayer(IPv6):
                parsed.ip = cls._parse_ipv6(packet[IPv6], raw_length)

            # 3. Transport Layer: TCP
            if TCP and packet.haslayer(TCP):
                parsed.tcp = cls._parse_tcp(packet[TCP])

            # 4. Transport Layer: UDP
            if UDP and packet.haslayer(UDP):
                parsed.udp = cls._parse_udp(packet[UDP])

            # 5. ICMP Layer
            if ICMP and packet.haslayer(ICMP):
                parsed.icmp = cls._parse_icmp(packet[ICMP])

            # 6. Application Layer: DNS
            if DNS and packet.haslayer(DNS):
                src_ip = parsed.ip.src_ip if parsed.ip else None
                dst_ip = parsed.ip.dst_ip if parsed.ip else None
                parsed.dns = cls._parse_dns(packet[DNS], src_ip, dst_ip)

            return parsed

        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None

    @staticmethod
    def _parse_ipv4(ip: Any, raw_length: int) -> IPHeader:
        proto_num = int(getattr(ip, "proto", 0) or 0)
        proto_name = PROTO_MAP.get(proto_num, f"PROTO_{proto_num}")
        raw_ip_len = getattr(ip, "len", None)
        pkt_len = int(raw_ip_len) if raw_ip_len is not None else raw_length
        ttl_val = getattr(ip, "ttl", 64)
        ttl = int(ttl_val) if ttl_val is not None else 64
        return IPHeader(
            src_ip=str(getattr(ip, "src", "0.0.0.0")),
            dst_ip=str(getattr(ip, "dst", "0.0.0.0")),
            protocol=proto_num,
            proto_name=proto_name,
            ttl=ttl,
            length=pkt_len,
            version=4,
        )

    @staticmethod
    def _parse_ipv6(ip6: Any, raw_length: int) -> IPHeader:
        nh = int(getattr(ip6, "nh", 0) or 0)
        proto_name = PROTO_MAP.get(nh, f"PROTO_{nh}")
        raw_plen = getattr(ip6, "plen", None)
        plen = int(raw_plen) if raw_plen is not None else raw_length
        hlim_val = getattr(ip6, "hlim", 64)
        hlim = int(hlim_val) if hlim_val is not None else 64
        return IPHeader(
            src_ip=str(getattr(ip6, "src", "::")),
            dst_ip=str(getattr(ip6, "dst", "::")),
            protocol=nh,
            proto_name=proto_name,
            ttl=hlim,
            length=plen,
            version=6,
        )

    @staticmethod
    def _parse_tcp(tcp: Any) -> TCPHeader:
        flags_val = getattr(tcp, "flags", "")
        flags_str = str(flags_val)
        try:
            flag_int = int(flags_val) if hasattr(flags_val, "__int__") else 0
        except Exception:
            flag_int = 0

        # Flag masks: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
        is_fin = bool("F" in flags_str or flag_int & 0x01)
        is_syn = bool("S" in flags_str or flag_int & 0x02)
        is_rst = bool("R" in flags_str or flag_int & 0x04)
        is_psh = bool("P" in flags_str or flag_int & 0x08)
        is_ack = bool("A" in flags_str or flag_int & 0x10)
        is_urg = bool("U" in flags_str or flag_int & 0x20)

        seq_val = getattr(tcp, "seq", 0)
        ack_val = getattr(tcp, "ack", 0)

        return TCPHeader(
            src_port=int(getattr(tcp, "sport", 0) or 0),
            dst_port=int(getattr(tcp, "dport", 0) or 0),
            flags=flags_str,
            seq=int(seq_val) if seq_val is not None else 0,
            ack=int(ack_val) if ack_val is not None else 0,
            is_syn=is_syn,
            is_ack=is_ack,
            is_fin=is_fin,
            is_rst=is_rst,
            is_psh=is_psh,
            is_urg=is_urg,
        )

    @staticmethod
    def _parse_udp(udp: Any) -> UDPHeader:
        raw_len = getattr(udp, "len", None)
        udp_len = int(raw_len) if raw_len is not None else 8
        return UDPHeader(
            src_port=int(getattr(udp, "sport", 0) or 0),
            dst_port=int(getattr(udp, "dport", 0) or 0),
            length=udp_len,
        )

    @staticmethod
    def _parse_icmp(icmp: Any) -> ICMPHeader:
        icmp_type = int(getattr(icmp, "type", 0) or 0)
        icmp_code = int(getattr(icmp, "code", 0) or 0)
        is_echo_req = bool(icmp_type == 8 and icmp_code == 0)
        is_echo_rep = bool(icmp_type == 0 and icmp_code == 0)
        return ICMPHeader(
            type=icmp_type,
            code=icmp_code,
            is_echo_request=is_echo_req,
            is_echo_reply=is_echo_rep,
        )

    @staticmethod
    def _parse_arp(arp: Any) -> ARPHeader:
        op_code = int(arp.op)
        op_name = "who-has" if op_code == 1 else ("is-at" if op_code == 2 else f"op_{op_code}")
        return ARPHeader(
            src_ip=str(arp.psrc),
            src_mac=str(arp.hwsrc),
            dst_ip=str(arp.pdst),
            dst_mac=str(arp.hwdst),
            operation=op_name,
            op_code=op_code,
        )

    @staticmethod
    def _parse_dns(
        dns: Any,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
    ) -> DNSHeader:
        is_response = bool(getattr(dns, "qr", 0) == 1)
        rcode = int(getattr(dns, "rcode", 0))

        qname = None
        qtype_str = None

        qd = getattr(dns, "qd", None)
        if qd is not None:
            try:
                # Scapy 2.5+ uses PacketListField for qd
                record = qd[0] if (hasattr(qd, "__getitem__") and not hasattr(qd, "qname")) else qd
                raw_qname = getattr(record, "qname", b"")
                if isinstance(raw_qname, bytes):
                    qname = raw_qname.decode("utf-8", errors="replace").rstrip(".")
                else:
                    qname = str(raw_qname).rstrip(".")
                qtype_num = int(getattr(record, "qtype", 1) or 1)
                qtype_str = DNS_QTYPE_MAP.get(qtype_num, f"TYPE_{qtype_num}")
            except Exception:
                pass

        return DNSHeader(
            query_name=qname,
            query_type=qtype_str,
            is_response=is_response,
            rcode=rcode,
            source_ip=source_ip,
            destination_ip=destination_ip,
        )
