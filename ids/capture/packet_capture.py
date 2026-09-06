"""
Packet Capture Engine for Python Network IDS.

Responsible for:
- Enumerating network interfaces.
- Interfacing with Scapy's sniff() engine for live and PCAP packet streams.
- Providing normalized basic packet summaries for Phase 2.
- Handling graceful capture termination.
"""

import sys
import logging
from typing import Callable, Optional, List, Dict, Any

try:
    from scapy.all import (
        sniff,
        conf,
        get_if_list,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        ARP,
        Packet,
    )
except ImportError:
    # Scapy may not yet be installed in the current environment
    sniff = None
    conf = None
    get_if_list = None
    IP = IPv6 = TCP = UDP = ICMP = ARP = Packet = None

logger = logging.getLogger("ids.capture")


def check_scapy_available() -> None:
    """Ensure Scapy is imported or raise an informative runtime error."""
    if sniff is None:
        raise ImportError(
            "Scapy is not installed or failed to import. "
            "Please activate your virtual environment and run: pip install -r requirements.txt"
        )


def format_packet_summary(packet: Any) -> str:
    """
    Format a captured packet into a readable, concise summary line.
    Safely handles packets with or without IP/TCP/UDP/ICMP/ARP layers.
    """
    if packet is None:
        return "[Empty packet]"

    # ARP handling
    if ARP and packet.haslayer(ARP):
        arp = packet[ARP]
        op_name = "Who-has" if arp.op == 1 else ("Is-at" if arp.op == 2 else f"Op:{arp.op}")
        return f"[ARP {op_name}] {arp.psrc} ({arp.hwsrc}) -> {arp.pdst} ({arp.hwdst})"

    # IPv4 handling
    if IP and packet.haslayer(IP):
        ip = packet[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
        length = ip.len if hasattr(ip, "len") else len(packet)

        if TCP and packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = str(tcp.flags)
            return f"{src}:{tcp.sport} -> {dst}:{tcp.dport} TCP [{flags}] (len={length}, ttl={ip.ttl})"

        if UDP and packet.haslayer(UDP):
            udp = packet[UDP]
            return f"{src}:{udp.sport} -> {dst}:{udp.dport} UDP (len={length}, ttl={ip.ttl})"

        if ICMP and packet.haslayer(ICMP):
            icmp = packet[ICMP]
            return f"{src} -> {dst} ICMP type={icmp.type} code={icmp.code} (ttl={ip.ttl})"

        return f"{src} -> {dst} IP (proto={proto}, len={length})"

    # IPv6 handling
    if IPv6 and packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        src = ip6.src
        dst = ip6.dst
        if TCP and packet.haslayer(TCP):
            tcp = packet[TCP]
            return f"[{src}]:{tcp.sport} -> [{dst}]:{tcp.dport} TCP [{tcp.flags}]"
        if UDP and packet.haslayer(UDP):
            udp = packet[UDP]
            return f"[{src}]:{udp.sport} -> [{dst}]:{udp.dport} UDP"
        return f"[{src}] -> [{dst}] IPv6"

    # Fallback to Scapy's built-in summary or class name
    if hasattr(packet, "summary"):
        return packet.summary()
    return repr(packet)


class PacketCaptureEngine:
    """
    Manages live packet sniffing and PCAP replay with statistics and callbacks.
    """

    def __init__(self, interface: Optional[str] = None):
        check_scapy_available()
        self.interface = interface
        self.packet_count = 0
        self._stop_requested = False

    @staticmethod
    def list_interfaces() -> List[Dict[str, str]]:
        """
        List all available network interfaces detected by the OS and Scapy.
        """
        check_scapy_available()
        results = []
        try:
            # Check scapy conf.ifaces
            if hasattr(conf, "ifaces"):
                for name, iface in conf.ifaces.items():
                    ip = getattr(iface, "ip", "N/A")
                    mac = getattr(iface, "mac", "N/A")
                    desc = getattr(iface, "description", name)
                    results.append({
                        "name": str(name),
                        "description": str(desc),
                        "ip": str(ip) if ip else "N/A",
                        "mac": str(mac) if mac else "N/A"
                    })
            if not results and get_if_list:
                for name in get_if_list():
                    results.append({
                        "name": str(name),
                        "description": str(name),
                        "ip": "N/A",
                        "mac": "N/A"
                    })
        except Exception as e:
            logger.warning(f"Error enumerating interfaces: {e}")
            if get_if_list:
                for name in get_if_list():
                    results.append({"name": str(name), "description": str(name), "ip": "N/A", "mac": "N/A"})
        return results

    def stop(self) -> None:
        """Signal the capture engine to gracefully stop."""
        self._stop_requested = True

    def _should_stop(self, packet: Any) -> bool:
        """Internal predicate callback evaluated by scapy for each packet."""
        return self._stop_requested

    def capture(
        self,
        packet_callback: Optional[Callable[[Any], None]] = None,
        count: int = 0,
        bpf_filter: Optional[str] = None,
        pcap_file: Optional[str] = None,
        store: bool = False,
    ) -> int:
        """
        Start capturing packets.
        
        Args:
            packet_callback: Function called for each received packet.
            count: Number of packets to capture (0 = infinite).
            bpf_filter: Optional BPF filter string (e.g. 'tcp or udp').
            pcap_file: Optional path to a PCAP file for offline playback.
            store: Whether to keep packets in memory (False to avoid memory leaks).

        Returns:
            Total number of packets processed during this session.
        """
        check_scapy_available()
        self._stop_requested = False
        self.packet_count = 0

        def internal_handler(pkt: Any):
            self.packet_count += 1
            if packet_callback:
                packet_callback(pkt)

        kwargs: Dict[str, Any] = {
            "prn": internal_handler,
            "count": count,
            "store": store,
            "stop_filter": self._should_stop,
        }

        if bpf_filter:
            kwargs["filter"] = bpf_filter

        if pcap_file:
            kwargs["offline"] = pcap_file
        elif self.interface:
            kwargs["iface"] = self.interface

        try:
            sniff(**kwargs)
        except PermissionError:
            raise PermissionError(
                "Permission denied starting packet capture. "
                "Capturing raw network packets requires administrator privileges (sudo on Linux, Admin on Windows)."
            )
        except OSError as e:
            raise OSError(f"Failed to capture on interface '{self.interface}': {e}")

        return self.packet_count
