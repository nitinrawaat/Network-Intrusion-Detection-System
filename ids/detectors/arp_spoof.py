"""
ARP Spoofing / Poisoning Threat Detector (Phase 9).

Detects Man-In-The-Middle (MITM) attacks and ARP cache poisoning by tracking IP-to-MAC
bindings in local network traffic. Flags conflicting MAC address announcements for known
IPs and mismatches against trusted static mappings.
"""

import time
from typing import Dict, Any, Optional

from ids.parser.packet_parser import ParsedPacket
from ids.models.events import SecurityEvent, Severity
from ids.detectors.base_detector import BaseDetector

# Reserved / invalid host MACs to ignore during binding updates
INVALID_MACS = {
    "00:00:00:00:00:00",
    "ff:ff:ff:ff:ff:ff",
}

# Special IPs to ignore
IGNORED_IPS = {
    "0.0.0.0",
    "255.255.255.255",
}


class ArpSpoofDetector(BaseDetector):
    """
    Detects ARP Cache Poisoning and spoofing attempts.

    Maintains a dynamic IP-to-MAC mapping table learned from observed ARP traffic.
    Triggers an alert when:
    1. An ARP packet advertises a MAC address differing from a pre-configured static mapping.
    2. An ARP packet updates a previously established IP-to-MAC mapping to a conflicting MAC.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(name="ArpSpoofDetector", config=config)
        self.alert_cooldown: float = float(self.config.get("alert_cooldown", 10.0))
        self.mac_ttl_seconds: float = float(self.config.get("mac_ttl_seconds", 300.0))

        # Static trusted IP -> MAC mappings (e.g. default gateway)
        raw_static = self.config.get("static_mappings", {})
        self.static_mappings: Dict[str, str] = {
            ip: mac.lower().strip() for ip, mac in raw_static.items()
        }

        # Dynamic table: ip -> mac (lowercase)
        self.ip_mac_table: Dict[str, str] = dict(self.static_mappings)
        # Last seen timestamp: ip -> float
        self.last_seen: Dict[str, float] = {}
        # Cooldown per IP: ip -> float
        self.last_alert_time: Dict[str, float] = {}

    def process(self, packet: ParsedPacket) -> Optional[SecurityEvent]:
        """
        Inspect a normalized packet for ARP spoofing / cache poisoning signatures.
        """
        if not self.enabled or not packet or not packet.arp:
            return None

        arp = packet.arp
        src_ip = arp.src_ip.strip()
        src_mac = arp.src_mac.lower().strip()
        timestamp = packet.timestamp or time.time()

        # Skip invalid IPs and broadcast/null MACs
        if not src_ip or src_ip in IGNORED_IPS:
            return None
        if not src_mac or src_mac in INVALID_MACS:
            return None

        # Check against existing mapping
        if src_ip in self.ip_mac_table:
            known_mac = self.ip_mac_table[src_ip]
            if known_mac != src_mac:
                # Mapping conflict detected!
                last_alert = self.last_alert_time.get(src_ip, 0.0)
                if timestamp - last_alert >= self.alert_cooldown:
                    self.last_alert_time[src_ip] = timestamp

                    is_static_conflict = src_ip in self.static_mappings
                    alert_desc = (
                        f"ARP Spoofing detected for {src_ip}: MAC conflict "
                        f"(expected {known_mac}, received {src_mac})"
                        + (" [STATIC PINNING VIOLATION]" if is_static_conflict else "")
                    )

                    return SecurityEvent(
                        timestamp=timestamp,
                        event_type="ARP_SPOOFING",
                        severity=Severity.HIGH,
                        source_ip=src_ip,
                        destination_ip=arp.dst_ip,
                        detector=self.name,
                        description=alert_desc,
                        evidence={
                            "ip_address": src_ip,
                            "original_mac": known_mac,
                            "spoofed_mac": src_mac,
                            "target_ip": arp.dst_ip,
                            "target_mac": arp.dst_mac.lower().strip(),
                            "operation": arp.operation,
                            "op_code": arp.op_code,
                            "static_pinned": is_static_conflict,
                        },
                    )
        else:
            # First time observing this IP: record mapping
            self.ip_mac_table[src_ip] = src_mac

        # Update last seen timestamp for dynamic entries
        if src_ip not in self.static_mappings:
            self.last_seen[src_ip] = timestamp

        return None

    def cleanup_expired_state(self, current_time: float) -> None:
        """
        Purge stale dynamic IP-to-MAC bindings older than mac_ttl_seconds.
        Static mappings are preserved indefinitely.
        """
        expired_ips = []
        for ip, seen_time in list(self.last_seen.items()):
            if ip not in self.static_mappings:
                if current_time - seen_time > self.mac_ttl_seconds:
                    expired_ips.append(ip)

        for ip in expired_ips:
            self.ip_mac_table.pop(ip, None)
            self.last_seen.pop(ip, None)
            self.last_alert_time.pop(ip, None)

    def reset_state(self) -> None:
        """Reset internal IP-to-MAC table back to configured static mappings."""
        self.ip_mac_table = dict(self.static_mappings)
        self.last_seen.clear()
        self.last_alert_time.clear()
