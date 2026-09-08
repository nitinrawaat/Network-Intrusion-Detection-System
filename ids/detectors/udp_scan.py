"""
UDP Scan Threat Detector (Phase 7).

Detects UDP port scanning and service enumeration (e.g. nmap -sU) by monitoring unique
destination ports probed per source IP within a memory-bounded sliding time window.
"""

import time
from typing import Dict, Any, Optional, Set

from ids.parser.packet_parser import ParsedPacket
from ids.models.events import SecurityEvent, Severity
from ids.detectors.base_detector import BaseDetector, SlidingWindowTracker


class UdpScanDetector(BaseDetector):
    """
    Detects UDP port scanning and probing sweeps.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(name="UdpScanDetector", config=config)
        self.unique_ports_threshold: int = int(self.config.get("unique_ports", 10))
        self.window_seconds: float = float(self.config.get("window_seconds", 5.0))
        self.alert_cooldown: float = float(self.config.get("alert_cooldown", 10.0))

        # Internal state
        self.trackers: Dict[str, SlidingWindowTracker] = {}
        self.last_alert_time: Dict[str, float] = {}
        self.target_ips: Dict[str, str] = {}

    def process(self, packet: ParsedPacket) -> Optional[SecurityEvent]:
        """
        Inspect a normalized packet for UDP port scan activity.

        Triggers an alert when a single source IP contacts at least
        `unique_ports_threshold` distinct UDP destination ports within `window_seconds`.
        """
        if not self.enabled or not packet:
            return None

        # Filter for IP packets carrying UDP payloads
        if not (packet.ip and packet.udp):
            return None

        src_ip = packet.ip.src_ip
        dst_ip = packet.ip.dst_ip
        dst_port = packet.udp.dst_port
        timestamp = packet.timestamp or time.time()

        if src_ip not in self.trackers:
            self.trackers[src_ip] = SlidingWindowTracker(window_seconds=self.window_seconds)

        self.trackers[src_ip].add(item=dst_port, timestamp=timestamp)
        self.target_ips[src_ip] = dst_ip

        # Check unique destination ports within the active window
        active_ports: Set[int] = set(self.trackers[src_ip].prune(timestamp))

        if len(active_ports) >= self.unique_ports_threshold:
            last_alert = self.last_alert_time.get(src_ip, 0.0)
            if timestamp - last_alert >= self.alert_cooldown:
                self.last_alert_time[src_ip] = timestamp

                probed_sample = sorted(list(active_ports))
                return SecurityEvent(
                    timestamp=timestamp,
                    event_type="UDP_PORT_SCAN",
                    severity=Severity.LOW,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    detector=self.name,
                    description=(
                        f"UDP Port Scan detected from {src_ip}: {len(active_ports)} "
                        f"unique ports probed in {self.window_seconds:.1f}s"
                    ),
                    evidence={
                        "probed_ports": probed_sample,
                        "port_count": len(active_ports),
                        "threshold": self.unique_ports_threshold,
                        "window_seconds": self.window_seconds,
                        "target_ip": dst_ip,
                    },
                )

        return None

    def cleanup_expired_state(self, current_time: float) -> None:
        """
        Purge inactive source IP trackers to bound memory usage.
        """
        expired_ips = []
        for src_ip, tracker in list(self.trackers.items()):
            active = tracker.prune(current_time)
            last_alert = self.last_alert_time.get(src_ip, 0.0)
            if not active and (current_time - last_alert >= self.alert_cooldown):
                expired_ips.append(src_ip)

        for ip in expired_ips:
            self.trackers.pop(ip, None)
            self.last_alert_time.pop(ip, None)
            self.target_ips.pop(ip, None)

    def reset_state(self) -> None:
        """Clear all active UDP trackers."""
        self.trackers.clear()
        self.last_alert_time.clear()
        self.target_ips.clear()
