"""
TCP SYN Flood Threat Detector (Phase 8).

Detects volumetric TCP SYN flood denial-of-service attempts targeting specific hosts
or services by tracking SYN transmission rates within a sliding time window.
Supports single-source and distributed/spoofed multi-source flood patterns.
"""

import time
from typing import Dict, Any, Optional, List, Set

from ids.parser.packet_parser import ParsedPacket
from ids.models.events import SecurityEvent, Severity
from ids.detectors.base_detector import BaseDetector, SlidingWindowTracker


class SynFloodDetector(BaseDetector):
    """
    Detects TCP SYN Flood DoS/DDoS attacks.

    Monitors incoming TCP SYN packets targeting destination endpoints (IP:Port)
    over a configurable sliding time window. Triggers a HIGH severity security event
    when the volume of half-open connection attempts exceeds the defined threshold.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(name="SynFloodDetector", config=config)
        self.syn_threshold: int = int(self.config.get("syn_threshold", 200))
        self.window_seconds: float = float(self.config.get("window_seconds", 5.0))
        self.alert_cooldown: float = float(self.config.get("alert_cooldown", 10.0))

        # Internal state tracked per destination target endpoint (dst_ip:dst_port)
        self.trackers: Dict[str, SlidingWindowTracker] = {}
        self.last_alert_time: Dict[str, float] = {}

    def process(self, packet: ParsedPacket) -> Optional[SecurityEvent]:
        """
        Inspect a normalized packet for TCP SYN flood activity.

        Triggers an alert when the number of SYN requests received for a target
        service (destination IP:port) reaches or exceeds `syn_threshold` within `window_seconds`.
        """
        if not self.enabled or not packet:
            return None

        # Must have IP and TCP layers
        if not (packet.ip and packet.tcp):
            return None

        # Filter strictly for TCP SYN packets without ACK flag set
        if not (packet.tcp.is_syn and not packet.tcp.is_ack):
            return None

        src_ip = packet.ip.src_ip
        dst_ip = packet.ip.dst_ip
        dst_port = packet.tcp.dst_port
        timestamp = packet.timestamp or time.time()

        target_key = f"{dst_ip}:{dst_port}"

        if target_key not in self.trackers:
            self.trackers[target_key] = SlidingWindowTracker(
                window_seconds=self.window_seconds,
                max_items=self.syn_threshold * 10,
            )

        # Record source IP in sliding window
        self.trackers[target_key].add(item=src_ip, timestamp=timestamp)

        # Check active items in the sliding window
        active_sources: List[str] = self.trackers[target_key].prune(timestamp)
        syn_count = len(active_sources)

        if syn_count >= self.syn_threshold:
            last_alert = self.last_alert_time.get(target_key, 0.0)
            if timestamp - last_alert >= self.alert_cooldown:
                self.last_alert_time[target_key] = timestamp

                unique_sources: Set[str] = set(active_sources)
                unique_source_count = len(unique_sources)
                syn_rate = round(syn_count / max(self.window_seconds, 0.001), 1)

                # Format primary source representation
                if unique_source_count == 1:
                    primary_source = list(unique_sources)[0]
                else:
                    primary_source = f"Distributed ({unique_source_count} sources)"

                sample_sources = sorted(list(unique_sources))[:5]

                return SecurityEvent(
                    timestamp=timestamp,
                    event_type="TCP_SYN_FLOOD",
                    severity=Severity.HIGH,
                    source_ip=primary_source,
                    destination_ip=dst_ip,
                    detector=self.name,
                    description=(
                        f"TCP SYN Flood detected targeting {dst_ip}:{dst_port}: {syn_count} "
                        f"SYNs in {self.window_seconds:.1f}s (Rate: {syn_rate} pps)"
                    ),
                    evidence={
                        "target_ip": dst_ip,
                        "target_port": dst_port,
                        "syn_count": syn_count,
                        "syn_rate_pps": syn_rate,
                        "unique_sources_count": unique_source_count,
                        "sample_sources": sample_sources,
                        "threshold": self.syn_threshold,
                        "window_seconds": self.window_seconds,
                    },
                )

        return None

    def cleanup_expired_state(self, current_time: float) -> None:
        """
        Purge inactive target trackers to bound memory usage.
        """
        expired_targets = []
        for target_key, tracker in list(self.trackers.items()):
            active = tracker.prune(current_time)
            last_alert = self.last_alert_time.get(target_key, 0.0)
            if not active and (current_time - last_alert >= self.alert_cooldown):
                expired_targets.append(target_key)

        for target in expired_targets:
            self.trackers.pop(target, None)
            self.last_alert_time.pop(target, None)

    def reset_state(self) -> None:
        """Clear all active SYN flood trackers."""
        self.trackers.clear()
        self.last_alert_time.clear()
