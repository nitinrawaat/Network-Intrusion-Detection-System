"""
DNS Anomaly Threat Detector (Phase 10).

Detects DNS-based threats including:
1. DNS Tunneling and data exfiltration (abnormally long domain names / labels).
2. DNS Query Floods / bursts (high rate of outbound queries per client).
3. NXDOMAIN Bursts (reconnaissance probing or DGA botnet rendezvous failures).
"""

import time
from typing import Dict, Any, Optional, List

from ids.parser.packet_parser import ParsedPacket
from ids.models.events import SecurityEvent, Severity
from ids.detectors.base_detector import BaseDetector, SlidingWindowTracker


class DnsAnomalyDetector(BaseDetector):
    """
    Detects DNS tunneling, query floods, and NXDOMAIN reconnaissance bursts.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(name="DnsAnomalyDetector", config=config)
        self.query_threshold: int = int(self.config.get("query_threshold", 100))
        self.window_seconds: float = float(self.config.get("window_seconds", 60.0))
        self.max_label_length: int = int(self.config.get("max_label_length", 50))
        self.max_domain_length: int = int(self.config.get("max_domain_length", 120))
        self.nxdomain_threshold: int = int(self.config.get("nxdomain_threshold", 20))
        self.alert_cooldown: float = float(self.config.get("alert_cooldown", 10.0))

        # Sliding window trackers per client IP
        self.query_trackers: Dict[str, SlidingWindowTracker] = {}
        self.nxdomain_trackers: Dict[str, SlidingWindowTracker] = {}
        self.last_alert_time: Dict[str, float] = {}

    def _get_client_and_server_ip(self, packet: ParsedPacket) -> tuple[str, str]:
        """Determine client and server IP based on query vs response direction."""
        dns = packet.dns
        if dns and not dns.is_response:
            client_ip = dns.source_ip or (packet.ip.src_ip if packet.ip else "unknown")
            server_ip = dns.destination_ip or (packet.ip.dst_ip if packet.ip else "unknown")
        else:
            client_ip = (dns.destination_ip if dns else None) or (packet.ip.dst_ip if packet.ip else "unknown")
            server_ip = (dns.source_ip if dns else None) or (packet.ip.src_ip if packet.ip else "unknown")
        return client_ip, server_ip

    def process(self, packet: ParsedPacket) -> Optional[SecurityEvent]:
        """
        Evaluate a packet for DNS tunneling, floods, or NXDOMAIN bursts.
        """
        if not self.enabled or not packet or not packet.dns:
            return None

        dns = packet.dns
        client_ip, server_ip = self._get_client_and_server_ip(packet)
        timestamp = packet.timestamp or time.time()

        # 1. Check for DNS Tunneling / Abnormally Long Domain/Labels
        if dns.query_name:
            labels = dns.query_name.split(".")
            max_label = max((len(l) for l in labels), default=0)
            total_len = len(dns.query_name)

            if max_label >= self.max_label_length or total_len >= self.max_domain_length:
                cooldown_key = f"TUNNELING:{client_ip}"
                last_alert = self.last_alert_time.get(cooldown_key, 0.0)
                if timestamp - last_alert >= self.alert_cooldown:
                    self.last_alert_time[cooldown_key] = timestamp
                    display_qname = dns.query_name if len(dns.query_name) <= 60 else dns.query_name[:57] + "..."
                    return SecurityEvent(
                        timestamp=timestamp,
                        event_type="DNS_TUNNELING",
                        severity=Severity.HIGH,
                        source_ip=client_ip,
                        destination_ip=server_ip,
                        detector=self.name,
                        description=(
                            f"Suspected DNS Tunneling from {client_ip}: query '{display_qname}' "
                            f"exceeds length bounds (max label: {max_label}, total: {total_len})"
                        ),
                        evidence={
                            "query_name": dns.query_name,
                            "query_type": dns.query_type,
                            "max_label_length": max_label,
                            "total_length": total_len,
                            "threshold_label": self.max_label_length,
                            "threshold_domain": self.max_domain_length,
                        },
                    )

        # 2. Check for DNS Query Flood (Outbound requests)
        if not dns.is_response:
            if client_ip not in self.query_trackers:
                self.query_trackers[client_ip] = SlidingWindowTracker(
                    window_seconds=self.window_seconds,
                    max_items=self.query_threshold * 5,
                )
            self.query_trackers[client_ip].add(item=dns.query_name, timestamp=timestamp)
            active_queries: List[Any] = self.query_trackers[client_ip].prune(timestamp)
            query_count = len(active_queries)

            if query_count >= self.query_threshold:
                cooldown_key = f"FLOOD:{client_ip}"
                last_alert = self.last_alert_time.get(cooldown_key, 0.0)
                if timestamp - last_alert >= self.alert_cooldown:
                    self.last_alert_time[cooldown_key] = timestamp
                    rate = round(query_count / max(self.window_seconds, 0.001), 1)
                    return SecurityEvent(
                        timestamp=timestamp,
                        event_type="DNS_QUERY_FLOOD",
                        severity=Severity.MEDIUM,
                        source_ip=client_ip,
                        destination_ip=server_ip,
                        detector=self.name,
                        description=(
                            f"DNS Query Flood detected from {client_ip}: {query_count} "
                            f"queries in {self.window_seconds:.1f}s ({rate} qps)"
                        ),
                        evidence={
                            "query_count": query_count,
                            "rate_qps": rate,
                            "threshold": self.query_threshold,
                            "window_seconds": self.window_seconds,
                            "target_dns_server": server_ip,
                        },
                    )

        # 3. Check for NXDOMAIN Burst (Inbound response with rcode == 3)
        if dns.is_response and dns.rcode == 3:
            if client_ip not in self.nxdomain_trackers:
                self.nxdomain_trackers[client_ip] = SlidingWindowTracker(
                    window_seconds=self.window_seconds,
                    max_items=self.nxdomain_threshold * 5,
                )
            self.nxdomain_trackers[client_ip].add(item=dns.query_name, timestamp=timestamp)
            active_nx: List[Any] = self.nxdomain_trackers[client_ip].prune(timestamp)
            nx_count = len(active_nx)

            if nx_count >= self.nxdomain_threshold:
                cooldown_key = f"NXDOMAIN:{client_ip}"
                last_alert = self.last_alert_time.get(cooldown_key, 0.0)
                if timestamp - last_alert >= self.alert_cooldown:
                    self.last_alert_time[cooldown_key] = timestamp
                    return SecurityEvent(
                        timestamp=timestamp,
                        event_type="DNS_NXDOMAIN_BURST",
                        severity=Severity.MEDIUM,
                        source_ip=client_ip,
                        destination_ip=server_ip,
                        detector=self.name,
                        description=(
                            f"DNS NXDOMAIN Burst detected for {client_ip}: {nx_count} "
                            f"nonexistent domain responses in {self.window_seconds:.1f}s"
                        ),
                        evidence={
                            "nxdomain_count": nx_count,
                            "threshold": self.nxdomain_threshold,
                            "window_seconds": self.window_seconds,
                            "dns_server": server_ip,
                            "last_query": dns.query_name,
                        },
                    )

        return None

    def cleanup_expired_state(self, current_time: float) -> None:
        """Purge inactive client trackers to bound memory usage."""
        for tracker_dict in (self.query_trackers, self.nxdomain_trackers):
            expired = []
            for ip, tracker in list(tracker_dict.items()):
                active = tracker.prune(current_time)
                if not active:
                    expired.append(ip)
            for ip in expired:
                tracker_dict.pop(ip, None)

        expired_alerts = [
            k for k, t in self.last_alert_time.items()
            if current_time - t > (self.window_seconds + self.alert_cooldown)
        ]
        for k in expired_alerts:
            self.last_alert_time.pop(k, None)

    def reset_state(self) -> None:
        """Clear all active trackers and cooldown records."""
        self.query_trackers.clear()
        self.nxdomain_trackers.clear()
        self.last_alert_time.clear()
