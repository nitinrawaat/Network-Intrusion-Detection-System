"""
Detection Engine for Python Network IDS (Phase 5).

Coordinates threat detectors:
- Config-driven initialization.
- Fault-tolerant packet dispatch (one failing detector cannot crash the IDS).
- Periodic memory cleanup across all registered detectors.
"""

import os
import json
import time
import logging
from typing import List, Dict, Optional, Any

from ids.parser.packet_parser import ParsedPacket
from ids.models.events import SecurityEvent
from ids.detectors.base_detector import BaseDetector

logger = logging.getLogger("ids.detectors")


class DetectionEngine:
    """
    Central orchestration engine for modular threat detection.
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        cleanup_interval_seconds: float = 10.0,
    ):
        self.config_path = config_path
        self.rules_config: Dict[str, Any] = self._load_config(config_path)
        self.detectors: List[BaseDetector] = []
        self.cleanup_interval = cleanup_interval_seconds
        self._last_cleanup = time.time()
        self.stats: Dict[str, int] = {
            "packets_processed": 0,
            "alerts_generated": 0,
            "detector_errors": 0,
        }

    def _load_config(self, path: Optional[str]) -> Dict[str, Any]:
        """Load JSON configuration file or return default dictionary."""
        if not path:
            # Default location
            default_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "config", "rules.json"
            )
            if os.path.exists(default_path):
                path = default_path

        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load rules config from {path}: {e}")
        return {}

    def get_detector_config(self, detector_name: str) -> Dict[str, Any]:
        """Retrieve config subsection for a given detector name."""
        return self.rules_config.get(detector_name, {})

    def register_detector(self, detector: BaseDetector) -> None:
        """Register a new threat detector in the pipeline."""
        self.detectors.append(detector)
        status = "ENABLED" if detector.enabled else "DISABLED"
        logger.info(f"Registered detector '{detector.name}' [{status}]")

    def register_default_detectors(self) -> None:
        """Register built-in threat detectors configured in rules.json."""
        port_scan_cfg = self.get_detector_config("port_scan")
        if port_scan_cfg.get("enabled", True):
            from ids.detectors.port_scan import PortScanDetector
            self.register_detector(PortScanDetector(config=port_scan_cfg))

    def unregister_detector(self, detector_name: str) -> bool:
        """Remove a detector by name."""
        initial_len = len(self.detectors)
        self.detectors = [d for d in self.detectors if d.name != detector_name]
        return len(self.detectors) < initial_len

    def get_active_detectors(self) -> List[BaseDetector]:
        """Return all currently enabled detectors."""
        return [d for d in self.detectors if d.enabled]

    def process_packet(self, packet: Optional[ParsedPacket]) -> List[SecurityEvent]:
        """
        Evaluate a parsed packet across all registered, enabled detectors.
        Guarantees fault-isolation: a broken detector will not stop others.
        """
        if packet is None:
            return []

        self.stats["packets_processed"] += 1
        alerts: List[SecurityEvent] = []
        current_time = packet.timestamp or time.time()

        # Run each enabled detector with isolated error handling
        for detector in self.detectors:
            if not detector.enabled:
                continue

            try:
                event = detector.process(packet)
                if event is not None:
                    alerts.append(event)
                    self.stats["alerts_generated"] += 1
            except Exception as e:
                self.stats["detector_errors"] += 1
                logger.error(
                    f"Unhandled exception in detector '{detector.name}': {e}",
                    exc_info=True,
                )

        # Periodic cleanup of expired detector state
        if current_time - self._last_cleanup >= self.cleanup_interval:
            self.cleanup_expired_state(current_time)
            self._last_cleanup = current_time

        return alerts

    def cleanup_expired_state(self, current_time: Optional[float] = None) -> None:
        """Invoke state cleanup on all registered detectors."""
        now = current_time if current_time is not None else time.time()
        for detector in self.detectors:
            try:
                detector.cleanup_expired_state(now)
            except Exception as e:
                logger.warning(
                    f"Error cleaning up state in detector '{detector.name}': {e}"
                )
