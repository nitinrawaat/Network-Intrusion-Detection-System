"""
Alert Manager Subsystem for Python Network IDS (Phase 11).

Provides centralized alert normalization, deduplication, rate limiting,
severity-based filtering, and dispatching to pluggable output sinks.
"""

import sys
import time
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Callable
from collections import deque

from ids.models.events import SecurityEvent, Severity

logger = logging.getLogger("ids.alerts")

SEVERITY_LEVELS: Dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# ANSI color codes for terminal triage
ANSI_COLORS = {
    Severity.LOW: "\033[96m",       # Bright Cyan
    Severity.MEDIUM: "\033[93m",    # Bright Yellow
    Severity.HIGH: "\033[91m",      # Bright Red
    Severity.CRITICAL: "\033[95m",  # Bright Magenta
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}


class AlertSink(ABC):
    """Abstract base class for alert destinations (console, storage, webhooks)."""

    @abstractmethod
    def dispatch(self, event: SecurityEvent) -> None:
        """Process and deliver a security event."""
        pass


class ConsoleAlertSink(AlertSink):
    """Formats and prints alerts to standard console with optional ANSI colors."""

    def __init__(self, use_color: Optional[bool] = None):
        if use_color is None:
            self.use_color = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        else:
            self.use_color = bool(use_color)

    def dispatch(self, event: SecurityEvent) -> None:
        sev_color = ANSI_COLORS.get(event.severity, "") if self.use_color else ""
        reset_color = ANSI_COLORS["RESET"] if self.use_color else ""
        bold = ANSI_COLORS["BOLD"] if self.use_color else ""

        banner_header = f"{sev_color}{bold}[!] ALERT: [{event.severity.value}] {event.event_type}{reset_color}"
        lines = [
            "",
            banner_header,
            f"    Source:      {event.source_ip or 'N/A'}",
            f"    Destination: {event.destination_ip or 'N/A'}",
            f"    Detector:    {event.detector}",
            f"    Description: {event.description}",
            f"    Evidence:    {json.dumps(event.evidence)}",
        ]
        print("\n".join(lines), flush=True)


class CallbackAlertSink(AlertSink):
    """Dispatches alerts to a user-provided callback function."""

    def __init__(self, callback: Callable[[SecurityEvent], None]):
        self.callback = callback

    def dispatch(self, event: SecurityEvent) -> None:
        self.callback(event)


class AlertManager:
    """
    Central alert management engine.
    Applies triage, deduplication, and rate limiting before dispatching.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        raw_sev = str(self.config.get("min_severity", "LOW")).upper()
        try:
            self.min_severity = Severity(raw_sev)
        except ValueError:
            self.min_severity = Severity.LOW

        self.dedup_window_seconds = float(self.config.get("dedup_window_seconds", 5.0))
        self.max_rate_per_minute = int(self.config.get("max_rate_per_minute", 120))

        self.sinks: List[AlertSink] = []

        # Deduplication state: (event_type, src, dst) -> last_dispatched_time
        self.last_dispatched: Dict[tuple, float] = {}

        # Rate limiting state: timestamps of dispatched events in the last 60s
        self.rate_window: deque = deque()

        # Operational metrics
        self.metrics: Dict[str, Any] = {
            "total_received": 0,
            "dispatched": 0,
            "suppressed_dedup": 0,
            "suppressed_severity": 0,
            "suppressed_rate_limit": 0,
            "by_severity": {s.value: 0 for s in Severity},
            "by_type": {},
        }

    def register_sink(self, sink: AlertSink) -> None:
        """Register a destination sink for dispatched alerts."""
        self.sinks.append(sink)

    def dispatch(self, event: Optional[SecurityEvent]) -> bool:
        """
        Process and dispatch an alert through triage filters and registered sinks.

        Returns:
            True if dispatched to sinks, False if suppressed or filtered.
        """
        if event is None:
            return False

        self.metrics["total_received"] += 1
        now = time.time()

        # 1. Severity Threshold Filter
        event_sev_rank = SEVERITY_LEVELS.get(event.severity, 0)
        min_sev_rank = SEVERITY_LEVELS.get(self.min_severity, 0)
        if event_sev_rank < min_sev_rank:
            self.metrics["suppressed_severity"] += 1
            return False

        # 2. Alert Deduplication Filter (permits severity escalation)
        dedup_key = (event.event_type, event.source_ip, event.destination_ip, event.severity)
        last_time = self.last_dispatched.get(dedup_key, 0.0)
        if (now - last_time) < self.dedup_window_seconds:
            self.metrics["suppressed_dedup"] += 1
            return False

        # 3. Rate Limiter (Max alerts per minute)
        cutoff = now - 60.0
        while self.rate_window and self.rate_window[0] < cutoff:
            self.rate_window.popleft()

        if len(self.rate_window) >= self.max_rate_per_minute:
            self.metrics["suppressed_rate_limit"] += 1
            logger.warning(
                f"Alert rate limit exceeded ({self.max_rate_per_minute}/min). Suppressing alert: {event.event_type}"
            )
            return False

        # Passed all filters: record dispatch
        self.last_dispatched[dedup_key] = now
        self.rate_window.append(now)

        # Update counters
        self.metrics["dispatched"] += 1
        sev_str = event.severity.value if isinstance(event.severity, Severity) else str(event.severity)
        self.metrics["by_severity"][sev_str] = self.metrics["by_severity"].get(sev_str, 0) + 1
        self.metrics["by_type"][event.event_type] = self.metrics["by_type"].get(event.event_type, 0) + 1

        # Deliver to all sinks safely
        for sink in self.sinks:
            try:
                sink.dispatch(event)
            except Exception as e:
                logger.error(f"Error dispatching alert to sink {type(sink).__name__}: {e}", exc_info=True)

        return True

    def get_metrics(self) -> Dict[str, Any]:
        """Return a copy of the current metrics."""
        return dict(self.metrics)

    def reset(self) -> None:
        """Reset internal filter states and counters."""
        self.last_dispatched.clear()
        self.rate_window.clear()
        self.metrics["total_received"] = 0
        self.metrics["dispatched"] = 0
        self.metrics["suppressed_dedup"] = 0
        self.metrics["suppressed_severity"] = 0
        self.metrics["suppressed_rate_limit"] = 0
        self.metrics["by_severity"] = {s.value: 0 for s in Severity}
        self.metrics["by_type"] = {}
