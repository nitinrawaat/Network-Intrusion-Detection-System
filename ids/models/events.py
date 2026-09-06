"""
Security Event Data Models for Python Network IDS (Phase 4).

Standardizes event structures across all detectors, storage engines, and alert dispatchers.
"""

import json
from enum import Enum
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class SecurityEvent:
    """
    Standardized security event produced by IDS detectors.
    """
    event_type: str
    severity: Severity
    detector: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert security event to dictionary format."""
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "detector": self.detector,
            "description": self.description,
            "evidence": self.evidence,
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Convert security event to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        """Reconstruct a SecurityEvent from a dictionary."""
        severity_val = data.get("severity", "MEDIUM")
        if isinstance(severity_val, str):
            try:
                severity = Severity(severity_val.upper())
            except ValueError:
                severity = Severity.MEDIUM
        else:
            severity = Severity.MEDIUM

        return cls(
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            event_type=data.get("event_type", "UNKNOWN"),
            severity=severity,
            source_ip=data.get("source_ip"),
            destination_ip=data.get("destination_ip"),
            detector=data.get("detector", "GenericDetector"),
            description=data.get("description", ""),
            evidence=data.get("evidence", {}) or {},
        )

    def format_alert(self) -> str:
        """Format event into a concise terminal alert block."""
        return (
            f"\n[!] ALERT: [{self.severity.value}] {self.event_type}\n"
            f"    Source:      {self.source_ip or 'N/A'}\n"
            f"    Destination: {self.destination_ip or 'N/A'}\n"
            f"    Detector:    {self.detector}\n"
            f"    Description: {self.description}\n"
            f"    Evidence:    {json.dumps(self.evidence)}\n"
        )
