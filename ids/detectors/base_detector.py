"""
Base Threat Detector Interface for Python Network IDS (Phase 5).

Defines the contract for all attack detectors:
- Config-driven initialization.
- Independent state maintenance.
- Memory-bounded sliding window state management.
- Pure evaluation on normalized ParsedPacket objects.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from collections import deque

from ids.parser.packet_parser import ParsedPacket
from ids.models.events import SecurityEvent, Severity


class SlidingWindowTracker:
    """
    Lightweight, memory-safe sliding window timestamp queue.
    Automatically prunes entries older than window_seconds.
    """

    def __init__(self, window_seconds: float, max_items: int = 10000):
        self.window_seconds = float(window_seconds)
        self.max_items = max_items
        self._items: deque = deque()

    def add(self, item: Any, timestamp: float) -> None:
        """Add an item with a timestamp, discarding old items if capacity exceeded."""
        self._items.append((timestamp, item))
        if len(self._items) > self.max_items:
            self._items.popleft()

    def prune(self, current_time: float) -> List[Any]:
        """
        Remove items outside the time window and return active items.
        """
        cutoff = current_time - self.window_seconds
        while self._items and self._items[0][0] < cutoff:
            self._items.popleft()
        return [item for _, item in self._items]

    def count(self, current_time: float) -> int:
        """Return the number of entries within the active time window."""
        self.prune(current_time)
        return len(self._items)

    def clear(self) -> None:
        """Empty the queue."""
        self._items.clear()


class BaseDetector(ABC):
    """
    Abstract Base Class for IDS threat detectors.
    """

    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.config = config or {}
        self.enabled = bool(self.config.get("enabled", True))

    @abstractmethod
    def process(self, packet: ParsedPacket) -> Optional[SecurityEvent]:
        """
        Evaluate a single normalized packet for suspicious activity.

        Args:
            packet: The normalized ParsedPacket instance.

        Returns:
            A SecurityEvent if a threat threshold is crossed, otherwise None.
        """
        pass

    @abstractmethod
    def cleanup_expired_state(self, current_time: float) -> None:
        """
        Purge expired state entries from internal memory.
        Called periodically by the DetectionEngine to prevent memory leaks.
        """
        pass

    def reset_state(self) -> None:
        """Reset internal detector state (useful during testing)."""
        pass
