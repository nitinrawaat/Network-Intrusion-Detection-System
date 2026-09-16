"""
JSON Append-Only Alert Storage for Python Network IDS (Phase 12).

Persists SecurityEvents as line-delimited JSON (JSONL) records to disk.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional

from ids.models.events import SecurityEvent
from ids.alerts.alert_manager import AlertSink

logger = logging.getLogger("ids.storage.json")


class JsonAlertStorage(AlertSink):
    """
    Append-only JSON log file storage sink.
    Writes each SecurityEvent as a single JSON object per line.
    """

    def __init__(self, file_path: str = "logs/alerts.json"):
        self.file_path = file_path
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        directory = os.path.dirname(self.file_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def dispatch(self, event: SecurityEvent) -> None:
        """Append a SecurityEvent to the JSON log file."""
        if not event:
            return

        try:
            self._ensure_directory()
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to write alert to JSON log ({self.file_path}): {e}", exc_info=True)

    def read_all(self) -> List[Dict[str, Any]]:
        """Read and parse all events from the JSON log file."""
        if not os.path.exists(self.file_path):
            return []

        records = []
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        records.append(json.loads(stripped))
        except Exception as e:
            logger.error(f"Failed to read JSON log ({self.file_path}): {e}", exc_info=True)

        return records

    def count(self) -> int:
        """Return the number of stored events."""
        return len(self.read_all())

    def clear(self) -> None:
        """Truncate the JSON log file."""
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, "w", encoding="utf-8") as f:
                    f.truncate(0)
            except Exception as e:
                logger.error(f"Failed to truncate JSON log ({self.file_path}): {e}", exc_info=True)
