"""
SQLite Relational Alert Storage for Python Network IDS (Phase 12).

Provides structured indexing, querying, and aggregation of SecurityEvents in a local SQLite database.
"""

import os
import json
import sqlite3
import logging
from typing import List, Dict, Any, Optional

from ids.models.events import SecurityEvent, Severity
from ids.alerts.alert_manager import AlertSink

logger = logging.getLogger("ids.storage.sqlite")


class SqliteAlertStorage(AlertSink):
    """
    Relational SQLite storage sink for security alerts with indexed querying.
    """

    def __init__(self, db_path: str = "logs/events.db"):
        self.db_path = db_path
        if db_path != ":memory:":
            directory = os.path.dirname(db_path)
            if directory:
                os.makedirs(directory, exist_ok=True)

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create a new SQLite connection configured for WAL mode and dictionary rows."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create table schema and indexes if they do not exist."""
        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        source_ip TEXT,
                        destination_ip TEXT,
                        detector TEXT NOT NULL,
                        description TEXT,
                        evidence TEXT
                    );
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_event_type ON security_events(event_type);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events(source_ip);")
        finally:
            conn.close()

    def dispatch(self, event: SecurityEvent) -> None:
        """Insert a SecurityEvent into the database."""
        if not event:
            return

        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO security_events (
                        timestamp, event_type, severity, source_ip, destination_ip,
                        detector, description, evidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.timestamp,
                        event.event_type,
                        event.severity.value if isinstance(event.severity, Severity) else str(event.severity),
                        event.source_ip,
                        event.destination_ip,
                        event.detector,
                        event.description,
                        json.dumps(event.evidence),
                    ),
                )
        except Exception as e:
            logger.error(f"Failed to insert alert into SQLite DB ({self.db_path}): {e}", exc_info=True)
        finally:
            conn.close()

    def get_events(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query security events with optional filters."""
        conn = self._get_connection()
        try:
            query = "SELECT * FROM security_events WHERE 1=1"
            params: List[Any] = []

            if severity:
                query += " AND severity = ?"
                params.append(severity.upper())
            if event_type:
                query += " AND event_type = ?"
                params.append(event_type.upper())
            if source_ip:
                query += " AND source_ip = ?"
                params.append(source_ip)

            query += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            results = []
            for r in rows:
                row_dict = dict(r)
                if row_dict.get("evidence"):
                    try:
                        row_dict["evidence"] = json.loads(row_dict["evidence"])
                    except Exception:
                        pass
                results.append(row_dict)
            return results
        finally:
            conn.close()

    def count(self) -> int:
        """Return the total number of security events stored."""
        conn = self._get_connection()
        try:
            cursor = conn.execute("SELECT COUNT(*) FROM security_events")
            return int(cursor.fetchone()[0])
        finally:
            conn.close()

    def get_summary(self) -> Dict[str, Any]:
        """Return aggregated summary metrics from the database."""
        conn = self._get_connection()
        try:
            total = self.count()

            # By severity
            cur = conn.execute("SELECT severity, COUNT(*) as cnt FROM security_events GROUP BY severity")
            by_severity = {row["severity"]: row["cnt"] for row in cur.fetchall()}

            # By event type
            cur = conn.execute("SELECT event_type, COUNT(*) as cnt FROM security_events GROUP BY event_type")
            by_type = {row["event_type"]: row["cnt"] for row in cur.fetchall()}

            # Top 5 source IPs
            cur = conn.execute(
                """
                SELECT source_ip, COUNT(*) as cnt
                FROM security_events
                WHERE source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY cnt DESC
                LIMIT 5
                """
            )
            top_sources = [{"source_ip": row["source_ip"], "count": row["cnt"]} for row in cur.fetchall()]

            return {
                "total_events": total,
                "by_severity": by_severity,
                "by_type": by_type,
                "top_sources": top_sources,
            }
        finally:
            conn.close()

    def clear(self) -> None:
        """Clear all events from the database."""
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM security_events")
        finally:
            conn.close()
