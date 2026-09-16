"""Alert management and dispatch."""

from ids.alerts.alert_manager import (
    AlertManager,
    AlertSink,
    ConsoleAlertSink,
    CallbackAlertSink,
)

__all__ = [
    "AlertManager",
    "AlertSink",
    "ConsoleAlertSink",
    "CallbackAlertSink",
]
