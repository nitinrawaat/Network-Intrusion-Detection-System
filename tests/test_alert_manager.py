"""
Unit tests for AlertManager subsystem (Phase 11).
"""

import io
import unittest
import time
from unittest.mock import patch

from ids.models.events import SecurityEvent, Severity
from ids.alerts.alert_manager import (
    AlertManager,
    AlertSink,
    ConsoleAlertSink,
    CallbackAlertSink,
)


def make_test_event(
    event_type: str = "TCP_PORT_SCAN",
    severity: Severity = Severity.MEDIUM,
    source_ip: str = "192.168.1.100",
    destination_ip: str = "192.168.1.50",
    detector: str = "PortScanDetector",
    description: str = "Test alert",
) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type,
        severity=severity,
        source_ip=source_ip,
        destination_ip=destination_ip,
        detector=detector,
        description=description,
        evidence={"sample_key": "sample_val"},
    )


class MockSink(AlertSink):
    def __init__(self):
        self.received = []

    def dispatch(self, event: SecurityEvent) -> None:
        self.received.append(event)


class FailingSink(AlertSink):
    def dispatch(self, event: SecurityEvent) -> None:
        raise RuntimeError("Simulated sink dispatch error!")


class TestAlertManager(unittest.TestCase):

    def setUp(self):
        self.manager = AlertManager(
            config={
                "min_severity": "LOW",
                "dedup_window_seconds": 2.0,
                "max_rate_per_minute": 10,
            }
        )
        self.sink = MockSink()
        self.manager.register_sink(self.sink)

    def test_default_dispatch_success(self):
        """Standard event is delivered to registered sink."""
        event = make_test_event()
        dispatched = self.manager.dispatch(event)
        self.assertTrue(dispatched)
        self.assertEqual(len(self.sink.received), 1)
        self.assertEqual(self.sink.received[0].event_type, "TCP_PORT_SCAN")

    def test_severity_filtering(self):
        """Events below min_severity are filtered out."""
        strict_manager = AlertManager(config={"min_severity": "HIGH"})
        mock_sink = MockSink()
        strict_manager.register_sink(mock_sink)

        low_ev = make_test_event(severity=Severity.LOW)
        med_ev = make_test_event(severity=Severity.MEDIUM)
        high_ev = make_test_event(severity=Severity.HIGH)
        crit_ev = make_test_event(severity=Severity.CRITICAL)

        self.assertFalse(strict_manager.dispatch(low_ev))
        self.assertFalse(strict_manager.dispatch(med_ev))
        self.assertTrue(strict_manager.dispatch(high_ev))
        self.assertTrue(strict_manager.dispatch(crit_ev))

        self.assertEqual(len(mock_sink.received), 2)
        metrics = strict_manager.get_metrics()
        self.assertEqual(metrics["suppressed_severity"], 2)
        self.assertEqual(metrics["dispatched"], 2)

    def test_alert_deduplication(self):
        """Duplicate alerts within dedup_window_seconds are suppressed."""
        ev1 = make_test_event(source_ip="10.0.0.1", destination_ip="10.0.0.2")
        ev2 = make_test_event(source_ip="10.0.0.1", destination_ip="10.0.0.2")

        # First alert passes
        self.assertTrue(self.manager.dispatch(ev1))
        # Second duplicate within 2.0s is suppressed
        self.assertFalse(self.manager.dispatch(ev2))

        self.assertEqual(len(self.sink.received), 1)
        self.assertEqual(self.manager.get_metrics()["suppressed_dedup"], 1)

    def test_deduplication_different_endpoints(self):
        """Alerts with different endpoints or event types are not suppressed."""
        ev1 = make_test_event(source_ip="10.0.0.1", destination_ip="10.0.0.2")
        ev2 = make_test_event(source_ip="10.0.0.99", destination_ip="10.0.0.2")
        ev3 = make_test_event(event_type="UDP_SCAN", source_ip="10.0.0.1", destination_ip="10.0.0.2")

        self.assertTrue(self.manager.dispatch(ev1))
        self.assertTrue(self.manager.dispatch(ev2))
        self.assertTrue(self.manager.dispatch(ev3))
        self.assertEqual(len(self.sink.received), 3)

    def test_rate_limiting(self):
        """Exceeding max_rate_per_minute suppresses subsequent alerts."""
        # max_rate_per_minute is set to 10 in setUp
        dispatched_count = 0
        for i in range(15):
            ev = make_test_event(source_ip=f"192.168.1.{i}")
            if self.manager.dispatch(ev):
                dispatched_count += 1

        self.assertEqual(dispatched_count, 10)
        self.assertEqual(self.manager.get_metrics()["suppressed_rate_limit"], 5)

    def test_multiple_sinks(self):
        """Alert is delivered to all registered sinks."""
        sink2 = MockSink()
        self.manager.register_sink(sink2)

        event = make_test_event()
        self.manager.dispatch(event)

        self.assertEqual(len(self.sink.received), 1)
        self.assertEqual(len(sink2.received), 1)

    def test_fault_tolerant_sink_failure(self):
        """A failing sink does not prevent remaining sinks from receiving the alert."""
        failing_sink = FailingSink()
        healthy_sink = MockSink()

        self.manager.sinks.clear()
        self.manager.register_sink(failing_sink)
        self.manager.register_sink(healthy_sink)

        event = make_test_event()
        dispatched = self.manager.dispatch(event)

        self.assertTrue(dispatched)
        self.assertEqual(len(healthy_sink.received), 1)

    def test_callback_sink(self):
        """CallbackAlertSink invokes callable."""
        callback_items = []
        cb_sink = CallbackAlertSink(lambda ev: callback_items.append(ev))

        manager = AlertManager()
        manager.register_sink(cb_sink)

        ev = make_test_event()
        manager.dispatch(ev)
        self.assertEqual(len(callback_items), 1)
        self.assertEqual(callback_items[0].event_type, "TCP_PORT_SCAN")

    def test_console_sink_formatting(self):
        """ConsoleAlertSink formats output cleanly to stdout."""
        sink = ConsoleAlertSink(use_color=False)
        event = make_test_event(description="Sample test description")

        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            sink.dispatch(event)
            output = fake_out.getvalue()

        self.assertIn("[!] ALERT: [MEDIUM] TCP_PORT_SCAN", output)
        self.assertIn("Source:      192.168.1.100", output)
        self.assertIn("Sample test description", output)

    def test_metrics_and_reset(self):
        """get_metrics returns accurate counters and reset restores initial state."""
        self.manager.dispatch(make_test_event(severity=Severity.HIGH, event_type="TCP_SYN_FLOOD"))
        metrics = self.manager.get_metrics()
        self.assertEqual(metrics["dispatched"], 1)
        self.assertEqual(metrics["by_severity"]["HIGH"], 1)
        self.assertEqual(metrics["by_type"]["TCP_SYN_FLOOD"], 1)

        self.manager.reset()
        clean_metrics = self.manager.get_metrics()
        self.assertEqual(clean_metrics["dispatched"], 0)
        self.assertEqual(clean_metrics["total_received"], 0)


if __name__ == "__main__":
    unittest.main()
