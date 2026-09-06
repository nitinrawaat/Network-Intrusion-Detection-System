"""
Main entrypoint for the Python Network Intrusion Detection System (IDS).

Provides CLI interface, banner rendering, interface discovery, and packet capture orchestration.
"""

import sys
import os
import signal
import argparse
import logging
from typing import Optional

from ids.capture.packet_capture import (
    PacketCaptureEngine,
    format_packet_summary,
    check_scapy_available,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ids")


# Ensure UTF-8 output on Windows terminals if possible
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BANNER = """
+------------------------------------------------------------+
|                PYTHON NETWORK IDS (PHASE 2)                |
+------------------------------------------------------------+
| Status: ACTIVE                                             |
| Mode: PACKET CAPTURE & INSPECTION                          |
| Active Detectors: 0 (Baseline Capture Stage)               |
+------------------------------------------------------------+
"""


def print_banner(interface: Optional[str] = None, pcap: Optional[str] = None):
    """Display the system startup banner."""
    print(BANNER)
    if pcap:
        print(f"[*] Mode: Offline PCAP Playback")
        print(f"[*] PCAP File: {pcap}")
    else:
        print(f"[*] Target Interface: {interface or 'Default / All'}")
    print("[*] Press Ctrl+C at any time to gracefully stop.\n" + "-" * 60)


def handle_list_interfaces():
    """Print detected network interfaces and exit."""
    try:
        check_scapy_available()
    except ImportError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n[+] Available Network Interfaces:")
    print(f"{'NAME':<20} | {'IP ADDRESS':<18} | {'MAC ADDRESS':<20} | {'DESCRIPTION'}")
    print("-" * 80)
    for iface in PacketCaptureEngine.list_interfaces():
        print(
            f"{iface['name']:<20} | {iface['ip']:<18} | {iface['mac']:<20} | {iface['description']}"
        )
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Python Network Intrusion Detection System (IDS) - Packet Capture"
    )
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        help="Network interface to capture from (e.g. eth0, wlan0).",
    )
    parser.add_argument(
        "-l",
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (default: 0 = continuous).",
    )
    parser.add_argument(
        "-r",
        "--pcap",
        type=str,
        help="Replay packets from a PCAP file instead of live capture.",
    )
    parser.add_argument(
        "-f",
        "--filter",
        type=str,
        default=None,
        help="BPF filter string (e.g. 'tcp or udp', 'port 80').",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed debug logging.",
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.list_interfaces:
        handle_list_interfaces()
        return

    try:
        check_scapy_available()
    except ImportError as e:
        print(f"[!] Initialization Error: {e}", file=sys.stderr)
        sys.exit(1)

    print_banner(interface=args.interface, pcap=args.pcap)

    engine = PacketCaptureEngine(interface=args.interface)

    # Signal handler for graceful stop
    def stop_signal_handler(sig, frame):
        print("\n\n[!] Interrupt received. Initiating graceful shutdown...")
        engine.stop()

    signal.signal(signal.SIGINT, stop_signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop_signal_handler)

    def packet_printer(pkt):
        summary = format_packet_summary(pkt)
        print(f"[{engine.packet_count:05d}] {summary}")

    print("[+] Packet capture started. Listening for network traffic...\n")
    try:
        total = engine.capture(
            packet_callback=packet_printer,
            count=args.count,
            bpf_filter=args.filter,
            pcap_file=args.pcap,
        )
        print(f"\n[+] Packet capture finished successfully.")
        print(f"[+] Total packets captured: {total}")
    except PermissionError as e:
        print(f"\n[!] PERMISSION ERROR: {e}", file=sys.stderr)
        print(
            "    On Linux (Kali): run with 'sudo python3 -m ids.main ...'\n"
            "    On Windows: run PowerShell or Command Prompt as Administrator.",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Capture encountered an error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
