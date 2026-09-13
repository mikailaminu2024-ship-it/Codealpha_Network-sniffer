#!/usr/bin/env python3
"""
Basic Network Sniffer
----------------------
Captures live network packets and displays source/destination IPs,
protocol, and payload info.

Requirements:
    pip install scapy

Usage:
    sudo python3 network_sniffer.py            # sniff all traffic
    sudo python3 network_sniffer.py -i eth0    # sniff on a specific interface
    sudo python3 network_sniffer.py -c 50      # stop after 50 packets
    sudo python3 network_sniffer.py -f "tcp"   # BPF filter, e.g. tcp/udp/icmp/port 80

Note: Sniffing requires elevated privileges (sudo/root on Linux/macOS,
Administrator + Npcap on Windows). Only capture traffic on networks
you own or are authorized to monitor.
"""

import argparse
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def describe_protocol(packet):
    """Return a human-readable protocol name for the packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def format_payload(packet, max_len=60):
    """Extract and safely display a snippet of the payload, if present."""
    if packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        # Try to show as text, fall back to hex for binary data
        try:
            text = raw_bytes.decode("utf-8")
            snippet = text.replace("\n", " ").replace("\r", " ")
        except UnicodeDecodeError:
            snippet = raw_bytes.hex()
        return snippet[:max_len] + ("..." if len(snippet) > max_len else "")
    return ""


def process_packet(packet):
    """Callback invoked by scapy for every captured packet."""
    if not packet.haslayer(IP):
        return  # skip non-IP packets (e.g. ARP) for this basic sniffer

    ip_layer = packet[IP]
    timestamp = datetime.now().strftime("%H:%M:%S")
    proto = describe_protocol(packet)

    src_port = dst_port = None
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    src = f"{ip_layer.src}:{src_port}" if src_port else ip_layer.src
    dst = f"{ip_layer.dst}:{dst_port}" if dst_port else ip_layer.dst

    payload = format_payload(packet)

    print(f"[{timestamp}] {proto:5} | {src:>21} -> {dst:<21} | len={len(packet):4}", end="")
    if payload:
        print(f" | payload: {payload}")
    else:
        print()


def main():
    parser = argparse.ArgumentParser(description="Basic Python network sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: scapy picks)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter string, e.g. 'tcp', 'udp port 53'")
    args = parser.parse_args()

    print("Starting packet capture... (Ctrl+C to stop)")
    print(f"{'TIME':10} {'PROTO':5}   {'SOURCE':>21}    {'DESTINATION':<21}   LEN  PAYLOAD")
    print("-" * 100)

    try:
        sniff(
            iface=args.interface or None,
            filter=args.filter or None,
            prn=process_packet,
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("\nPermission denied. Try running with sudo/administrator privileges.")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")


if __name__ == "__main__":
    main()
