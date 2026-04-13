#!/usr/bin/env python3
"""
Argus — Phase 2
Network Scanner
Author: Aryan Khanna, Purdue University

What this does:
- Scans your local network using ARP
- Shows every device: IP, MAC address, hostname, vendor
- Flags unknown/new devices
- Integrates into the main sentinel.py dashboard
"""

import subprocess
import socket
import urllib.request
import urllib.parse
import json
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp
except ImportError:
    print("Run: pip3 install scapy")
    exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.rule import Rule
    from rich import box
    from rich.text import Text
    from rich.align import Align
except ImportError:
    print("Run: pip3 install rich")
    exit(1)

console = Console()

# ─────────────────────────────────────────────
# GET YOUR NETWORK RANGE
# ─────────────────────────────────────────────

def get_network_range():
    """
    Figure out your local network range automatically.
    e.g. if your IP is 192.168.4.98, your range is 192.168.4.0/24
    which means scan all 255 devices on that subnet.
    """
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Turn 192.168.4.98 into 192.168.4.0/24
        parts = local_ip.split(".")
        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return network, local_ip
    except Exception:
        return "192.168.1.0/24", "unknown"

# ─────────────────────────────────────────────
# ARP SCAN
# ─────────────────────────────────────────────

def scan_network(network_range):
    """
    Send ARP requests to every IP in the range.
    Devices that respond are active on your network.
    
    ARP (Address Resolution Protocol) is how devices on a 
    local network announce themselves. When you send an ARP 
    request to an IP, the device at that IP responds with 
    its MAC address. No response = no device there.
    """
    try:
        # Create ARP packet targeting the whole subnet
        arp_request = ARP(pdst=network_range)
        # Wrap it in an Ethernet broadcast frame
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        # Send packets, collect responses, timeout after 3 seconds
        answered, _ = srp(packet, timeout=3, verbose=False)

        devices = []
        for sent, received in answered:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
            })

        # Sort by last octet of IP for clean display
        devices.sort(key=lambda x: int(x["ip"].split(".")[-1]))
        return devices

    except PermissionError:
        console.print("[bold red]Permission denied.[/] Run with sudo: [bold]sudo python3 scanner.py[/]")
        return []
    except Exception as e:
        console.print(f"[red]Scan error: {e}[/]")
        return []

# ─────────────────────────────────────────────
# HOSTNAME LOOKUP
# ─────────────────────────────────────────────

def get_hostname(ip):
    """Try to resolve IP to a hostname."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname.split(".")[0]  # Just the short name
    except Exception:
        return "unknown"

# ─────────────────────────────────────────────
# MAC VENDOR LOOKUP
# ─────────────────────────────────────────────

def get_vendor(mac):
    """
    Look up who manufactured a device based on its MAC address.
    The first 3 bytes of a MAC address identify the manufacturer.
    This uses the free macvendors.com API.
    """
    try:
        mac_prefix = mac.replace(":", "").upper()[:6]
        url = f"https://api.macvendors.com/{urllib.parse.quote(mac)}"
        req = urllib.request.Request(url, headers={"User-Agent": "Argus/2.0"})
        with urllib.request.urlopen(req, timeout=3) as r:
            vendor = r.read().decode().strip()
            return vendor[:30] if vendor else "Unknown"
    except Exception:
        return "Unknown"

# ─────────────────────────────────────────────
# RENDER SCANNER
# ─────────────────────────────────────────────

def run_scanner():
    console.clear()

    now = datetime.now().strftime("%A, %B %d %Y  •  %H:%M:%S")
    console.print()
    console.print(Align.center(Text("⚔  SENTINEL DASH", style="bold white")))
    console.print(Align.center(Text(f"Network Scanner  •  {now}", style="dim #888888")))
    console.print()

    network_range, local_ip = get_network_range()

    console.print(Rule("[bold #00ff9f]● SCANNING NETWORK[/]", style="#1a1a1a"))
    console.print()
    console.print(f"  [dim]Network:[/] [white]{network_range}[/]   [dim]Your IP:[/] [cyan]{local_ip}[/]")
    console.print()

    with console.status("[dim]Sending ARP requests across subnet...[/]", spinner="dots"):
        devices = scan_network(network_range)

    if not devices:
        console.print("  [red]No devices found. Try running with sudo:[/]")
        console.print("  [bold]sudo python3 ~/Desktop/sentineldash/scanner.py[/]")
        return

    console.print(f"  [bold #00ff9f]Found {len(devices)} device(s) on your network[/]")
    console.print()

    # Build table
    table = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
    table.add_column("IP Address", style="bold cyan", width=16)
    table.add_column("MAC Address", style="dim white", width=20)
    table.add_column("Hostname", style="white", width=20)
    table.add_column("Vendor", style="#ff9f00", width=28)
    table.add_column("", width=8)

    for device in devices:
        ip = device["ip"]
        mac = device["mac"]

        with console.status(f"[dim]Looking up {ip}...[/]", spinner="dots"):
            hostname = get_hostname(ip)
            vendor = get_vendor(mac)

        # Flag your own device
        tag = ""
        if ip == local_ip:
            tag = "[bold #00ff9f]← you[/]"

        table.add_row(ip, mac, hostname, vendor, tag)

    console.print(table)
    console.print()
    console.print(Rule(style="#1a1a1a"))
    console.print(Align.center(
        Text("Phase 2 complete  •  Next: CVE alerts to Discord (Phase 3)", style="dim #555555")
    ))
    console.print()

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    run_scanner()
