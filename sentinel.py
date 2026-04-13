#!/usr/bin/env python3
"""
SentinelDash — Phase 1
Personal Mac Security Dashboard
Author: Aryan Khanna, Purdue University

What this does:
- Shows your local IP, public IP, and VPN status
- Lists network interfaces
- Shows your Mac's open ports
- Pulls the latest Critical CVEs from NVD API
- Displays everything in a clean, styled terminal UI
"""

import socket
import subprocess
import json
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone
import os

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.text import Text
    from rich.rule import Rule
    from rich import box
    from rich.live import Live
    from rich.spinner import Spinner
    from rich.align import Align
except ImportError:
    print("Installing rich... run: pip install rich")
    exit(1)

console = Console()

# ─────────────────────────────────────────────
# NETWORK INFO
# ─────────────────────────────────────────────

def get_local_ip():
    """Get your local network IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Unknown"

def get_public_ip():
    """Get your public IP address."""
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as r:
            data = json.loads(r.read().decode())
            return data.get("ip", "Unknown")
    except Exception:
        return "Could not reach internet"

def get_vpn_status():
    """
    Check if a VPN is active by looking for tun/utun interfaces.
    Most VPNs (WireGuard, OpenVPN, etc.) create these interfaces.
    """
    try:
        result = subprocess.run(
            ["ifconfig"],
            capture_output=True, text=True, timeout=5
        )
        interfaces = result.stdout
        vpn_interfaces = []

        for line in interfaces.split("\n"):
            if line.startswith("utun") or line.startswith("tun") or line.startswith("ppp"):
                iface_name = line.split(":")[0]
                vpn_interfaces.append(iface_name)

        if vpn_interfaces:
            return ("ACTIVE", vpn_interfaces)
        else:
            return ("OFF", [])
    except Exception:
        return ("Unknown", [])

def get_wifi_name():
    """Get current WiFi network name (SSID)."""
    try:
        result = subprocess.run(
            ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            if " SSID:" in line:
                return line.strip().replace("SSID:", "").strip()
        return "Unknown"
    except Exception:
        try:
            result = subprocess.run(
                ["networksetup", "-getairportnetwork", "en0"],
                capture_output=True, text=True, timeout=5
            )
            if "Current Wi-Fi Network:" in result.stdout:
                return result.stdout.split("Current Wi-Fi Network:")[-1].strip()
        except Exception:
            pass
        return "Unknown"

# ─────────────────────────────────────────────
# OPEN PORTS
# ─────────────────────────────────────────────

def get_open_ports():
    """
    Get open listening ports on your Mac using lsof.
    This shows you what services are exposed on your machine.
    """
    try:
        result = subprocess.run(
            ["lsof", "-i", "-n", "-P"],
            capture_output=True, text=True, timeout=10
        )
        ports = {}
        for line in result.stdout.split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 9 and "LISTEN" in line:
                process = parts[0]
                addr = parts[8]
                if "*:" in addr or "0.0.0.0:" in addr or "127.0.0.1:" in addr:
                    port_num = addr.split(":")[-1]
                    if port_num not in ports:
                        ports[port_num] = process
        return ports
    except Exception:
        return {}

# ─────────────────────────────────────────────
# CVE FEED
# ─────────────────────────────────────────────

def get_recent_cves(limit=8):
    """
    Pull recent Critical and High CVEs from the NVD API.
    Free, no API key needed for basic usage.
    """
    try:
        # Look back 2 days for recent CVEs
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=2)

        start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
            f"pubStartDate={urllib.parse.quote(start_str)}&"
            f"pubEndDate={urllib.parse.quote(end_str)}&"
            f"cvssV3Severity=CRITICAL&"
            f"resultsPerPage={limit}"
        )

        req = urllib.request.Request(url, headers={"User-Agent": "SentinelDash/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "Unknown")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
            desc = desc[:80] + "..." if len(desc) > 80 else desc

            metrics = cve.get("metrics", {})
            score = "N/A"
            severity = "CRITICAL"
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                score = str(cvss.get("baseScore", "N/A"))
                severity = cvss.get("baseSeverity", "CRITICAL")
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                score = str(cvss.get("baseScore", "N/A"))
                severity = cvss.get("baseSeverity", "CRITICAL")

            cves.append({
                "id": cve_id,
                "description": desc,
                "score": score,
                "severity": severity
            })

        return cves

    except Exception as e:
        return [{"id": "Error", "description": f"Could not fetch CVEs: {str(e)[:60]}", "score": "N/A", "severity": "N/A"}]

# ─────────────────────────────────────────────
# RENDER DASHBOARD
# ─────────────────────────────────────────────

def render_dashboard():
    console.clear()

    # Header
    now = datetime.now().strftime("%A, %B %d %Y  •  %H:%M:%S")
    console.print()
    console.print(Align.center(
        Text("⚔  SENTINEL DASH", style="bold white on #0a0a0a") 
    ))
    console.print(Align.center(
        Text(f"Personal Security Dashboard  •  {now}", style="dim #888888")
    ))
    console.print()

    # ── Network Status Panel ──
    console.print(Rule("[bold #00ff9f]● NETWORK STATUS[/]", style="#1a1a1a"))
    console.print()

    local_ip = get_local_ip()
    public_ip = get_public_ip()
    vpn_status, vpn_ifaces = get_vpn_status()
    wifi = get_wifi_name()

    net_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    net_table.add_column("Label", style="dim #888888", width=18)
    net_table.add_column("Value", style="white")

    net_table.add_row("WiFi Network", f"[bold cyan]{wifi}[/]")
    net_table.add_row("Local IP", f"[bold white]{local_ip}[/]")
    net_table.add_row("Public IP", f"[bold white]{public_ip}[/]")

    if vpn_status == "ACTIVE":
        vpn_display = f"[bold #00ff9f]● ACTIVE[/]  [dim]({', '.join(vpn_ifaces)})[/]"
    elif vpn_status == "OFF":
        vpn_display = "[bold #ff4444]● OFF[/]  [dim](no VPN interface detected)[/]"
    else:
        vpn_display = "[bold yellow]? UNKNOWN[/]"

    net_table.add_row("VPN Status", vpn_display)
    console.print(net_table)

    # ── Open Ports Panel ──
    console.print(Rule("[bold #00ff9f]● OPEN PORTS ON THIS MACHINE[/]", style="#1a1a1a"))
    console.print()

    ports = get_open_ports()

    if ports:
        port_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
        port_table.add_column("Port", style="bold #ff9f00", width=8)
        port_table.add_column("Process", style="white", width=20)
        port_table.add_column("Risk", style="dim", width=20)

        # Common port risk notes
        risk_map = {
            "22": ("SSH", "#ff4444"),
            "80": ("HTTP — unencrypted", "#ff9f00"),
            "443": ("HTTPS — normal", "#00ff9f"),
            "3000": ("Dev server", "#888888"),
            "5000": ("Dev server", "#888888"),
            "8080": ("Alt HTTP", "#ff9f00"),
            "8443": ("Alt HTTPS", "#00ff9f"),
            "3306": ("MySQL — check exposure", "#ff4444"),
            "5432": ("PostgreSQL", "#ff9f00"),
            "6379": ("Redis — check exposure", "#ff4444"),
        }

        for port, process in sorted(ports.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 9999)[:12]:
            risk_label, risk_color = risk_map.get(port, ("", "#888888"))
            port_table.add_row(port, process[:18], f"[{risk_color}]{risk_label}[/]")

        console.print(port_table)
    else:
        console.print("  [dim]No open ports detected (or lsof permission denied)[/]")
        console.print()

    # ── CVE Feed ──
    console.print(Rule("[bold #00ff9f]● LATEST CRITICAL CVEs  [dim](past 48h)[/][/]", style="#1a1a1a"))
    console.print()

    with console.status("[dim]Fetching from NVD...[/]", spinner="dots"):
        cves = get_recent_cves()

    if cves:
        cve_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
        cve_table.add_column("CVE ID", style="bold #ff4444", width=18)
        cve_table.add_column("Score", style="bold white", width=6)
        cve_table.add_column("Description", style="dim white")

        for cve in cves:
            score = cve["score"]
            try:
                score_f = float(score)
                score_color = "#ff4444" if score_f >= 9.0 else "#ff9f00" if score_f >= 7.0 else "#ffff00"
            except Exception:
                score_color = "#888888"

            cve_table.add_row(
                cve["id"],
                f"[{score_color}]{score}[/]",
                cve["description"]
            )

        console.print(cve_table)
    else:
        console.print("  [dim]No critical CVEs found in the past 48 hours.[/]")

    console.print()
    console.print(Rule(style="#1a1a1a"))
    console.print(Align.center(
        Text("Phase 1 complete  •  Next: network scanner (Phase 2)", style="dim #555555")
    ))
    console.print()

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    render_dashboard()
