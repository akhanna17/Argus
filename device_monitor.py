#!/usr/bin/env python3
"""
Argus — New Device Monitor
Detects when unknown devices join your network and alerts via Discord.
Author: Aryan Khanna, Purdue University

Run this on a schedule (every 5 minutes via cron) or manually.
It will alert you instantly when a new device joins your WiFi.
"""

import socket, json, os, urllib.request
from datetime import datetime
from scapy.all import ARP, Ether, srp

KNOWN_FILE = os.path.expanduser("~/Desktop/argus/data/known_devices.json")
DEVICES_FILE = os.path.expanduser("~/Desktop/argus/data/devices.json")
WEBHOOK_FILE = os.path.expanduser("~/Desktop/argus/webhook.txt")

# ─────────────────────────────────────────────
# LOAD WEBHOOK
# ─────────────────────────────────────────────

def get_webhook():
    try:
        return open(WEBHOOK_FILE).read().strip()
    except:
        return None

# ─────────────────────────────────────────────
# LOAD / SAVE KNOWN DEVICES
# ─────────────────────────────────────────────

def load_known():
    try:
        return json.load(open(KNOWN_FILE))
    except:
        return {}

def save_known(known):
    json.dump(known, open(KNOWN_FILE, "w"), indent=2)

# ─────────────────────────────────────────────
# SCAN NETWORK
# ─────────────────────────────────────────────

def scan():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        network = parts[0]+"."+parts[1]+"."+parts[2]+".0/24"

        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(ether/arp, timeout=3, verbose=False)

        devices = []
        for _, r in answered:
            try:
                hostname = socket.gethostbyaddr(r.psrc)[0].split(".")[0]
            except:
                hostname = "unknown"
            devices.append({"ip": r.psrc, "mac": r.hwsrc, "hostname": hostname})

        # Save all devices for dashboard
        json.dump(devices, open(DEVICES_FILE, "w"))
        return devices, local_ip
    except Exception as e:
        print(f"Scan error: {e}")
        return [], ""

# ─────────────────────────────────────────────
# GET VENDOR
# ─────────────────────────────────────────────

def get_vendor(mac):
    try:
        req = urllib.request.Request(
            f"https://api.macvendors.com/{mac}",
            headers={"User-Agent": "Argus/1.0"}
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.read().decode().strip()[:40]
    except:
        return "Unknown"

# ─────────────────────────────────────────────
# AI EXPLAIN NEW DEVICE
# ─────────────────────────────────────────────

def explain_device(hostname, vendor, ip, mac):
    try:
        prompt = f"""A new device just joined a home WiFi network. Explain in 2 short sentences:
1. What this device probably is
2. Whether the owner should be concerned or not
Device info: hostname={hostname}, vendor={vendor}, IP={ip}
Be friendly and simple. If it seems harmless, reassure them. If it seems suspicious, say so clearly."""

        payload = json.dumps({
            "model": "llama3.2",
            "prompt": prompt,
            "stream": False
        }).encode()

        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode()).get("response", "").strip()
    except:
        return "A new device joined your network. If you do not recognize it, consider changing your WiFi password."

# ─────────────────────────────────────────────
# SEND DISCORD ALERT
# ─────────────────────────────────────────────

def send_alert(device, vendor, explanation, webhook_url):
    try:
        now = datetime.now().strftime("%b %d at %I:%M %p")
        payload = json.dumps({
            "username": "Argus",
            "embeds": [{
                "title": "New Device Joined Your Network",
                "description": (
                    f"**Device:** {device['hostname']}\n"
                    f"**IP Address:** {device['ip']}\n"
                    f"**MAC Address:** {device['mac']}\n"
                    f"**Manufacturer:** {vendor}\n"
                    f"**Detected:** {now}\n\n"
                    f"**What Argus thinks:**\n{explanation}"
                ),
                "color": 0xFF9F0A,
                "footer": {"text": "Argus Network Monitor"}
            }]
        }).encode()

        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 204
    except Exception as e:
        print(f"Alert failed: {e}")
        return False

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def run():
    print(f"\n  Argus Device Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  " + "-" * 40)

    webhook = get_webhook()
    if not webhook:
        print("  No webhook found. Add webhook URL to ~/Desktop/argus/webhook.txt")
        return

    known = load_known()
    print(f"  Known devices: {len(known)}")

    print("  Scanning network...")
    devices, local_ip = scan()
    print(f"  Found {len(devices)} devices")

    new_devices = []
    for device in devices:
        mac = device["mac"]
        if mac not in known:
            new_devices.append(device)
            known[mac] = {
                "ip": device["ip"],
                "hostname": device["hostname"],
                "first_seen": str(datetime.now())
            }

    if not new_devices:
        print("  No new devices detected. All clear.")
    else:
        print(f"  NEW DEVICES DETECTED: {len(new_devices)}")
        for device in new_devices:
            print(f"  -> {device['ip']} ({device['hostname']})")
            vendor = get_vendor(device["mac"])
            print(f"     Vendor: {vendor}")
            print(f"     Getting AI explanation...")
            explanation = explain_device(device["hostname"], vendor, device["ip"], device["mac"])
            print(f"     Sending Discord alert...")
            success = send_alert(device, vendor, explanation, webhook)
            print(f"     {'Sent!' if success else 'Failed to send'}")

    save_known(known)
    print(f"  Done. Total known devices: {len(known)}")

if __name__ == "__main__":
    run()
