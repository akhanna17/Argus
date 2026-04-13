#!/usr/bin/env python3
"""
Argus — Device CVE Matcher
Scans your network, matches devices to known CVEs, sends personalized Discord alerts.
Author: Aryan Khanna, Purdue University
"""

import urllib.request, urllib.parse, json, os, subprocess, socket
from datetime import datetime, timezone

WEBHOOK_URL = open(os.path.expanduser("~/Desktop/sentineldash/webhook.txt")).read().strip()
SEEN_FILE = os.path.expanduser("~/.sentineldash_device_cves.json")

# ─────────────────────────────────────────────
# LOAD / SAVE SEEN
# ─────────────────────────────────────────────

def load_seen():
    try:
        with open(SEEN_FILE) as f: return set(json.load(f))
    except: return set()

def save_seen(seen):
    with open(SEEN_FILE, "w") as f: json.dump(list(seen), f)

# ─────────────────────────────────────────────
# NETWORK SCAN
# ─────────────────────────────────────────────

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def scan_network():
    """ARP scan to find devices on the network."""
    try:
        from scapy.all import ARP, Ether, srp
        local_ip = get_local_ip()
        parts = local_ip.split(".")
        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(ether/arp, timeout=3, verbose=False)

        devices = []
        for _, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0].split(".")[0]
            except:
                hostname = "unknown"
            vendor = get_vendor(mac)
            devices.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor})

        return devices
    except Exception as e:
        print(f"Scan error: {e}")
        return []

def get_vendor(mac):
    try:
        req = urllib.request.Request(
            f"https://api.macvendors.com/{urllib.parse.quote(mac)}",
            headers={"User-Agent": "Argus/1.0"}
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.read().decode().strip()[:40]
    except:
        return "Unknown"

# ─────────────────────────────────────────────
# CVE LOOKUP PER DEVICE
# ─────────────────────────────────────────────

def search_cves_for_device(vendor, hostname):
    """
    Search NVD for CVEs matching this device's vendor or hostname.
    Uses keyword search to find relevant vulnerabilities.
    """
    # Build smart search keywords from vendor/hostname
    keywords = []
    
    if vendor and vendor != "Unknown":
        # Extract brand name (e.g. "Calix Inc." -> "Calix")
        brand = vendor.split()[0].replace(",", "").replace(".", "")
        keywords.append(brand)
    
    if hostname and hostname not in ["unknown", "devicedhcp"]:
        keywords.append(hostname.split(".")[0])

    if not keywords:
        return []

    all_cves = []
    for keyword in keywords[:2]:  # Max 2 keywords to avoid rate limiting
        try:
            url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
                   f"keywordSearch={urllib.parse.quote(keyword)}&"
                   f"cvssV3Severity=CRITICAL&"
                   f"resultsPerPage=3")
            req = urllib.request.Request(url, headers={"User-Agent": "Argus/4.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode())

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "Unknown")
                desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
                metrics = cve.get("metrics", {})
                score = "N/A"
                if "cvssMetricV31" in metrics:
                    score = str(metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", "N/A"))
                elif "cvssMetricV30" in metrics:
                    score = str(metrics["cvssMetricV30"][0]["cvssData"].get("baseScore", "N/A"))

                all_cves.append({
                    "id": cve_id,
                    "description": desc[:300],
                    "score": score,
                    "keyword": keyword,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })
        except Exception as e:
            print(f"  CVE lookup error for {keyword}: {e}")

    # Deduplicate
    seen_ids = set()
    unique = []
    for c in all_cves:
        if c["id"] not in seen_ids:
            seen_ids.add(c["id"])
            unique.append(c)
    return unique

# ─────────────────────────────────────────────
# AI EXPLANATION
# ─────────────────────────────────────────────

def explain_device_cve(device_name, cve_id, description, score):
    """Use local Ollama to explain this CVE in context of the specific device."""
    try:
        prompt = f"""Explain this security vulnerability to a non-technical person in 2 short paragraphs.
First paragraph: what the vulnerability is and what an attacker could do with it.
Second paragraph: what the owner of a {device_name} device should do about it.
Keep it clear, friendly, and under 100 words total. No jargon.

CVE: {cve_id} (Score: {score}/10)
Details: {description}"""

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
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode()).get("response", "").strip()
    except:
        return "This is a critical vulnerability that could allow attackers to compromise your device. Apply any available firmware or software updates immediately."

# ─────────────────────────────────────────────
# DISCORD ALERT
# ─────────────────────────────────────────────

def send_device_alert(device, cve, explanation):
    """Send a personalized device vulnerability alert to Discord."""
    device_label = device.get("vendor", "Unknown Device")
    if device_label == "Unknown":
        device_label = device.get("hostname", "Unknown Device")

    try:
        score = float(cve["score"])
        color = 0xFF0000 if score >= 9.0 else 0xFF8800
    except:
        color = 0xFF0000

    payload = json.dumps({
        "username": "Argus",
        "embeds": [{
            "title": f"⚠️ Device on Your Network is Vulnerable",
            "description": (
                f"**Device:** {device_label} (`{device['ip']}`)\n"
                f"**CVE:** [{cve['id']}]({cve['url']}) — Score: **{cve['score']}/10**\n\n"
                f"**What this means:**\n{explanation}"
            ),
            "color": color,
            "footer": {"text": f"Argus Device Scanner • {datetime.now().strftime('%b %d %Y %H:%M')}"}
        }]
    }).encode()

    req = urllib.request.Request(
        WEBHOOK_URL, data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status == 204

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def run():
    print(f"\n🛡  Argus Device CVE Matcher — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("─" * 55)

    seen = load_seen()
    print("Scanning network for devices...")
    devices = scan_network()
    print(f"Found {len(devices)} device(s)\n")

    total_alerts = 0

    for device in devices:
        label = device.get("vendor", "Unknown")
        if label == "Unknown":
            label = device.get("hostname", "unknown")

        print(f"  Checking {device['ip']} ({label})...")
        cves = search_cves_for_device(device["vendor"], device["hostname"])

        if not cves:
            print(f"    No critical CVEs found")
            continue

        print(f"    Found {len(cves)} critical CVE(s)")

        for cve in cves:
            alert_key = f"{device['ip']}:{cve['id']}"
            if alert_key in seen:
                print(f"    Already alerted: {cve['id']}")
                continue

            print(f"    Explaining {cve['id']} with AI...")
            explanation = explain_device_cve(label, cve["id"], cve["description"], cve["score"])

            print(f"    Sending Discord alert...")
            try:
                send_device_alert(device, cve, explanation)
                seen.add(alert_key)
                total_alerts += 1
                print(f"    ✓ Sent")
            except Exception as e:
                print(f"    ✗ Failed: {e}")

    save_seen(seen)
    print(f"\n✓ Done — {total_alerts} new alert(s) sent")
    print("─" * 55)

if __name__ == "__main__":
    run()
