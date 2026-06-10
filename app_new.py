#!/usr/bin/env python3
"""
Argus — Web dashboard for personal Mac security monitoring.

This file powers a Flask web application for the Argus dashboard.
It provides a better UI structure, caching, improved network detection,
critical CVE reporting, device discovery, and status summary information.

Requirements:
- Python 3
- Flask installed: pip install flask
- macOS tools (optional): ifconfig, airport, lsof
- Optional scanner device data file: ~/Desktop/argus/data/devices.json
"""

from flask import Flask, jsonify, render_template
import json
import logging
import os
import socket
import subprocess
import time
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["ARGUS_DIR"] = os.getenv("ARGUS_DIR", "~/Desktop/argus")
app.config["CACHE_TTL"] = int(os.getenv("ARGUS_CACHE_TTL", "45"))
ARGUS_DIR = os.path.expanduser(app.config["ARGUS_DIR"])
DEVICES_FILE = os.path.join(ARGUS_DIR, "data", "devices.json")
DATA_CACHE = {"timestamp": 0, "payload": None}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("argus")


def safe_run(command, timeout=8):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        logger.debug("Subprocess failed for %s: %s", command, exc)
        return None


def get_network_info():
    local_ip = "Unknown"
    public_ip = "Unknown"
    vpn_active = False
    wifi_name = "Unknown"
    vpn_interface = "Unknown"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
    except Exception:
        logger.debug("Unable to resolve local IP")

    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as response:
            public_ip = json.loads(response.read().decode()).get("ip", public_ip)
    except Exception:
        logger.debug("Unable to get public IP")

    result = safe_run(["ifconfig"], timeout=6)
    if result and result.stdout:
        for line in result.stdout.splitlines():
            if not line or line.startswith("\t"):
                continue
            iface = line.split(":")[0].strip()
            if iface.startswith(("utun", "tun", "ppp")):
                vpn_active = True
                vpn_interface = iface
                break

    airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    if os.path.exists(airport_path):
        result = safe_run([airport_path, "-I"], timeout=5)
        if result and result.stdout:
            for line in result.stdout.splitlines():
                if " SSID:" in line:
                    wifi_name = line.split(":", 1)[1].strip()
                    break

    return {
        "local_ip": local_ip,
        "public_ip": public_ip,
        "vpn": vpn_active,
        "wifi": wifi_name,
        "interface": vpn_interface,
    }


def get_open_ports():
    ports = []
    result = safe_run(["lsof", "-i", "-n", "-P"], timeout=10)
    if not result or not result.stdout:
        return ports

    risk_map = {
        "22": "SSH",
        "80": "HTTP",
        "443": "HTTPS",
        "3000": "Dev",
        "5000": "Dev",
        "8080": "HTTP",
        "3306": "MySQL",
        "5432": "Postgres",
        "6379": "Redis",
        "8443": "HTTPS",
    }

    seen = set()
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9 or "LISTEN" not in line:
            continue
        address = parts[8]
        if any(prefix in address for prefix in ["*:", "0.0.0.0:", "127.0.0.1:"]):
            port = address.split(":")[-1]
            if port in seen:
                continue
            seen.add(port)
            ports.append({
                "port": port,
                "process": parts[0],
                "type": risk_map.get(port, parts[0]),
                "risk": "high" if port in ["22", "3306", "5432", "6379"] else "medium" if port in ["80", "8080"] else "low",
            })
            if len(ports) >= 15:
                break

    return ports


def get_cves():
    cves = []
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=48)
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?"
            f"pubStartDate={urllib.parse.quote(start.strftime('%Y-%m-%dT%H:%M:%S.000'))}&"
            f"pubEndDate={urllib.parse.quote(end.strftime('%Y-%m-%dT%H:%M:%S.000'))}&"
            "cvssV3Severity=CRITICAL&resultsPerPage=10"
        )
        req = urllib.request.Request(url, headers={"User-Agent": "Argus/1.0"})
        with urllib.request.urlopen(req, timeout=12) as response:
            data = json.loads(response.read().decode())

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "No description")
            metrics = cve.get("metrics", {})
            score = "N/A"
            if "cvssMetricV31" in metrics:
                score = str(metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", "N/A"))
            elif "cvssMetricV30" in metrics:
                score = str(metrics["cvssMetricV30"][0]["cvssData"].get("baseScore", "N/A"))

            cves.append({
                "id": cve.get("id", "Unknown"),
                "score": score,
                "description": desc[:120] + ("..." if len(desc) > 120 else ""),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
                "published": cve.get("published", "")[:10],
            })
    except Exception as exc:
        logger.debug("Unable to load CVEs: %s", exc)

    return cves


def get_devices():
    try:
        if os.path.exists(DEVICES_FILE):
            with open(DEVICES_FILE, "r", encoding="utf-8") as payload:
                return json.load(payload)
    except Exception as exc:
        logger.debug("Unable to read devices file %s: %s", DEVICES_FILE, exc)
    return []


def compute_health(network, ports, cves):
    score = 100
    if not network.get("vpn"):
        score -= 20
    score -= min(25, len([p for p in ports if p["risk"] == "high"]) * 10)
    score -= min(20, len([p for p in ports if p["risk"] == "medium"]) * 5)
    score -= min(20, len(cves) * 4)
    score = max(0, score)
    label = "Healthy" if score >= 80 else "Monitor" if score >= 55 else "At Risk"
    return {"score": score, "label": label}


def get_dashboard_data():
    now = time.time()
    if DATA_CACHE["payload"] and now - DATA_CACHE["timestamp"] < app.config["CACHE_TTL"]:
        return DATA_CACHE["payload"]

    data = {
        "network": get_network_info(),
        "ports": get_open_ports(),
        "cves": get_cves(),
        "devices": get_devices(),
        "health": None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    data["health"] = compute_health(data["network"], data["ports"], data["cves"])
    DATA_CACHE["payload"] = data
    DATA_CACHE["timestamp"] = now
    return data


@app.route("/api/data")
def api_data():
    return jsonify(get_dashboard_data())


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('ARGUS_PORT', '5001')), debug=False)
