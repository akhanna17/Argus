#!/usr/bin/env python3
"""
Argus — Web dashboard for personal Mac security monitoring.

This file powers a simple browser dashboard that shows:
- VPN status
- local and public IPs
- open ports on the Mac
- latest critical CVEs from the NVD
- device scan data if available

Requirements:
- Python 3
- Flask installed: pip install flask
- macOS tools: ifconfig, airport, lsof
- Optional: device scan output in ~/Desktop/argus/data/devices.json
"""

from flask import Flask, jsonify, render_template_string
import json
import os
import socket
import subprocess
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
ARGUS_DIR = os.path.expanduser("~/Desktop/argus")
DEVICES_FILE = os.path.join(ARGUS_DIR, "data", "devices.json")


def get_network_info():
    """Return local IP, public IP, VPN state, and Wi-Fi name."""
    local_ip = "Unknown"
    public_ip = "Unknown"
    vpn_active = False
    wifi_name = "Unknown"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
    except Exception:
        pass

    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as response:
            public_ip = json.loads(response.read().decode()).get("ip", public_ip)
    except Exception:
        pass

    try:
        result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
        vpn_active = any(line.startswith("utun") or line.startswith("tun") or line.startswith("ppp") for line in result.stdout.splitlines())
    except Exception:
        pass

    try:
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        result = subprocess.run([airport, "-I"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if " SSID:" in line:
                wifi_name = line.split(":", 1)[1].strip()
                break
    except Exception:
        pass

    return {
        "local_ip": local_ip,
        "public_ip": public_ip,
        "vpn": vpn_active,
        "wifi": wifi_name,
    }


def get_open_ports():
    """Return the list of open listening ports on this Mac."""
    ports = []
    try:
        result = subprocess.run(["lsof", "-i", "-n", "-P"], capture_output=True, text=True, timeout=10)
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
                if len(ports) >= 10:
                    break
    except Exception:
        pass
    return ports


def get_cves():
    """Fetch the latest critical CVEs from the NVD API."""
    cves = []
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=48)
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0?"
            f"pubStartDate={urllib.parse.quote(start.strftime('%Y-%m-%dT%H:%M:%S.000'))}&"
            f"pubEndDate={urllib.parse.quote(end.strftime('%Y-%m-%dT%H:%M:%S.000'))}&"
            "cvssV3Severity=CRITICAL&resultsPerPage=8"
        )
        req = urllib.request.Request(url, headers={"User-Agent": "Argus/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
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
    except Exception:
        pass
    return cves


def get_devices():
    """Read saved device scan results if they exist."""
    try:
        if os.path.exists(DEVICES_FILE):
            return json.load(open(DEVICES_FILE))
    except Exception:
        pass
    return []


def compute_health(network, ports, cves):
    """Create a simple score for the main dashboard."""
    score = 100
    if not network.get("vpn"):
        score -= 20
    score -= min(25, len([p for p in ports if p["risk"] == "high"]) * 10)
    score -= min(20, len([p for p in ports if p["risk"] == "medium"]) * 5)
    score -= min(30, len(cves) * 4)
    score = max(0, score)
    label = "Healthy" if score >= 80 else "Monitor" if score >= 55 else "At Risk"
    return {"score": score, "label": label}


@app.route("/api/data")
def api_data():
    network = get_network_info()
    ports = get_open_ports()
    cves = get_cves()
    devices = get_devices()
    health = compute_health(network, ports, cves)
    return jsonify({"network": network, "ports": ports, "cves": cves, "devices": devices, "health": health})


@app.route("/")
def index():
    return render_template_string(HTML)


HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Argus</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#070b14;--surface:rgba(255,255,255,.06);--surface-strong:rgba(255,255,255,.12);--border:rgba(255,255,255,.1);--text:#f8fafc;--muted:#9aa5b5;--green:#30d158;--yellow:#ffd60a;--red:#ff6b6b;--blue:#5ac8fa;--radius:20px;--max:1180px}
body{background:var(--bg);color:var(--text);font-family:'Inter',-apple-system,system-ui,sans-serif;min-height:100vh}
.container{max-width:var(--max);margin:0 auto;padding:28px 24px 48px}
.topbar{display:flex;flex-wrap:wrap;justify-content:space-between;gap:18px;margin-bottom:24px}
.brand{font-size:28px;font-weight:700;letter-spacing:-.04em}
.subtitle{color:var(--muted);max-width:720px;line-height:1.6;margin-top:8px}
.button{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:10px 16px;border-radius:999px;font-size:13px;cursor:pointer;transition:all .2s}
.button:hover{background:var(--surface-strong)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:22px;backdrop-filter:blur(20px)}
.card-title{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.16em;color:var(--muted);margin-bottom:16px}
.row{display:flex;justify-content:space-between;gap:12px;padding:12px 0;border-bottom:1px solid rgba(255,255,255,.05)}
.row:last-child{border-bottom:none}
.label{color:var(--muted);font-size:13px}
.value{font-size:15px;font-weight:600}
.badge{display:inline-flex;align-items:center;padding:6px 10px;border-radius:999px;font-size:12px;font-weight:700}
.badge.green{background:rgba(48,209,88,.18);color:var(--green)}
.badge.yellow{background:rgba(255,214,10,.18);color:var(--yellow)}
.badge.red{background:rgba(255,107,107,.18);color:var(--red)}
.table{width:100%;border-collapse:collapse;font-size:13px}
.table th{text-align:left;color:var(--muted);font-size:12px;font-weight:700;padding-bottom:12px}
.table td{padding:12px 0;border-top:1px solid rgba(255,255,255,.05)}
.table a{color:var(--blue);text-decoration:none}
.table a:hover{text-decoration:underline}
.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:30px 0 16px}
.section-head h2{font-size:18px;font-weight:700}
.note{color:var(--muted);font-size:13px;line-height:1.6}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="container">
  <div class="topbar">
    <div>
      <div class="brand">Argus</div>
      <div class="subtitle">A clean security dashboard for your Mac. See your network, VPN, open ports, devices, and critical threats.</div>
    </div>
    <button class="button" onclick="refresh()">Refresh</button>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-title">Live security snapshot</div>
      <div class="row"><div class="label">Score</div><div id="score" class="value">—</div></div>
      <div class="row"><div class="label">VPN</div><div id="vpn" class="value">—</div></div>
      <div class="row"><div class="label">Wi-Fi</div><div id="wifi" class="value">—</div></div>
      <div class="row"><div class="label">Local IP</div><div id="local_ip" class="value">—</div></div>
      <div class="row"><div class="label">Public IP</div><div id="public_ip" class="value">—</div></div>
    </div>
    <div class="card">
      <div class="card-title">What Argus sees</div>
      <div id="summary" class="note">Loading data from your Mac...</div>
    </div>
  </div>

  <div class="section-head"><h2>Network map</h2><span class="note">Devices found by the scanner script.</span></div>
  <div id="devices" class="card"><div class="note">Loading devices…</div></div>

  <div class="section-head"><h2>Open ports</h2><span class="note">Services listening on your machine.</span></div>
  <div id="ports" class="card"><div class="note">Loading open ports…</div></div>

  <div class="section-head"><h2>Latest critical CVEs</h2><span class="note">Recent vulnerabilities from NVD.</span></div>
  <div id="cves" class="card"><div class="note">Loading CVE data…</div></div>

  <div class="card">
    <div class="card-title">Alerts</div>
    <div class="note">Discord and phone alerting is handled by the Argus alert scripts. This dashboard gives you a live view of your Mac and network.</div>
  </div>
</div>

<script>
function badge(level){
  if(level === 'high') return 'badge red';
  if(level === 'medium') return 'badge yellow';
  return 'badge green';
}

function setText(id, value){document.getElementById(id).textContent = value}

async function refresh(){
  setText('summary', 'Refreshing data…')
  try {
    const data = await fetch('/api/data').then(r => r.json())
    setText('score', data.health.score + ' / 100')
    document.getElementById('vpn').innerHTML = data.network.vpn ? '<span class="badge green">Active</span>' : '<span class="badge red">Off</span>'
    setText('wifi', data.network.wifi || 'Unknown')
    setText('local_ip', data.network.local_ip)
    setText('public_ip', data.network.public_ip)
    setText('summary', `Argus sees ${data.devices.length} device(s), ${data.ports.length} open port(s), and ${data.cves.length} recent critical CVE(s).`)
    document.getElementById('devices').innerHTML = data.devices.length ? data.devices.map(d => `\n      <div class="row"><div><strong>${d.hostname || 'unknown'}</strong><div class="note">${d.ip} · ${d.mac}</div></div><div class="note">${d.vendor || 'Unknown'}</div></div>\n    `).join('') : '<div class="note">No device scan data available. Run scanner.py to collect network devices.</div>'
    document.getElementById('ports').innerHTML = data.ports.length ? `\n      <table class="table"><thead><tr><th>Port</th><th>Process</th><th>Type</th><th>Risk</th></tr></thead><tbody>${data.ports.map(p => `\n        <tr><td>${p.port}</td><td>${p.process}</td><td>${p.type}</td><td><span class="${badge(p.risk)}">${p.risk}</span></td></tr>\n      `).join('')}</tbody></table>\n    ` : '<div class="note">No open ports found or lsof could not run.</div>'
    document.getElementById('cves').innerHTML = data.cves.length ? `\n      <table class="table"><thead><tr><th>CVE</th><th>Score</th><th>Published</th><th>Description</th></tr></thead><tbody>${data.cves.map(c => `\n        <tr><td><a href="${c.url}" target="_blank">${c.id}</a></td><td><span class="${badge(parseFloat(c.score) >= 9 ? 'high' : 'medium')}">${c.score}</span></td><td>${c.published}</td><td>${c.description}</td></tr>\n      `).join('')}</tbody></table>\n    ` : '<div class="note">No critical CVEs found in the last 48 hours.</div>'
  } catch (error) {
    setText('summary', 'Unable to load dashboard data. Make sure Argus is running on macOS with network access.')
  }
}

refresh()
setInterval(refresh, 60000)
</script>
</body>
</html>''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
