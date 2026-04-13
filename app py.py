#!/usr/bin/env python3
"""
SentinelDash — Phase 5: Web UI (Apple aesthetic)
Author: Aryan Khanna, Purdue University
"""

from flask import Flask, jsonify, render_template_string
import subprocess, socket, json, os, urllib.request, urllib.parse
from datetime import datetime, timedelta, timezone

app = Flask(__name__)

def get_network_info():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "Unknown"
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as r:
            public_ip = json.loads(r.read().decode()).get("ip", "Unknown")
    except:
        public_ip = "Unknown"
    try:
        result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
        vpn_active = any(line.startswith("utun") or line.startswith("tun") for line in result.stdout.split("\n"))
    except:
        vpn_active = False
    try:
        result = subprocess.run(
            ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
            capture_output=True, text=True, timeout=5)
        wifi = "Unknown"
        for line in result.stdout.split("\n"):
            if " SSID:" in line:
                wifi = line.strip().replace("SSID:", "").strip()
                break
    except:
        wifi = "Unknown"
    return {"local_ip": local_ip, "public_ip": public_ip, "vpn": vpn_active, "wifi": wifi}

def get_open_ports():
    try:
        result = subprocess.run(["lsof", "-i", "-n", "-P"], capture_output=True, text=True, timeout=10)
        ports = {}
        risk_map = {"22": "SSH", "80": "HTTP", "443": "HTTPS", "3000": "Dev", "5000": "Dev",
                    "8080": "HTTP", "3306": "MySQL", "5432": "Postgres", "6379": "Redis", "8443": "HTTPS"}
        for line in result.stdout.split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 9 and "LISTEN" in line:
                addr = parts[8]
                if "*:" in addr or "0.0.0.0:" in addr or "127.0.0.1:" in addr:
                    port = addr.split(":")[-1]
                    if port not in ports:
                        ports[port] = {"process": parts[0], "risk": risk_map.get(port, "—")}
        return [{"port": k, "process": v["process"], "risk": v["risk"]}
                for k, v in sorted(ports.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 9999)[:8]]
    except:
        return []

def get_cves():
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=48)
        url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
               f"pubStartDate={urllib.parse.quote(start.strftime('%Y-%m-%dT%H:%M:%S.000'))}&"
               f"pubEndDate={urllib.parse.quote(end.strftime('%Y-%m-%dT%H:%M:%S.000'))}&"
               f"cvssV3Severity=CRITICAL&resultsPerPage=8")
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelDash/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
            metrics = cve.get("metrics", {})
            score = "N/A"
            if "cvssMetricV31" in metrics:
                score = str(metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", "N/A"))
            elif "cvssMetricV30" in metrics:
                score = str(metrics["cvssMetricV30"][0]["cvssData"].get("baseScore", "N/A"))
            cves.append({
                "id": cve.get("id"), "score": score,
                "description": desc[:110] + "…" if len(desc) > 110 else desc,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
                "published": cve.get("published", "")[:10]
            })
        return cves
    except:
        return []

@app.route("/api/network")
def api_network(): return jsonify(get_network_info())

@app.route("/api/ports")
def api_ports(): return jsonify(get_open_ports())

@app.route("/api/cves")
def api_cves(): return jsonify(get_cves())

@app.route("/")
def index(): return render_template_string(HTML)

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentinelDash</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg: #0a0a0a;
  --surface: rgba(255,255,255,0.04);
  --surface-hover: rgba(255,255,255,0.07);
  --border: rgba(255,255,255,0.08);
  --border-strong: rgba(255,255,255,0.14);
  --text: rgba(255,255,255,0.9);
  --text-2: rgba(255,255,255,0.45);
  --text-3: rgba(255,255,255,0.25);
  --accent: #2997ff;
  --red: #ff453a;
  --orange: #ff9f0a;
  --green: #30d158;
  --r: 16px;
}
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 14px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
  min-height: 100vh;
}
nav {
  position: sticky; top: 0; z-index: 50;
  padding: 0 28px; height: 52px;
  display: flex; align-items: center; justify-content: space-between;
  background: rgba(10,10,10,0.8);
  backdrop-filter: blur(24px) saturate(1.8);
  -webkit-backdrop-filter: blur(24px) saturate(1.8);
  border-bottom: 1px solid var(--border);
}
.brand { font-size: 15px; font-weight: 600; letter-spacing: -0.02em; }
.nav-r { display: flex; align-items: center; gap: 16px; }
.live { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-2); font-weight: 500; }
.dot { width: 6px; height: 6px; border-radius: 50%; background: var(--green); animation: breathe 2.4s ease-in-out infinite; }
@keyframes breathe { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.4;transform:scale(.85)} }
#clock { font-size: 12px; color: var(--text-3); font-variant-numeric: tabular-nums; }
.btn {
  background: var(--surface); border: 1px solid var(--border);
  color: var(--text-2); font-family: inherit; font-size: 12px; font-weight: 500;
  padding: 5px 14px; border-radius: 20px; cursor: pointer; transition: all .15s;
}
.btn:hover { background: var(--surface-hover); border-color: var(--border-strong); color: var(--text); }
main { max-width: 1080px; margin: 0 auto; padding: 32px 28px 60px; }
h1 { font-size: 26px; font-weight: 600; letter-spacing: -.03em; margin-bottom: 4px; }
.sub { font-size: 13px; color: var(--text-2); margin-bottom: 32px; }
.section { font-size: 11px; font-weight: 600; letter-spacing: .06em; text-transform: uppercase; color: var(--text-3); margin: 28px 0 12px; }
.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--r); padding: 20px 22px; transition: border-color .2s;
}
.card:hover { border-color: var(--border-strong); }
.g2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.clabel { font-size: 11px; font-weight: 600; letter-spacing: .05em; text-transform: uppercase; color: var(--text-3); margin-bottom: 16px; }
.row { display: flex; align-items: center; justify-content: space-between; padding: 9px 0; border-bottom: 1px solid var(--border); }
.row:last-child { border-bottom: none; }
.rk { font-size: 13px; color: var(--text-2); }
.rv { font-size: 13px; font-weight: 500; color: var(--text); }
.vpn-on { color: var(--green); }
.vpn-off { color: var(--red); }
.pill { display: inline-flex; align-items: center; padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 500; }
.pn { background: rgba(255,255,255,.06); color: var(--text-2); }
.pr { background: rgba(255,69,58,.15); color: #ff6961; }
.po { background: rgba(255,159,10,.15); color: #ffb340; }
.pg { background: rgba(48,209,88,.12); color: #34c759; }
.pb { background: rgba(41,151,255,.15); color: #64aaff; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; font-size: 11px; font-weight: 600; letter-spacing: .05em; text-transform: uppercase; color: var(--text-3); padding: 0 0 12px; border-bottom: 1px solid var(--border); }
td { padding: 11px 0; font-size: 13px; border-bottom: 1px solid var(--border); vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,.015); }
a.cid { color: var(--accent); text-decoration: none; font-weight: 500; }
a.cid:hover { text-decoration: underline; }
.cdesc { color: var(--text-2); font-size: 12px; line-height: 1.4; max-width: 460px; }
.sc { font-weight: 600; }
.sc-c { color: var(--red); }
.sc-h { color: var(--orange); }
.dt { font-size: 11px; color: var(--text-3); font-variant-numeric: tabular-nums; }
.loading { font-size: 13px; color: var(--text-3); padding: 6px 0; }
footer { border-top: 1px solid var(--border); padding: 14px 28px; display: flex; justify-content: space-between; }
.ft { font-size: 12px; color: var(--text-3); }
</style>
</head>
<body>
<nav>
  <span class="brand">SentinelDash</span>
  <div class="nav-r">
    <span class="live"><span class="dot"></span>Live</span>
    <span id="clock">--:--:--</span>
    <button class="btn" onclick="loadAll()">Refresh</button>
  </div>
</nav>
<main>
  <h1>Security Overview</h1>
  <p class="sub">Personal network monitor &middot; Aryan Khanna, Purdue University</p>
  <div class="section">Network</div>
  <div class="g2">
    <div class="card">
      <div class="clabel">Connection</div>
      <div id="net"><div class="loading">Loading&hellip;</div></div>
    </div>
    <div class="card">
      <div class="clabel">Open Ports</div>
      <div id="ports"><div class="loading">Loading&hellip;</div></div>
    </div>
  </div>
  <div class="section">Threat Intelligence</div>
  <div class="card">
    <div class="clabel">Critical CVEs &middot; Past 48 hours</div>
    <div id="cves"><div class="loading">Fetching from NVD&hellip;</div></div>
  </div>
</main>
<footer>
  <span class="ft">SentinelDash &middot; Built by Aryan Khanna</span>
  <span class="ft" id="upd">&mdash;</span>
</footer>
<script>
setInterval(()=>{ document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-US',{hour12:false}); },1000);
document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-US',{hour12:false});

async function loadNet(){
  try{
    const d=await fetch('/api/network').then(r=>r.json());
    document.getElementById('net').innerHTML=`
      <div class="row"><span class="rk">Wi-Fi</span><span class="rv">${d.wifi}</span></div>
      <div class="row"><span class="rk">Local IP</span><span class="rv">${d.local_ip}</span></div>
      <div class="row"><span class="rk">Public IP</span><span class="rv">${d.public_ip}</span></div>
      <div class="row"><span class="rk">VPN</span><span class="rv ${d.vpn?'vpn-on':'vpn-off'}">${d.vpn?'Active':'Off'}</span></div>`;
  }catch{document.getElementById('net').innerHTML='<div class="loading">Failed</div>';}
}

async function loadPorts(){
  try{
    const p=await fetch('/api/ports').then(r=>r.json());
    if(!p.length){document.getElementById('ports').innerHTML='<div class="loading">No open ports</div>';return;}
    const pc=r=>r==='SSH'?'pr':r==='HTTP'?'po':r==='HTTPS'?'pg':r==='Dev'?'pb':'pn';
    document.getElementById('ports').innerHTML=p.map(x=>`
      <div class="row">
        <span class="rk">${x.port} <span style="color:var(--text-3);font-size:12px">${x.process}</span></span>
        <span class="pill ${pc(x.risk)}">${x.risk||'—'}</span>
      </div>`).join('');
  }catch{document.getElementById('ports').innerHTML='<div class="loading">Failed</div>';}
}

async function loadCVEs(){
  try{
    const c=await fetch('/api/cves').then(r=>r.json());
    if(!c.length){document.getElementById('cves').innerHTML='<div class="loading">No critical CVEs in the past 48 hours</div>';return;}
    document.getElementById('cves').innerHTML=`<table>
      <thead><tr><th style="width:146px">CVE ID</th><th style="width:60px">Score</th><th style="width:96px">Published</th><th>Description</th></tr></thead>
      <tbody>${c.map(x=>`<tr>
        <td><a class="cid" href="${x.url}" target="_blank">${x.id}</a></td>
        <td><span class="sc ${parseFloat(x.score)>=9?'sc-c':'sc-h'}">${x.score}</span></td>
        <td><span class="dt">${x.published}</span></td>
        <td class="cdesc">${x.description}</td>
      </tr>`).join('')}</tbody></table>`;
  }catch{document.getElementById('cves').innerHTML='<div class="loading">Failed</div>';}
}

function loadAll(){
  loadNet(); loadPorts(); loadCVEs();
  document.getElementById('upd').textContent='Updated '+new Date().toLocaleTimeString();
}
loadAll();
setInterval(loadAll,60000);
</script>
</body>
</html>"""

if __name__ == "__main__":
    print("\n  SentinelDash Web UI")
    print("  http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
