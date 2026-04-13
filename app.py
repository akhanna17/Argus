#!/usr/bin/env python3
from flask import Flask, jsonify, render_template_string
import subprocess, socket, json, os, urllib.request, urllib.parse
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
DEVICES_FILE = "/tmp/argus_devices.json"

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
        vpn_ifaces = [l.split(":")[0] for l in result.stdout.split("\n") if l.startswith("utun")]
        vpn_active = len(vpn_ifaces) > 2
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
        risk_map = {
            "22": {"name": "SSH", "risk": "high", "explain": "Remote access port that lets someone control your computer from anywhere. If this is open unintentionally, it could let hackers in."},
            "80": {"name": "HTTP", "risk": "medium", "explain": "A web server running without encryption. Any data sent through this port can be read by others on the network."},
            "443": {"name": "HTTPS", "risk": "low", "explain": "A secure, encrypted web server. This is completely normal and safe to have open."},
            "3000": {"name": "Dev Server", "risk": "low", "explain": "A local development server, probably running an app you are building. Safe as long as it is not exposed to the internet."},
            "5000": {"name": "Dev Server", "risk": "low", "explain": "A local development server. Safe as long as it is not exposed to the internet."},
            "5001": {"name": "Argus", "risk": "low", "explain": "This is Argus itself running. Completely normal."},
            "8080": {"name": "Web Server", "risk": "medium", "explain": "An alternate web port. Check if you intentionally have a web server running here."},
            "3306": {"name": "MySQL", "risk": "high", "explain": "Your database is listening for connections. If exposed to the internet, attackers could try to access all your data."},
            "5432": {"name": "PostgreSQL", "risk": "high", "explain": "Your database is exposed. This should never be publicly accessible."},
            "6379": {"name": "Redis", "risk": "high", "explain": "A cache server that is exposed. Attackers can use this to steal data or take over your system."},
        }
        for line in result.stdout.split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 9 and "LISTEN" in line:
                addr = parts[8]
                if "*:" in addr or "0.0.0.0:" in addr or "127.0.0.1:" in addr:
                    port = addr.split(":")[-1]
                    if port not in ports:
                        info = risk_map.get(port, {"name": parts[0], "risk": "low", "explain": "A service is running on this port on your machine."})
                        ports[port] = {"process": parts[0], **info}
        return [{"port": k, **v} for k, v in sorted(ports.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 9999)[:10]]
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
        req = urllib.request.Request(url, headers={"User-Agent": "Argus/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
            metrics = cve.get("metrics", {})
            score = 0
            score_str = "N/A"
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", 0)
                score_str = str(score)
            elif "cvssMetricV30" in metrics:
                score = metrics["cvssMetricV30"][0]["cvssData"].get("baseScore", 0)
                score_str = str(score)
            cve_id = cve.get("id", "Unknown")
            cves.append({
                "id": cve_id, "score": score_str, "score_num": float(score),
                "description": desc[:300],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": cve.get("published", "")[:10]
            })
        return cves
    except:
        return []

def get_devices():
    try:
        if os.path.exists(DEVICES_FILE):
            return json.load(open(DEVICES_FILE))
        return []
    except:
        return []

def ai_explain(prompt):
    try:
        payload = json.dumps({"model": "llama3.2", "prompt": prompt, "stream": False}).encode()
        req = urllib.request.Request("http://localhost:11434/api/generate", data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode()).get("response", "").strip()
    except:
        return None

def compute_health(network, ports, cves, devices):
    score = 100
    issues = []
    good = []
    if not network.get("vpn"):
        score -= 15
        issues.append({"text": "VPN is off", "detail": "Your internet traffic is not encrypted. Anyone on the same network can potentially see what you are doing online.", "action": "Turn on a VPN app like ProtonVPN or Mullvad to encrypt your traffic."})
    else:
        good.append({"text": "VPN is active", "detail": "Your internet traffic is encrypted and private."})
    high_risk_ports = [p for p in ports if p.get("risk") == "high"]
    if high_risk_ports:
        score -= 10 * len(high_risk_ports)
        for p in high_risk_ports:
            issues.append({"text": f"High-risk port open: {p['port']} ({p['name']})", "detail": p['explain'], "action": f"Close port {p['port']} if you do not need it running."})
    else:
        good.append({"text": "No high-risk ports open", "detail": "None of your open ports pose an immediate security risk."})
    if cves:
        score -= min(20, len(cves) * 3)
        issues.append({"text": f"{len(cves)} critical vulnerabilities published this week", "detail": "New security flaws have been discovered in widely used software. If you use affected software and have not updated it, you could be at risk.", "action": "Keep all your apps, operating system, and firmware up to date."})
    else:
        good.append({"text": "No new critical threats this week", "detail": "No critical vulnerabilities have been published in the past 48 hours."})
    score = max(0, min(100, score))
    if score >= 80:
        grade_label = "Good"; grade_msg = "Your network looks healthy."
    elif score >= 55:
        grade_label = "Fair"; grade_msg = "A few things to keep an eye on."
    else:
        grade_label = "At Risk"; grade_msg = "Some issues need your attention."
    return {"score": score, "grade_label": grade_label, "grade_msg": grade_msg, "issues": issues, "good": good}

@app.route("/api/data")
def api_data():
    network = get_network_info()
    ports = get_open_ports()
    cves = get_cves()
    devices = get_devices()
    health = compute_health(network, ports, cves, devices)
    return jsonify({"network": network, "ports": ports, "cves": cves, "health": health, "devices": devices})

@app.route("/api/explain/cve", methods=["POST"])
def explain_cve():
    try:
        data = json.loads(urllib.request.urlopen(
            urllib.request.Request(
                "http://localhost:5001/api/data",
                headers={"Content-Type": "application/json"}
            )
        ).read())
    except:
        pass
    body = json.loads(urllib.request.urlopen(
        urllib.request.Request("http://127.0.0.1:5001/api/explain/cve",
                               method="POST")).read()) if False else {}
    from flask import request
    body = request.get_json()
    cve_id = body.get("id", "")
    score = body.get("score", "")
    desc = body.get("description", "")
    prompt = f"""Explain this security vulnerability to someone with no technical background. Use 2-3 short paragraphs.
Paragraph 1: What is the problem and what could a hacker do with it?
Paragraph 2: Who is at risk and how serious is it?
Paragraph 3: What should a regular person do about it?
Keep it simple, friendly, and under 120 words total. No jargon.

CVE: {cve_id} Score: {score}/10
Details: {desc}"""
    result = ai_explain(prompt)
    if not result:
        result = "This is a critical security vulnerability that could allow attackers to compromise affected systems. Keep your software updated to stay protected."
    return jsonify({"explanation": result})

@app.route("/api/explain/network", methods=["POST"])
def explain_network():
    from flask import request
    body = request.get_json()
    network = body.get("network", {})
    ports = body.get("ports", [])
    high = [p for p in ports if p.get("risk") == "high"]
    prompt = f"""Explain this person's network security situation in 2 short paragraphs. Be friendly and simple. No jargon.
Their setup: WiFi={network.get('wifi','Unknown')}, VPN={'on' if network.get('vpn') else 'OFF - not protected'}, 
Public IP={network.get('public_ip','Unknown')}, Open ports={len(ports)} total, {len(high)} high-risk.
Paragraph 1: Overall situation - are they safe or not?
Paragraph 2: The most important thing they should do right now.
Keep it under 80 words."""
    result = ai_explain(prompt)
    if not result:
        result = "Your network connection is active. Make sure you keep your VPN on and your software updated for best protection."
    return jsonify({"explanation": result})

@app.route("/api/explain/device", methods=["POST"])
def explain_device():
    from flask import request
    body = request.get_json()
    hostname = body.get("hostname", "unknown")
    vendor = body.get("vendor", "Unknown")
    ip = body.get("ip", "")
    prompt = f"""In 1-2 sentences, explain what kind of device this likely is on a home network and whether the user should be concerned about it.
Device: hostname={hostname}, vendor={vendor}, IP={ip}
Be friendly and simple. If vendor is Unknown, make an educated guess based on hostname."""
    result = ai_explain(prompt)
    if not result:
        result = "This is a device connected to your network. If you do not recognize it, consider changing your WiFi password."
    return jsonify({"explanation": result})

@app.route("/")
def index():
    return HTML

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Argus</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0a0a;--bg2:#111;--s1:rgba(255,255,255,0.04);--s2:rgba(255,255,255,0.08);--bd:rgba(255,255,255,0.08);--bd2:rgba(255,255,255,0.16);--t1:rgba(255,255,255,0.92);--t2:rgba(255,255,255,0.5);--t3:rgba(255,255,255,0.25);--green:#30d158;--yellow:#ffd60a;--red:#ff453a;--orange:#ff9f0a;--blue:#2997ff;--r:16px}
body.light{--bg:#f5f5f7;--bg2:#fff;--s1:rgba(0,0,0,0.04);--s2:rgba(0,0,0,0.07);--bd:rgba(0,0,0,0.08);--bd2:rgba(0,0,0,0.16);--t1:rgba(0,0,0,0.9);--t2:rgba(0,0,0,0.5);--t3:rgba(0,0,0,0.3)}
body{background:var(--bg);color:var(--t1);font-family:'Inter',-apple-system,sans-serif;font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased;min-height:100vh;transition:background .3s,color .3s}
nav{position:sticky;top:0;z-index:50;padding:0 28px;height:52px;display:flex;align-items:center;justify-content:space-between;background:rgba(10,10,10,0.85);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border-bottom:1px solid var(--bd);transition:background .3s}
body.light nav{background:rgba(245,245,247,0.85)}
.brand{font-size:15px;font-weight:600;letter-spacing:-.02em}
.nav-r{display:flex;align-items:center;gap:10px}
.live{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--t2)}
.dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:breathe 2.4s ease-in-out infinite}
@keyframes breathe{0%,100%{opacity:1}50%{opacity:.3}}
#clock{font-size:12px;color:var(--t3);font-variant-numeric:tabular-nums}
.btn{background:var(--s1);border:1px solid var(--bd);color:var(--t2);font-family:inherit;font-size:12px;font-weight:500;padding:5px 12px;border-radius:20px;cursor:pointer;transition:all .15s}
.btn:hover{background:var(--s2);border-color:var(--bd2);color:var(--t1)}
.theme-btn{font-size:14px;padding:4px 10px}
main{max-width:960px;margin:0 auto;padding:28px 24px 60px}
.health-card{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);padding:24px 28px;margin-bottom:20px;display:flex;align-items:center;gap:24px}
.score-ring{position:relative;width:80px;height:80px;flex-shrink:0}
.score-ring svg{transform:rotate(-90deg)}
.track{fill:none;stroke:rgba(128,128,128,0.15);stroke-width:7}
.fill{fill:none;stroke-width:7;stroke-linecap:round}
.score-num{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:600;letter-spacing:-.03em}
.health-text h2{font-size:18px;font-weight:600;letter-spacing:-.02em;margin-bottom:2px}
.health-text p{font-size:13px;color:var(--t2)}
.ai-explain-box{margin-top:10px;font-size:13px;color:var(--t2);line-height:1.6;font-style:italic}
.tabs{display:flex;gap:4px;margin-bottom:20px;background:var(--s1);padding:4px;border-radius:12px;border:1px solid var(--bd)}
.tab{flex:1;padding:8px;border-radius:9px;font-size:13px;font-weight:500;text-align:center;cursor:pointer;color:var(--t2);transition:all .2s;border:none;background:none;font-family:inherit}
.tab.active{background:var(--s2);color:var(--t1);border:1px solid var(--bd2)}
.tab-content{display:none}
.tab-content.active{display:block}
.section-title{font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--t3);margin:24px 0 12px}
.card{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);padding:20px 22px;margin-bottom:12px;transition:border-color .2s}
.card:hover{border-color:var(--bd2)}
.card-title{font-size:11px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--t3);margin-bottom:14px}
.row{display:flex;align-items:flex-start;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--bd);gap:12px}
.row:last-child{border-bottom:none}
.rk{font-size:13px;color:var(--t2)}
.rv{font-size:13px;font-weight:500;color:var(--t1);text-align:right}
.vpn-on{color:var(--green)}
.vpn-off{color:var(--red)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.badge{display:inline-flex;align-items:center;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:500}
.b-red{background:rgba(255,69,58,.15);color:#ff6961}
.b-orange{background:rgba(255,159,10,.15);color:#ffb340}
.b-green{background:rgba(48,209,88,.12);color:#34c759}
.b-gray{background:rgba(128,128,128,.15);color:var(--t2)}
.b-blue{background:rgba(41,151,255,.15);color:#64aaff}
.status-item{background:var(--s1);border:1px solid var(--bd);border-radius:14px;padding:14px 18px;display:flex;align-items:flex-start;gap:12px;margin-bottom:10px}
.si-icon{font-size:16px;flex-shrink:0;margin-top:1px}
.si-body{flex:1}
.si-title{font-size:14px;font-weight:500;margin-bottom:2px}
.si-detail{font-size:12px;color:var(--t2);line-height:1.5;margin-bottom:4px}
.si-action{font-size:12px;color:var(--blue)}
.si-good .si-title{color:rgba(48,209,88,.9)}
.port-row{display:flex;align-items:flex-start;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--bd);gap:12px}
.port-row:last-child{border-bottom:none}
.port-left{flex:1}
.port-num{font-size:13px;font-weight:600;font-variant-numeric:tabular-nums;color:var(--t1)}
.port-name{font-size:12px;color:var(--t2)}
.port-explain{font-size:12px;color:var(--t2);margin-top:4px;line-height:1.4}
.device-row{background:var(--s1);border:1px solid var(--bd);border-radius:12px;padding:14px 16px;display:flex;align-items:flex-start;gap:12px;margin-bottom:8px;transition:border-color .2s;cursor:pointer}
.device-row:hover{border-color:var(--bd2)}
.device-icon{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;background:var(--s2)}
.device-info{flex:1}
.device-name{font-size:13px;font-weight:500}
.device-meta{font-size:11px;color:var(--t3);margin-top:2px;font-variant-numeric:tabular-nums}
.device-vendor{font-size:12px;color:var(--t2);text-align:right}
.device-ai{font-size:12px;color:var(--t2);margin-top:8px;font-style:italic;line-height:1.5;display:none}
.you-tag{display:inline-flex;align-items:center;padding:1px 7px;border-radius:20px;font-size:10px;font-weight:600;background:rgba(41,151,255,.15);color:#64aaff;margin-left:6px}
.cve-card{background:var(--s1);border:1px solid var(--bd);border-radius:14px;padding:16px 18px;margin-bottom:10px;cursor:pointer;transition:border-color .2s}
.cve-card:hover{border-color:var(--bd2)}
.cve-top{display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap}
.cve-id{font-size:12px;color:var(--t3);font-variant-numeric:tabular-nums}
.cve-date{font-size:11px;color:var(--t3);margin-left:auto}
.cve-desc{font-size:13px;color:var(--t2);line-height:1.5}
.cve-ai{font-size:13px;color:var(--t1);margin-top:12px;line-height:1.6;display:none;border-top:1px solid var(--bd);padding-top:12px}
.cve-ai-label{font-size:10px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--blue);margin-bottom:6px}
.cve-link{display:inline-flex;align-items:center;gap:4px;font-size:12px;color:var(--blue);text-decoration:none;margin-top:8px}
.cve-link:hover{text-decoration:underline}
.score-pill{display:inline-flex;align-items:center;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600}
.pill-c{background:rgba(255,69,58,.15);color:#ff6961}
.pill-h{background:rgba(255,159,10,.15);color:#ffb340}
.spin{display:inline-block;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.loading{font-size:13px;color:var(--t3);padding:8px 0}
footer{border-top:1px solid var(--bd);padding:14px 28px;display:flex;justify-content:space-between}
.ft{font-size:12px;color:var(--t3)}
</style>
</head>
<body>
<nav>
  <span class="brand">Argus</span>
  <div class="nav-r">
    <span class="live"><span class="dot"></span>Live</span>
    <span id="clock">--:--:--</span>
    <button class="btn theme-btn" onclick="toggleTheme()" id="theme-btn">Light</button>
    <button class="btn" onclick="loadAll()">Refresh</button>
  </div>
</nav>

<main>
  <div id="health-wrap"><div class="health-card"><div class="loading">Checking your network...</div></div></div>

  <div class="tabs">
    <button class="tab active" onclick="switchTab('overview')">Overview</button>
    <button class="tab" onclick="switchTab('network')">Network</button>
    <button class="tab" onclick="switchTab('devices')">Devices</button>
    <button class="tab" onclick="switchTab('threats')">Threats</button>
  </div>

  <div id="tab-overview" class="tab-content active">
    <div id="status-items"></div>
  </div>

  <div id="tab-network" class="tab-content">
    <div class="grid2">
      <div class="card"><div class="card-title">Your Connection</div><div id="net-info"><div class="loading">Loading...</div></div></div>
      <div class="card"><div class="card-title">Active Services</div><div id="port-info"><div class="loading">Loading...</div></div></div>
    </div>
    <div class="card"><div class="card-title">AI Network Summary</div><div id="net-ai"><div class="loading"><span class="spin">&#9696;</span> Analyzing...</div></div></div>
  </div>

  <div id="tab-devices" class="tab-content">
    <div class="section-title" id="device-count">Scanning...</div>
    <div id="device-list"><div class="loading">Loading devices...</div></div>
  </div>

  <div id="tab-threats" class="tab-content">
    <div class="section-title">Critical vulnerabilities published in the past 48 hours</div>
    <div id="cve-list"><div class="loading">Fetching from National Vulnerability Database...</div></div>
  </div>
</main>

<footer>
  <span class="ft">Argus - Built by Aryan Khanna, Purdue University</span>
  <span class="ft" id="upd">-</span>
</footer>

<script>
var DATA = {};
var currentTab = 'overview';

function toggleTheme(){
  document.body.classList.toggle('light');
  document.getElementById('theme-btn').textContent = document.body.classList.contains('light') ? 'Dark' : 'Light';
}

function switchTab(t){
  currentTab = t;
  document.querySelectorAll('.tab').forEach(function(el,i){
    var tabs = ['overview','network','devices','threats'];
    el.classList.toggle('active', tabs[i]===t);
  });
  document.querySelectorAll('.tab-content').forEach(function(el){
    el.classList.remove('active');
  });
  document.getElementById('tab-'+t).classList.add('active');
}

setInterval(function(){document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-US',{hour12:false});},1000);
document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-US',{hour12:false});

function scoreColor(s){return s>=80?'#30d158':s>=55?'#ffd60a':'#ff453a';}

function deviceIcon(vendor,hostname){
  var v=(vendor||'').toLowerCase(), h=(hostname||'').toLowerCase();
  if(v.includes('apple')||h.includes('iphone')||h.includes('macbook')||h.includes('ipad')) return '&#x1F4BB;';
  if(v.includes('samsung')||v.includes('android')) return '&#x1F4F1;';
  if(v.includes('intel')||v.includes('msi')||v.includes('dell')||v.includes('hp')||v.includes('lenovo')||v.includes('asus')) return '&#x1F5A5;';
  if(v.includes('calix')||v.includes('eero')||v.includes('netgear')||v.includes('linksys')||h.includes('router')) return '&#x1F4E1;';
  if(v.includes('amazon')||h.includes('echo')||h.includes('ring')) return '&#x1F50A;';
  return '&#x1F4BB;';
}

function renderHealth(health){
  var c=scoreColor(health.score);
  var radius=34, circ=2*Math.PI*radius, offset=circ-(health.score/100)*circ;
  document.getElementById('health-wrap').innerHTML='<div class="health-card"><div class="score-ring"><svg width="80" height="80" viewBox="0 0 80 80"><circle class="track" cx="40" cy="40" r="'+radius+'"/><circle class="fill" cx="40" cy="40" r="'+radius+'" stroke="'+c+'" stroke-dasharray="'+circ+'" stroke-dashoffset="'+offset+'"/></svg><div class="score-num" style="color:'+c+'">'+health.score+'</div></div><div class="health-text"><h2>'+health.grade_label+'</h2><p>'+health.grade_msg+'</p></div></div>';
}

function renderOverview(health){
  var html='';
  health.issues.forEach(function(i){
    html+='<div class="status-item"><div class="si-icon">&#9888;</div><div class="si-body"><div class="si-title">'+i.text+'</div><div class="si-detail">'+i.detail+'</div><div class="si-action">What to do: '+i.action+'</div></div></div>';
  });
  health.good.forEach(function(g){
    html+='<div class="status-item si-good"><div class="si-icon">&#10003;</div><div class="si-body"><div class="si-title">'+g.text+'</div><div class="si-detail">'+g.detail+'</div></div></div>';
  });
  document.getElementById('status-items').innerHTML=html;
}

function renderNetwork(network,ports){
  document.getElementById('net-info').innerHTML='<div class="row"><span class="rk">Wi-Fi Network</span><span class="rv">'+network.wifi+'</span></div><div class="row"><span class="rk">Local IP</span><span class="rv">'+network.local_ip+'</span></div><div class="row"><span class="rk">Public IP</span><span class="rv">'+network.public_ip+'</span></div><div class="row"><span class="rk">VPN</span><span class="rv '+(network.vpn?'vpn-on':'vpn-off')+'">'+(network.vpn?'Active':'Off')+'</span></div>';

  if(!ports.length){document.getElementById('port-info').innerHTML='<div class="loading">No open ports detected</div>';return;}
  var ph='';
  ports.forEach(function(p){
    var bc=p.risk==='high'?'b-red':p.risk==='medium'?'b-orange':'b-green';
    var bl=p.risk==='high'?'High Risk':p.risk==='medium'?'Monitor':'Safe';
    ph+='<div class="port-row"><div class="port-left"><div class="port-num">'+p.port+' <span class="port-name">'+( p.name||p.process)+'</span></div><div class="port-explain">'+p.explain+'</div></div><span class="badge '+bc+'">'+bl+'</span></div>';
  });
  document.getElementById('port-info').innerHTML=ph;

  fetch('/api/explain/network',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({network:network,ports:ports})})
    .then(function(r){return r.json();})
    .then(function(d){document.getElementById('net-ai').innerHTML='<p style="font-size:13px;line-height:1.6;color:var(--t2)">'+d.explanation+'</p>';})
    .catch(function(){document.getElementById('net-ai').innerHTML='<p class="loading">AI explanation unavailable</p>';});
}

function renderDevices(devices, localIp){
  if(!devices||!devices.length){
    document.getElementById('device-list').innerHTML='<div class="card"><p class="loading">No scan data. Run the scanner from terminal first.</p></div>';
    document.getElementById('device-count').textContent='No devices found';
    return;
  }
  document.getElementById('device-count').textContent=devices.length+' devices on your network - click any device for an AI explanation';
  var html='';
  devices.forEach(function(dev,idx){
    var isYou=dev.ip===localIp;
    var icon=deviceIcon(dev.vendor,dev.hostname);
    html+='<div class="device-row" onclick="explainDevice('+idx+')" id="drow-'+idx+'">';
    html+='<div class="device-icon">'+icon+'</div>';
    html+='<div class="device-info">';
    html+='<div class="device-name">'+dev.hostname+(isYou?'<span class="you-tag">You</span>':'')+'</div>';
    html+='<div class="device-meta">'+dev.ip+' &nbsp;|&nbsp; '+dev.mac+'</div>';
    html+='<div class="device-ai" id="dai-'+idx+'"></div>';
    html+='</div>';
    html+='<div class="device-vendor">'+(dev.vendor&&dev.vendor!=='Unknown'?dev.vendor:'Unknown')+'</div>';
    html+='</div>';
  });
  document.getElementById('device-list').innerHTML=html;
}

function explainDevice(idx){
  var box=document.getElementById('dai-'+idx);
  if(box.style.display==='block'){box.style.display='none';return;}
  box.style.display='block';
  box.innerHTML='<span class="spin">&#9696;</span> Asking AI...';
  var dev=DATA.devices[idx];
  fetch('/api/explain/device',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(dev)})
    .then(function(r){return r.json();})
    .then(function(d){box.innerHTML=d.explanation;})
    .catch(function(){box.innerHTML='Could not get AI explanation right now.';});
}

function renderCVEs(cves){
  if(!cves.length){document.getElementById('cve-list').innerHTML='<div class="card"><p style="color:var(--t2);font-size:14px">No critical threats in the past 48 hours - you are all clear.</p></div>';return;}
  var html='';
  cves.forEach(function(cv,idx){
    var isc=parseFloat(cv.score)>=9;
    html+='<div class="cve-card" onclick="expandCVE('+idx+')" id="cve-'+idx+'">';
    html+='<div class="cve-top"><span class="score-pill '+(isc?'pill-c':'pill-h')+'">'+(isc?'Critical':'High')+' '+cv.score+'/10</span><span class="cve-id">'+cv.id+'</span><span class="cve-date">'+cv.published+'</span></div>';
    html+='<div class="cve-desc">'+cv.description+'</div>';
    html+='<div class="cve-ai" id="cai-'+idx+'"><div class="cve-ai-label">AI Explanation</div><div id="cai-text-'+idx+'"></div></div>';
    html+='<a class="cve-link" href="'+cv.url+'" target="_blank" onclick="event.stopPropagation()">View technical details &rarr;</a>';
    html+='</div>';
  });
  document.getElementById('cve-list').innerHTML=html;
}

function expandCVE(idx){
  var aiBox=document.getElementById('cai-'+idx);
  var textBox=document.getElementById('cai-text-'+idx);
  if(aiBox.style.display==='block'){aiBox.style.display='none';return;}
  aiBox.style.display='block';
  textBox.innerHTML='<span class="spin">&#9696;</span> AI is explaining this...';
  var cv=DATA.cves[idx];
  fetch('/api/explain/cve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cv)})
    .then(function(r){return r.json();})
    .then(function(d){textBox.innerHTML=d.explanation;})
    .catch(function(){textBox.innerHTML='Could not get AI explanation right now.';});
}

function loadAll(){
  fetch('/api/data').then(function(r){return r.json();}).then(function(d){
    DATA=d;
    renderHealth(d.health);
    renderOverview(d.health);
    renderNetwork(d.network,d.ports);
    renderDevices(d.devices,d.network.local_ip);
    renderCVEs(d.cves);
    document.getElementById('upd').textContent='Updated '+new Date().toLocaleTimeString();
  }).catch(function(e){console.error(e);});
}

loadAll();
setInterval(loadAll,60000);
</script>
</body>
</html>"""

if __name__ == "__main__":
    print("\n  Argus Security Monitor")
    print("  http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
