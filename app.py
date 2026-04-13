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
            "22": {"name": "SSH", "risk": "high", "explain": "Remote access port - could allow hackers in if misconfigured"},
            "80": {"name": "HTTP", "risk": "medium", "explain": "Unencrypted web traffic - data sent here is not private"},
            "443": {"name": "HTTPS", "risk": "low", "explain": "Encrypted web traffic - this is normal and safe"},
            "3000": {"name": "Dev Server", "risk": "low", "explain": "A development server running locally"},
            "5000": {"name": "Dev Server", "risk": "low", "explain": "A development server running locally"},
            "8080": {"name": "Web Server", "risk": "medium", "explain": "An alternate web port - check if this is intentional"},
            "3306": {"name": "Database", "risk": "high", "explain": "Your database is exposed - this could be dangerous"},
            "5432": {"name": "Database", "risk": "high", "explain": "Your database is exposed - this could be dangerous"},
            "6379": {"name": "Cache Server", "risk": "high", "explain": "Redis cache exposed - should not be publicly accessible"},
        }
        for line in result.stdout.split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 9 and "LISTEN" in line:
                addr = parts[8]
                if "*:" in addr or "0.0.0.0:" in addr or "127.0.0.1:" in addr:
                    port = addr.split(":")[-1]
                    if port not in ports:
                        info = risk_map.get(port, {"name": parts[0], "risk": "low", "explain": "A service running on your machine"})
                        ports[port] = {"process": parts[0], **info}
        return [{"port": k, **v} for k, v in sorted(ports.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 9999)[:8]]
    except:
        return []

def get_cves():
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=48)
        url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
               f"pubStartDate={urllib.parse.quote(start.strftime('%Y-%m-%dT%H:%M:%S.000'))}&"
               f"pubEndDate={urllib.parse.quote(end.strftime('%Y-%m-%dT%H:%M:%S.000'))}&"
               f"cvssV3Severity=CRITICAL&resultsPerPage=6")
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
                "description": desc[:200],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": cve.get("published", "")[:10]
            })
        return cves
    except:
        return []

def get_devices():
    try:
        if os.path.exists(DEVICES_FILE):
            devices = json.load(open(DEVICES_FILE))
            return devices
        return []
    except:
        return []

def compute_health(network, ports, cves):
    score = 100
    issues = []
    good = []
    if not network.get("vpn"):
        score -= 15
        issues.append({"icon": "!", "text": "VPN is off - your internet traffic is not encrypted", "action": "Turn on a VPN app to protect your privacy"})
    else:
        good.append({"icon": "ok", "text": "VPN is active - your traffic is encrypted"})
    high_risk_ports = [p for p in ports if p.get("risk") == "high"]
    if high_risk_ports:
        score -= 10 * len(high_risk_ports)
        for p in high_risk_ports:
            issues.append({"icon": "!", "text": f"Port {p['port']} ({p['name']}) is open - {p['explain']}", "action": "Close this port if you do not need it"})
    else:
        good.append({"icon": "ok", "text": "No high-risk ports detected"})
    if cves:
        score -= min(20, len(cves) * 3)
        issues.append({"icon": "!", "text": f"{len(cves)} critical security vulnerabilities published in the past 48 hours", "action": "Keep your software and devices updated"})
    else:
        good.append({"icon": "ok", "text": "No new critical threats in the past 48 hours"})
    score = max(0, min(100, score))
    if score >= 80:
        grade = "good"; grade_label = "Good"; grade_msg = "Your network looks healthy. Keep it up!"
    elif score >= 55:
        grade = "warning"; grade_label = "Fair"; grade_msg = "A few things to keep an eye on."
    else:
        grade = "danger"; grade_label = "At Risk"; grade_msg = "Some issues need your attention."
    return {"score": score, "grade": grade, "grade_label": grade_label, "grade_msg": grade_msg, "issues": issues, "good": good}

@app.route("/api/data")
def api_data():
    network = get_network_info()
    ports = get_open_ports()
    cves = get_cves()
    health = compute_health(network, ports, cves)
    devices = get_devices()
    return jsonify({"network": network, "ports": ports, "cves": cves, "health": health, "devices": devices})

@app.route("/")
def index():
    return HTML

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Argus</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0a0a;--s1:rgba(255,255,255,0.04);--s2:rgba(255,255,255,0.07);--bd:rgba(255,255,255,0.08);--bd2:rgba(255,255,255,0.14);--t1:rgba(255,255,255,0.9);--t2:rgba(255,255,255,0.5);--t3:rgba(255,255,255,0.25);--green:#30d158;--yellow:#ffd60a;--red:#ff453a;--orange:#ff9f0a;--blue:#2997ff;--r:18px}
body{background:var(--bg);color:var(--t1);font-family:'Inter',-apple-system,sans-serif;font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased;min-height:100vh}
nav{position:sticky;top:0;z-index:50;padding:0 28px;height:52px;display:flex;align-items:center;justify-content:space-between;background:rgba(10,10,10,0.85);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border-bottom:1px solid var(--bd)}
.brand{font-size:15px;font-weight:600;letter-spacing:-.02em}
.nav-r{display:flex;align-items:center;gap:14px}
.live{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--t2)}
.dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:breathe 2.4s ease-in-out infinite}
@keyframes breathe{0%,100%{opacity:1}50%{opacity:.3}}
#clock{font-size:12px;color:var(--t3);font-variant-numeric:tabular-nums}
.btn{background:var(--s1);border:1px solid var(--bd);color:var(--t2);font-family:inherit;font-size:12px;font-weight:500;padding:5px 14px;border-radius:20px;cursor:pointer;transition:all .15s}
.btn:hover{background:var(--s2);border-color:var(--bd2);color:var(--t1)}
main{max-width:960px;margin:0 auto;padding:36px 24px 60px}
.health-card{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);padding:28px;margin-bottom:16px;display:flex;align-items:center;gap:28px}
.score-ring{position:relative;width:88px;height:88px;flex-shrink:0}
.score-ring svg{transform:rotate(-90deg)}
.track{fill:none;stroke:rgba(255,255,255,0.06);stroke-width:7}
.fill{fill:none;stroke-width:7;stroke-linecap:round}
.score-num{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:600;letter-spacing:-.03em}
.health-text h2{font-size:20px;font-weight:600;letter-spacing:-.02em;margin-bottom:4px}
.health-text p{font-size:14px;color:var(--t2)}
.status-list{display:flex;flex-direction:column;gap:10px;margin-bottom:16px}
.status-item{background:var(--s1);border:1px solid var(--bd);border-radius:14px;padding:14px 18px;display:flex;align-items:flex-start;gap:12px}
.status-icon{font-size:18px;flex-shrink:0;margin-top:1px}
.status-body{flex:1}
.status-title{font-size:14px;font-weight:500;color:var(--t1);margin-bottom:2px}
.status-action{font-size:12px;color:var(--t2)}
.status-good .status-title{color:rgba(48,209,88,0.9)}
.section{font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--t3);margin:28px 0 12px;display:flex;align-items:center;justify-content:space-between}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}
.card{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);padding:20px 22px}
.clabel{font-size:11px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--t3);margin-bottom:16px}
.row{display:flex;align-items:flex-start;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--bd);gap:12px}
.row:last-child{border-bottom:none}
.rk{font-size:13px;color:var(--t2);flex-shrink:0}
.rv{font-size:13px;font-weight:500;color:var(--t1);text-align:right}
.vpn-on{color:var(--green)}
.vpn-off{color:var(--red)}
.port-row{display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--bd)}
.port-row:last-child{border-bottom:none}
.port-left{display:flex;align-items:center;gap:10px}
.port-num{font-size:13px;font-weight:500;font-variant-numeric:tabular-nums;width:44px}
.port-name{font-size:13px;color:var(--t2)}
.port-explain{font-size:11px;color:var(--t3);margin-top:1px}
.badge{display:inline-flex;align-items:center;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:500}
.badge-red{background:rgba(255,69,58,.15);color:#ff6961}
.badge-orange{background:rgba(255,159,10,.15);color:#ffb340}
.badge-green{background:rgba(48,209,88,.12);color:#34c759}
.badge-gray{background:rgba(255,255,255,.06);color:var(--t2)}
.badge-blue{background:rgba(41,151,255,.15);color:#64aaff}
.device-grid{display:flex;flex-direction:column;gap:8px;margin-bottom:16px}
.device-row{background:var(--s1);border:1px solid var(--bd);border-radius:12px;padding:12px 16px;display:flex;align-items:center;gap:12px;transition:border-color .2s}
.device-row:hover{border-color:var(--bd2)}
.device-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0}
.device-info{flex:1}
.device-hostname{font-size:13px;font-weight:500;color:var(--t1)}
.device-meta{font-size:11px;color:var(--t3);margin-top:1px;font-variant-numeric:tabular-nums}
.device-vendor{font-size:12px;color:var(--t2)}
.you-badge{display:inline-flex;align-items:center;padding:1px 8px;border-radius:20px;font-size:10px;font-weight:600;background:rgba(41,151,255,.15);color:#64aaff;margin-left:6px}
.cve-list{display:flex;flex-direction:column;gap:10px}
.cve-card{background:var(--s1);border:1px solid var(--bd);border-radius:14px;padding:16px 18px}
.cve-top{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.cve-id{font-size:12px;color:var(--t3);font-variant-numeric:tabular-nums}
.cve-date{font-size:11px;color:var(--t3);margin-left:auto}
.cve-desc{font-size:13px;color:var(--t2);line-height:1.5}
.cve-link{display:inline-flex;align-items:center;gap:4px;font-size:12px;color:var(--blue);text-decoration:none;margin-top:8px}
.cve-link:hover{text-decoration:underline}
.score-pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600}
.pill-c{background:rgba(255,69,58,.15);color:#ff6961}
.pill-h{background:rgba(255,159,10,.15);color:#ffb340}
.loading{font-size:13px;color:var(--t3);padding:8px 0}
.scan-note{font-size:11px;color:var(--t3)}
footer{border-top:1px solid var(--bd);padding:16px 28px;display:flex;justify-content:space-between}
.ft{font-size:12px;color:var(--t3)}
</style>
</head>
<body>
<nav>
  <span class="brand">Argus</span>
  <div class="nav-r">
    <span class="live"><span class="dot"></span>Live</span>
    <span id="clock">--:--:--</span>
    <button class="btn" onclick="loadAll()">Refresh</button>
  </div>
</nav>
<main>
  <div class="section">Your Security Health</div>
  <div id="health-wrap"><div class="health-card"><div class="loading">Checking your network...</div></div></div>
  <div id="status-list"></div>

  <div class="section">Network Details</div>
  <div class="info-grid">
    <div class="card"><div class="clabel">Your Connection</div><div id="net"><div class="loading">Loading...</div></div></div>
    <div class="card"><div class="clabel">Active Services</div><div id="ports"><div class="loading">Loading...</div></div></div>
  </div>

  <div class="section">
    <span>Devices on Your Network</span>
    <span class="scan-note">Run <code style="font-size:11px;color:var(--t2)">sudo venv/bin/python3 scanner.py</code> to refresh</span>
  </div>
  <div id="devices"><div class="loading">Loading devices...</div></div>

  <div class="section">Latest Security Threats</div>
  <div id="cves"><div class="loading">Fetching threats...</div></div>
</main>
<footer>
  <span class="ft">Argus - Built by Aryan Khanna, Purdue University</span>
  <span class="ft" id="upd">-</span>
</footer>
<script>
setInterval(function(){document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-US',{hour12:false});},1000);
document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-US',{hour12:false});

function scoreColor(s){return s>=80?'#30d158':s>=55?'#ffd60a':'#ff453a';}

function deviceIcon(vendor, hostname){
  var v=(vendor||'').toLowerCase();
  var h=(hostname||'').toLowerCase();
  if(v.includes('apple')||h.includes('iphone')||h.includes('mac')||h.includes('ipad')) return '&#x1F4BB;';
  if(v.includes('samsung')||v.includes('android')) return '&#x1F4F1;';
  if(v.includes('intel')||v.includes('msi')||v.includes('asus')||v.includes('dell')||v.includes('hp')||v.includes('lenovo')) return '&#x1F5A5;';
  if(v.includes('calix')||v.includes('eero')||v.includes('netgear')||v.includes('asus')||v.includes('linksys')||h.includes('router')||h.includes('gateway')) return '&#x1F4E1;';
  if(v.includes('amazon')||h.includes('echo')||h.includes('alexa')||h.includes('ring')) return '&#x1F50A;';
  return '&#x1F4BB;';
}

function loadAll(){
  fetch('/api/data').then(function(r){return r.json();}).then(function(d){
    var network=d.network, ports=d.ports, cves=d.cves, health=d.health, devices=d.devices;

    var c=scoreColor(health.score);
    var radius=37;
    var circ=2*Math.PI*radius;
    var offset=circ-(health.score/100)*circ;
    document.getElementById('health-wrap').innerHTML='<div class="health-card"><div class="score-ring"><svg width="88" height="88" viewBox="0 0 88 88"><circle class="track" cx="44" cy="44" r="'+radius+'"/><circle class="fill" cx="44" cy="44" r="'+radius+'" stroke="'+c+'" stroke-dasharray="'+circ+'" stroke-dashoffset="'+offset+'"/></svg><div class="score-num" style="color:'+c+'">'+health.score+'</div></div><div class="health-text"><h2>'+health.grade_label+'</h2><p>'+health.grade_msg+'</p></div></div>';

    var sl='<div class="status-list">';
    health.issues.forEach(function(i){sl+='<div class="status-item"><div class="status-icon">&#9888;</div><div class="status-body"><div class="status-title">'+i.text+'</div><div class="status-action">What to do: '+i.action+'</div></div></div>';});
    health.good.forEach(function(g){sl+='<div class="status-item status-good"><div class="status-icon">&#10003;</div><div class="status-body"><div class="status-title">'+g.text+'</div></div></div>';});
    sl+='</div>';
    document.getElementById('status-list').innerHTML=sl;

    document.getElementById('net').innerHTML='<div class="row"><span class="rk">Wi-Fi</span><span class="rv">'+network.wifi+'</span></div><div class="row"><span class="rk">Local IP</span><span class="rv">'+network.local_ip+'</span></div><div class="row"><span class="rk">Public IP</span><span class="rv">'+network.public_ip+'</span></div><div class="row"><span class="rk">VPN</span><span class="rv '+(network.vpn?'vpn-on':'vpn-off')+'">'+(network.vpn?'Active - traffic encrypted':'Off - traffic visible')+'</span></div>';

    if(!ports.length){document.getElementById('ports').innerHTML='<div class="loading">No open services</div>';}
    else{
      var ph='';
      ports.forEach(function(p){
        var bc=p.risk==='high'?'badge-red':p.risk==='medium'?'badge-orange':p.risk==='low'?'badge-green':'badge-gray';
        var bl=p.risk==='high'?'Needs attention':p.risk==='medium'?'Monitor':'Normal';
        ph+='<div class="port-row"><div class="port-left"><span class="port-num">'+p.port+'</span><div><div class="port-name">'+(p.name||p.process)+'</div><div class="port-explain">'+p.explain+'</div></div></div><span class="badge '+bc+'">'+bl+'</span></div>';
      });
      document.getElementById('ports').innerHTML=ph;
    }

    if(!devices||!devices.length){
      document.getElementById('devices').innerHTML='<div class="card"><p class="loading">No device scan data. Run the scanner from terminal to populate this.</p></div>';
    } else {
      var dh='<div class="device-grid">';
      devices.forEach(function(dev){
        var isYou = dev.ip === network.local_ip;
        var icon = deviceIcon(dev.vendor, dev.hostname);
        var bgColor = isYou ? 'rgba(41,151,255,0.12)' : 'rgba(255,255,255,0.06)';
        dh+='<div class="device-row">';
        dh+='<div class="device-icon" style="background:'+bgColor+'">'+icon+'</div>';
        dh+='<div class="device-info">';
        dh+='<div class="device-hostname">'+dev.hostname+(isYou?'<span class="you-badge">You</span>':'')+'</div>';
        dh+='<div class="device-meta">'+dev.ip+' &nbsp;&bull;&nbsp; '+dev.mac+'</div>';
        dh+='</div>';
        dh+='<div class="device-vendor">'+(dev.vendor&&dev.vendor!=='Unknown'?dev.vendor:'Unknown device')+'</div>';
        dh+='</div>';
      });
      dh+='</div>';
      document.getElementById('devices').innerHTML=dh;
    }

    if(!cves.length){document.getElementById('cves').innerHTML='<div class="card"><p style="color:var(--t2);font-size:14px">No critical threats in the past 48 hours - you are all clear.</p></div>';}
    else{
      var ch='<div class="cve-list">';
      cves.forEach(function(cv){
        var isc=parseFloat(cv.score)>=9;
        ch+='<div class="cve-card"><div class="cve-top"><span class="score-pill '+(isc?'pill-c':'pill-h')+'">'+(isc?'Critical':'High')+' '+cv.score+'/10</span><span class="cve-id">'+cv.id+'</span><span class="cve-date">'+cv.published+'</span></div><div class="cve-desc">'+cv.description+'</div><a class="cve-link" href="'+cv.url+'" target="_blank">View full details</a></div>';
      });
      ch+='</div>';
      document.getElementById('cves').innerHTML=ch;
    }

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
