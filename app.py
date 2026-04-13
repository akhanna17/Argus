#!/usr/bin/env python3
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
    return jsonify({"network": network, "ports": ports, "cves": cves, "health": health})

@app.route("/")
def index():
    return HTML


HTML = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n<title>Argus</title>\n<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">\n<style>\n*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n:root{--bg:#0a0a0a;--s1:rgba(255,255,255,0.04);--s2:rgba(255,255,255,0.07);--bd:rgba(255,255,255,0.08);--bd2:rgba(255,255,255,0.14);--t1:rgba(255,255,255,0.9);--t2:rgba(255,255,255,0.5);--t3:rgba(255,255,255,0.25);--green:#30d158;--yellow:#ffd60a;--red:#ff453a;--orange:#ff9f0a;--blue:#2997ff;--r:18px}\nbody{background:var(--bg);color:var(--t1);font-family:\'Inter\',-apple-system,sans-serif;font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased;min-height:100vh}\nnav{position:sticky;top:0;z-index:50;padding:0 28px;height:52px;display:flex;align-items:center;justify-content:space-between;background:rgba(10,10,10,0.85);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border-bottom:1px solid var(--bd)}\n.brand{font-size:15px;font-weight:600;letter-spacing:-.02em}\n.nav-r{display:flex;align-items:center;gap:14px}\n.live{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--t2)}\n.dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:breathe 2.4s ease-in-out infinite}\n@keyframes breathe{0%,100%{opacity:1}50%{opacity:.3}}\n#clock{font-size:12px;color:var(--t3);font-variant-numeric:tabular-nums}\n.btn{background:var(--s1);border:1px solid var(--bd);color:var(--t2);font-family:inherit;font-size:12px;font-weight:500;padding:5px 14px;border-radius:20px;cursor:pointer;transition:all .15s}\n.btn:hover{background:var(--s2);border-color:var(--bd2);color:var(--t1)}\nmain{max-width:900px;margin:0 auto;padding:36px 24px 60px}\n.health-card{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);padding:28px;margin-bottom:16px;display:flex;align-items:center;gap:28px}\n.score-ring{position:relative;width:88px;height:88px;flex-shrink:0}\n.score-ring svg{transform:rotate(-90deg)}\n.track{fill:none;stroke:rgba(255,255,255,0.06);stroke-width:7}\n.fill{fill:none;stroke-width:7;stroke-linecap:round;transition:stroke-dashoffset .8s ease,stroke .4s ease}\n.score-num{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:600;letter-spacing:-.03em}\n.health-text h2{font-size:20px;font-weight:600;letter-spacing:-.02em;margin-bottom:4px}\n.health-text p{font-size:14px;color:var(--t2)}\n.status-list{display:flex;flex-direction:column;gap:10px;margin-bottom:16px}\n.status-item{background:var(--s1);border:1px solid var(--bd);border-radius:14px;padding:14px 18px;display:flex;align-items:flex-start;gap:12px}\n.status-icon{font-size:18px;flex-shrink:0;margin-top:1px}\n.status-body{flex:1}\n.status-title{font-size:14px;font-weight:500;color:var(--t1);margin-bottom:2px}\n.status-action{font-size:12px;color:var(--t2)}\n.status-good .status-title{color:rgba(48,209,88,0.9)}\n.section{font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--t3);margin:28px 0 12px}\n.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}\n.card{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);padding:20px 22px}\n.clabel{font-size:11px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--t3);margin-bottom:16px}\n.row{display:flex;align-items:flex-start;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--bd);gap:12px}\n.row:last-child{border-bottom:none}\n.rk{font-size:13px;color:var(--t2);flex-shrink:0}\n.rv{font-size:13px;font-weight:500;color:var(--t1);text-align:right}\n.vpn-on{color:var(--green)}\n.vpn-off{color:var(--red)}\n.port-row{display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--bd)}\n.port-row:last-child{border-bottom:none}\n.port-left{display:flex;align-items:center;gap:10px}\n.port-num{font-size:13px;font-weight:500;font-variant-numeric:tabular-nums;width:44px}\n.port-name{font-size:13px;color:var(--t2)}\n.port-explain{font-size:11px;color:var(--t3);margin-top:1px}\n.badge{display:inline-flex;align-items:center;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:500}\n.badge-red{background:rgba(255,69,58,.15);color:#ff6961}\n.badge-orange{background:rgba(255,159,10,.15);color:#ffb340}\n.badge-green{background:rgba(48,209,88,.12);color:#34c759}\n.badge-gray{background:rgba(255,255,255,.06);color:var(--t2)}\n.cve-list{display:flex;flex-direction:column;gap:10px}\n.cve-card{background:var(--s1);border:1px solid var(--bd);border-radius:14px;padding:16px 18px}\n.cve-top{display:flex;align-items:center;gap:10px;margin-bottom:8px}\n.cve-id{font-size:12px;color:var(--t3);font-variant-numeric:tabular-nums}\n.cve-date{font-size:11px;color:var(--t3);margin-left:auto}\n.cve-title{font-size:14px;font-weight:500;color:var(--t1);margin-bottom:4px}\n.cve-desc{font-size:13px;color:var(--t2);line-height:1.5}\n.cve-link{display:inline-flex;align-items:center;gap:4px;font-size:12px;color:var(--blue);text-decoration:none;margin-top:8px}\n.cve-link:hover{text-decoration:underline}\n.score-pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600}\n.pill-c{background:rgba(255,69,58,.15);color:#ff6961}\n.pill-h{background:rgba(255,159,10,.15);color:#ffb340}\n.loading{font-size:13px;color:var(--t3);padding:8px 0}\nfooter{border-top:1px solid var(--bd);padding:16px 28px;display:flex;justify-content:space-between}\n.ft{font-size:12px;color:var(--t3)}\n</style>\n</head>\n<body>\n<nav>\n  <span class="brand">Argus</span>\n  <div class="nav-r">\n    <span class="live"><span class="dot"></span>Live</span>\n    <span id="clock">--:--:--</span>\n    <button class="btn" onclick="loadAll()">Refresh</button>\n  </div>\n</nav>\n<main>\n  <div class="section">Your Security Health</div>\n  <div id="health-wrap"><div class="health-card"><div class="loading">Checking your network...</div></div></div>\n  <div id="status-list"></div>\n  <div class="section">Network Details</div>\n  <div class="info-grid">\n    <div class="card"><div class="clabel">Your Connection</div><div id="net"><div class="loading">Loading...</div></div></div>\n    <div class="card"><div class="clabel">Active Services</div><div id="ports"><div class="loading">Loading...</div></div></div>\n  </div>\n  <div class="section">Latest Security Threats</div>\n  <div id="cves"><div class="loading">Fetching threats...</div></div>\n</main>\n<footer>\n  <span class="ft">Argus - Built by Aryan Khanna, Purdue University</span>\n  <span class="ft" id="upd">-</span>\n</footer>\n<script>\nsetInterval(function(){document.getElementById(\'clock\').textContent=new Date().toLocaleTimeString(\'en-US\',{hour12:false});},1000);\ndocument.getElementById(\'clock\').textContent=new Date().toLocaleTimeString(\'en-US\',{hour12:false});\n\nfunction scoreColor(s){return s>=80?\'#30d158\':s>=55?\'#ffd60a\':\'#ff453a\';}\n\nfunction loadAll(){\n  fetch(\'/api/data\').then(function(r){return r.json();}).then(function(d){\n    var network=d.network, ports=d.ports, cves=d.cves, health=d.health;\n    var c=scoreColor(health.score);\n    var radius=37;\n    var circ=2*Math.PI*radius;\n    var offset=circ-(health.score/100)*circ;\n    document.getElementById(\'health-wrap\').innerHTML=\'<div class="health-card"><div class="score-ring"><svg width="88" height="88" viewBox="0 0 88 88"><circle class="track" cx="44" cy="44" r="\'+radius+\'"/><circle class="fill" cx="44" cy="44" r="\'+radius+\'" stroke="\'+c+\'" stroke-dasharray="\'+circ+\'" stroke-dashoffset="\'+offset+\'"/></svg><div class="score-num" style="color:\'+c+\'">\'+health.score+\'</div></div><div class="health-text"><h2>\'+health.grade_label+\'</h2><p>\'+health.grade_msg+\'</p></div></div>\';\n    var sl=\'<div class="status-list">\';\n    health.issues.forEach(function(i){sl+=\'<div class="status-item"><div class="status-icon">&#9888;</div><div class="status-body"><div class="status-title">\'+i.text+\'</div><div class="status-action">What to do: \'+i.action+\'</div></div></div>\';});\n    health.good.forEach(function(g){sl+=\'<div class="status-item status-good"><div class="status-icon">&#10003;</div><div class="status-body"><div class="status-title">\'+g.text+\'</div></div></div>\';});\n    sl+=\'</div>\';\n    document.getElementById(\'status-list\').innerHTML=sl;\n    document.getElementById(\'net\').innerHTML=\'<div class="row"><span class="rk">Wi-Fi</span><span class="rv">\'+network.wifi+\'</span></div><div class="row"><span class="rk">Local IP</span><span class="rv">\'+network.local_ip+\'</span></div><div class="row"><span class="rk">Public IP</span><span class="rv">\'+network.public_ip+\'</span></div><div class="row"><span class="rk">VPN</span><span class="rv \'+(network.vpn?\'vpn-on\':\'vpn-off\')+\'">\'+(network.vpn?\'Active - traffic encrypted\':\'Off - traffic visible\')+\'</span></div>\';\n    if(!ports.length){document.getElementById(\'ports\').innerHTML=\'<div class="loading">No open services</div>\';}\n    else{\n      var ph=\'\';\n      ports.forEach(function(p){\n        var bc=p.risk===\'high\'?\'badge-red\':p.risk===\'medium\'?\'badge-orange\':p.risk===\'low\'?\'badge-green\':\'badge-gray\';\n        var bl=p.risk===\'high\'?\'Needs attention\':p.risk===\'medium\'?\'Monitor\':\'Normal\';\n        ph+=\'<div class="port-row"><div class="port-left"><span class="port-num">\'+p.port+\'</span><div><div class="port-name">\'+(p.name||p.process)+\'</div><div class="port-explain">\'+p.explain+\'</div></div></div><span class="badge \'+bc+\'">\'+bl+\'</span></div>\';\n      });\n      document.getElementById(\'ports\').innerHTML=ph;\n    }\n    if(!cves.length){document.getElementById(\'cves\').innerHTML=\'<div class="card"><p style="color:var(--t2);font-size:14px">No critical threats in the past 48 hours - you are all clear.</p></div>\';}\n    else{\n      var ch=\'<div class="cve-list">\';\n      cves.forEach(function(c){\n        var isc=parseFloat(c.score)>=9;\n        ch+=\'<div class="cve-card"><div class="cve-top"><span class="score-pill \'+(isc?\'pill-c\':\'pill-h\')+\'">\'+(isc?\'Critical\':\'High\')+\' \'+c.score+\'/10</span><span class="cve-id">\'+c.id+\'</span><span class="cve-date">\'+c.published+\'</span></div><div class="cve-desc">\'+c.description+\'</div><a class="cve-link" href="\'+c.url+\'" target="_blank">View full details</a></div>\';\n      });\n      ch+=\'</div>\';\n      document.getElementById(\'cves\').innerHTML=ch;\n    }\n    document.getElementById(\'upd\').textContent=\'Updated \'+new Date().toLocaleTimeString();\n  }).catch(function(e){console.error(e);});\n}\nloadAll();\nsetInterval(loadAll,60000);\n</script>\n</body>\n</html>\n'

if __name__ == "__main__":
    print("\n  Argus Security Monitor")
    print("  http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
