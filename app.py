#!/usr/bin/env python3
from flask import Flask, jsonify, render_template_string, request
import subprocess, socket, json, os, urllib.request, urllib.parse, hashlib
from datetime import datetime, timedelta, timezone

app = Flask(__name__)
ARGUS_DIR = os.path.expanduser("~/Desktop/argus")
DATA_DIR = os.path.join(ARGUS_DIR, "data")
DEVICES_FILE = os.path.join(DATA_DIR, "devices.json")

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
            "443": {"name": "HTTPS", "risk": "low", "explain": "Encrypted web traffic - normal and safe"},
            "3000": {"name": "Dev Server", "risk": "low", "explain": "A development server running locally"},
            "5000": {"name": "Dev Server", "risk": "low", "explain": "A development server running locally"},
            "5001": {"name": "Argus", "risk": "low", "explain": "This is Argus itself running"},
            "8080": {"name": "Web Server", "risk": "medium", "explain": "An alternate web port - check if intentional"},
            "3306": {"name": "MySQL", "risk": "high", "explain": "Database exposed - could be dangerous if public"},
            "5432": {"name": "PostgreSQL", "risk": "high", "explain": "Database exposed - should not be public"},
            "6379": {"name": "Redis", "risk": "high", "explain": "Cache server exposed - attackers can steal data"},
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
            cves.append({"id": cve_id, "score": score_str, "score_num": float(score),
                        "description": desc[:300], "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "published": cve.get("published", "")[:10]})
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

def compute_health(network, ports, cves):
    score = 100
    items = []

    # VPN check
    if not network.get("vpn"):
        score -= 15
        items.append({
            "id": "vpn",
            "severity": "high",
            "emoji": "🔓",
            "title": "Your internet is not private",
            "simple": "Anyone on the same WiFi as you could potentially see your internet activity.",
            "technical": "No VPN tunnel detected. Network traffic is unencrypted and vulnerable to MITM attacks on untrusted networks.",
            "action_simple": "Download a VPN app like ProtonVPN (free) and turn it on.",
            "action_technical": "Deploy WireGuard or OpenVPN. Verify tunnel with: curl ifconfig.me",
            "status": "issue"
        })
    else:
        items.append({
            "id": "vpn",
            "severity": "low",
            "emoji": "🔒",
            "title": "VPN is active",
            "simple": "Your internet traffic is encrypted and private.",
            "technical": "VPN tunnel detected via utun interface. Traffic is encrypted end-to-end.",
            "action_simple": None,
            "action_technical": None,
            "status": "good"
        })

    # Port checks
    high_ports = [p for p in ports if p.get("risk") == "high"]
    medium_ports = [p for p in ports if p.get("risk") == "medium"]
    if high_ports:
        score -= 10 * len(high_ports)
        for p in high_ports:
            items.append({
                "id": f"port_{p['port']}",
                "severity": "critical",
                "emoji": "⚠️",
                "title": f"Dangerous port open: {p['name']}",
                "simple": f"A door called port {p['port']} is open on your computer that could let hackers in.",
                "technical": f"Port {p['port']} ({p['name']}) is in LISTEN state. {p['explain']} Process: {p['process']}",
                "action_simple": f"If you are not using {p['name']}, close it in your settings or firewall.",
                "action_technical": f"Run: sudo lsof -i :{p['port']} to identify process. Use: sudo pfctl or launchctl to disable.",
                "status": "issue"
            })
    if medium_ports:
        for p in medium_ports:
            items.append({
                "id": f"port_med_{p['port']}",
                "severity": "medium",
                "emoji": "👁️",
                "title": f"Port worth monitoring: {p['name']} ({p['port']})",
                "simple": f"Port {p['port']} is open. It is not dangerous but worth knowing about.",
                "technical": f"Port {p['port']} ({p['name']}) is open. {p['explain']}",
                "action_simple": "No immediate action needed, but check periodically.",
                "action_technical": f"Monitor with: sudo lsof -i :{p['port']}",
                "status": "warn"
            })
    if not high_ports:
        items.append({
            "id": "ports_safe",
            "severity": "low",
            "emoji": "✅",
            "title": "No dangerous ports open",
            "simple": "None of the services running on your computer pose an immediate security risk.",
            "technical": f"{len(ports)} ports in LISTEN state. No high-risk services detected.",
            "action_simple": None,
            "action_technical": None,
            "status": "good"
        })

    # CVE check
    if cves:
        score -= min(20, len(cves) * 3)
        top_cve = cves[0]
        items.append({
            "id": "cves",
            "severity": "high",
            "emoji": "🚨",
            "title": f"{len(cves)} critical security flaws discovered this week",
            "simple": "Researchers found serious security holes in popular software. If you use affected apps and have not updated them, you could be at risk.",
            "technical": f"{len(cves)} CRITICAL CVEs published in past 48h. Highest score: {top_cve['score']} ({top_cve['id']}). Attack surface unknown without device correlation.",
            "action_simple": "Update all your apps, your Mac system, and any router or smart home devices.",
            "action_technical": "Check: softwareupdate --list. Review CVE details in Threats tab. Cross-reference with device inventory.",
            "status": "issue"
        })
    else:
        items.append({
            "id": "cves_safe",
            "severity": "low",
            "emoji": "✅",
            "title": "No new critical threats this week",
            "simple": "No major security vulnerabilities have been published in the past 48 hours.",
            "technical": "NVD query returned 0 CRITICAL CVEs in past 48h window.",
            "action_simple": None,
            "action_technical": None,
            "status": "good"
        })

    score = max(0, min(100, score))
    issues = [i for i in items if i["status"] == "issue"]
    warns = [i for i in items if i["status"] == "warn"]
    good = [i for i in items if i["status"] == "good"]

    if score >= 80:
        grade_label = "Good"; grade_msg = "Your network looks healthy."
    elif score >= 55:
        grade_label = "Fair"; grade_msg = "A few things to keep an eye on."
    else:
        grade_label = "At Risk"; grade_msg = "Some issues need your attention."

    return {
        "score": score,
        "grade_label": grade_label,
        "grade_msg": grade_msg,
        "items": items,
        "issues": issues,
        "warns": warns,
        "good": good
    }

@app.route("/api/data")
def api_data():
    network = get_network_info()
    ports = get_open_ports()
    cves = get_cves()
    devices = get_devices()
    health = compute_health(network, ports, cves)
    return jsonify({"network": network, "ports": ports, "cves": cves, "health": health, "devices": devices})

@app.route("/api/explain/cve", methods=["POST"])
def explain_cve():
    body = request.get_json()
    cve_id = body.get("id", "")
    score = body.get("score", "")
    desc = body.get("description", "")
    prompt = f"""Explain this security vulnerability to someone non-technical in 2-3 short paragraphs.
Paragraph 1: What is the problem in simple terms.
Paragraph 2: Who is affected and how serious is it.
Paragraph 3: What should a regular person do about it.
Keep it friendly, under 100 words total. No jargon.
CVE: {cve_id} Score: {score}/10
Details: {desc}"""
    result = ai_explain(prompt) or "This is a critical security vulnerability. Keep your software updated to stay protected."
    return jsonify({"explanation": result})

@app.route("/api/explain/network", methods=["POST"])
def explain_network():
    body = request.get_json()
    network = body.get("network", {})
    ports = body.get("ports", [])
    high = [p for p in ports if p.get("risk") == "high"]
    prompt = f"""Explain this network security situation in 2 short paragraphs. Friendly and simple. No jargon.
Setup: WiFi={network.get('wifi','Unknown')}, VPN={'on' if network.get('vpn') else 'OFF'}, 
Public IP={network.get('public_ip','Unknown')}, Open ports={len(ports)} total, {len(high)} high-risk.
Paragraph 1: Overall situation.
Paragraph 2: Most important thing to do right now.
Under 80 words."""
    result = ai_explain(prompt) or "Your network is active. Keep your VPN on and software updated."
    return jsonify({"explanation": result})

@app.route("/api/explain/device", methods=["POST"])
def explain_device():
    body = request.get_json()
    hostname = body.get("hostname", "unknown")
    vendor = body.get("vendor", "Unknown")
    ip = body.get("ip", "")
    prompt = f"""In 1-2 sentences, explain what kind of device this is on a home network and if the user should be concerned.
Device: hostname={hostname}, vendor={vendor}, IP={ip}
Be friendly and simple."""
    result = ai_explain(prompt) or "This is a device on your network. If you do not recognize it, consider changing your WiFi password."
    return jsonify({"explanation": result})

@app.route("/api/checkpassword", methods=["POST"])
def check_password():
    body = request.get_json()
    password = body.get("password", "")
    if not password:
        return jsonify({"error": "No password provided"}), 400
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "Argus-Security-Monitor", "Add-Padding": "true"})
        with urllib.request.urlopen(req, timeout=10) as r:
            hashes = r.read().decode()
        count = 0
        for line in hashes.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].strip() == suffix:
                count = int(parts[1].strip())
                break
        if count == 0:
            status = "safe"
            summary = "Great news! This password has never appeared in any known data breach."
            advice_prompt = "In 1 friendly sentence, tell someone their password is safe but remind them not to reuse it on multiple sites. Under 25 words."
        elif count < 10:
            status = "warning"
            summary = f"This password appeared {count} time(s) in data breaches. You should change it."
            advice_prompt = f"In 2 friendly sentences, explain why a password found {count} times in breach data should be changed. Simple language. Under 40 words."
        elif count < 1000:
            status = "high"
            summary = f"This password appeared {count} times in data breaches. Change it immediately."
            advice_prompt = f"In 2 friendly sentences, explain the danger of a password found {count} times in breach databases. Simple. Under 40 words."
        else:
            status = "critical"
            summary = f"This password appeared {count:,} times in data breaches. It is extremely dangerous to use."
            advice_prompt = f"In 2 urgent but friendly sentences, warn someone that a password seen {count:,} times in breaches is extremely dangerous. Simple. Under 40 words."
        advice = ai_explain(advice_prompt) or summary
        return jsonify({"status": status, "summary": summary, "count": count, "advice": advice, "safe": count == 0})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/api/briefing")
def get_briefing():
    network = get_network_info()
    ports = get_open_ports()
    cves = get_cves()
    devices = get_devices()
    health = compute_health(network, ports, cves)

    issue_count = len(health["issues"])
    if issue_count == 0:
        briefing_instruction = "Tell them everything looks good in one short friendly sentence. Like texting a friend."
    elif issue_count == 1:
        briefing_instruction = "Tell them there is one thing to fix. One sentence saying what it is. One sentence saying what to do. Simple words only."
    else:
        briefing_instruction = f"Tell them there are {issue_count} things to fix. One sentence on the most urgent one. One sentence on what to do first. Simple words only."

    prompt = f"""You are a friendly security assistant texting someone who knows nothing about technology.
{briefing_instruction}
No jargon. No corporate speak. Max 2 sentences. Write like you are talking to your grandmother.
Score: {health["score"]}/100, VPN: {"on" if network.get("vpn") else "OFF - not protected"}, Issues: {issue_count}, CVEs this week: {len(cves)}"""

    briefing = ai_explain(prompt)
    if not briefing:
        briefing = f"Your security score is {health['score']}/100. " + (health["grade_msg"])
    return jsonify({"briefing": briefing, "score": health["score"], "grade": health["grade_label"]})

@app.route("/api/chat", methods=["POST"])
def chat():
    body = request.get_json()
    user_message = body.get("message", "").strip()
    if not user_message:
        return jsonify({"reply": "Please ask me something."}), 400

    # Gather all current context
    network = get_network_info()
    ports = get_open_ports()
    cves = get_cves()
    devices = get_devices()
    health = compute_health(network, ports, cves)

    high_ports = [p for p in ports if p.get("risk") == "high"]
    cve_summary = ", ".join([c["id"] + " (score " + c["score"] + ")" for c in cves[:5]]) if cves else "none"
    device_summary = ", ".join([d.get("hostname","unknown") + " (" + d.get("ip","") + ")" for d in devices[:8]]) if devices else "none scanned yet"

    context = f"""You are Argus, a friendly personal security assistant. You have full access to this user's network data.

CURRENT NETWORK STATUS:
- Security health score: {health["score"]}/100 ({health["grade_label"]})
- WiFi: {network.get("wifi","Unknown")}
- Local IP: {network.get("local_ip","Unknown")}
- Public IP: {network.get("public_ip","Unknown")}
- VPN: {"ACTIVE - traffic is encrypted" if network.get("vpn") else "OFF - traffic is not encrypted"}
- Open ports: {len(ports)} total, {len(high_ports)} high-risk
- High-risk ports: {", ".join([p["port"] + " (" + p["name"] + ")" for p in high_ports]) if high_ports else "none"}
- Critical CVEs this week: {len(cves)} ({cve_summary})
- Devices on network: {device_summary}
- Issues found: {", ".join([i["text"] for i in health["issues"]]) if health["issues"] else "none"}

RULES:
- Answer in plain English that anyone can understand
- Be friendly, clear, and concise
- Use the actual data above to give specific answers
- If asked about something not in your data, say so honestly
- Keep responses under 100 words unless the question needs more detail
- Never use technical jargon without explaining it

USER QUESTION: {user_message}"""

    reply = ai_explain(context)
    if not reply:
        reply = "I'm having trouble connecting to the AI right now. Make sure Ollama is running with: ollama serve"

    return jsonify({"reply": reply})

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
main{max-width:960px;margin:0 auto;padding:28px 24px 60px}
.health-card{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);padding:24px 28px;margin-bottom:20px;display:flex;align-items:center;gap:24px}
.score-ring{position:relative;width:80px;height:80px;flex-shrink:0}
.score-ring svg{transform:rotate(-90deg)}
.track{fill:none;stroke:rgba(128,128,128,0.15);stroke-width:7}
.fill{fill:none;stroke-width:7;stroke-linecap:round}
.score-num{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:600;letter-spacing:-.03em}
.health-text h2{font-size:18px;font-weight:600;letter-spacing:-.02em;margin-bottom:2px}
.health-text p{font-size:13px;color:var(--t2)}
.tabs{display:flex;gap:4px;margin-bottom:20px;background:var(--s1);padding:4px;border-radius:12px;border:1px solid var(--bd)}
.tab{flex:1;padding:8px;border-radius:9px;font-size:13px;font-weight:500;text-align:center;cursor:pointer;color:var(--t2);transition:all .2s;border:none;background:none;font-family:inherit}
.tab.active{background:var(--s2);color:var(--t1);border:1px solid var(--bd2)}
.tab-content{display:none}
.tab-content.active{display:block}
.section-title{font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--t3);margin:24px 0 12px}
.card{background:var(--s1);border:1px solid var(--bd);border-radius:var(--r);padding:20px 22px;margin-bottom:12px}
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
.port-num{font-size:13px;font-weight:600;font-variant-numeric:tabular-nums}
.port-explain{font-size:12px;color:var(--t2);margin-top:3px;line-height:1.4}
.device-row{background:var(--s1);border:1px solid var(--bd);border-radius:12px;padding:14px 16px;display:flex;align-items:flex-start;gap:12px;margin-bottom:8px;cursor:pointer}
.device-row:hover{border-color:var(--bd2)}
.device-icon{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;background:var(--s2)}
.device-info{flex:1}
.device-name{font-size:13px;font-weight:500}
.device-meta{font-size:11px;color:var(--t3);margin-top:2px}
.device-vendor{font-size:12px;color:var(--t2);flex-shrink:0}
.device-ai{font-size:12px;color:var(--t2);margin-top:8px;font-style:italic;line-height:1.5;display:none}
.you-tag{display:inline-flex;align-items:center;padding:1px 7px;border-radius:20px;font-size:10px;font-weight:600;background:rgba(41,151,255,.15);color:#64aaff;margin-left:6px}
.cve-card{background:var(--s1);border:1px solid var(--bd);border-radius:14px;padding:16px 18px;margin-bottom:10px;cursor:pointer}
.cve-card:hover{border-color:var(--bd2)}
.cve-top{display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap}
.cve-id{font-size:12px;color:var(--t3)}
.cve-date{font-size:11px;color:var(--t3);margin-left:auto}
.cve-desc{font-size:13px;color:var(--t2);line-height:1.5}
.cve-ai{font-size:13px;color:var(--t1);margin-top:12px;line-height:1.6;display:none;border-top:1px solid var(--bd);padding-top:12px}
.cve-ai-label{font-size:10px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--blue);margin-bottom:6px}
.cve-link{display:inline-flex;align-items:center;gap:4px;font-size:12px;color:var(--blue);text-decoration:none;margin-top:8px}
.cve-link:hover{text-decoration:underline}
.score-pill{display:inline-flex;align-items:center;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600}
.pill-c{background:rgba(255,69,58,.15);color:#ff6961}
.pill-h{background:rgba(255,159,10,.15);color:#ffb340}
.pw-input{width:100%;background:var(--s1);border:1px solid var(--bd2);border-radius:10px;padding:10px 14px;color:var(--t1);font-family:inherit;font-size:14px;outline:none;margin-bottom:12px}
.pw-input:focus{border-color:var(--blue)}
.check-btn{background:var(--blue);border:none;color:#fff;font-family:inherit;font-size:14px;font-weight:500;padding:10px 24px;border-radius:10px;cursor:pointer;transition:opacity .15s}
.check-btn:hover{opacity:.85}
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
    <button class="btn" onclick="toggleTheme()" id="theme-btn">Light</button>
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
    <button class="tab" onclick="switchTab('password')">Password Check</button>
  </div>
  <div id="tab-overview" class="tab-content active">
    <div id="ai-briefing" style="background:linear-gradient(135deg,rgba(41,151,255,0.08),rgba(41,151,255,0.03));border:1px solid rgba(41,151,255,0.2);border-radius:16px;padding:18px 22px;margin-bottom:20px">
      <div style="font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--blue);margin-bottom:8px">Today&#39;s Briefing from Argus</div>
      <div id="briefing-text" style="font-size:14px;color:var(--t1);line-height:1.6"><span class="spin">&#9696;</span> Generating your daily briefing...</div>
    </div>
    <div id="mode-toggle" style="display:flex;gap:8px;margin-bottom:16px">
      <button id="mode-simple" onclick="setMode('simple')" style="flex:1;padding:8px;border-radius:10px;font-size:12px;font-weight:500;cursor:pointer;border:1px solid var(--blue);background:rgba(41,151,255,0.15);color:var(--blue);font-family:inherit">Simple View</button>
      <button id="mode-technical" onclick="setMode('technical')" style="flex:1;padding:8px;border-radius:10px;font-size:12px;font-weight:500;cursor:pointer;border:1px solid var(--bd);background:var(--s1);color:var(--t2);font-family:inherit">Technical View</button>
    </div>
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
    <div class="section-title" id="device-count">Loading...</div>
    <div id="device-list"><div class="loading">Loading devices...</div></div>
  </div>
  <div id="tab-threats" class="tab-content">
    <div class="section-title">Critical vulnerabilities published in the past 48 hours</div>
    <div id="cve-list"><div class="loading">Fetching from National Vulnerability Database...</div></div>
  </div>
  <div id="tab-password" class="tab-content">
    <div style="max-width:520px;margin:0 auto;padding:8px 0">
      <div style="font-size:22px;font-weight:600;letter-spacing:-.02em;margin-bottom:8px">Password Checker</div>
      <div style="font-size:14px;color:var(--t2);margin-bottom:6px;line-height:1.5">Check if your password has appeared in known data breaches. Your password is never sent anywhere — only a partial hash is checked using k-anonymity.</div>
      <div style="font-size:12px;color:var(--t3);margin-bottom:20px">Powered by HaveIBeenPwned</div>
      <input id="pw-input" class="pw-input" type="password" placeholder="Enter a password to check" onkeydown="if(event.key==='Enter')checkPassword()"/>
      <button class="check-btn" onclick="checkPassword()" id="pw-btn">Check Password</button>
      <div id="pw-result" style="margin-top:20px"></div>
    </div>
  </div>
</main>
<footer>
  <span class="ft">Argus - Built by Aryan Khanna, Purdue University</span>
  <span class="ft" id="upd">-</span>
</footer>

<!-- AI Chat -->
<div id="chat-container" style="position:fixed;bottom:24px;right:24px;z-index:1000;width:380px;font-family:inherit">
  <div id="chat-box" style="display:none;background:var(--bg2,#111);border:1px solid var(--bd2);border-radius:20px;box-shadow:0 8px 32px rgba(0,0,0,0.4);overflow:hidden;margin-bottom:12px;max-height:480px;display:none;flex-direction:column">
    <div style="padding:14px 18px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between">
      <div>
        <div style="font-size:13px;font-weight:600">Ask Argus</div>
        <div style="font-size:11px;color:var(--t3)">Your AI security advisor</div>
      </div>
      <button onclick="toggleChat()" style="background:none;border:none;color:var(--t3);cursor:pointer;font-size:18px;padding:4px">&#10005;</button>
    </div>
    <div id="chat-messages" style="flex:1;overflow-y:auto;padding:14px 18px;max-height:320px;display:flex;flex-direction:column;gap:10px">
      <div class="msg-argus" style="background:var(--s1);border-radius:12px 12px 12px 4px;padding:10px 14px;font-size:13px;color:var(--t2);line-height:1.5;max-width:90%">
        Hi! I am Argus, your personal security advisor. Ask me anything about your network, devices, or threats. For example: "Is my network safe?" or "What should I do first?"
      </div>
    </div>
    <div style="padding:12px 14px;border-top:1px solid var(--bd);display:flex;gap:8px">
      <input id="chat-input" placeholder="Ask me anything..." style="flex:1;background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:8px 12px;color:var(--t1);font-family:inherit;font-size:13px;outline:none" onkeydown="if(event.key==='Enter')sendChat()"/>
      <button onclick="sendChat()" style="background:var(--blue,#2997ff);border:none;color:#fff;font-family:inherit;font-size:13px;font-weight:500;padding:8px 14px;border-radius:10px;cursor:pointer;white-space:nowrap">Send</button>
    </div>
    <div style="padding:0 14px 10px;display:flex;flex-wrap:wrap;gap:6px">
      <button onclick="quickAsk('Is my network safe right now?')" style="background:var(--s1);border:1px solid var(--bd);color:var(--t2);font-family:inherit;font-size:11px;padding:4px 10px;border-radius:20px;cursor:pointer">Is my network safe?</button>
      <button onclick="quickAsk('What is the most important thing I should do today?')" style="background:var(--s1);border:1px solid var(--bd);color:var(--t2);font-family:inherit;font-size:11px;padding:4px 10px;border-radius:20px;cursor:pointer">Top priority?</button>
      <button onclick="quickAsk('What devices are on my network and should I be worried?')" style="background:var(--s1);border:1px solid var(--bd);color:var(--t2);font-family:inherit;font-size:11px;padding:4px 10px;border-radius:20px;cursor:pointer">My devices</button>
      <button onclick="quickAsk('Explain the latest threats in simple terms')" style="background:var(--s1);border:1px solid var(--bd);color:var(--t2);font-family:inherit;font-size:11px;padding:4px 10px;border-radius:20px;cursor:pointer">Latest threats</button>
    </div>
  </div>
  <button onclick="toggleChat()" id="chat-toggle" style="width:52px;height:52px;border-radius:50%;background:var(--blue,#2997ff);border:none;color:#fff;font-size:22px;cursor:pointer;box-shadow:0 4px 16px rgba(41,151,255,0.4);display:flex;align-items:center;justify-content:center;margin-left:auto;transition:transform .2s" onmouseover="this.style.transform='scale(1.08)'" onmouseout="this.style.transform='scale(1)'">&#x1F916;</button>
</div>
<script>
var DATA = {};
function toggleTheme(){
  document.body.classList.toggle('light');
  document.getElementById('theme-btn').textContent=document.body.classList.contains('light')?'Dark':'Light';
}
function switchTab(t){
  var tabs=['overview','network','devices','threats','password'];
  document.querySelectorAll('.tab').forEach(function(el,i){el.classList.toggle('active',tabs[i]===t);});
  document.querySelectorAll('.tab-content').forEach(function(el){el.classList.remove('active');});
  document.getElementById('tab-'+t).classList.add('active');
}
setInterval(function(){document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-US',{hour12:false});},1000);
document.getElementById('clock').textContent=new Date().toLocaleTimeString('en-US',{hour12:false});
function scoreColor(s){return s>=80?'#30d158':s>=55?'#ffd60a':'#ff453a';}
function deviceIcon(v,h){
  v=(v||'').toLowerCase();h=(h||'').toLowerCase();
  if(v.includes('apple')||h.includes('iphone')||h.includes('mac')||h.includes('ipad')) return '&#x1F4BB;';
  if(v.includes('samsung')||v.includes('android')) return '&#x1F4F1;';
  if(v.includes('intel')||v.includes('msi')||v.includes('dell')||v.includes('hp')||v.includes('lenovo')) return '&#x1F5A5;';
  if(v.includes('calix')||v.includes('eero')||v.includes('netgear')||v.includes('linksys')||h.includes('router')) return '&#x1F4E1;';
  if(v.includes('amazon')||h.includes('echo')||h.includes('ring')) return '&#x1F50A;';
  return '&#x1F4BB;';
}
function loadAll(){
  fetch('/api/data').then(function(r){return r.json();}).then(function(d){
    DATA=d;
    var c=scoreColor(d.health.score);
    var radius=34,circ=2*Math.PI*radius,offset=circ-(d.health.score/100)*circ;
    document.getElementById('health-wrap').innerHTML='<div class="health-card"><div class="score-ring"><svg width="80" height="80" viewBox="0 0 80 80"><circle class="track" cx="40" cy="40" r="'+radius+'"/><circle class="fill" cx="40" cy="40" r="'+radius+'" stroke="'+c+'" stroke-dasharray="'+circ+'" stroke-dashoffset="'+offset+'"/></svg><div class="score-num" style="color:'+c+'">'+d.health.score+'</div></div><div class="health-text"><h2>'+d.health.grade_label+'</h2><p>'+d.health.grade_msg+'</p></div></div>';
    renderOverview(d.health);
    // Load briefing
    fetch('/api/briefing').then(function(r){return r.json();}).then(function(b){
      document.getElementById('briefing-text').textContent=b.briefing;
    }).catch(function(){document.getElementById('briefing-text').textContent='Your security score is '+d.health.score+'/100. '+d.health.grade_msg;});
    document.getElementById('net-info').innerHTML='<div class="row"><span class="rk">Wi-Fi</span><span class="rv">'+d.network.wifi+'</span></div><div class="row"><span class="rk">Local IP</span><span class="rv">'+d.network.local_ip+'</span></div><div class="row"><span class="rk">Public IP</span><span class="rv">'+d.network.public_ip+'</span></div><div class="row"><span class="rk">VPN</span><span class="rv '+(d.network.vpn?'vpn-on':'vpn-off')+'">'+(d.network.vpn?'Active':'Off')+'</span></div>';
    if(!d.ports.length){document.getElementById('port-info').innerHTML='<div class="loading">No open ports</div>';}
    else{var ph='';d.ports.forEach(function(p){var bc=p.risk==='high'?'b-red':p.risk==='medium'?'b-orange':'b-green';var bl=p.risk==='high'?'High Risk':p.risk==='medium'?'Monitor':'Safe';ph+='<div class="port-row"><div class="port-left"><div class="port-num">'+p.port+' <span style="color:var(--t2);font-weight:400">'+(p.name||p.process)+'</span></div><div class="port-explain">'+p.explain+'</div></div><span class="badge '+bc+'">'+bl+'</span></div>';});document.getElementById('port-info').innerHTML=ph;}
    fetch('/api/explain/network',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({network:d.network,ports:d.ports})}).then(function(r){return r.json();}).then(function(r){document.getElementById('net-ai').innerHTML='<p style="font-size:13px;line-height:1.6;color:var(--t2)">'+r.explanation+'</p>';}).catch(function(){document.getElementById('net-ai').innerHTML='<p class="loading">AI unavailable</p>';});
    if(!d.devices||!d.devices.length){document.getElementById('device-list').innerHTML='<div class="card"><p class="loading">No scan data. Run scanner.py from terminal first.</p></div>';document.getElementById('device-count').textContent='No devices found';}
    else{
      document.getElementById('device-count').textContent=d.devices.length+' devices on your network - click any for AI explanation';
      var dh='';
      d.devices.forEach(function(dev,idx){
        var isYou=dev.ip===d.network.local_ip;
        dh+='<div class="device-row" onclick="explainDevice('+idx+')" id="drow-'+idx+'"><div class="device-icon">'+deviceIcon(dev.vendor,dev.hostname)+'</div><div class="device-info"><div class="device-name">'+dev.hostname+(isYou?'<span class="you-tag">You</span>':'')+'</div><div class="device-meta">'+dev.ip+' | '+dev.mac+'</div><div class="device-ai" id="dai-'+idx+'"></div></div><div class="device-vendor">'+(dev.vendor&&dev.vendor!=='Unknown'?dev.vendor:'Unknown')+'</div></div>';
      });
      document.getElementById('device-list').innerHTML=dh;
    }
    if(!d.cves.length){document.getElementById('cve-list').innerHTML='<div class="card"><p style="color:var(--t2)">No critical threats in the past 48 hours.</p></div>';}
    else{var ch='';d.cves.forEach(function(cv,idx){var isc=parseFloat(cv.score)>=9;ch+='<div class="cve-card" onclick="expandCVE('+idx+')" id="cve-'+idx+'"><div class="cve-top"><span class="score-pill '+(isc?'pill-c':'pill-h')+'">'+(isc?'Critical':'High')+' '+cv.score+'/10</span><span class="cve-id">'+cv.id+'</span><span class="cve-date">'+cv.published+'</span></div><div class="cve-desc">'+cv.description+'</div><div class="cve-ai" id="cai-'+idx+'"><div class="cve-ai-label">AI Explanation</div><div id="cai-text-'+idx+'"></div></div><a class="cve-link" href="'+cv.url+'" target="_blank" onclick="event.stopPropagation()">View technical details</a></div>';});document.getElementById('cve-list').innerHTML=ch;}
    document.getElementById('upd').textContent='Updated '+new Date().toLocaleTimeString();
  }).catch(function(e){console.error(e);});
}

var currentMode = 'simple';
function setMode(mode){
  currentMode = mode;
  document.getElementById('mode-simple').style.background = mode==='simple'?'rgba(41,151,255,0.15)':'var(--s1)';
  document.getElementById('mode-simple').style.color = mode==='simple'?'var(--blue)':'var(--t2)';
  document.getElementById('mode-simple').style.borderColor = mode==='simple'?'var(--blue)':'var(--bd)';
  document.getElementById('mode-technical').style.background = mode==='technical'?'rgba(41,151,255,0.15)':'var(--s1)';
  document.getElementById('mode-technical').style.color = mode==='technical'?'var(--blue)':'var(--t2)';
  document.getElementById('mode-technical').style.borderColor = mode==='technical'?'var(--blue)':'var(--bd)';
  if(DATA.health) renderOverview(DATA.health);
}
function renderOverview(health){
  var items = health.items || [];
  var sl='';
  // Issues first (sorted by severity)
  var order = {critical:0, high:1, medium:2, low:3};
  items.sort(function(a,b){return (order[a.severity]||3)-(order[b.severity]||3);});
  items.forEach(function(item){
    var isIssue = item.status==='issue';
    var isWarn = item.status==='warn';
    var isGood = item.status==='good';
    var borderColor = isIssue?'rgba(255,69,58,.25)':isWarn?'rgba(255,159,10,.2)':'rgba(48,209,88,.15)';
    var titleColor = isIssue?'var(--red)':isWarn?'var(--orange)':isGood?'var(--green)':'var(--t1)';
    var desc = currentMode==='simple' ? item.simple : item.technical;
    var action = currentMode==='simple' ? item.action_simple : item.action_technical;
    sl+='<div style="background:var(--s1);border:1px solid '+borderColor+';border-radius:14px;padding:14px 18px;margin-bottom:10px">';
    sl+='<div style="display:flex;align-items:flex-start;gap:10px">';
    sl+='<span style="font-size:18px;flex-shrink:0;margin-top:1px">'+item.emoji+'</span>';
    sl+='<div style="flex:1">';
    sl+='<div style="font-size:14px;font-weight:500;color:'+titleColor+';margin-bottom:4px">'+item.title+'</div>';
    sl+='<div style="font-size:13px;color:var(--t2);line-height:1.5;margin-bottom:'+(action?'8px':'0')+'px">'+desc+'</div>';
    if(action){
      sl+='<div style="font-size:12px;color:var(--blue);font-weight:500">'+( currentMode==="simple"?"What to do: ":"Technical fix: ")+action+'</div>';
    }
    sl+='</div>';
    if(currentMode==="technical"){
      var badge = item.severity==="critical"?"CRITICAL":item.severity==="high"?"HIGH":item.severity==="medium"?"MEDIUM":"LOW";
      var bc = item.severity==="critical"||item.severity==="high"?"b-red":item.severity==="medium"?"b-orange":"b-green";
      sl+='<span class="badge '+bc+'" style="flex-shrink:0;margin-top:2px">'+badge+'</span>';
    }
    sl+='</div></div>';
  });
  document.getElementById('status-items').innerHTML=sl;
}

function explainDevice(idx){
  var box=document.getElementById('dai-'+idx);
  if(box.style.display==='block'){box.style.display='none';return;}
  box.style.display='block';box.innerHTML='<span class="spin">&#9696;</span> Asking AI...';
  fetch('/api/explain/device',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(DATA.devices[idx])}).then(function(r){return r.json();}).then(function(d){box.innerHTML=d.explanation;}).catch(function(){box.innerHTML='Could not get explanation.';});
}
function expandCVE(idx){
  var ai=document.getElementById('cai-'+idx);var txt=document.getElementById('cai-text-'+idx);
  if(ai.style.display==='block'){ai.style.display='none';return;}
  ai.style.display='block';txt.innerHTML='<span class="spin">&#9696;</span> AI is explaining this...';
  fetch('/api/explain/cve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(DATA.cves[idx])}).then(function(r){return r.json();}).then(function(d){txt.innerHTML=d.explanation;}).catch(function(){txt.innerHTML='Could not get explanation.';});
}
function checkPassword(){
  var pw=document.getElementById('pw-input').value;
  if(!pw){alert('Please enter a password');return;}
  document.getElementById('pw-btn').textContent='Checking...';
  document.getElementById('pw-result').innerHTML='<div class="loading"><span class="spin">&#9696;</span> Checking against breach database...</div>';
  fetch('/api/checkpassword',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})}).then(function(r){return r.json();}).then(function(d){
    document.getElementById('pw-btn').textContent='Check Password';
    if(d.error){document.getElementById('pw-result').innerHTML='<p style="color:var(--red)">'+d.error+'</p>';return;}
    var statusColor=d.status==='safe'?'var(--green)':d.status==='critical'||d.status==='high'?'var(--red)':'var(--orange)';
    var borderColor=d.safe?'rgba(48,209,88,.3)':'rgba(255,69,58,.3)';
    var icon=d.safe?'&#10003;':'&#9888;';
    var html='<div style="background:var(--s1);border:1px solid '+borderColor+';border-radius:14px;padding:20px 22px">';
    html+='<div style="font-size:15px;font-weight:600;color:'+statusColor+';margin-bottom:10px">'+icon+' '+d.summary+'</div>';
    html+='<div style="font-size:13px;color:var(--t2);line-height:1.6;margin-bottom:12px">'+d.advice+'</div>';
    if(!d.safe){html+='<div style="font-size:12px;color:var(--t3);border-top:1px solid var(--bd);padding-top:10px">Use a password manager like 1Password or Bitwarden to generate unique strong passwords for every site.</div>';}
    html+='</div>';
    document.getElementById('pw-result').innerHTML=html;
  }).catch(function(){document.getElementById('pw-btn').textContent='Check Password';document.getElementById('pw-result').innerHTML='<p style="color:var(--red)">Could not check. Try again.</p>';});
}

var chatOpen = false;
function toggleChat(){
  chatOpen = !chatOpen;
  var box = document.getElementById('chat-box');
  box.style.display = chatOpen ? 'flex' : 'none';
  if(chatOpen) document.getElementById('chat-input').focus();
}
function quickAsk(msg){
  document.getElementById('chat-input').value = msg;
  sendChat();
}
function addMessage(text, isUser){
  var messages = document.getElementById('chat-messages');
  var div = document.createElement('div');
  div.style.cssText = isUser
    ? 'background:rgba(41,151,255,0.15);border-radius:12px 12px 4px 12px;padding:10px 14px;font-size:13px;color:var(--t1);line-height:1.5;max-width:90%;align-self:flex-end;margin-left:auto'
    : 'background:var(--s1);border-radius:12px 12px 12px 4px;padding:10px 14px;font-size:13px;color:var(--t2);line-height:1.5;max-width:90%';
  div.textContent = text;
  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
  return div;
}
function sendChat(){
  var input = document.getElementById('chat-input');
  var msg = input.value.trim();
  if(!msg) return;
  input.value = '';
  addMessage(msg, true);
  var thinking = addMessage('Thinking...', false);
  thinking.style.color = 'var(--t3)';
  thinking.style.fontStyle = 'italic';
  fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg})})
    .then(function(r){return r.json();})
    .then(function(d){
      thinking.textContent = d.reply;
      thinking.style.color = 'var(--t2)';
      thinking.style.fontStyle = 'normal';
      document.getElementById('chat-messages').scrollTop = 999999;
    })
    .catch(function(){
      thinking.textContent = 'Could not reach AI. Make sure Ollama is running.';
      thinking.style.color = 'var(--red)';
    });
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
