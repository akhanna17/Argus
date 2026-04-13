#!/usr/bin/env python3
import urllib.request, urllib.parse, json, os
from datetime import datetime, timedelta, timezone

WEBHOOK_URL = open(os.path.expanduser("~/Desktop/sentineldash/webhook.txt")).read().strip()
SEEN_FILE = os.path.expanduser("~/.sentineldash_seen_cves.json")

def load_seen():
    try:
        with open(SEEN_FILE) as f: return set(json.load(f))
    except: return set()

def save_seen(seen):
    with open(SEEN_FILE, "w") as f: json.dump(list(seen), f)

def explain_cve(cve_id, description, score):
    """Use local Ollama AI to explain the CVE in plain English."""
    try:
        prompt = f"""You are explaining a computer security problem to a 5 year old. Use simple words, no technical terms, short sentences. Be friendly and clear.
Write 3 short paragraphs explaining this security vulnerability to a non-technical person. First paragraph: what the vulnerability is and how it works in simple terms. Second paragraph: who is affected and what an attacker could do. Third paragraph: what steps should be taken to stay safe. No jargon, clear and conversational tone.
- What is it? (one sentence, no jargon)
- Who is affected? (one sentence)
- What should they do? (one sentence)

CVE: {cve_id}
Score: {score}/10
Description: {description}

Keep each bullet point under 15 words. Be direct and clear."""

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
            data = json.loads(r.read().decode())
            return data.get("response", "").strip()
    except Exception as e:
        return f"• What: Critical security vulnerability\n• Who: Users of affected software\n• Do: Apply patches immediately"

def fetch_cves():
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=24)
    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
           f"pubStartDate={urllib.parse.quote(start.strftime('%Y-%m-%dT%H:%M:%S.000'))}&"
           f"pubEndDate={urllib.parse.quote(end.strftime('%Y-%m-%dT%H:%M:%S.000'))}&"
           f"cvssV3Severity=CRITICAL&resultsPerPage=10")
    req = urllib.request.Request(url, headers={"User-Agent": "SentinelDash/3.0"})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read().decode())
    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "No description")
        metrics = cve.get("metrics", {})
        score = "N/A"
        if "cvssMetricV31" in metrics:
            score = str(metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", "N/A"))
        elif "cvssMetricV30" in metrics:
            score = str(metrics["cvssMetricV30"][0]["cvssData"].get("baseScore", "N/A"))
        cve_id = cve.get("id", "Unknown")
        cves.append({"id": cve_id, "description": desc[:400], "score": score,
                     "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"})
    return cves

def send_alert(cve, explanation):
    payload = json.dumps({
        "username": "SentinelDash",
        "embeds": [{
            "title": f"🚨 {cve['id']} — Score: {cve['score']}/10",
            "description": f"**Plain English Summary:**\n{explanation}\n\n**Technical Details:**\n{cve['description'][:200]}...",
            "color": 16711680,
            "url": cve["url"],
            "footer": {"text": "SentinelDash • Powered by NVD + Llama 3.2"}
        }]
    }).encode()
    req = urllib.request.Request(WEBHOOK_URL, data=payload,
                                  headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                                  method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status == 204

seen = load_seen()
print(f"🛡  SentinelDash CVE Alerts — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
cves = fetch_cves()
new_cves = [c for c in cves if c["id"] not in seen]
print(f"Found {len(cves)} critical CVEs, {len(new_cves)} new")

for cve in new_cves:
    print(f"  Explaining {cve['id']} with AI...")
    explanation = explain_cve(cve["id"], cve["description"], cve["score"])
    print(f"  Sending to Discord...")
    try:
        send_alert(cve, explanation)
        seen.add(cve["id"])
        print(f"  ✓ Sent")
    except Exception as e:
        print(f"  ✗ Failed: {e}")

save_seen(seen)
print("Done.")
