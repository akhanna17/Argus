#!/usr/bin/env python3
import urllib.request, urllib.parse, json, os
from datetime import datetime, timedelta, timezone

WEBHOOK_URL = "https://discord.com/api/webhooks/1493108550912835694/UNqORuxbc28WrmpBo0CIRjb4l5LbuziuB5A-47BLDLnqAY8nsQnyO6jvmYB5DlB3UnHt"

SEEN_FILE = os.path.expanduser("~/.sentineldash_seen_cves.json")

def load_seen():
    try:
        with open(SEEN_FILE) as f: return set(json.load(f))
    except: return set()

def save_seen(seen):
    with open(SEEN_FILE, "w") as f: json.dump(list(seen), f)

def fetch_cves():
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=24)
    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
           f"pubStartDate={urllib.parse.quote(start.strftime('%Y-%m-%dT%H:%M:%S.000'))}&"
           f"pubEndDate={urllib.parse.quote(end.strftime('%Y-%m-%dT%H:%M:%S.000'))}&"
           f"cvssV3Severity=CRITICAL&resultsPerPage=20")
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
        cves.append({"id": cve_id, "description": desc[:300], "score": score,
                     "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"})
    return cves

def send_alert(cve):
    payload = json.dumps({
        "username": "SentinelDash",
        "embeds": [{
            "title": f"🚨 {cve['id']} — Score: {cve['score']}",
            "description": cve["description"],
            "color": 16711680,
            "url": cve["url"],
            "footer": {"text": "SentinelDash • NVD Feed"}
        }]
    }).encode()
    req = urllib.request.Request(WEBHOOK_URL, data=payload,
                                  headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status == 204

seen = load_seen()
print(f"🛡  SentinelDash CVE Alerts — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
cves = fetch_cves()
print(f"Found {len(cves)} critical CVEs, {len([c for c in cves if c['id'] not in seen])} new")
for cve in cves:
    if cve["id"] not in seen:
        print(f"  Sending {cve['id']} (Score: {cve['score']})")
        try:
            send_alert(cve)
            seen.add(cve["id"])
            print(f"  ✓ Sent")
        except Exception as e:
            print(f"  ✗ Failed: {e}")
save_seen(seen)
print("Done.")
