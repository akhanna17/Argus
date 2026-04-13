# Argus — Project Roadmap

## Phase 1 ✅ — Terminal Dashboard (You are here)
**Goal:** Get something on screen that looks impressive and is actually useful.

Files: `sentinel.py`
Run: `python sentinel.py`

What it shows:
- WiFi network name
- Local + public IP
- VPN status (detects tun/utun interfaces)
- Open listening ports on your Mac
- Latest Critical CVEs from NVD (past 48h)

What you learn:
- Python subprocess (running system commands from code)
- Socket networking
- REST APIs (NVD)
- Rich terminal UI library

---

## Phase 2 — Network Scanner
**Goal:** See every device on your WiFi right now.

New file: `scanner.py`
Add to dashboard: a live device table with hostname, IP, MAC, vendor

What you'll use:
- `scapy` for ARP scanning
- MAC vendor lookup API (macvendors.com — free)
- Alert if unknown device joins

What you learn:
- ARP protocol
- Packet crafting basics
- MAC addresses and OUI lookup

Install: `pip install scapy`

---

## Phase 3 — CVE Alerting
**Goal:** Get a Discord ping when a critical CVE drops.

New file: `alerts.py`
Set up a Discord webhook (free, 2 minutes to create)
Run on a schedule with `cron` on Mac

What you'll use:
- Discord webhooks (just an HTTP POST)
- `cron` for scheduling (`crontab -e`)
- NVD API (already built in Phase 1)

What you learn:
- Webhooks
- Cron scheduling
- Building automation that runs without you

---

## Phase 4 — VPN Kill Monitor
**Goal:** Alert you the moment your VPN drops.

New file: `vpn_watch.py`
Runs in background, polls every 30 seconds
Sends Discord alert + optionally blocks internet with `pf` firewall rules

What you learn:
- Background processes / daemons
- macOS `pf` firewall
- Network interface monitoring

---

## Phase 5 — Web UI
**Goal:** A beautiful browser dashboard you can show anyone.

New files: `app.py` (Flask), `templates/index.html`
All Phase 1-4 data served as a local web app
Runs at `http://localhost:5000`

What you learn:
- Flask web framework
- REST API design (you're now building one, not just consuming)
- Frontend (HTML/CSS/JS)
- WebSockets for live updates

---

## Phase 6 (Stretch) — macOS Menu Bar App
**Goal:** A tiny icon in your Mac menu bar that shows VPN status at a glance.

Tool: `rumps` library
Shows green/red dot for VPN, click to see full dashboard

---

## How to Build This Properly (Git Workflow)

```bash
# Start the project
git init
git add .
git commit -m "Phase 1: terminal dashboard"

# Each phase gets its own branch + commit
git checkout -b phase-2-scanner
# ... build it ...
git add .
git commit -m "Phase 2: network scanner with ARP"
git checkout main
git merge phase-2-scanner
```

Push to GitHub. Each commit shows your progression. Recruiters can see the history.

---

## Resume Bullet Points (fill these in as you complete phases)

- Built a personal macOS security dashboard in Python that monitors VPN status, open ports, and live CVE feeds from the NVD API
- Implemented ARP network scanning to detect and alert on unknown devices joining the local network
- Automated Critical CVE alerts via Discord webhooks using cron scheduling
- Designed a Flask web UI to visualize real-time security telemetry from the local machine and network
