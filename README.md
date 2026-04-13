# 🛡️ SentinelDash

> Your personal Mac security dashboard. Know what's on your network, whether your VPN is holding, and what threats are trending — all in one place.

---

## What It Does

SentinelDash is a personal security monitoring tool built for your Mac. It runs in your terminal (and eventually as a web UI) and gives you a live view of:

- **Network Map** — Every device currently on your WiFi, with hostname, IP, and MAC address
- **VPN Status** — Whether your VPN is actually active or silently dropped
- **CVE Feed** — Latest Critical/High vulnerabilities from the NVD in the past 24 hours
- **Open Ports** — What's listening on your machine right now and why
- **Alerts** — Discord/phone notifications when something changes

---

## Project Phases

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | Terminal UI — network info, IP, VPN status | 🔲 Up next |
| 2 | Network scanner — who's on your WiFi | 🔲 Planned |
| 3 | CVE feed — live vulnerability alerts | 🔲 Planned |
| 4 | Push alerts — Discord/phone notifications | 🔲 Planned |
| 5 | Web UI — beautiful browser dashboard | 🔲 Planned |

---

## Tech Stack

- **Language:** Python 3
- **Terminal UI:** `rich`
- **Networking:** `scapy`, `nmap`
- **APIs:** NVD (National Vulnerability Database)
- **Alerts:** Discord webhooks
- **Web UI (Phase 5):** Flask or FastAPI + HTML/CSS

---

## Setup

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/sentineldash.git
cd sentineldash

# Install dependencies
pip install -r requirements.txt

# Run Phase 1
python sentinel.py
```

---

## Requirements

- macOS (tested on Ventura/Sonoma)
- Python 3.9+
- `nmap` installed via Homebrew: `brew install nmap`

---

## Author

Aryan Khanna — Cybersecurity Student @ Purdue University

---

## Roadmap

- [ ] Phase 1: Terminal dashboard
- [ ] Phase 2: Network scanner
- [ ] Phase 3: CVE feed integration
- [ ] Phase 4: Discord alerts
- [ ] Phase 5: Web UI
- [ ] Phase 6: macOS menu bar app
