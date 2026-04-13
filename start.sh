#!/bin/bash
# ─────────────────────────────────────────────
# Argus — Single Startup Script
# Starts everything you need with one command
# Usage: ./start.sh
# ─────────────────────────────────────────────

ARGUS_DIR="$HOME/Desktop/argus"
DATA_DIR="$ARGUS_DIR/data"
LOG_DIR="$ARGUS_DIR/logs"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo "  ██████████████████████████████████"
echo "  ██                              ██"
echo "  ██   ARGUS Security Monitor     ██"
echo "  ██   Built by Aryan Khanna     ██"
echo "  ██                              ██"
echo "  ██████████████████████████████████"
echo ""

# Create dirs
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"

cd "$ARGUS_DIR"

# ── Check venv ──
if [ ! -d "$ARGUS_DIR/venv" ]; then
    echo -e "  ${RED}Error: venv not found. Run setup first.${NC}"
    exit 1
fi

source "$ARGUS_DIR/venv/bin/activate"

# ── Check Ollama ──
echo -e "  ${BLUE}[1/4]${NC} Checking Ollama AI..."
if pgrep -x "ollama" > /dev/null; then
    echo -e "  ${GREEN}✓${NC} Ollama already running"
else
    echo -e "  ${YELLOW}→${NC} Starting Ollama..."
    ollama serve > "$LOG_DIR/ollama.log" 2>&1 &
    sleep 3
    echo -e "  ${GREEN}✓${NC} Ollama started"
fi

# ── Run network scan ──
echo -e "  ${BLUE}[2/4]${NC} Running network scan..."
sudo python3 "$ARGUS_DIR/device_monitor.py" > "$LOG_DIR/scan.log" 2>&1 &
SCAN_PID=$!
echo -e "  ${GREEN}✓${NC} Network scan running in background (PID $SCAN_PID)"

# ── Start Flask ──
echo -e "  ${BLUE}[3/4]${NC} Starting Argus dashboard..."
if lsof -ti:5001 > /dev/null 2>&1; then
    echo -e "  ${YELLOW}→${NC} Port 5001 in use, killing old instance..."
    lsof -ti:5001 | xargs kill -9 2>/dev/null
    sleep 1
fi
"$ARGUS_DIR/venv/bin/python3" "$ARGUS_DIR/app.py" > "$LOG_DIR/flask.log" 2>&1 &
FLASK_PID=$!
sleep 2
echo -e "  ${GREEN}✓${NC} Dashboard running (PID $FLASK_PID)"

# ── Start ngrok ──
echo -e "  ${BLUE}[4/4]${NC} Starting public URL..."
if pgrep -x "ngrok" > /dev/null; then
    echo -e "  ${YELLOW}→${NC} Killing old ngrok..."
    pkill ngrok
    sleep 1
fi
ngrok http 5001 > "$LOG_DIR/ngrok.log" 2>&1 &
sleep 3

# Get ngrok URL
NGROK_URL=$(curl -s http://localhost:4040/api/tunnels 2>/dev/null | python3 -c "import sys,json; tunnels=json.load(sys.stdin).get('tunnels',[]); print(tunnels[0]['public_url'] if tunnels else 'Starting...')" 2>/dev/null)

echo ""
echo "  ─────────────────────────────────────"
echo -e "  ${GREEN}Argus is running!${NC}"
echo ""
echo -e "  Local:  ${BLUE}http://localhost:5001${NC}"
if [ "$NGROK_URL" != "Starting..." ] && [ -n "$NGROK_URL" ]; then
    echo -e "  Public: ${BLUE}$NGROK_URL${NC}"
else
    echo -e "  Public: ${YELLOW}Check http://localhost:4040 for URL${NC}"
fi
echo ""
echo "  Logs: ~/Desktop/argus/logs/"
echo "  Stop: Press Ctrl+C or run ./stop.sh"
echo "  ─────────────────────────────────────"
echo ""

# Open browser
sleep 1
open "http://localhost:5001" 2>/dev/null || true

# Wait and keep running
echo "  Press Ctrl+C to stop all services"
echo ""

trap 'echo ""; echo "  Stopping Argus..."; kill $FLASK_PID 2>/dev/null; pkill ngrok 2>/dev/null; echo "  Done."; exit 0' INT

wait $FLASK_PID
