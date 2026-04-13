#!/bin/bash
echo ""
echo "  Stopping Argus..."
lsof -ti:5001 | xargs kill -9 2>/dev/null
pkill ngrok 2>/dev/null
echo "  Done."
echo ""
