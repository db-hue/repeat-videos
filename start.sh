#!/usr/bin/env bash
# Repeat Videos local launcher
# Opens a local HTTP server and launches the browser

PORT=8765
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Kill any previous instance on this port
fuser -k ${PORT}/tcp 2>/dev/null

echo "Starting Repeat Videos at http://localhost:${PORT}"
echo "Press Ctrl+C to stop."

# Open browser after a short delay
(sleep 1 && xdg-open "http://localhost:${PORT}") &

# Serve the directory
cd "$DIR"
python3 -m http.server ${PORT}
