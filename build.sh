#!/bin/bash
# Embeds relay_server.py into main.js as base64
# Run this after modifying the relay server script

set -e

JS_FILE="main.js"

if [ -f "relay_server.py" ]; then
    B64=$(base64 -i "relay_server.py" | tr -d '\n')
    sed -i '' "s|RELAY_SERVER_B64 = \"[^\"]*\"|RELAY_SERVER_B64 = \"$B64\"|" "$JS_FILE"
    echo "✓ Embedded relay_server.py into $JS_FILE"
else
    echo "Error: relay_server.py not found"
    exit 1
fi
