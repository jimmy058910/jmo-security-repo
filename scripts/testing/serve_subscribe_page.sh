#!/bin/bash

# Serve the subscribe page via HTTP (avoids CORS issues with file://)

cd /home/jimmy058910/jmo-security-repo/docs

echo "=============================================="
echo "🌐 Starting local web server for testing"
echo "=============================================="
echo ""
echo "📄 Subscribe page will be available at:"
echo "   http://localhost:8000/subscribe.html"
echo ""
echo "🌐 Opening in Windows browser..."
echo ""

# Start Python HTTP server in background
python3 -m http.server 8000 &
SERVER_PID=$!

# Wait a moment for server to start
sleep 2

# Open in Windows browser
if command -v wslview &> /dev/null; then
    wslview "http://localhost:8000/subscribe.html"
elif command -v explorer.exe &> /dev/null; then
    # Create a temporary HTML redirect file for explorer
    echo '<html><head><meta http-equiv="refresh" content="0; url=http://localhost:8000/subscribe.html"></head></html>' > /tmp/redirect.html
    explorer.exe "$(wslpath -w /tmp/redirect.html)"
fi

echo "✅ Server started on http://localhost:8000"
echo "📄 Subscribe page: http://localhost:8000/subscribe.html"
echo ""
echo "Press Ctrl+C to stop the server when done testing"
echo ""

# Wait for Ctrl+C
trap "kill $SERVER_PID; echo ''; echo '✅ Server stopped'; exit 0" INT TERM
wait $SERVER_PID
