#!/usr/bin/env bash
set -euo pipefail

HTML=${1:-results/summaries/dashboard.html}
OUTDIR=${2:-docs/screenshots}
mkdir -p "$OUTDIR"

if command -v chromium >/dev/null 2>&1; then
  chromium --headless --disable-gpu --screenshot="$OUTDIR/dashboard.png" "file://$(pwd)/$HTML"
  echo "Saved $OUTDIR/dashboard.png"
elif command -v google-chrome >/dev/null 2>&1; then
  google-chrome --headless --disable-gpu --screenshot="$OUTDIR/dashboard.png" "file://$(pwd)/$HTML"
  echo "Saved $OUTDIR/dashboard.png"
else
  echo "No chromium/google-chrome found. Please capture manually."
fi
