#!/usr/bin/env bash
# run_noseyparker_docker.sh — Run Nosey Parker in a container and emit JSON.
# Purpose: Avoid host glibc constraints by using the official container image.
#
# Usage:
#   bash scripts/core/run_noseyparker_docker.sh /path/to/repo /path/to/output.json
#   bash scripts/core/run_noseyparker_docker.sh --repo /path/to/repo --out results/individual-repos/<name>/noseyparker.json
#
# Requirements:
#   - Docker daemon available (Docker Desktop or similar)
#   - Internet access to pull ghcr.io/praetorian-inc/noseyparker:latest

set -Eeuo pipefail
IFS=$'\n\t'

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[np-docker]${NC} $*"; }
ok() { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err() { echo -e "${RED}[err]${NC} $*"; }

IMAGE="ghcr.io/praetorian-inc/noseyparker:latest"

REPO_DIR=""
OUT_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
  --repo)
    REPO_DIR="$2"
    shift 2
    ;;
  --out)
    OUT_FILE="$2"
    shift 2
    ;;
  -h | --help)
    sed -n '1,60p' "$0" | sed -n '1,30p'
    exit 0
    ;;
  *)
    if [ -z "$REPO_DIR" ]; then
      REPO_DIR="$1"
      shift
      continue
    fi
    if [ -z "$OUT_FILE" ]; then
      OUT_FILE="$1"
      shift
      continue
    fi
    shift
    ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  err "docker not found on PATH. Install/start Docker Desktop and retry."
  exit 1
fi

if [ -z "${REPO_DIR}" ] || [ -z "${OUT_FILE}" ]; then
  err "Missing arguments. Provide repo path and output file."
  echo "Example: $0 /path/to/repo results/individual-repos/<name>/noseyparker.json"
  exit 2
fi

REPO_DIR=$(readlink -f "$REPO_DIR")
OUT_FILE=$(readlink -f "$OUT_FILE")
OUT_DIR=$(dirname "$OUT_FILE")
mkdir -p "$OUT_DIR"

if [ ! -d "$REPO_DIR" ]; then
  err "Repo directory does not exist: $REPO_DIR"
  exit 3
fi

log "Pulling container image (first time may take a while): $IMAGE"
docker pull "$IMAGE" >/dev/null 2>&1 || warn "Unable to pull; using local image if present"

VOL_NAME="npdata_$(date +%s)_$RANDOM"
DS_PATH="/npdata"
cleanup() {
  docker volume rm -f "$VOL_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Create a fresh volume for this run
docker volume create "$VOL_NAME" >/dev/null

log "Preparing Nosey Parker datastore in docker volume $VOL_NAME…"
docker run --rm \
  -u 0:0 \
  -v "$VOL_NAME:/npdata" \
  "$IMAGE" \
  datastore init --datastore "$DS_PATH" >/dev/null 2>&1 || true

log "Scanning repo via container…"
docker run --rm \
  -u 0:0 \
  -v "$REPO_DIR:/repo:ro" \
  -v "$VOL_NAME:/npdata" \
  "$IMAGE" \
  scan --datastore "$DS_PATH" /repo >/dev/null
SCAN_RC=$?
if [ "$SCAN_RC" -ne 0 ]; then
  err "Nosey Parker scan failed (rc=$SCAN_RC)."
  exit $SCAN_RC
fi

log "Producing JSON report…"
docker run --rm \
  -u 0:0 \
  -v "$VOL_NAME:/npdata:ro" \
  "$IMAGE" \
  report --format json --datastore "$DS_PATH" >"$OUT_FILE"
REPORT_RC=$?
if [ "$REPORT_RC" -ne 0 ]; then
  err "Nosey Parker report failed (rc=$REPORT_RC)."
  exit $REPORT_RC
fi

ok "Wrote Nosey Parker JSON to: $OUT_FILE"
