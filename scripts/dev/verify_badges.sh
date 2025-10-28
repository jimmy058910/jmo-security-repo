#!/usr/bin/env bash
set -euo pipefail

#
# verify_badges.sh - Verify README badges match pyproject.toml version
#
# Usage:
#   ./scripts/dev/verify_badges.sh          # Check and report
#   ./scripts/dev/verify_badges.sh --fix    # Force badge cache refresh
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PYPROJECT="$REPO_ROOT/pyproject.toml"
README="$REPO_ROOT/README.md"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Extract version from pyproject.toml
get_local_version() {
    grep '^version = ' "$PYPROJECT" | sed 's/version = "\(.*\)"/\1/'
}

# Get version from PyPI
get_pypi_version() {
    curl -s https://pypi.org/pypi/jmo-security/json | jq -r '.info.version'
}

# Get version from shields.io badge (what users see)
get_badge_version() {
    # shields.io SVG contains the version as text
    curl -sL "https://img.shields.io/pypi/v/jmo-security.svg?$(date +%s)" | grep -oP '\d+\.\d+\.\d+' | head -1
}

# Force badge cache refresh by appending timestamp
refresh_badge_cache() {
    local badge_url="https://img.shields.io/pypi/v/jmo-security.svg"
    echo -e "${YELLOW}Forcing badge cache refresh...${NC}"

    # Make multiple requests to different CDN nodes to trigger cache invalidation
    for i in {1..5}; do
        curl -sL "${badge_url}?t=$(date +%s)" -o /dev/null -w "Request $i: HTTP %{http_code}\n"
        sleep 0.5
    done

    echo -e "${GREEN}Badge cache refresh initiated. Wait 30-60s for propagation.${NC}"
}

main() {
    local fix_mode=false
    if [[ "${1:-}" == "--fix" ]]; then
        fix_mode=true
    fi

    echo "=== JMo Security Badge Verification ==="
    echo ""

    # Get versions
    local_version=$(get_local_version)
    echo "📦 Local version (pyproject.toml): $local_version"

    pypi_version=$(get_pypi_version)
    if [[ -n "$pypi_version" ]]; then
        echo "🐍 PyPI version: $pypi_version"
    else
        echo -e "${RED}❌ Failed to fetch PyPI version${NC}"
        exit 1
    fi

    badge_version=$(get_badge_version)
    if [[ -n "$badge_version" ]]; then
        echo "🏷️  Badge version (shields.io): $badge_version"
    else
        echo -e "${YELLOW}⚠️  Could not parse badge version${NC}"
    fi

    echo ""
    echo "=== Verification ==="

    # Check if this is a release commit or release branch
    is_release_commit=false
    current_branch=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)

    if git -C "$REPO_ROOT" log -1 --format=%s | grep -q '^release: v'; then
        is_release_commit=true
        echo -e "${YELLOW}ℹ️  Detected release commit${NC}"
    elif [[ "$current_branch" =~ ^release/v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        is_release_commit=true
        echo -e "${YELLOW}ℹ️  Detected release branch: $current_branch${NC}"
    fi

    # Check if PyPI matches local
    if [[ "$pypi_version" == "$local_version" ]]; then
        echo -e "${GREEN}✅ PyPI matches local version${NC}"
    else
        if $is_release_commit; then
            echo -e "${YELLOW}⚠️  Version mismatch (expected for release PR):${NC}"
            echo -e "   Local:  $local_version"
            echo -e "   PyPI:   $pypi_version"
            echo ""
            echo "This is a release commit - version will sync after tag push triggers release workflow."
            echo "Skipping version mismatch check."
        else
            echo -e "${RED}❌ Version mismatch:${NC}"
            echo -e "   Local:  $local_version"
            echo -e "   PyPI:   $pypi_version"
            echo ""
            echo "Action needed: Tag and release v$local_version"
            echo "  git tag v$local_version"
            echo "  git push --tags"
            exit 1
        fi
    fi

    # Check if badge matches PyPI
    if [[ "$badge_version" == "$pypi_version" ]]; then
        echo -e "${GREEN}✅ Badge matches PyPI version${NC}"
    else
        echo -e "${YELLOW}⚠️  Badge cache outdated:${NC}"
        echo -e "   Badge:  $badge_version"
        echo -e "   PyPI:   $pypi_version"

        if $fix_mode; then
            refresh_badge_cache
        else
            echo ""
            echo "Badge caching is normal. Shields.io caches for 5-15 minutes."
            echo "To force refresh, run: $0 --fix"
            echo "Or wait 15 minutes and check: https://img.shields.io/pypi/v/jmo-security"
        fi
    fi

    echo ""
    echo "=== Badge URLs in README ==="
    grep -n "badge.fury.io\|shields.io/pypi" "$README" | head -3

    echo ""
    echo "All badges auto-update from PyPI. No manual edits needed."
}

main "$@"
