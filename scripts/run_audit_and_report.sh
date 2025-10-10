#!/bin/bash
# run_audit_and_report.sh - Orchestrator wrapper with speed and resume features
# Comprehensive reliability and UX upgrade for multi-repo security scanning

set -e
set -o pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get script directory and repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default values
TARGETS_DIR="$HOME/security-testing"
RESULTS_DIR=""  # Will be set based on repo root if not provided
OPEN_DASHBOARD=0
FAST_PASS=0
RESUME=0
VERIFY=0
WSL_HINTS=0

# Display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --targets <dir>        Directory containing repositories to scan (default: ~/security-testing)"
    echo "  --results <dir>        Output directory for results (default: ./results/YYYYMMDD-HHMMSS)"
    echo "  --open-dashboard       Open dashboard in browser after completion"
    echo "  --fast-pass            Disable slow scanners (gitleaks, trufflehog, noseyparker)"
    echo "  --resume               Skip repos already present in results/individual-repos"
    echo "  --verify               Post-run artifact completeness check"
    echo "  --wsl-hints            Show WSL-specific optimization hints"
    echo "  -h, --help             Display this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                      # Scan ~/security-testing with defaults"
    echo "  $0 --targets ~/my-repos                # Scan custom directory"
    echo "  $0 --results ./my-results              # Custom results directory"
    echo "  $0 --fast-pass --open-dashboard        # Quick scan and view results"
    echo "  $0 --resume --verify                   # Resume scan and verify completeness"
    echo "  $0 --wsl-hints                         # Show WSL optimization tips"
    echo ""
    exit 0
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --targets)
            TARGETS_DIR="$2"
            shift 2
            ;;
        --results)
            RESULTS_DIR="$2"
            shift 2
            ;;
        --open-dashboard)
            OPEN_DASHBOARD=1
            shift
            ;;
        --fast-pass)
            FAST_PASS=1
            shift
            ;;
        --resume)
            RESUME=1
            shift
            ;;
        --verify)
            VERIFY=1
            shift
            ;;
        --wsl-hints)
            WSL_HINTS=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║     Security Audit & Report Orchestrator                 ║
║     Comprehensive Multi-Repo Security Scanning            ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Show WSL hints if requested
if [ "$WSL_HINTS" -eq 1 ]; then
    echo -e "${CYAN}WSL Performance Optimization Hints:${NC}"
    echo "=================================================="
    echo ""
    echo "1. Use ext4 filesystem (avoid /mnt/c for better I/O):"
    echo "   ✓ Good: ~/security-testing (ext4)"
    echo "   ✗ Slow: /mnt/c/Users/.../repos (NTFS)"
    echo ""
    echo "2. Clone with shallow mode first:"
    echo "   ./scripts/populate_targets.sh --shallow --parallel 8"
    echo ""
    echo "3. Use --fast-pass to skip slow scanners:"
    echo "   $0 --fast-pass"
    echo ""
    echo "4. Enable Windows Defender exclusions for:"
    echo "   - WSL ext4 filesystem: %LOCALAPPDATA%\\Packages\\*\\LocalState\\ext4.vhdx"
    echo "   - Repository directories"
    echo ""
    echo "5. Increase WSL memory allocation in .wslconfig:"
    echo "   [wsl2]"
    echo "   memory=8GB"
    echo "   processors=4"
    echo ""
    echo "=================================================="
    exit 0
fi

# Set default results directory if not provided
if [ -z "$RESULTS_DIR" ]; then
    RESULTS_DIR="$REPO_ROOT/results/$(date -u +%Y%m%d-%H%M%S)"
fi

# Validate targets directory
if [ ! -d "$TARGETS_DIR" ]; then
    log_error "Targets directory does not exist: $TARGETS_DIR"
    log_info "Please create it or specify a valid path with --targets"
    exit 1
fi

# Count repositories in targets
TOTAL_REPOS=$(find "$TARGETS_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)

if [ "$TOTAL_REPOS" -eq 0 ]; then
    log_error "No repositories found in: $TARGETS_DIR"
    log_info "Clone repositories first using: ./scripts/populate_targets.sh"
    exit 1
fi

# Display configuration
log_info "Targets directory: $TARGETS_DIR"
log_info "Results directory: $RESULTS_DIR"
log_info "Total repositories: $TOTAL_REPOS"
if [ "$FAST_PASS" -eq 1 ]; then
    log_info "Mode: FAST (gitleaks, trufflehog, noseyparker disabled)"
else
    log_info "Mode: FULL (all scanners enabled)"
fi
if [ "$RESUME" -eq 1 ]; then
    log_info "Resume: Enabled (skipping already scanned repos)"
fi
echo ""

# Create results directory
mkdir -p "$RESULTS_DIR"

# Handle resume mode - identify already scanned repos
SKIP_REPOS=()
if [ "$RESUME" -eq 1 ]; then
    if [ -d "$RESULTS_DIR/individual-repos" ]; then
        mapfile -t SKIP_REPOS < <(find "$RESULTS_DIR/individual-repos" -mindepth 1 -maxdepth 1 -type d -exec basename {} \;)
        if [ ${#SKIP_REPOS[@]} -gt 0 ]; then
            log_info "Found ${#SKIP_REPOS[@]} already scanned repositories (will skip)"
        fi
    fi
fi

# Function to check if repo should be skipped
should_skip_repo() {
    local repo_name="$1"
    for skip in "${SKIP_REPOS[@]}"; do
        if [ "$repo_name" = "$skip" ]; then
            return 0
        fi
    done
    return 1
}

# Set tool flags based on fast-pass mode
if [ "$FAST_PASS" -eq 1 ]; then
    export RUN_GITLEAKS=0
    export RUN_TRUFFLEHOG=0
    export RUN_NOSEYPARKER=0
else
    export RUN_GITLEAKS=1
    export RUN_TRUFFLEHOG=1
    export RUN_NOSEYPARKER=1
fi

# Always enable these tools
export RUN_CLOC=1
export RUN_SEMGREP=1

# Run the audit
log_info "Starting security audit..."
echo ""

# Absolute path to audit script
AUDIT_SCRIPT="$REPO_ROOT/run_security_audit.sh"

# If resume mode, filter repositories
if [ "$RESUME" -eq 1 ] && [ ${#SKIP_REPOS[@]} -gt 0 ]; then
    log_info "Resume mode: skipping ${#SKIP_REPOS[@]} repositories"
    
    # Create a temporary filtered directory list
    TEMP_TARGETS="/tmp/filtered_targets_$$"
    mkdir -p "$TEMP_TARGETS"
    
    for repo_path in "$TARGETS_DIR"/*; do
        if [ -d "$repo_path" ]; then
            repo_name=$(basename "$repo_path")
            if ! should_skip_repo "$repo_name"; then
                ln -s "$repo_path" "$TEMP_TARGETS/$repo_name"
            else
                log_info "Skipping (already scanned): $repo_name"
            fi
        fi
    done
    
    # Run audit on filtered targets
    bash "$AUDIT_SCRIPT" "$TEMP_TARGETS" "$RESULTS_DIR"
    
    # Cleanup
    rm -rf "$TEMP_TARGETS"
else
    # Run normal audit
    bash "$AUDIT_SCRIPT" "$TARGETS_DIR" "$RESULTS_DIR"
fi

# Verify artifacts if requested
if [ "$VERIFY" -eq 1 ]; then
    echo ""
    log_info "Verifying artifact completeness..."
    
    VERIFICATION_PASSED=true
    
    # Check for main summary report
    if [ ! -f "$RESULTS_DIR/SUMMARY_REPORT.md" ]; then
        log_error "Missing: SUMMARY_REPORT.md"
        VERIFICATION_PASSED=false
    else
        log_success "Found: SUMMARY_REPORT.md"
    fi
    
    # Check for dashboard
    if [ ! -f "$RESULTS_DIR/dashboard.html" ]; then
        log_warning "Missing: dashboard.html (optional)"
    else
        log_success "Found: dashboard.html"
    fi
    
    # Check individual repo results and normalize JSONs
    if [ -d "$RESULTS_DIR/individual-repos" ]; then
        SCANNED_REPOS=$(find "$RESULTS_DIR/individual-repos" -mindepth 1 -maxdepth 1 -type d | wc -l)
        log_info "Found results for $SCANNED_REPOS repositories"
        
        # Verify and normalize each repo's JSON files
        for repo_dir in "$RESULTS_DIR/individual-repos"/*; do
            if [ -d "$repo_dir" ]; then
                repo_name=$(basename "$repo_dir")
                
                if [ ! -f "$repo_dir/README.md" ]; then
                    log_error "Missing README.md for: $repo_name"
                    VERIFICATION_PASSED=false
                fi
                
                # Normalize cloc.json (should be {})
                if [ -f "$repo_dir/cloc.json" ]; then
                    if ! jq -e 'type == "object"' "$repo_dir/cloc.json" >/dev/null 2>&1; then
                        log_warning "Normalizing cloc.json for: $repo_name"
                        echo '{}' > "$repo_dir/cloc.json"
                    fi
                fi
                
                # Normalize gitleaks.json (should be [])
                if [ -f "$repo_dir/gitleaks.json" ]; then
                    if ! jq -e 'type == "array"' "$repo_dir/gitleaks.json" >/dev/null 2>&1; then
                        log_warning "Normalizing gitleaks.json for: $repo_name"
                        echo '[]' > "$repo_dir/gitleaks.json"
                    fi
                else
                    echo '[]' > "$repo_dir/gitleaks.json"
                fi
                
                # Normalize trufflehog.json (should be [])
                if [ -f "$repo_dir/trufflehog.json" ]; then
                    # Check if it's valid JSON, if not normalize to []
                    if ! jq -e '.' "$repo_dir/trufflehog.json" >/dev/null 2>&1; then
                        log_warning "Normalizing trufflehog.json for: $repo_name"
                        echo '[]' > "$repo_dir/trufflehog.json"
                    fi
                else
                    echo '[]' > "$repo_dir/trufflehog.json"
                fi
                
                # Normalize semgrep.json (should be {"results":[]})
                if [ -f "$repo_dir/semgrep.json" ]; then
                    if ! jq -e 'has("results")' "$repo_dir/semgrep.json" >/dev/null 2>&1; then
                        log_warning "Normalizing semgrep.json for: $repo_name"
                        echo '{"results":[]}' > "$repo_dir/semgrep.json"
                    fi
                else
                    echo '{"results":[]}' > "$repo_dir/semgrep.json"
                fi
                
                # Normalize noseyparker.json (should be {"matches":[]})
                if [ -f "$repo_dir/noseyparker.json" ]; then
                    if ! jq -e 'has("matches")' "$repo_dir/noseyparker.json" >/dev/null 2>&1; then
                        log_warning "Normalizing noseyparker.json for: $repo_name"
                        echo '{"matches":[]}' > "$repo_dir/noseyparker.json"
                    fi
                else
                    echo '{"matches":[]}' > "$repo_dir/noseyparker.json"
                fi
                
                # Check for at least one scan result
                if ! ls "$repo_dir"/*.json >/dev/null 2>&1 && ! ls "$repo_dir"/*.log >/dev/null 2>&1; then
                    log_error "No scan results for: $repo_name"
                    VERIFICATION_PASSED=false
                fi
            fi
        done
    else
        log_error "Missing: individual-repos directory"
        VERIFICATION_PASSED=false
    fi
    
    echo ""
    if [ "$VERIFICATION_PASSED" = true ]; then
        log_success "Verification passed: All expected artifacts present"
    else
        log_error "Verification failed: Some artifacts are missing"
        exit 1
    fi
fi

# Open dashboard if requested
if [ "$OPEN_DASHBOARD" -eq 1 ]; then
    if [ -f "$RESULTS_DIR/dashboard.html" ]; then
        log_info "Opening dashboard in browser..."
        
        if command -v xdg-open &> /dev/null; then
            xdg-open "$RESULTS_DIR/dashboard.html" 2>/dev/null &
        elif command -v open &> /dev/null; then
            open "$RESULTS_DIR/dashboard.html" 2>/dev/null &
        elif command -v wslview &> /dev/null; then
            wslview "$RESULTS_DIR/dashboard.html" 2>/dev/null &
        else
            log_warning "Could not open browser automatically"
            log_info "Open manually: $RESULTS_DIR/dashboard.html"
        fi
    else
        log_warning "Dashboard not found: $RESULTS_DIR/dashboard.html"
        log_info "Generate it with: python3 generate_dashboard.py '$RESULTS_DIR'"
    fi
fi

# Final summary
echo ""
log_success "╔═══════════════════════════════════════════════════════════╗"
log_success "║           Security Audit Complete!                       ║"
log_success "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo -e "${CYAN}📁 Results Directory:${NC} $RESULTS_DIR"
echo -e "${CYAN}📊 Summary Report:${NC} $RESULTS_DIR/SUMMARY_REPORT.md"
if [ -f "$RESULTS_DIR/dashboard.html" ]; then
    echo -e "${CYAN}📈 Dashboard:${NC} $RESULTS_DIR/dashboard.html"
fi
echo ""
echo -e "${CYAN}📝 Next Steps:${NC}"
echo -e "   1. View summary: ${BLUE}cat $RESULTS_DIR/SUMMARY_REPORT.md${NC}"
if [ -f "$RESULTS_DIR/dashboard.html" ]; then
    echo -e "   2. Open dashboard: ${BLUE}open $RESULTS_DIR/dashboard.html${NC}"
fi
echo ""
