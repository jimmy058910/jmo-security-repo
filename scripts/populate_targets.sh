#!/bin/bash
# populate_targets.sh - Clone multiple GitHub repositories for security scanning
# Optimized for WSL with shallow clones and parallel processing

set -e
set -o pipefail

# Color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default values
REPO_LIST="${SCRIPT_DIR}/../samples/repos.txt"
DEST_DIR="$HOME/security-testing"
SHALLOW=1
PARALLEL=4
UNSHALLOW=0

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║     Repository Cloning Tool - Multi-Repo Setup           ║
║     Optimized for WSL with parallel shallow clones        ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --list <file>          Path to repository list file (default: samples/repos.txt)"
    echo "  --dest <dir>           Destination directory for cloned repos (default: ~/security-testing)"
    echo "  --shallow              Use shallow clones (depth=1) for faster cloning (default)"
    echo "  --full                 Use full clones (includes complete git history)"
    echo "  --parallel <N>         Number of parallel clone operations (default: 4)"
    echo "  --unshallow            Unshallow existing repos (useful for secret scanners)"
    echo "  -h, --help             Display this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                           # Use defaults"
    echo "  $0 --list repos.txt --dest ~/test-repos     # Custom list and destination"
    echo "  $0 --full --parallel 8                      # Full clones with 8 parallel jobs"
    echo "  $0 --unshallow                              # Unshallow all repos in destination"
    echo ""
    echo "Performance Tips:"
    echo "  - Use --shallow for faster initial cloning (recommended for WSL)"
    echo "  - Adjust --parallel based on network speed and CPU cores"
    echo "  - Use --unshallow after shallow clone if secret scanners need full history"
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
        --list)
            REPO_LIST="$2"
            shift 2
            ;;
        --dest)
            DEST_DIR="$2"
            shift 2
            ;;
        --shallow)
            SHALLOW=1
            shift
            ;;
        --full)
            SHALLOW=0
            shift
            ;;
        --parallel)
            PARALLEL="$2"
            shift 2
            ;;
        --unshallow)
            UNSHALLOW=1
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

# Validate inputs
if [ ! -f "$REPO_LIST" ]; then
    log_error "Repository list file not found: $REPO_LIST"
    log_info "Create a file with one GitHub repository URL per line"
    exit 1
fi

# Create destination directory
mkdir -p "$DEST_DIR"
log_success "Destination directory: $DEST_DIR"

# Function to clone a single repository
clone_repo() {
    local repo_url="$1"
    local dest_dir="$2"
    local shallow="$3"
    
    # Extract repo name from URL
    local repo_name=$(basename "$repo_url" .git)
    local repo_path="$dest_dir/$repo_name"
    
    # Skip if already exists
    if [ -d "$repo_path" ]; then
        log_warning "Repository already exists: $repo_name (skipping)"
        return 0
    fi
    
    # Clone with appropriate depth
    if [ "$shallow" -eq 1 ]; then
        log_info "Cloning (shallow): $repo_name"
        if git clone --depth 1 --quiet "$repo_url" "$repo_path" 2>&1; then
            log_success "Cloned: $repo_name"
        else
            log_error "Failed to clone: $repo_name"
            return 1
        fi
    else
        log_info "Cloning (full): $repo_name"
        if git clone --quiet "$repo_url" "$repo_path" 2>&1; then
            log_success "Cloned: $repo_name"
        else
            log_error "Failed to clone: $repo_name"
            return 1
        fi
    fi
}

# Function to unshallow a repository
unshallow_repo() {
    local repo_path="$1"
    local repo_name=$(basename "$repo_path")
    
    if [ ! -d "$repo_path/.git" ]; then
        log_warning "Not a git repository: $repo_name (skipping)"
        return 0
    fi
    
    # Check if repo is shallow
    if [ -f "$repo_path/.git/shallow" ]; then
        log_info "Unshallowing: $repo_name"
        if (cd "$repo_path" && git fetch --unshallow --quiet 2>&1); then
            log_success "Unshallowed: $repo_name"
        else
            log_error "Failed to unshallow: $repo_name"
            return 1
        fi
    else
        log_info "Already full clone: $repo_name (skipping)"
    fi
}

# Export functions for parallel execution
export -f clone_repo
export -f log_info
export -f log_success
export -f log_warning
export -f log_error
export RED GREEN YELLOW BLUE CYAN NC

# Handle unshallow operation
if [ "$UNSHALLOW" -eq 1 ]; then
    log_info "Unshallowing repositories in: $DEST_DIR"
    echo ""
    
    # Count repos
    total_repos=$(find "$DEST_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)
    
    if [ "$total_repos" -eq 0 ]; then
        log_warning "No repositories found in: $DEST_DIR"
        exit 0
    fi
    
    log_info "Found $total_repos repositories"
    echo ""
    
    # Unshallow each repo
    success_count=0
    for repo_path in "$DEST_DIR"/*; do
        if [ -d "$repo_path" ]; then
            if unshallow_repo "$repo_path"; then
                ((success_count++)) || true
            fi
        fi
    done
    
    echo ""
    log_success "Unshallowed $success_count out of $total_repos repositories"
    exit 0
fi

# Read repository list and filter comments/empty lines
log_info "Reading repository list from: $REPO_LIST"
mapfile -t repos < <(grep -v '^#' "$REPO_LIST" | grep -v '^[[:space:]]*$' || true)

if [ ${#repos[@]} -eq 0 ]; then
    log_error "No repositories found in list file"
    log_info "Add GitHub repository URLs (one per line) to: $REPO_LIST"
    exit 1
fi

log_info "Found ${#repos[@]} repositories to clone"
echo ""

# Display clone mode
if [ "$SHALLOW" -eq 1 ]; then
    log_info "Clone mode: SHALLOW (depth=1) - faster but limited history"
else
    log_info "Clone mode: FULL - complete git history"
fi
log_info "Parallel jobs: $PARALLEL"
echo ""

# Clone repositories in parallel
if command -v parallel &> /dev/null; then
    # Use GNU parallel if available (better for WSL)
    log_info "Using GNU parallel for efficient cloning..."
    printf '%s\n' "${repos[@]}" | parallel -j "$PARALLEL" --bar \
        "clone_repo {} '$DEST_DIR' $SHALLOW" 2>/dev/null || true
else
    # Fallback to xargs (more widely available)
    log_info "Using xargs for parallel cloning..."
    printf '%s\n' "${repos[@]}" | xargs -n 1 -P "$PARALLEL" -I {} \
        bash -c "clone_repo '{}' '$DEST_DIR' $SHALLOW" || true
fi

echo ""

# Count successful clones
cloned_count=$(find "$DEST_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)

# Summary
echo ""
log_success "╔═══════════════════════════════════════════════════════════╗"
log_success "║              Repository Cloning Complete!                ║"
log_success "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo -e "${CYAN}📁 Destination:${NC} $DEST_DIR"
echo -e "${CYAN}📊 Total Repositories:${NC} $cloned_count"
echo -e "${CYAN}🔧 Clone Type:${NC} $([ $SHALLOW -eq 1 ] && echo 'Shallow (depth=1)' || echo 'Full')"
echo ""

if [ "$SHALLOW" -eq 1 ]; then
    echo -e "${YELLOW}💡 Tip:${NC} If secret scanners need full history, run:"
    echo -e "   ${BLUE}$0 --unshallow${NC}"
    echo ""
fi

echo -e "${CYAN}📝 Next Steps:${NC}"
echo -e "   1. Run security audit: ${BLUE}./security_audit.sh -d $DEST_DIR${NC}"
echo -e "   2. View repositories:  ${BLUE}ls -la $DEST_DIR${NC}"
echo ""
