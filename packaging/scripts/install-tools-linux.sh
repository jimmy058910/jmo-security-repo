#!/bin/bash
# Install all JMo Security external tools on Linux
# Supports Ubuntu, Debian, Fedora, Arch Linux

set -e  # Exit on error

echo "🔧 Installing JMo Security external tools on Linux..."
echo ""

# Detect Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
    VERSION="$VERSION_ID"
else
    echo "❌ Cannot detect Linux distribution"
    exit 1
fi

echo "✅ Detected: $PRETTY_NAME"
echo ""

# Function to install a tool from GitHub releases
install_from_github() {
    local tool_name="$1"
    local repo="$2"
    local asset_pattern="$3"
    local install_path="$4"

    echo "📦 Installing $tool_name from GitHub..."

    # Get latest release
    local latest_url=$(curl -s "https://api.github.com/repos/$repo/releases/latest" | grep "browser_download_url.*$asset_pattern" | cut -d '"' -f 4 | head -1)

    if [ -z "$latest_url" ]; then
        echo "   ⚠️  Could not find release for $tool_name"
        return 1
    fi

    echo "   Downloading from: $latest_url"
    wget -q "$latest_url" -O "/tmp/$tool_name.tar.gz"

    # Extract and install
    tar -xzf "/tmp/$tool_name.tar.gz" -C /tmp/
    sudo mv "/tmp/$tool_name" "$install_path/$tool_name"
    sudo chmod +x "$install_path/$tool_name"
    rm -f "/tmp/$tool_name.tar.gz"

    echo "   ✅ $tool_name installed to $install_path/$tool_name"
    echo ""
}

# Install based on distribution
case "$DISTRO" in
    ubuntu|debian)
        echo "📦 Using apt package manager..."
        echo ""

        # Update package lists
        sudo apt-get update -qq

        # Install Python and pip (for Python-based tools)
        sudo apt-get install -y python3 python3-pip curl wget

        # Install Go (for some tools)
        if ! command -v go &> /dev/null; then
            echo "📦 Installing Go..."
            wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
            sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
            export PATH=$PATH:/usr/local/go/bin
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            rm go1.21.0.linux-amd64.tar.gz
            echo "   ✅ Go installed"
        fi

        # Install Trivy (has official apt repo)
        echo "📦 Installing Trivy (Vulnerability scanner)..."
        sudo apt-get install -y wget apt-transport-https gnupg lsb-release
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
        echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
        sudo apt-get update -qq
        sudo apt-get install -y trivy
        echo "   ✅ Trivy installed"
        echo ""

        # Install Python-based tools
        echo "📦 Installing Python-based tools..."
        sudo pip3 install checkov bandit semgrep --quiet
        echo "   ✅ Checkov, Bandit, Semgrep installed"
        echo ""

        # Install TruffleHog (Go binary)
        install_from_github "trufflehog" "trufflesecurity/trufflehog" "linux_amd64.tar.gz" "/usr/local/bin"

        # Install Syft (Go binary)
        install_from_github "syft" "anchore/syft" "linux_amd64.tar.gz" "/usr/local/bin"

        # Install Hadolint (Haskell binary)
        echo "📦 Installing Hadolint (Dockerfile linting)..."
        wget -q https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 -O /tmp/hadolint
        sudo mv /tmp/hadolint /usr/local/bin/hadolint
        sudo chmod +x /usr/local/bin/hadolint
        echo "   ✅ Hadolint installed"
        echo ""

        # Install Nuclei (Go binary)
        echo "📦 Installing Nuclei (Fast vulnerability scanner)..."
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        sudo mv ~/go/bin/nuclei /usr/local/bin/
        echo "   ✅ Nuclei installed"
        echo ""

        ;;

    fedora|rhel|centos)
        echo "📦 Using dnf/yum package manager..."
        echo ""

        # Install Python and pip
        sudo dnf install -y python3 python3-pip curl wget

        # Install Python-based tools
        sudo pip3 install checkov bandit semgrep --quiet

        # Install Go tools (similar to Ubuntu)
        # ... (same as Ubuntu section for GitHub installs)

        ;;

    arch|manjaro)
        echo "📦 Using pacman package manager..."
        echo ""

        # Install Python and pip
        sudo pacman -S --noconfirm python python-pip curl wget

        # Many tools available in AUR
        if command -v yay &> /dev/null; then
            echo "📦 Installing tools from AUR..."
            yay -S --noconfirm trivy syft hadolint
        fi

        # Install Python-based tools
        sudo pip3 install checkov bandit semgrep --quiet

        ;;

    *)
        echo "⚠️  Unsupported distribution: $DISTRO"
        echo "   Install tools manually or use Homebrew (Linuxbrew)"
        echo "   Install Homebrew: https://brew.sh"
        echo "   Then run: ./install-tools-homebrew.sh"
        exit 1
        ;;
esac

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "⚠️  Optional tools (require Docker):"
echo ""
echo "   • Nosey Parker (deep secrets scanning):"
echo "     docker pull ghcr.io/praetorian-inc/noseyparker:latest"
echo ""
echo "   • Falco (runtime security):"
echo "     Requires Kubernetes or Docker with privileged mode"
echo ""
echo "   • AFL++ (fuzzing):"
echo "     docker pull aflplusplus/aflplusplus"
echo ""
echo "   • OWASP ZAP (DAST):"
echo "     Requires Java JRE 11+"
echo "     Download from: https://www.zaproxy.org/download/"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✅ Tool installation complete!"
echo ""
echo "Verify installation:"
echo "  jmotools setup --check"
echo ""
echo "Start scanning:"
echo "  jmotools wizard"
echo ""
echo "💡 TIP: For ALL 12 tools with zero setup, use Docker mode:"
echo "  jmotools wizard --docker"
echo ""
