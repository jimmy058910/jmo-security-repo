#!/bin/bash
# Install all JMo Security external tools via Homebrew
# Works on macOS and Linux (with Linuxbrew)

set -e # Exit on error

echo "🔧 Installing JMo Security external tools via Homebrew..."
echo ""

# Check if Homebrew is installed
if ! command -v brew &>/dev/null; then
  echo "❌ Homebrew not found. Install from: https://brew.sh"
  exit 1
fi

echo "✅ Homebrew found: $(brew --version | head -1)"
echo ""

# Function to install a tool
install_tool() {
  local tool_name="$1"
  local brew_formula="$2"
  local description="$3"

  echo "📦 Installing $tool_name ($description)..."
  if brew install "$brew_formula" 2>&1; then
    echo "   ✅ $tool_name installed"
  else
    echo "   ⚠️  $tool_name failed to install (may already be installed)"
  fi
  echo ""
}

# Install tools in order
echo "Installing security tools..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Secrets Scanning
install_tool "TruffleHog" "trufflesecurity/trufflehog/trufflehog" "Verified secrets detection"

# SAST
install_tool "Semgrep" "semgrep" "Multi-language static analysis"

# SBOM + Vulnerabilities
install_tool "Syft" "syft" "SBOM generation"
install_tool "Trivy" "aquasecurity/trivy/trivy" "Vulnerability scanner"

# IaC Security
install_tool "Checkov" "checkov" "Infrastructure as Code security"

# Dockerfile Linting
install_tool "Hadolint" "hadolint" "Dockerfile best practices"

# DAST
install_tool "Nuclei" "nuclei" "Fast vulnerability scanner"

echo "⚠️  Note: Some tools require manual installation:"
echo ""
echo "   • OWASP ZAP (DAST web scanning):"
echo "     macOS: brew install --cask owasp-zap"
echo "     Requires Java JRE 11+"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✅ Tool installation complete!"
echo ""
echo "Verify installation:"
echo "  jmo tools check"
echo ""
echo "Start scanning:"
echo "  jmo wizard"
echo ""
echo "💡 TIP: For every tool with zero setup, use Docker mode:"
echo "  jmo wizard --docker"
echo ""
