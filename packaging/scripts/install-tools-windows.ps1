# Install JMo Security external tools on Windows
# PowerShell script for Windows 10+

$ErrorActionPreference = "Continue"  # Continue on errors

Write-Host "🔧 Installing JMo Security external tools on Windows..." -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "⚠️  Not running as Administrator. Some tools may require elevated privileges." -ForegroundColor Yellow
    Write-Host ""
}

# Function to check if a command exists
function Test-Command {
    param($Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

# Function to install a tool via winget
function Install-Tool {
    param(
        [string]$ToolName,
        [string]$WingetId,
        [string]$Description
    )

    Write-Host "📦 Installing $ToolName ($Description)..." -ForegroundColor White

    if (Test-Command $ToolName.ToLower()) {
        Write-Host "   ✅ $ToolName already installed" -ForegroundColor Green
    } else {
        try {
            winget install --id $WingetId --silent --accept-source-agreements --accept-package-agreements
            Write-Host "   ✅ $ToolName installed" -ForegroundColor Green
        } catch {
            Write-Host "   ⚠️  $ToolName installation failed: $_" -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

# Function to install a tool via pip
function Install-PythonTool {
    param(
        [string]$ToolName,
        [string]$PipPackage,
        [string]$Description
    )

    Write-Host "📦 Installing $ToolName ($Description)..." -ForegroundColor White

    try {
        pip install $PipPackage --quiet
        Write-Host "   ✅ $ToolName installed via pip" -ForegroundColor Green
    } catch {
        Write-Host "   ⚠️  $ToolName installation failed: $_" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Check prerequisites
Write-Host "🔍 Checking prerequisites..." -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Command winget)) {
    Write-Host "❌ Winget not found. Install from Microsoft Store or Windows Package Manager." -ForegroundColor Red
    exit 1
}
Write-Host "✅ Winget found: $(winget --version)" -ForegroundColor Green

if (-not (Test-Command python)) {
    Write-Host "⚠️  Python not found. Some tools (Checkov, Bandit) require Python." -ForegroundColor Yellow
    Write-Host "   Install from: https://www.python.org/downloads/" -ForegroundColor Yellow
} else {
    Write-Host "✅ Python found: $(python --version)" -ForegroundColor Green
}
Write-Host ""

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Installing 7/12 Windows-compatible tools..." -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# Install Windows-compatible tools
# Note: Some tools may not have winget packages, we'll try scoop as fallback

# 1. TruffleHog (Go binary)
if (Test-Command scoop) {
    Write-Host "📦 Installing TruffleHog (Verified secrets detection)..." -ForegroundColor White
    try {
        scoop install trufflehog
        Write-Host "   ✅ TruffleHog installed via scoop" -ForegroundColor Green
    } catch {
        Write-Host "   ⚠️  Install manually from: https://github.com/trufflesecurity/trufflehog/releases" -ForegroundColor Yellow
    }
} else {
    Write-Host "📦 TruffleHog: Install Scoop first (https://scoop.sh) or download from:" -ForegroundColor Yellow
    Write-Host "   https://github.com/trufflesecurity/trufflehog/releases" -ForegroundColor Yellow
}
Write-Host ""

# 2. Trivy (Go binary)
if (Test-Command scoop) {
    Write-Host "📦 Installing Trivy (Vulnerability scanner)..." -ForegroundColor White
    try {
        scoop install trivy
        Write-Host "   ✅ Trivy installed via scoop" -ForegroundColor Green
    } catch {
        Write-Host "   ⚠️  Install manually from: https://github.com/aquasecurity/trivy/releases" -ForegroundColor Yellow
    }
} else {
    Write-Host "📦 Trivy: Install Scoop first (https://scoop.sh) or download from:" -ForegroundColor Yellow
    Write-Host "   https://github.com/aquasecurity/trivy/releases" -ForegroundColor Yellow
}
Write-Host ""

# 3. Syft (Go binary)
if (Test-Command scoop) {
    Write-Host "📦 Installing Syft (SBOM generation)..." -ForegroundColor White
    try {
        scoop install syft
        Write-Host "   ✅ Syft installed via scoop" -ForegroundColor Green
    } catch {
        Write-Host "   ⚠️  Install manually from: https://github.com/anchore/syft/releases" -ForegroundColor Yellow
    }
} else {
    Write-Host "📦 Syft: Install Scoop first (https://scoop.sh) or download from:" -ForegroundColor Yellow
    Write-Host "   https://github.com/anchore/syft/releases" -ForegroundColor Yellow
}
Write-Host ""

# 4. Checkov (Python package)
if (Test-Command python) {
    Install-PythonTool "Checkov" "checkov" "Infrastructure as Code security"
} else {
    Write-Host "📦 Checkov: Requires Python. Install Python first." -ForegroundColor Yellow
    Write-Host ""
}

# 5. Hadolint (Haskell binary)
Write-Host "📦 Installing Hadolint (Dockerfile linting)..." -ForegroundColor White
Write-Host "   Download from: https://github.com/hadolint/hadolint/releases" -ForegroundColor Yellow
Write-Host "   Add to PATH manually after download" -ForegroundColor Yellow
Write-Host ""

# 6. Nuclei (Go binary)
if (Test-Command go) {
    Write-Host "📦 Installing Nuclei (Fast vulnerability scanner)..." -ForegroundColor White
    try {
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        Write-Host "   ✅ Nuclei installed via go install" -ForegroundColor Green
    } catch {
        Write-Host "   ⚠️  Install manually from: https://github.com/projectdiscovery/nuclei/releases" -ForegroundColor Yellow
    }
} else {
    Write-Host "📦 Nuclei: Requires Go. Install from https://go.dev or download binary:" -ForegroundColor Yellow
    Write-Host "   https://github.com/projectdiscovery/nuclei/releases" -ForegroundColor Yellow
}
Write-Host ""

# 7. Bandit (Python package)
if (Test-Command python) {
    Install-PythonTool "Bandit" "bandit" "Python security linter"
} else {
    Write-Host "📦 Bandit: Requires Python. Install Python first." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

Write-Host "⚠️  Windows Limitations (5/12 tools NOT available natively):" -ForegroundColor Yellow
Write-Host ""
Write-Host "   ❌ Semgrep: Some rules require Linux (use Docker)" -ForegroundColor Red
Write-Host "   ❌ OWASP ZAP: Requires Java JRE 11+ (complex setup)" -ForegroundColor Red
Write-Host "   ❌ Nosey Parker: No Windows build (Docker only)" -ForegroundColor Red
Write-Host "   ❌ Falco: Requires Linux kernel + eBPF (Docker/WSL2 only)" -ForegroundColor Red
Write-Host "   ❌ AFL++: Requires Linux kernel (Docker only)" -ForegroundColor Red
Write-Host ""

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

Write-Host "✅ Windows-compatible tools installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Next Steps:" -ForegroundColor Cyan
Write-Host ""
Write-Host "   1. Verify installation:" -ForegroundColor White
Write-Host "      jmotools setup --check" -ForegroundColor Gray
Write-Host ""
Write-Host "   2. Start scanning (use fast or balanced profile):" -ForegroundColor White
Write-Host "      jmotools wizard --profile fast" -ForegroundColor Gray
Write-Host ""
Write-Host "   3. 💡 RECOMMENDED: For ALL 12 tools, use Docker mode:" -ForegroundColor White
Write-Host "      # Install WSL2 + Docker Desktop first" -ForegroundColor Gray
Write-Host "      jmotools wizard --docker" -ForegroundColor Gray
Write-Host ""

if (-not (Test-Command scoop)) {
    Write-Host "💡 TIP: Install Scoop package manager for easier tool management:" -ForegroundColor Cyan
    Write-Host "   https://scoop.sh" -ForegroundColor Gray
    Write-Host ""
}
