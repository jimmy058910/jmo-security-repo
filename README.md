# IOD Capstone - Security Audit Tool Suite

A comprehensive security audit toolkit for analyzing repositories using multiple security scanning tools including Gitleaks, TruffleHog, Semgrep, and Nosey Parker.

## 🎯 Overview

This project provides an automated framework for conducting thorough security audits on code repositories. It orchestrates multiple industry-standard security tools to detect secrets, vulnerabilities, and security issues.

### Key Features

- ✅ **Multi-Tool Scanning**: Integrates Gitleaks, TruffleHog, Semgrep, and Nosey Parker
- 📊 **Comprehensive Reporting**: Generates HTML dashboards, markdown summaries, and detailed findings
- 🎨 **Easy-to-Read Outputs**: Well-formatted reports with severity categorization
- 🔄 **Automated Workflows**: Single command to run complete security audits
- 📈 **Comparative Analysis**: Tool performance comparison and metrics
- 🎯 **Actionable Insights**: Prioritized recommendations based on severity

## 🚀 Quick Start

### Prerequisites

Install the required security tools:

```bash
# Check if tools are installed
./security_audit.sh --check

# Or manually check
./check_tools.sh
```

Required tools:
- **cloc**: Code metrics
- **Gitleaks**: Git secret scanning
- **TruffleHog**: Secret scanning with verification
- **Semgrep**: Pattern-based vulnerability detection
- **Nosey Parker**: Deep pattern matching
- **jq**: JSON processing

### Installation

1. Clone this repository:
```bash
git clone https://github.com/jimmy058910/iod-capstone.git
cd iod-capstone
```

2. Make scripts executable:
```bash
chmod +x *.sh scripts/*.sh
```

3. Install required tools (see Tool Installation section below)

### Basic Usage

#### Quick Setup with Helper Script

Use the `populate_targets.sh` helper script to clone multiple repositories for testing (optimized for WSL):

```bash
# Clone sample vulnerable repos (fast shallow clones)
./scripts/populate_targets.sh

# Clone from custom list with full history
./scripts/populate_targets.sh --list my-repos.txt --full

# Clone with 8 parallel jobs for faster performance
./scripts/populate_targets.sh --parallel 8

# Unshallow repos if secret scanners need full git history
./scripts/populate_targets.sh --unshallow
```

#### Running Security Scans

1. **Simple Scan** - Scan repositories in default directory:
```bash
./security_audit.sh -d ~/security-testing
```

2. **Custom Output** - Specify custom output directory:
```bash
./security_audit.sh -d ~/my-repos -o ~/scan-results
```

3. **Check Tools** - Verify tool installation:
```bash
./security_audit.sh --check
```

#### End-to-End Workflow

```bash
# 1. Clone test repositories (shallow for speed)
./scripts/populate_targets.sh --dest ~/test-repos --parallel 4

# 2. Run security audit
./security_audit.sh -d ~/test-repos

# 3. View results
cat ~/security-results-*/SUMMARY_REPORT.md
open ~/security-results-*/dashboard.html
```

## 📚 Documentation

### Workflow

The security audit follows this workflow:

1. **Tool Verification**: Checks all required tools are installed
2. **Repository Scanning**: Runs all security tools on each repository
3. **Results Aggregation**: Collects and processes findings
4. **Report Generation**: Creates multiple report formats
5. **Dashboard Creation**: Generates interactive HTML dashboard

### Output Structure

```
security-results-YYYYMMDD-HHMMSS/
├── SUMMARY_REPORT.md              # Executive summary
├── dashboard.html                  # Interactive HTML dashboard
├── individual-repos/               # Per-repository results
│   └── [repo-name]/
│       ├── README.md              # Formatted findings report
│       ├── gitleaks.json          # Gitleaks raw output
│       ├── trufflehog.json        # TruffleHog raw output
│       ├── semgrep.json           # Semgrep raw output
│       ├── noseyparker.json       # Nosey Parker raw output
│       └── *.log                  # Tool execution logs
├── tool-comparisons/
│   └── comparison.md              # Tool performance comparison
├── summaries/
│   └── metrics.csv                # Aggregated metrics
└── raw-outputs/                   # Additional raw data
```

### Report Types

1. **Summary Report** (`SUMMARY_REPORT.md`)
   - Executive summary
   - Aggregate statistics
   - Repository breakdown table
   - Prioritized recommendations

2. **HTML Dashboard** (`dashboard.html`)
   - Visual metrics cards
   - Severity breakdown
   - Repository comparison table
   - Tool performance analysis

3. **Individual Reports** (`individual-repos/*/README.md`)
   - Repository-specific findings
   - Tool-by-tool breakdown
   - Detailed issue listings
   - Severity classifications

4. **Tool Comparison** (`tool-comparisons/comparison.md`)
   - Detection metrics
   - Tool capabilities matrix
   - Implementation strategy guide
   - Tool selection recommendations

## 🛠️ Tool Installation

### macOS (Homebrew)

```bash
# Core tools
brew install cloc jq

# Gitleaks
brew install gitleaks

# Semgrep
brew install semgrep

# TruffleHog
brew install trufflesecurity/trufflehog/trufflehog

# Nosey Parker
# Download from: https://github.com/praetorian-inc/noseyparker/releases
```

### Linux (Ubuntu/Debian)

```bash
# Core tools
sudo apt-get install cloc jq

# Gitleaks
wget https://github.com/zricethezav/gitleaks/releases/latest/download/gitleaks-linux-amd64
chmod +x gitleaks-linux-amd64
sudo mv gitleaks-linux-amd64 /usr/local/bin/gitleaks

# Semgrep
pip install semgrep

# TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Nosey Parker
# Download from: https://github.com/praetorian-inc/noseyparker/releases
```

## 📋 Advanced Usage

### Helper Scripts for Multi-Repo Scanning

#### `scripts/populate_targets.sh` - Automated Repository Cloning

This helper script streamlines the process of cloning multiple repositories for security scanning, with performance optimizations for WSL environments.

**Features:**
- 🚀 Shallow clones (depth=1) for faster cloning
- ⚡ Parallel cloning for improved performance
- 🔄 Unshallow option for secret scanners requiring full history
- 📝 Reads from repository list file

**Usage Examples:**

```bash
# Basic usage with defaults (samples/repos.txt → ~/security-testing)
./scripts/populate_targets.sh

# Custom repository list and destination
./scripts/populate_targets.sh --list custom-repos.txt --dest ~/my-test-repos

# Full clones with 8 parallel jobs
./scripts/populate_targets.sh --full --parallel 8

# Unshallow existing shallow clones
./scripts/populate_targets.sh --dest ~/security-testing --unshallow

# Show all options
./scripts/populate_targets.sh --help
```

**Repository List Format (`samples/repos.txt`):**
```
# One GitHub repository URL per line
# Lines starting with # are comments
https://github.com/user/repo1.git
https://github.com/user/repo2.git
```

**Performance Tips for WSL:**
1. Use shallow clones initially for 10x faster cloning
2. Adjust `--parallel` based on network speed (default: 4)
3. Use `--unshallow` only if secret scanners need full git history
4. Clone to WSL filesystem (not Windows mount) for better performance

### Running Individual Scripts

1. **Tool Check Only**:
```bash
./check_tools.sh
```

2. **Main Audit Script**:
```bash
./run_security_audit.sh [testing_directory] [output_directory]
```

3. **Generate Dashboard Only**:
```bash
python3 generate_dashboard.py /path/to/results
```

4. **Generate Comparison Report**:
```bash
./generate_comparison_report.sh /path/to/results
```

### Customizing Tool Execution

Edit `run_security_audit.sh` to enable/disable tools:

```bash
# Tool flags (set to 1 to enable, 0 to disable)
RUN_CLOC=1
RUN_GITLEAKS=1
RUN_TRUFFLEHOG=1
RUN_SEMGREP=1
RUN_NOSEYPARKER=1
```

## 🔍 Understanding Results

### Severity Levels

- **CRITICAL**: Verified secrets requiring immediate action
- **HIGH**: Likely secrets or serious vulnerabilities
- **MEDIUM**: Potential issues requiring review
- **LOW/INFO**: Informational findings

### Key Metrics

- **Total Findings**: All security issues detected
- **Verified Secrets**: Confirmed active credentials (TruffleHog)
- **Unique Issues**: Distinct types of security problems
- **Tool Coverage**: Number of tools that found issues

### Recommendations Priority

1. **Immediate**: Rotate/revoke verified secrets
2. **High Priority**: Fix critical and high severity issues
3. **Medium Priority**: Address medium severity findings
4. **Long-term**: Implement preventive measures

## 🎯 Three-Stage Implementation Strategy

### Stage 1: Pre-commit Hooks
- **Tool**: Gitleaks
- **Purpose**: Prevent secrets before commit
- **Speed**: Fast (suitable for developer workflow)

### Stage 2: CI/CD Pipeline
- **Tools**: Gitleaks + Semgrep
- **Purpose**: Automated PR/commit scanning
- **Coverage**: Secrets + vulnerabilities

### Stage 3: Deep Periodic Audits
- **Tools**: All tools
- **Purpose**: Comprehensive security assessment
- **Frequency**: Weekly/monthly

## 📊 Sample Output

### Dashboard Preview
The HTML dashboard provides:
- Visual metric cards with key statistics
- Severity breakdown tables
- Repository-by-repository comparison
- Tool performance analysis
- Actionable recommendations

### Sample Summary Report
```markdown
## Aggregate Results

### Overall Statistics
- Total Issues Found: 156
- Critical Issues: 12
- High Severity Issues: 45
- Medium Severity Issues: 99

### Recommendations
- Review all 12 critical issues immediately
- Verified secrets should be rotated/revoked urgently
- Address 45 high severity issues in next sprint
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📝 License

This project is part of the IOD Capstone program.

## 🔗 Related Resources

- [Gitleaks Documentation](https://github.com/zricethezav/gitleaks)
- [TruffleHog Documentation](https://github.com/trufflesecurity/trufflehog)
- [Semgrep Documentation](https://semgrep.dev)
- [Nosey Parker Documentation](https://github.com/praetorian-inc/noseyparker)

## 💡 Tips

1. **Start Small**: Test on a single repository first
2. **Review Regularly**: Schedule periodic audits
3. **Act Quickly**: Rotate verified secrets immediately
4. **Prevent Issues**: Implement pre-commit hooks
5. **Monitor Trends**: Track metrics over time

## 🆘 Troubleshooting

### Common Issues

**Problem**: Tools not found
- **Solution**: Run `./security_audit.sh --check` to verify installation

**Problem**: JSON parsing errors
- **Solution**: Ensure jq is installed and tools are outputting valid JSON

**Problem**: Permission denied
- **Solution**: Run `chmod +x *.sh` to make scripts executable

**Problem**: Out of memory
- **Solution**: Scan repositories in smaller batches

---

**Last Updated**: October 9th, 2025
**Author**: James Moceri
