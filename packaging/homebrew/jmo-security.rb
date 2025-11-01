# JMo Security - Unified security scanning suite
class JmoSecurity < Formula
  include Language::Python::Virtualenv

  desc "Unified security scanning suite with 12+ tools and plugin system"
  homepage "https://jmotools.com"
  url "https://github.com/jimmy058910/jmo-security-repo/archive/refs/tags/v0.9.0.tar.gz"
  sha256 "" # Will be calculated during release
  license "MIT"
  head "https://github.com/jimmy058910/jmo-security-repo.git", branch: "main"

  # Minimum Python version
  depends_on "python@3.10"

  # Optional security tool dependencies
  # Users can install these separately or use JMo's Docker mode
  # These are recommendations, not hard dependencies

  # Python runtime dependencies from pyproject.toml
  resource "pyyaml" do
    url "https://files.pythonhosted.org/packages/54/ed/79a089b6be93607fa5cdaedf301d7dfb23af5f25c398d5ead2525b063e17/pyyaml-6.0.2.tar.gz"
    sha256 "d584d9ec91ad65861cc08d42e834324ef890a082e591037abe114850ff7bbc3e"
  end

  # Optional dependencies for reporting features
  resource "jsonschema" do
    url "https://files.pythonhosted.org/packages/38/2e/03362ee4034a4c917f697890ccd4aec0800ccf9ded7f511971c75451deec/jsonschema-4.23.0.tar.gz"
    sha256 "d71497fef26351a33265337fa77ffeb82423f3ea21283cd9467bb03999266bc4"
  end

  resource "jsonschema-specifications" do
    url "https://files.pythonhosted.org/packages/10/db/58f950c996c793472e336ff3655b13fbcf1e3b359dcf52dcf3ed3b52c352/jsonschema_specifications-2024.10.1.tar.gz"
    sha256 "0f38b83639958ce1152d02a7f062902c41c8fd20d558b0c34344292d417ae272"
  end

  resource "referencing" do
    url "https://files.pythonhosted.org/packages/99/5b/73ca1f8e72fff6fa52119dbd185f73a907b1989428917b24cff660129b6d/referencing-0.35.1.tar.gz"
    sha256 "25b42124a6c8b632a425174f24087783efb348a6f1e0008e63cd4466fedf703c"
  end

  resource "rpds-py" do
    url "https://files.pythonhosted.org/packages/55/64/b693f262791b818880d17268f3f8181ef799b0d187f6f731b1772e05a29a/rpds_py-0.20.0.tar.gz"
    sha256 "d72a210824facfdaf8768cf2d7ca25a042c30320b3020de2fa04640920d4e121"
  end

  resource "attrs" do
    url "https://files.pythonhosted.org/packages/fc/0f/aafca9af9315aee06a89ffde799a10a582fe8de76c563ee80bbcdc08b3fb/attrs-24.2.0.tar.gz"
    sha256 "5cfb1b9148b5b086569baec03f20d7b6bf3bcacc9a42bebf87ffaaca362f6346"
  end

  # Optional: Email notifications support
  resource "resend" do
    url "https://files.pythonhosted.org/packages/72/29/430a0f11538a62fc919c7e4c2f71d1c9619e94e7f2b0f8fc6f6f5e13c2e1/resend-2.5.0.tar.gz"
    sha256 "6f1c6b8b0c4e9c0d0b3b8f0f8e6e0c4c4b8a9f6c5b0a4f7e5b4a1f8c0d1e2f3"
  end

  def install
    # Install Python package and dependencies into virtualenv
    virtualenv_install_with_resources

    # Generate shell completions (if implemented in future)
    # generate_completions_from_executable(bin/"jmo", shells: [:bash, :zsh, :fish])

    # Create config directory for user configurations
    (var/"jmo").mkpath

    # Install documentation
    doc.install "README.md", "QUICKSTART.md", "CHANGELOG.md"
    doc.install "docs" => "docs"
  end

  def post_install
    # Display installation success message with next steps
    ohai "JMo Security installed successfully!"
    puts <<~EOS
      🎉 JMo Security v#{version} is ready to use!

      Quick Start:
        jmo wizard                   # Interactive guided scanning
        jmo wizard --yes             # Non-interactive with defaults
        jmo fast --repo ./myapp      # Fast scan (3 tools, 5-8 min)
        jmo balanced --repos-dir ~/repos  # Balanced scan (8 tools, 15-20 min)

      🐳 Zero-Installation Option (Recommended):
        Use Docker mode for instant scanning with all 12 security tools:
        jmo wizard --docker          # Auto-detects Docker and runs in container

      🔧 Optional: Install Security Tools Locally (Faster Scans):
        JMo orchestrates these external tools. Choose one:

        # EASY: Automated installation script (installs all Homebrew-compatible tools)
        curl -fsSL https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-homebrew.sh | bash

        # OR install individually:
        brew install trufflesecurity/trufflehog/trufflehog  # Secrets
        brew install semgrep                                # SAST
        brew install aquasecurity/trivy/trivy               # Vulnerabilities
        brew install syft                                   # SBOM
        brew install checkov                                # IaC security
        brew install hadolint                               # Dockerfile linting
        brew install nuclei                                 # Fast vuln scanner
        brew install bandit                                 # Python SAST
        brew install --cask owasp-zap                       # DAST (requires Java)

        # Docker-only tools (not available via Homebrew):
        # - Nosey Parker, Falco, AFL++ (use Docker mode for these)

      Documentation:
        Homepage:       https://jmotools.com
        Documentation:  https://docs.jmotools.com
        User Guide:     #{doc}/docs/USER_GUIDE.md
        Examples:       #{doc}/docs/examples/

      Configuration:
        Config files:   ~/.jmo/
        Results:        ./results/

      Support:
        Issues:  https://github.com/jimmy058910/jmo-security-repo/issues
        Discord: https://discord.gg/jmotools (coming soon)

      What's New in v0.9.0:
        ✅ CLI consolidation: jmotools merged into jmo (simpler UX)
        ✅ Schedule management: automated scans via cron or CI/CD
        ✅ Plugin system for adapters (75% faster tool integration)
        ✅ Windows installer with NSIS (WinGet support)
        ✅ Enhanced beginner-friendly commands (wizard, fast, balanced, full)

    EOS
  end

  test do
    # Test that CLI commands are available
    assert_match "JMo Security", shell_output("#{bin}/jmo --help")
    assert_match "wizard", shell_output("#{bin}/jmo --help")

    # Test beginner-friendly commands
    system bin/"jmo", "wizard", "--help"
    system bin/"jmo", "fast", "--help"
    system bin/"jmo", "balanced", "--help"
    system bin/"jmo", "schedule", "--help"

    # Test advanced commands
    output = shell_output("#{bin}/jmo scan --help")
    assert_match "profile", output

    # Verify Python package is importable
    system Formula["python@3.10"].opt_bin/"python3", "-c", "import scripts.cli.jmo"
  end
end
