# Manual Installation Guide (MobSF, Akto)

**v1.0.0 Status**: Two tools (MobSF, Akto) require manual installation due to complex dependencies. Full Docker support is planned for v1.0.1.

## Why Manual Installation?

**MobSF (Mobile Security Framework)**:
- Requires Android SDK subset (~200 MB)
- Needs specific APK tooling (aapt2, apktool, jadx)
- Complex multi-stage Docker build (not ready for v1.0.0)

**Akto (API Security)**:
- Runs as standalone Docker service (not embeddable in JMo container)
- Requires separate port mapping and service orchestration
- Best deployed as sidecar container in CI/CD

## Docker Image Tool Counts (v1.0.0)

| Variant | Total Tools | Docker-Ready Tools | Manual Tools | Status |
|---------|-------------|--------------------|--------------| ------|
| **Full** | 28 | **26** | 2 (MobSF, Akto) | ✅ Production |
| **Balanced** | 21 | **21** | 0 | ✅ Production |
| **Slim** | 15 | **15** | 0 | ✅ Production |
| **Fast** | 8 | **8** | 0 | ✅ Production |

**Note**: MobSF and Akto are available in `jmo.yml` deep profile but excluded from Docker images.

---

## MobSF: Manual Installation

### Prerequisites

- **Platform**: Linux, macOS, or WSL2
- **Python**: 3.10+ (`python3 --version`)
- **Java**: JDK 8+ (`java -version`)
- **Storage**: 2 GB for Android SDK subset

### Installation Steps

#### Step 1: Install MobSF via pip

```bash
# Install MobSF Python package
pip install mobsf==4.2.0

# Verify installation
mobsf --help
```

#### Step 2: Install Android SDK Tools (Minimal)

```bash
# Download Android SDK command-line tools
wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
unzip commandlinetools-linux-9477386_latest.zip -d ~/android-sdk
export ANDROID_HOME=~/android-sdk

# Install minimal SDK components
$ANDROID_HOME/cmdline-tools/bin/sdkmanager --sdk_root=$ANDROID_HOME \
  "build-tools;30.0.3" \
  "platforms;android-30"

# Persist environment variable
echo "export ANDROID_HOME=~/android-sdk" >> ~/.bashrc
```

#### Step 3: Install APK Tooling

```bash
# Install aapt2 (Android Asset Packaging Tool)
sudo apt-get install -y aapt

# Install apktool (APK reverse engineering)
wget https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar
sudo mv apktool_2.10.0.jar /usr/local/bin/apktool.jar
echo '#!/bin/bash\njava -jar /usr/local/bin/apktool.jar "$@"' | sudo tee /usr/local/bin/apktool
sudo chmod +x /usr/local/bin/apktool

# Install jadx (Dex to Java decompiler)
wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d ~/jadx
export PATH="$HOME/jadx/bin:$PATH"
echo 'export PATH="$HOME/jadx/bin:$PATH"' >> ~/.bashrc
```

#### Step 4: Verify MobSF Setup

```bash
# Test APK analysis
mobsf --version
mobsf analyze --apk ./test-app.apk --output ./mobsf-results.json

# Expected: JSON output with security findings
```

### JMo Integration

Once MobSF is installed, it's automatically available to JMo:

```bash
# Scan with MobSF enabled
jmo scan --repo ./mobile-app --profile deep --tools mobsf

# Verify MobSF tool detected
jmotools setup
# Output: ✅ MobSF v4.2.0 - Mobile app security
```

### Troubleshooting

**Issue**: `mobsf command not found`
- **Fix**: Add pip install location to PATH: `export PATH="$HOME/.local/bin:$PATH"`

**Issue**: `ANDROID_HOME not set`
- **Fix**: Verify environment variable: `echo $ANDROID_HOME`
- Re-run Step 2

**Issue**: `APK analysis fails with aapt2 error`
- **Fix**: Install missing build-tools: `sdkmanager "build-tools;30.0.3"`

---

## Akto: Manual Installation

### Prerequisites

- **Platform**: Linux, macOS, WSL2, or Docker Desktop
- **Docker**: 20.10+ (`docker --version`)
- **Docker Compose**: 1.29+ (`docker-compose --version`)
- **Network**: Port 8080 available (Akto dashboard)

### Installation Steps

#### Step 1: Deploy Akto Docker Service

```bash
# Clone Akto repository
git clone https://github.com/akto-api-security/akto.git
cd akto

# Start Akto services
docker-compose up -d

# Verify services running
docker-compose ps
# Expected output:
#   akto-api-security_mongo_1     Up   27017/tcp
#   akto-api-security_akto_1      Up   0.0.0.0:8080->8080/tcp
```

#### Step 2: Configure Akto API Endpoint

```bash
# Create Akto config for JMo
mkdir -p ~/.jmo
cat > ~/.jmo/akto.yml << EOF
akto:
  endpoint: http://localhost:8080/api
  api_key: YOUR_AKTO_API_KEY_HERE
  timeout: 600
EOF

# Set environment variable (alternative)
export AKTO_API_ENDPOINT=http://localhost:8080/api
export AKTO_API_KEY=YOUR_API_KEY
```

#### Step 3: Obtain Akto API Key

1. Open Akto dashboard: http://localhost:8080
2. Navigate to **Settings → API Keys**
3. Click **Generate New API Key**
4. Copy API key and update `~/.jmo/akto.yml`

#### Step 4: Verify Akto Integration

```bash
# Test Akto API connectivity
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8080/api/health

# Expected: {"status": "healthy"}
```

### JMo Integration

Once Akto is running, JMo automatically detects it:

```bash
# Scan API with Akto enabled
jmo scan --url https://api.example.com --profile deep --tools akto

# Verify Akto tool detected
jmotools setup
# Output: ✅ Akto v1.0.0 - API business logic testing
```

### CI/CD Integration (Docker Sidecar)

For GitHub Actions or GitLab CI, deploy Akto as a sidecar service:

#### GitHub Actions Example

```yaml
name: Security Scan with Akto

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    services:
      akto:
        image: akto-api-security/akto:latest
        ports:
          - 8080:8080
        options: >-
          --health-cmd="curl -f http://localhost:8080/api/health || exit 1"
          --health-interval=10s
          --health-timeout=5s
          --health-retries=5

    steps:
      - uses: actions/checkout@v4

      - name: Run JMo Security Scan
        run: |
          export AKTO_API_ENDPOINT=http://akto:8080/api
          export AKTO_API_KEY=${{ secrets.AKTO_API_KEY }}
          docker run --rm --network host \
            -v $(pwd):/scan \
            -e AKTO_API_ENDPOINT \
            -e AKTO_API_KEY \
            ghcr.io/jimmy058910/jmo-security:1.0.0-full \
            scan --url https://api.example.com --profile deep --tools akto
```

### Troubleshooting

**Issue**: `Akto service not responding`
- **Fix**: Check Docker logs: `docker-compose logs akto`
- Restart services: `docker-compose restart`

**Issue**: `API key authentication failed`
- **Fix**: Regenerate API key from Akto dashboard
- Update `~/.jmo/akto.yml`

**Issue**: `Port 8080 already in use`
- **Fix**: Change port in `docker-compose.yml`:
  ```yaml
  ports:
    - "8090:8080"  # Use port 8090 instead
  ```

---

## Roadmap: Full Docker Support (v1.0.1)

**Planned for v1.0.1** (2-4 weeks after v1.0.0 release):

### MobSF Docker Integration

- **Approach**: Multi-stage build with minimal Android SDK subset
- **Size Impact**: +200 MB to Full variant (1.97 GB → 2.17 GB)
- **Tools Included**:
  - aapt2 (binary only, ~15 MB)
  - apktool (JAR only, ~12 MB)
  - jadx (JAR only, ~18 MB)
  - Minimal platform tools (~150 MB)

### Akto Docker Integration

- **Approach**: Embedded MongoDB + Akto API server in JMo container
- **Size Impact**: +150 MB to Full variant
- **Configuration**: Auto-start Akto service on container launch
- **Limitations**: Single-container deployment (no external Mongo)

**Expected v1.0.1 Tool Count**: **28 Docker-ready tools** (all tools)

---

## Community Contributions

**Want to help add Docker support for MobSF/Akto in v1.0.1?**

See [CONTRIBUTING.md](../CONTRIBUTING.md) for:
- Docker multi-stage build patterns
- Tool integration guidelines
- Testing requirements (≥85% coverage)
- PR submission process

**Bounty**: First PR that adds full MobSF/Akto Docker support gets mentioned in CHANGELOG.md release notes! 🎉

---

**Last Updated**: 2025-11-01 (v1.0.0)
**Questions?**: [GitHub Discussions](https://github.com/jimmy058910/jmo-security-repo/discussions)
