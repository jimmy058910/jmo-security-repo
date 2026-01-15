# Platform Notes

Cross-platform compatibility guide for JMo Security development on Windows, WSL, Linux, and macOS.

## Windows/WSL

### Path Handling

- Use forward slashes in code (`path/to/file`), Windows handles both
- Docker paths require POSIX format (`/c/Projects/...` or `/mnt/c/...`)
- Always use `pathlib.Path` for cross-platform path operations

### Docker Desktop

- Enable WSL 2 backend for performance
- Mount volumes: `-v "$(pwd):/scan"` works in Git Bash/WSL
- For native PowerShell: `-v "${PWD}:/scan"`

### Pre-commit

- Install via pip, not system package manager
- May need `git config core.autocrlf false` for line ending issues
- If hooks fail on Windows, check for CRLF vs LF issues

### Environment Variables

| Variable | Windows | Unix |
|----------|---------|------|
| Home directory | `USERPROFILE` | `HOME` |
| Temp directory | `TEMP` or `TMP` | `TMPDIR` or `/tmp` |
| Path separator | `;` | `:` |

**Best Practice:** Use Python's `pathlib.Path.home()` and `tempfile.gettempdir()` instead of environment variables directly.

## macOS

### Tool Installation

```bash
# Homebrew is recommended for security tools
brew install trivy semgrep shellcheck

# Some tools require Rosetta 2 on Apple Silicon
softwareupdate --install-rosetta
```

### File System

- macOS uses case-insensitive filesystem by default (APFS)
- Be careful with imports: `from Module import X` vs `from module import X`
- Docker volumes may have performance issues on macOS; use `:cached` or `:delegated` flags

## Linux

### Tool Installation

```bash
# Ubuntu/Debian
sudo apt-get install shellcheck

# Tools installed via pip
pip install --user bandit semgrep

# Ensure ~/.local/bin is in PATH
export PATH="$HOME/.local/bin:$PATH"
```

### Permissions

- Unix file permissions (`chmod`) work as expected
- Docker may require adding user to `docker` group: `sudo usermod -aG docker $USER`

## Cross-Platform Development Best Practices

### 1. Path Operations

```python
# GOOD: Use pathlib everywhere
from pathlib import Path
config_path = Path.home() / ".jmo" / "config.yml"

# BAD: String concatenation with hardcoded separators
config_path = os.environ["HOME"] + "/.jmo/config.yml"
```

### 2. Process Execution

```python
# GOOD: List arguments, shell=False (default)
subprocess.run(["trivy", "image", image_name], capture_output=True)

# BAD: Shell=True is a security vulnerability AND platform-inconsistent
subprocess.run(f"trivy image {image_name}", shell=True)
```

### 3. Temporary Files

```python
# GOOD: Platform-agnostic temp directory
import tempfile
with tempfile.TemporaryDirectory() as tmpdir:
    work_path = Path(tmpdir) / "work"

# BAD: Hardcoded Unix paths
work_path = Path("/tmp/work")
```

### 4. Line Endings

- Configure Git: `git config core.autocrlf input` (Linux/macOS) or `git config core.autocrlf true` (Windows)
- Use `.gitattributes` for explicit control:

```gitattributes
* text=auto
*.py text eol=lf
*.sh text eol=lf
*.bat text eol=crlf
```

### 5. Environment Variable Access

```python
# GOOD: Cross-platform home directory
from pathlib import Path
home = Path.home()

# GOOD: With fallback
import os
home = os.environ.get("HOME") or os.environ.get("USERPROFILE")

# BAD: Unix-only
home = os.environ["HOME"]  # Fails on Windows
```

## CI/CD Platform Matrix

JMo Security CI tests on:

| Platform | Python | Runner |
|----------|--------|--------|
| Ubuntu 22.04 | 3.11, 3.12 | `ubuntu-latest` |
| macOS 14 | 3.11 | `macos-latest` |
| Windows Server 2022 | 3.11 | `windows-latest` |

### Platform-Specific CI Considerations

1. **Ubuntu:** Primary target, full test suite runs here
2. **macOS:** Some tools may not be available; tests skip gracefully
3. **Windows:** File locking issues more common; close file handles explicitly

## Troubleshooting

### "Command not found" variations

| Platform | Error Message |
|----------|---------------|
| Linux/macOS | `command not found: trivy` |
| Windows CMD | `'trivy' is not recognized as an internal or external command` |
| Windows PowerShell | `The term 'trivy' is not recognized` |
| Python subprocess | `FileNotFoundError: [WinError 2] The system cannot find the file specified` |

**Solution:** Use `is_command_not_found_error()` from `tests/conftest.py` for cross-platform error detection in tests.

### File Permission Errors

| Platform | Issue | Solution |
|----------|-------|----------|
| Windows | `chmod` has no effect | Skip permission tests with `@skip_on_windows` |
| Linux | Permission denied | Check file ownership, use `sudo` if needed |
| macOS | Operation not permitted | Check System Preferences > Security |

### Docker Volume Mount Issues

| Platform | Issue | Solution |
|----------|-------|----------|
| Windows | Paths not found | Use `/c/path` format in Git Bash |
| macOS | Slow performance | Add `:cached` to volume mount |
| Linux | Permission denied | Match container UID/GID with host |

## Related Documentation

- [TEST.md](../TEST.md) - Cross-platform testing guidelines
- [DOCKER_README.md](DOCKER_README.md) - Docker-specific guidance
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development workflow
