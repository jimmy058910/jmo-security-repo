# Python Compatibility Patterns

Before implementing security fixes, verify Python version compatibility.

---

## Check Minimum Python Version

```bash
# Check pyproject.toml for minimum version
grep "requires-python" pyproject.toml
# Example output: requires-python = ">=3.12"
```

## Python 3.8 Compatibility Gotchas

| Feature | Python 3.9+ | Python 3.8 Workaround |
|---------|-------------|----------------------|
| `Path.is_relative_to()` | Native | Use `try/except ValueError` with `relative_to()` |
| `str.removeprefix()` | Native | Use `str.lstrip()` or slicing |
| `str.removesuffix()` | Native | Use `str.rstrip()` or slicing |
| Union types (`str \| Path`) | Native | Use `Union[str, Path]` from typing |

**Note:** JMo Security now requires Python >= 3.12, but these patterns are useful if backporting fixes to other projects.

## Example: Python 3.8 Compatible Path Validation

```python
# Python 3.9+ only
def _validate_output_path(base_dir: Path, output_dir: Path) -> Path:
    if not output_dir.is_relative_to(base_dir):  # Doesn't exist in 3.8!
        raise ValueError("Path traversal detected")
    return output_dir

# Python 3.8 compatible
def _validate_output_path(base_dir: Path, output_dir: Path) -> Path:
    base_resolved = base_dir.resolve()
    output_resolved = output_dir.resolve()
    try:
        output_resolved.relative_to(base_resolved)  # Works in 3.8+
        return output_resolved
    except ValueError:
        raise ValueError(f"Path traversal detected: {output_dir} outside {base_dir}")
```

**Always test security fixes on the minimum supported Python version before committing.**
