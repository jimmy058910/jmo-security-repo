#!/usr/bin/env python3
"""Pre-commit hook: flag literal `~/` in YAML `env:` blocks.

GitHub Actions does NOT shell-expand `~` in `env:` values — `~/` is passed
as a literal string. PR #331 fixed this for `PRE_COMMIT_HOME: ~/.cache/pre-commit`
which had silently created a `$PWD/~/.cache/pre-commit/` directory at the repo
root + made `actions/cache` ineffective for the workflow's lifetime (cache action
uses Node `~`-expansion, so paths never matched the literal version pre-commit
created).

This hook prevents the same regression by walking workflow YAML and flagging
any `env:` value that starts with `~/`. Other forms where `~/` works (Node-side
`actions/cache` `path:` values, bash inside `run:` blocks, comments) are NOT
flagged because they're handled correctly.

Exit code 0 = clean, 1 = violations found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
ACTIONS_DIR = REPO_ROOT / ".github" / "actions"


def _find_line_number(text: str, key: str, value_prefix: str) -> int:
    """Locate the line where `<key>: <value_prefix>...` first appears.

    Returns 1-based line number, or 0 if not found.
    """
    pattern = re.compile(
        rf"^\s*{re.escape(key)}\s*:\s*['\"]?{re.escape(value_prefix)}",
        re.MULTILINE,
    )
    match = pattern.search(text)
    if match:
        return text[: match.start()].count("\n") + 1
    return 0


def find_env_tilde_violations(yaml_path: Path) -> list[tuple[int, str, str]]:
    """Walk the YAML and return [(line_num, env_key, value)] for `~/`-prefixed env values.

    Detects `env:` blocks at any nesting level (workflow, job, step). Skips
    non-string values (lists, ints, etc.). Skips bash heredocs and `with:` blocks
    by virtue of only matching on the literal `env:` key.
    """
    text = yaml_path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return []  # malformed YAML — let the YAML linter report it

    violations: list[tuple[int, str, str]] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                if key == "env" and isinstance(val, dict):
                    for env_key, env_val in val.items():
                        if isinstance(env_val, str) and env_val.startswith("~/"):
                            line_num = _find_line_number(text, str(env_key), "~/")
                            violations.append((line_num, str(env_key), env_val))
                walk(val)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return violations


def main() -> int:
    yaml_paths: list[Path] = []
    if WORKFLOWS_DIR.is_dir():
        yaml_paths.extend(WORKFLOWS_DIR.glob("*.yml"))
        yaml_paths.extend(WORKFLOWS_DIR.glob("*.yaml"))
    if ACTIONS_DIR.is_dir():
        yaml_paths.extend(ACTIONS_DIR.rglob("*.yml"))
        yaml_paths.extend(ACTIONS_DIR.rglob("*.yaml"))

    all_violations: list[tuple[Path, int, str, str]] = []
    for path in sorted(yaml_paths):
        for line_num, key, val in find_env_tilde_violations(path):
            all_violations.append((path, line_num, key, val))

    if not all_violations:
        return 0

    print(
        "ERROR: Found literal `~/` in YAML `env:` block(s). GitHub Actions "
        "does NOT shell-expand `~` in env values — the `~` is passed as a "
        "literal string, producing `$PWD/~/...` directories at runtime.\n",
        file=sys.stderr,
    )
    for path, line_num, key, val in all_violations:
        rel = path.relative_to(REPO_ROOT).as_posix()
        print(f"  {rel}:{line_num}  {key}: {val}", file=sys.stderr)
    print(
        "\nFix: replace with an absolute path (e.g. `/home/runner/.cache/X` "
        "on Linux runners), or remove the env var entirely if the default "
        "from the consuming tool is correct. See `.claude/rules/release.rules.md` "
        "Scheduled Lint yamllint entry for the original PRE_COMMIT_HOME case.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
