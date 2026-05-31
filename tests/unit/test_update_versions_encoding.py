"""Regression tests: update_versions.py file ops must specify encoding="utf-8".

`open()`, `Path.read_text()` and `Path.write_text()` without an `encoding=`
argument fall back to the locale-default codec. On Windows that is the legacy
ANSI code page (e.g. cp1252), not UTF-8 — so a non-ASCII byte in versions.yaml
(a tool description, an em-dash, an accented name) would round-trip wrong or
raise. PEP 597 calls this out; ruff's PLW1514 is the same warning. Follow-up to
the CRLF fix on these same call sites (#555 / PR #556).

Two complementary checks:
  * an AST scan that deterministically flags any text file op missing
    `encoding=` (covers every site on every platform), and
  * a behavioral check that runs the real functions under
    `-X warn_default_encoding -W error::EncodingWarning`, which turns the
    omission itself into an error — so it goes RED regardless of the runner's
    locale (a byte-compare test would be a tautology on a UTF-8 runner).
"""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "dev" / "update_versions.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("update_versions", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


update_versions = _load_module()


def _binary_mode(call: ast.Call) -> bool:
    """True if an open() call is binary mode (encoding= is invalid there)."""
    mode = ""
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
        mode = str(call.args[1].value)
    for kw in call.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = str(kw.value.value)
    return "b" in mode


def test_all_text_file_ops_specify_encoding():
    """Every open()/read_text()/write_text() in the script must pass encoding=."""
    tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "open":
            if _binary_mode(node):
                continue
            name = "open"
        elif isinstance(func, ast.Attribute) and func.attr in (
            "read_text",
            "write_text",
        ):
            name = func.attr
        else:
            continue
        if not any(kw.arg == "encoding" for kw in node.keywords):
            offenders.append(f"{name}() at line {node.lineno}")
    assert not offenders, "file ops missing encoding=: " + ", ".join(offenders)


def test_file_ops_emit_no_encoding_warning(tmp_path):
    """save_versions + sync_dockerfiles must raise no EncodingWarning.

    Run in a subprocess under `-X warn_default_encoding -W error::EncodingWarning`
    so any file op missing `encoding=` raises. GREEN therefore proves every site
    (the write at save_versions, the read in load_versions, and the two
    read_text/write_text pairs in sync_dockerfiles) is guarded.
    """
    driver = tmp_path / "driver.py"
    driver.write_text(
        textwrap.dedent(f"""\
            import importlib.util, sys, tempfile, pathlib
            spec = importlib.util.spec_from_file_location(
                "update_versions", {str(SCRIPT_PATH)!r}
            )
            m = importlib.util.module_from_spec(spec)
            sys.modules["update_versions"] = m
            spec.loader.exec_module(m)

            d = pathlib.Path(tempfile.mkdtemp())
            m.VERSIONS_YAML = d / "versions.yaml"
            # write (save_versions) + later read (load_versions) of versions.yaml
            m.save_versions({{"binary_tools": {{"trivy": {{"version": "0.70.0"}}}}}})

            # Dockerfile + workflow pinned stale so sync rewrites (exercises both
            # read_text and write_text). Driver's own writes set encoding to avoid
            # tripping the warning on the test scaffolding itself.
            df = d / "Dockerfile.test"
            df.write_text('ENV TRIVY_VERSION="0.69.0"\\n', encoding="utf-8", newline="\\n")
            m.DOCKERFILE = df
            for a in ("DOCKERFILE_BALANCED", "DOCKERFILE_SLIM", "DOCKERFILE_FAST"):
                setattr(m, a, d / ("absent_" + a))
            wfd = d / "workflows"
            wfd.mkdir()
            (wfd / "t.yml").write_text(
                '  TRIVY_VERSION: "0.69.0"\\n', encoding="utf-8", newline="\\n"
            )
            m.WORKFLOWS_DIR = wfd

            m.sync_dockerfiles(dry_run=False)
            print("DRIVER_OK")
            """),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-X",
            "warn_default_encoding",
            "-W",
            "error::EncodingWarning",
            str(driver),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        "EncodingWarning fired — a file op is missing encoding=:\n" + result.stderr
    )
    assert "DRIVER_OK" in result.stdout
