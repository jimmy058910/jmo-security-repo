#!/usr/bin/env python3
"""Capture golden fixtures through `jmo scan`.

    python scripts/dev/generate_golden.py --tool <tool> [--tool ...] [--update]
    python scripts/dev/generate_golden.py --all [--update]
    python scripts/dev/generate_golden.py --check [--tool <tool> ...]

A golden fixture is one tool's real output, what JMo's adapter reads from it,
and how it was made (`tests/adapters/test_adapter_golden.py` replays it). This
script makes one the way a user's scan does: `jmo scan --tools <tool>` on a
tracked sample, in a HOME of its own, so the command is the descriptor's and
never a copy kept here (#1349 measured such a copy drifting). It keeps the
`<tool>.json` the scan wrote as `raw-output.json`, the adapter's findings as
`expected-findings.json`, and `metadata.json` in Phase 0's shape, under
`tests/fixtures/golden/<adapter>/v<version>/`.

`--check` captures every tool again in scratch, writes nothing, and fails when
a tool does not run or its output parses to no finding: the silent-adapter
class #1097 is about. A count that moved from the committed fixture's is
reported, not failed: trivy's database and zap's spider move it with no change
to JMo.

What a capture changes in the tool's output, each recorded in its metadata:

- The capture's working directory reads as `/golden`. A file-fed tool names
  each file absolutely (shellcheck, hadolint, checkov, osv-scanner, syft,
  yara-x, nuclei's template), so a fixture would otherwise carry the capturing
  machine's path and differ on every machine.
- trufflehog's credential fields are replaced (`SECRET_BEARING_FIELDS`, the
  adapter's own list). Its target is a key generated for the capture, since no
  tracked sample holds one it reports, and a key never enters the tree. The
  capture fails if the replacement changes a finding.

The HOME links the real `~/.jmo/bin`, `tools` and `yara-rules` (read, never
installed into), copies the frozen OSV database from `tests/fixtures/osv-db`,
and points trivy at the developer's own cache (`TRIVY_CACHE_DIR`, as the e2e
helper does). `--home DIR` uses a HOME you prepared instead, for a tool held at
another version there.

Linux and macOS: the HOME is made of symbolic links.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Run directly, sys.path[0] is scripts/dev: the project root makes `scripts`
# importable, as in scripts/dev/fetch_answer_keys.py.
if __package__ in (None, ""):  # pragma: no cover - only on direct execution
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.core.plugin_loader import get_plugin_loader, get_plugin_registry  # noqa: E402
from scripts.core.tool_registry import TOOL_MATRIX  # noqa: E402

SAMPLES_DIR = PROJECT_ROOT / "tests" / "fixtures" / "samples"
GOLDEN_DIR = PROJECT_ROOT / "tests" / "fixtures" / "golden"
FROZEN_OSV_DB = PROJECT_ROOT / "tests" / "fixtures" / "osv-db"
FIXTURE_SERVER = SAMPLES_DIR / "zap" / "fixture_server.py"

# What the capture's working directory reads as in a fixture.
PLACEHOLDER = "/golden"
# A trufflehog credential field's value in a fixture.
REMOVED = "<removed by generate_golden.py>"

SCAN_TIMEOUT = 1800


class CaptureError(Exception):
    """A capture that must not become a fixture: the tool did not run, wrote
    nothing, or its output parses to no finding."""


# --- what each tool scans ---------------------------------------------------------

# A string only JMo's tests write (tests/integration/test_yara_x_canary.py's
# canary): never EICAR, never a real sample (decision 7).
YARA_X_CANARY = "jmo-yara-x-canary-7d3f9a: a test marker, not malware"
YARA_X_RULE = f"""rule JMO_Canary_Test {{
    meta:
        author = "JMo Security test suite"
        description = "A string only JMo's tests write"
    strings:
        $canary = "{YARA_X_CANARY}"
    condition:
        $canary
}}
"""

# fixture_server.py's spider site reflects `q` into its page unescaped.
NUCLEI_TEMPLATE = """id: jmo-golden-reflected-query
info:
  name: JMo golden fixture - a query parameter reflected unescaped
  author: jmo-security
  severity: medium
  tags: jmo,golden
http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=jmo-golden-7c1e%3Cb%3E"
    matchers:
      - type: word
        part: body
        words:
          - "jmo-golden-7c1e<b>"
"""


def _generated_key() -> bytes:
    """A private key made now, as tests/conftest.py's `generated_rsa_pem`."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def _trufflehog_key(work: Path, port: int | None) -> dict[str, Any]:
    # Every credential in credential-patterns is a shape trufflehog refuses
    # (AWS's documented example key, `ghp_xxx...`, a truncated PEM): 0
    # findings, measured on 3.99.8.
    (work / "target" / "deploy.pem").write_bytes(_generated_key())
    return {}


def _yara_x_canary(work: Path, port: int | None) -> dict[str, Any]:
    target = work / "target"
    for rel in ("src/index.js", "node_modules/left-pad/index.js"):
        (target / rel).parent.mkdir(parents=True, exist_ok=True)
        (target / rel).write_bytes(f"// {YARA_X_CANARY}\n".encode())
    (work / "canary.yar").write_bytes(YARA_X_RULE.encode())
    return {"rules_path": str(work / "canary.yar")}


def _zap_through_the_fixture(work: Path, port: int | None) -> dict[str, Any]:
    # Every request goes through the fixture, which answers for itself and
    # refuses any other host (fixture_server.proxy_flags).
    return {
        "flags": [
            "-config",
            "network.connection.httpProxy.enabled=true",
            "-config",
            "network.connection.httpProxy.host=127.0.0.1",
            "-config",
            f"network.connection.httpProxy.port={port}",
        ]
    }


def _nuclei_template(work: Path, port: int | None) -> dict[str, Any]:
    (work / "golden.yaml").write_bytes(NUCLEI_TEMPLATE.encode())
    # `-duc`: with `-t` alone nuclei still fetched its public templates (87 MB
    # into a fresh HOME, measured on 3.11.1); with it, nothing.
    return {"flags": ["-t", str(work / "golden.yaml"), "-duc"]}


Prepare = Callable[[Path, int | None], dict[str, Any]]


@dataclass(frozen=True)
class Capture:
    """One tool's target. A repo capture copies `samples` into the target's
    root, then `prepare` adds what is made for it and returns the tool's
    `per_tool` config; a URL capture scans fixture_server.py's spider site."""

    samples: tuple[str, ...] = ()
    url: bool = False
    prepare: Prepare | None = None
    scrub: bool = False

    def recipe(self) -> dict[str, Any]:
        """What a fixture's metadata records, and `--check` compares by: a
        count from another target is not this capture's."""
        return {
            "samples": list(self.samples),
            "url": "fixture_server.py --mode spider" if self.url else None,
            "prepared": self.prepare.__name__ if self.prepare else None,
        }


CAPTURES: dict[str, Capture] = {
    "trufflehog": Capture(
        ("credential-patterns",), prepare=_trufflehog_key, scrub=True
    ),
    "gitleaks": Capture(("credential-patterns",)),
    "opengrep": Capture(("python-vulnerable",)),
    "syft": Capture(("python-vulnerable",)),
    # Both of its repository classes: vulnerabilities (requirements.txt) and
    # misconfigurations (a Dockerfile, Terraform and a Pod).
    "trivy": Capture(
        (
            "python-vulnerable",
            "dockerfile-issues",
            "terraform-misconfig",
            "k8s-insecure-pod",
        )
    ),
    # A repository scan reads Terraform, not Kubernetes (`--framework`).
    "checkov": Capture(("terraform-misconfig",)),
    "hadolint": Capture(("dockerfile-issues",)),
    "shellcheck": Capture(("shell-issues",)),
    "zizmor": Capture(("github-actions",)),
    "jmo-native": Capture(("native",)),
    "yara-x": Capture(prepare=_yara_x_canary),
    # Against tests/fixtures/osv-db's synthetic advisories, offline.
    "osv-scanner": Capture(("python-vulnerable",)),
    "zap": Capture(url=True, prepare=_zap_through_the_fixture),
    "nuclei": Capture(url=True, prepare=_nuclei_template),
}


# --- running jmo ------------------------------------------------------------------


def run_jmo(
    args: list[str], *, env: dict[str, str], cwd: Path, timeout: int
) -> subprocess.CompletedProcess[str]:
    """`jmo <args>` from this checkout (PYTHONPATH), never an installed one."""
    return subprocess.run(
        [sys.executable, "-m", "scripts.cli.jmo", *args],
        env={**env, "PYTHONPATH": str(PROJECT_ROOT)},
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def isolated_home(home: Path) -> Path:
    """A HOME whose scanners are the developer's and whose OSV database is the
    frozen one: `.jmo/bin`, `tools` and `yara-rules` link the real ones,
    `osv-db` is a copy of tests/fixtures/osv-db."""
    real = Path.home() / ".jmo"
    jmo = home / ".jmo"
    jmo.mkdir(parents=True, exist_ok=True)
    for name in ("bin", "tools", "yara-rules"):
        if (real / name).exists() and not (jmo / name).exists():
            (jmo / name).symlink_to(real / name, target_is_directory=True)
    if not (jmo / "osv-db").exists():
        shutil.copytree(FROZEN_OSV_DB, jmo / "osv-db")
    return home


def _env(home: Path) -> dict[str, str]:
    return {
        **os.environ,
        "HOME": str(home),
        "USERPROFILE": str(home),
        "JMO_NON_INTERACTIVE": "1",
        # trivy keeps its database under the home: without this a capture
        # fetches it again (#1517's measurement).
        "TRIVY_CACHE_DIR": os.environ.get(
            "TRIVY_CACHE_DIR", str(Path.home() / ".cache" / "trivy")
        ),
    }


# --- one capture ------------------------------------------------------------------


def fixture_dir_name(tool: str) -> str:
    """The golden directory's name: the adapter name the report looks the
    tool up by (`count_findings`), `osv-scanner` -> `osv_scanner`."""
    return get_plugin_loader()._tool_to_adapter_name(tool)


def run_adapter(tool: str, raw_output_path: Path) -> list[dict[str, Any]]:
    """What the report reads from one output: the adapter `count_findings`
    uses, its findings as dicts. `secretDigest` is transient (a keyed digest
    the report pairs by and removes; its key is random per process), so a
    fixture holding it would change on every capture."""
    adapter = get_plugin_registry().get(fixture_dir_name(tool))
    if adapter is None:
        raise CaptureError(f"{tool}: no adapter is registered for it")
    found = []
    for f in adapter().parse(raw_output_path):
        d = asdict(f)
        d.pop("secretDigest", None)
        found.append(d)
    return found


def _rewrite(raw: bytes, work: Path, home: Path | None = None) -> bytes:
    """The capture HOME as `PLACEHOLDER/home`, then the work directory as
    PLACEHOLDER, each in its plain and its JSON spelling. The HOME goes first:
    one given with --home is outside the work directory (syft records its Go
    and Maven caches under it), and the default one is inside it."""
    text = raw.decode("utf-8")
    # The HOME as given and as resolved: a symlink, or a Windows short name
    # (RUNNER~1), spells it two ways, and the scan writes the one it was given.
    homes = {home.absolute(), home.resolve()} if home else set()
    pairs = [
        (h, f"{PLACEHOLDER}/home") for h in sorted(homes, key=lambda h: -len(str(h)))
    ]
    for path, placeholder in [*pairs, (work, PLACEHOLDER)]:
        plain = str(path)
        for spelling in (json.dumps(plain)[1:-1], plain):
            text = text.replace(spelling, placeholder)
    return text.encode("utf-8")


def _as_committed(raw: bytes) -> bytes:
    """The bytes pre-commit would commit: no whitespace at a line's end, and a
    final newline (trailing-whitespace, end-of-file-fixer). A JSON string never
    holds a raw line break, so this changes no value."""
    lines = raw.decode("utf-8").splitlines()
    return ("\n".join(line.rstrip(" \t") for line in lines) + "\n").encode("utf-8")


def _scrub(tool: str, raw: bytes) -> bytes:
    """trufflehog's NDJSON with every credential-bearing field replaced."""
    from scripts.core.adapters.trufflehog_adapter import SECRET_BEARING_FIELDS

    lines = []
    for line in raw.decode("utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        for key in SECRET_BEARING_FIELDS & record.keys():
            record[key] = REMOVED
        lines.append(json.dumps(record, sort_keys=True))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _ids(findings: list[dict[str, Any]]) -> list[str]:
    return sorted(str(f.get("id")) for f in findings)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass
class Captured:
    tool: str
    version: str
    raw: bytes
    findings: list[dict[str, Any]]
    binary: str | None
    binary_sha256: str | None
    target: dict[str, Any]
    command: str
    config: dict[str, Any]
    metadata_extra: dict[str, Any] = field(default_factory=dict)


def _version(tool: str, env: dict[str, str], work: Path) -> tuple[str, Path | None]:
    """The version and binary `jmo tools check` finds under the capture's
    HOME: the tool the scan ran, not the pin."""
    done = run_jmo(["tools", "check", tool, "--json"], env=env, cwd=work, timeout=120)
    try:
        info = json.loads(done.stdout)["tools"][tool]
    except (ValueError, KeyError) as e:
        raise CaptureError(f"{tool}: `jmo tools check` named no version ({e})") from e
    version = info.get("installed_version")
    if not version:
        raise CaptureError(f"{tool}: `jmo tools check` found it with no version")
    binary = Path(info["binary_path"]) if info.get("binary_path") else None
    return str(version), binary


def _start_fixture(work: Path) -> tuple[subprocess.Popen[bytes], int]:
    port_file = work / "port"
    server = subprocess.Popen(
        [
            sys.executable,
            str(FIXTURE_SERVER),
            "--mode",
            "spider",
            "--log",
            str(work / "requests.jsonl"),
            "--port-file",
            str(port_file),
        ],
        stdout=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if port_file.exists() and port_file.read_bytes().strip():
            return server, int(port_file.read_bytes())
        time.sleep(0.1)
    server.kill()
    raise CaptureError("fixture_server.py did not report its port in 30 s")


def capture(tool: str, *, home: Path, work: Path) -> Captured:
    """Run `jmo scan --tools <tool>` on its target in `work`, and return what a
    fixture holds. Raises CaptureError when the tool did not run, wrote no
    output, or its output parses to no finding."""
    spec = CAPTURES[tool]
    work.mkdir(parents=True, exist_ok=True)
    work = work.resolve()
    if any(work.iterdir()):
        raise CaptureError(f"{tool}: {work} is not empty")
    env = _env(home)
    target = work / "target"
    server = None
    port = None
    if spec.url:
        server, port = _start_fixture(work)
        target_arg = ["--url", f"http://127.0.0.1:{port}"]
        target_record: dict[str, Any] = {
            "server": "tests/fixtures/samples/zap/fixture_server.py",
            "mode": "spider",
        }
    else:
        target.mkdir()
        for sample in spec.samples:
            shutil.copytree(SAMPLES_DIR / sample, target, dirs_exist_ok=True)
        target_arg = ["--repo", str(target)]
        target_record = {"samples": list(spec.samples)}
    try:
        per_tool = spec.prepare(work, port) if spec.prepare else {}
        if not spec.url:
            target_record["files"] = {
                p.relative_to(target).as_posix(): _sha256(p)
                for p in sorted(target.rglob("*"))
                if p.is_file()
            }
        config = work / "jmo.yml"
        config.write_bytes(
            yaml.safe_dump({"per_tool": {tool: per_tool} if per_tool else {}}).encode()
        )
        args = [
            "scan",
            *target_arg,
            "--tools",
            tool,
            "--config",
            str(config),
            "--results-dir",
            str(work / "results"),
            "--history-db",
            str(work / "history.db"),
            "--no-store-history",
        ]
        done = run_jmo(args, env=env, cwd=work, timeout=SCAN_TIMEOUT)
    finally:
        if server is not None:
            server.terminate()
            server.wait(timeout=10)

    kind = "individual-web" if spec.url else "individual-repos"
    out_dirs = sorted((work / "results" / kind).glob("*/"))
    if len(out_dirs) != 1:
        raise CaptureError(
            f"{tool}: the scan wrote {len(out_dirs)} target directories "
            f"(rc {done.returncode}): {done.stderr[-500:]}"
        )
    (out_dir,) = out_dirs
    timings = json.loads((out_dir / "scan-timings.json").read_bytes())
    row = next((r for r in timings.get("tools", []) if r.get("tool") == tool), None)
    if row is None or row.get("state") != "ran":
        state = row.get("state") if row else "absent"
        reason = row.get("reason") if row else None
        raise CaptureError(f"{tool}: its row is {state} ({reason}), not ran")
    output = out_dir / f"{tool}.json"
    if not output.is_file():
        raise CaptureError(f"{tool}: ran and wrote no {output.name}")

    raw = _as_committed(_rewrite(output.read_bytes(), work, home))
    developer = str(Path.home())
    named = {developer, json.dumps(developer)[1:-1]}
    if len(developer) > 1 and any(n in raw.decode("utf-8") for n in named):
        raise CaptureError(
            f"{tool}: its output names your home directory, which a fixture must not"
        )
    rewritten = work / "raw-output.json"
    rewritten.write_bytes(raw)
    findings = run_adapter(tool, rewritten)
    extra: dict[str, Any] = {}
    if spec.scrub:
        scrubbed = _scrub(tool, raw)
        rewritten.write_bytes(scrubbed)
        after = run_adapter(tool, rewritten)
        if _ids(after) != _ids(findings):
            raise CaptureError(
                f"{tool}: stripping its credential fields changed what the "
                f"adapter reads ({len(findings)} findings before, {len(after)} after)"
            )
        raw, findings = scrubbed, after
        extra["stripped"] = (
            "Every credential-bearing field (the trufflehog adapter's "
            f"SECRET_BEARING_FIELDS) reads {REMOVED!r}: the key was generated "
            "for this capture, and no key enters the tree. The adapter's "
            "findings are the same with and without them."
        )
    if not findings:
        raise CaptureError(f"{tool}: its output parses to 0 findings")

    version, binary = _version(tool, env, work)
    binary_name = binary_sha = None
    if binary is not None and binary.is_file() and binary.suffix != ".py":
        binary_name, binary_sha = binary.name, _sha256(binary)
    command = (
        " ".join(["jmo", *(_rewrite(a.encode(), work, home).decode() for a in args)])
        + f"  (cwd: {PLACEHOLDER}; HOME: a capture home)"
    )
    return Captured(
        tool=tool,
        version=version,
        raw=raw,
        findings=findings,
        binary=binary_name,
        binary_sha256=binary_sha,
        target=target_record,
        command=command,
        config=json.loads(_rewrite(json.dumps(per_tool).encode(), work, home)),
        metadata_extra=extra,
    )


def write_fixture(
    tool: str,
    captured: Captured,
    *,
    golden_dir: Path = GOLDEN_DIR,
    update: bool = False,
) -> Path:
    """Write the three files under `<golden>/<adapter>/v<version>/`; an
    existing version is left as it is unless `update`."""
    out = golden_dir / fixture_dir_name(tool) / f"v{captured.version}"
    if out.exists() and not update:
        raise CaptureError(f"{out} exists: pass --update to replace it")
    out.mkdir(parents=True, exist_ok=True)
    metadata = {
        "tool": tool,
        "version": captured.version,
        "generated_at": datetime.now(UTC).isoformat(),
        "finding_count": len(captured.findings),
        "raw_output_hash": hashlib.sha256(captured.raw).hexdigest()[:12],
        "binary": captured.binary,
        "binary_sha256": captured.binary_sha256,
        "recipe": CAPTURES[tool].recipe(),
        "target": captured.target,
        "config": captured.config,
        "command": captured.command,
        "rewritten": (
            f"the capture's working directory reads as {PLACEHOLDER} and its HOME as "
            f"{PLACEHOLDER}/home; no line ends in whitespace and the file ends in a "
            "newline, as the pre-commit hooks commit it"
        ),
        **captured.metadata_extra,
    }
    (out / "raw-output.json").write_bytes(captured.raw)
    (out / "expected-findings.json").write_bytes(
        (json.dumps(captured.findings, indent=2, default=str) + "\n").encode()
    )
    (out / "metadata.json").write_bytes(
        (json.dumps(metadata, indent=2) + "\n").encode()
    )
    return out


# --- --check ----------------------------------------------------------------------


def _committed(tool: str, golden_dir: Path) -> list[dict[str, Any]]:
    tool_dir = golden_dir / fixture_dir_name(tool)
    if not tool_dir.is_dir():
        return []
    return [
        json.loads(meta.read_bytes())
        for meta in sorted(tool_dir.glob("*/metadata.json"))
    ]


def check(
    tools: list[str], *, home: Path, golden_dir: Path = GOLDEN_DIR, scratch: Path
) -> int:
    """Capture each tool again in `scratch`; 1 when any could not be."""
    failed = 0
    for tool in tools:
        try:
            got = capture(tool, home=home, work=scratch / fixture_dir_name(tool))
        except (CaptureError, OSError, ValueError, subprocess.SubprocessError) as e:
            failed += 1
            print(f"FAIL {tool}: {e}", flush=True)
            continue
        now = f"v{got.version}, {len(got.findings)} findings"
        recipe = CAPTURES[tool].recipe()
        committed = _committed(tool, golden_dir)
        same = [m for m in committed if m.get("recipe") == recipe]
        if same:
            ref = next(
                (m for m in same if m.get("version") == got.version),
                max(same, key=lambda m: str(m.get("generated_at", ""))),
            )
            was, count = ref.get("finding_count"), len(got.findings)
            moved = "" if was == count else "  (changed: re-capture with --update)"
            print(
                f"ok   {tool}: {now}; fixture v{ref.get('version')}: {was} -> {count}{moved}"
            )
        elif committed:
            versions = ", ".join(f"v{m.get('version')}" for m in committed)
            print(
                f"ok   {tool}: {now}; fixture {versions} from another recipe, not compared"
            )
        else:
            print(f"ok   {tool}: {now}; no fixture committed")
    return 1 if failed else 0


# --- the command line -------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=(__doc__ or "").split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--tool", action="append", choices=sorted(CAPTURES), default=[])
    ap.add_argument("--all", action="store_true", help="every tool in TOOL_MATRIX")
    ap.add_argument("--update", action="store_true", help="replace an existing version")
    ap.add_argument(
        "--check", action="store_true", help="capture again in scratch, write nothing"
    )
    ap.add_argument(
        "--home", type=Path, help="a HOME you prepared (default: made here)"
    )
    ap.add_argument(
        "--work", type=Path, help="scratch for the captures (default: a temp directory)"
    )
    args = ap.parse_args(argv)

    tools = (
        list(TOOL_MATRIX) if args.all or (args.check and not args.tool) else args.tool
    )
    if not tools:
        ap.error("name --tool, --all or --check")

    work = args.work or Path(tempfile.mkdtemp(prefix="jmo-golden-"))
    try:
        home = args.home or isolated_home(work / "home")
        if args.check:
            return check(tools, home=home, scratch=work / "check")
        failed = 0
        for tool in tools:
            try:
                got = capture(tool, home=home, work=work / fixture_dir_name(tool))
                out = write_fixture(tool, got, update=args.update)
            except (CaptureError, OSError, ValueError, subprocess.SubprocessError) as e:
                failed += 1
                print(f"FAIL {tool}: {e}", flush=True)
                continue
            print(f"ok   {tool}: {len(got.findings)} findings -> {out}", flush=True)
        return 1 if failed else 0
    finally:
        if args.work is None:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
