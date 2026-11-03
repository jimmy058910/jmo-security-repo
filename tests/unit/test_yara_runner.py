"""Contracts for the yara-x runner.

The runner drives yara-x's Python bindings over a repository and writes the JSON
the yara-x adapter parses. yara-x is a runtime dependency of JMo (v2.0.0 Phase 6,
PR Y), so nothing here skips: a test that needs the engine has it wherever JMo is
installed. The honest-failure contracts that patch the engine away remain,
because a broken install is still a way to scan nothing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from scripts.cli.scan_utils import tool_exclusion_flags
from scripts.core import yara_runner
from tests.conftest import skip_on_windows

# The marker is deliberately inert. An earlier version of these fixtures wrote a
# real webshell payload (`<?php eval($_POST['cmd']); ?>`) and every matching
# test failed on Windows with `OSError: [Errno 22] Invalid argument` from
# Path.read_bytes - on a file that Path.exists() reported as present with a
# non-zero st_size. That is Defender's real-time protection intercepting the
# write: measured, the same bytes are unwritable as .php *and* .txt, while
# benign content at either extension is fine.
#
# So a fixture containing genuine malware is unwritable on a developer's Windows
# machine but would likely pass in CI - the exact environment-dependent lie this
# whole area exists to eliminate. The rule matches an arbitrary string, so an
# inert marker proves identical wiring with nothing to quarantine.
MARKER = b"JMO_YARA_SELFTEST_MARKER_NOT_MALWARE"

RULE_HIT = b"""
rule JMo_Test_Webshell
{
    meta:
        description = "test marker"
        severity = "HIGH"
    strings:
        $a = "JMO_YARA_SELFTEST_MARKER_NOT_MALWARE"
    condition:
        $a
}
"""

RULE_MISS = b"""
rule JMo_Test_NeverMatches
{
    strings:
        $a = "zzz_this_string_is_not_present_zzz"
    condition:
        $a
}
"""

RULE_BROKEN = b"""
rule JMo_Test_Broken
{
    condition:
        this is not valid yara syntax (((
}
"""

# DRL 1.1 requires a rule's author to travel with what it detects.
RULE_AUTHORED = b"""
rule JMo_Test_Authored
{
    meta:
        description = "authored marker"
        author = "Jane Q. Analyst"
        reference = "https://example.invalid/jmo-authored"
    strings:
        $a = "JMO_YARA_SELFTEST_MARKER_NOT_MALWARE"
    condition:
        $a
}
"""

# signature-base's rules read five externals LOKI defines per file.
RULE_BY_FILENAME = b"""
rule JMo_Test_ByFilename
{
    condition:
        filename == "a.js"
}
"""


def _rules_dir(tmp_path: Path, **files: bytes) -> Path:
    d = tmp_path / "rules"
    d.mkdir()
    for name, body in files.items():
        # write_bytes, not write_text: Path.write_text translates LF to CRLF on
        # Windows (newline=None -> os.linesep).
        (d / f"{name}.yar").write_bytes(body)
    return d


def _target_dir(tmp_path: Path, **files: bytes) -> Path:
    d = tmp_path / "target"
    d.mkdir()
    for name, body in files.items():
        (d / name).write_bytes(body)
    return d


def _plant(root: Path, rel: str, body: bytes = MARKER) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


def _run(rules: Path, target: Path, out: Path, *extra: str) -> int:
    return yara_runner.main(
        ["--rules", str(rules), "--target", str(target), "--output", str(out), *extra]
    )


def _matched(out: Path, target: Path) -> list[str]:
    matches = json.loads(out.read_text(encoding="utf-8"))
    return sorted(Path(m["file"]).relative_to(target).as_posix() for m in matches)


class TestHonestFailure:
    """The runner must never report a clean scan it did not perform.

    This is the whole reason it exists. trufflehog once reported version 3.95.9
    correctly while being completely inert, and the `zero-secrets` gate PASSED;
    the discriminator was a line in stderr, not the exit code. Every path below
    is a way to scan nothing, and each one must be loud.
    """

    def test_zero_compiled_rules_is_an_error_not_a_clean_scan(self, tmp_path, capsys):
        """No rules compiled means nothing was examined - never exit 0.

        A rules directory that yields no usable rules produces exactly the same
        empty findings list as a genuinely clean repository. Exiting 0 there is
        the inert-scanner bug: a confident all-clear over an unexamined tree.
        """
        rules = _rules_dir(tmp_path, broken=RULE_BROKEN)
        target = _target_dir(tmp_path, **{"app.php": MARKER})
        out = tmp_path / "yara-x.json"

        rc = _run(rules, target, out)

        assert rc not in (0, 1), (
            "zero rules compiled but the runner returned an accepted code, so "
            "the scan would be recorded as a completed clean malware scan"
        )
        assert "0" in capsys.readouterr().err

    def test_missing_rules_path_is_an_error(self, tmp_path):
        """A rules path that does not exist must not read as 'nothing to find'."""
        target = _target_dir(tmp_path, **{"a.txt": b"hello"})

        rc = _run(tmp_path / "does-not-exist", target, tmp_path / "yara-x.json")

        assert rc not in (0, 1)

    def test_missing_target_is_an_error(self, tmp_path):
        """Scanning a path that is not there is a failure, not an empty result."""
        rules = _rules_dir(tmp_path, hit=RULE_HIT)

        rc = _run(rules, tmp_path / "no-such-repo", tmp_path / "yara-x.json")

        assert rc not in (0, 1)

    def test_absent_engine_is_reported_not_swallowed(
        self, tmp_path, monkeypatch, capsys
    ):
        """yara-x ships with JMo, but a broken install still scans nothing:
        the runner must fail loudly and must not resemble success."""
        monkeypatch.setattr(yara_runner, "_import_yara_x", lambda: None)
        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        target = _target_dir(tmp_path, **{"a.txt": b"hello"})
        out = tmp_path / "yara-x.json"

        rc = _run(rules, target, out)

        assert rc not in (0, 1)
        assert "yara-x" in capsys.readouterr().err
        assert not out.exists(), "an output file was written for a scan that never ran"


class TestMatching:
    """Real yara-x behaviour, exercised end to end."""

    def test_match_exits_1_and_records_the_file(self, tmp_path):
        """Exit 1 is 'findings', matching the scanner's ok_return_codes=(0, 1)."""
        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        target = _target_dir(
            tmp_path,
            **{"app.php": MARKER, "clean.txt": b"nothing here"},
        )
        out = tmp_path / "yara-x.json"

        rc = _run(rules, target, out)

        assert rc == 1
        matches = json.loads(out.read_text(encoding="utf-8"))
        assert len(matches) == 1
        assert matches[0]["rule"] == "JMo_Test_Webshell"
        assert matches[0]["file"].endswith("app.php")
        assert matches[0]["meta"]["severity"] == "HIGH"
        assert matches[0]["strings"] == ["$a"]

    def test_no_match_exits_0_with_an_empty_array(self, tmp_path):
        """A genuinely clean tree: exit 0, and a real (empty) artifact."""
        rules = _rules_dir(tmp_path, miss=RULE_MISS)
        target = _target_dir(tmp_path, **{"clean.txt": b"nothing to see"})
        out = tmp_path / "yara-x.json"

        rc = _run(rules, target, out)

        assert rc == 0
        assert json.loads(out.read_text(encoding="utf-8")) == []

    def test_one_broken_rule_file_does_not_lose_the_others(self, tmp_path, capsys):
        """A rule file this engine cannot compile must not cost every other
        rule. yara-x compiles rule by rule: what fails is skipped, and the run
        says which file it was in."""
        rules = _rules_dir(tmp_path, hit=RULE_HIT, broken=RULE_BROKEN)
        target = _target_dir(tmp_path, **{"app.php": MARKER})
        out = tmp_path / "yara-x.json"

        rc = _run(rules, target, out)

        assert rc == 1, "a broken sibling rule file suppressed a real detection"
        assert len(json.loads(out.read_text(encoding="utf-8"))) == 1
        err = capsys.readouterr().err
        assert "skipped" in err.lower()
        assert "broken.yar" in err

    def test_namespace_does_not_leak_local_filesystem_layout(self, tmp_path):
        """The namespace reaches every finding as a tag - keep paths out of it.

        The adapter emits it as `namespace:<value>`. Keying namespaces by
        absolute path put the developer's full home directory into every
        finding, and from there into reports, the history database and any
        shared export. The relative stem is both safe and better signal.
        """
        rules_root = tmp_path / "rules"
        (rules_root / "ransomware").mkdir(parents=True)
        (rules_root / "ransomware" / "probe.yar").write_bytes(RULE_HIT)
        target = _target_dir(tmp_path, **{"hit.txt": MARKER})
        out = tmp_path / "yara-x.json"

        rc = _run(rules_root, target, out)

        assert rc == 1
        ns = json.loads(out.read_text(encoding="utf-8"))[0]["namespace"]
        assert ns == "ransomware/probe", ns
        assert str(tmp_path) not in ns

    def test_metadata_reaches_the_output_whatever_its_escapes(self, tmp_path):
        """yara-x hands a metadata string written with `\\x` escapes back as
        bytes (measured, 1.22.1), which JSON cannot hold: one such rule in a
        user's set crashed the whole scan. A key a rule repeats keeps every
        value: 5 signature-base rules list two `reference`s."""
        rule = rb"""
rule JMo_Test_Meta
{
    meta:
        note = "caf\xc3\xa9 \xff"
        reference = "https://example.invalid/one"
        reference = "https://example.invalid/two"
    strings:
        $a = "JMO_YARA_SELFTEST_MARKER_NOT_MALWARE"
    condition:
        $a
}
"""
        rules = _rules_dir(tmp_path, meta=rule)
        target = _target_dir(tmp_path, **{"app.php": MARKER})
        out = tmp_path / "yara-x.json"

        rc = _run(rules, target, out)

        assert rc == 1
        meta = json.loads(out.read_text(encoding="utf-8"))[0]["meta"]
        assert meta["note"] == "café �"
        assert meta["reference"] == [
            "https://example.invalid/one",
            "https://example.invalid/two",
        ]

    def test_a_single_rule_file(self, tmp_path):
        """#1413: `--rules` naming one file (`per_tool.yara-x.rules_path` at a
        user's own rule) took its namespace from a relative path of `.`, whose
        stem raised ValueError, so the scan exited 2. Its namespace is the
        file's stem."""
        rule = tmp_path / "mine.yar"
        rule.write_bytes(RULE_HIT)
        target = _target_dir(tmp_path, **{"app.php": MARKER})
        out = tmp_path / "yara-x.json"

        rc = _run(rule, target, out)

        assert rc == 1
        assert json.loads(out.read_text(encoding="utf-8"))[0]["namespace"] == "mine"


class TestVendoredTrees:
    """Decision 4: yara-x is the one tool that reads `node_modules`, `vendor`,
    `.venv` and `venv`. signature-base's npm supply-chain rules can match
    nowhere else. `.git` and JMo's results directory stay out."""

    def test_the_walk_reads_vendored_trees_and_prunes_git(self, tmp_path):
        target = _target_dir(tmp_path)
        for rel in (
            "src/a.js",
            "node_modules/x/b.js",
            "vendor/c.php",
            ".venv/d.py",
            "venv/e.py",
            ".git/objects/f",
            "results/g.json",
        ):
            _plant(target, rel)

        files, _ = yara_runner.iter_target_files(target, 10_000, frozenset({"results"}))

        assert sorted(f.relative_to(target).as_posix() for f in files) == [
            ".venv/d.py",
            "node_modules/x/b.js",
            "src/a.js",
            "vendor/c.php",
            "venv/e.py",
        ]

    def test_vendored_trees_are_read(self, tmp_path):
        """Through the flags `jmo scan` passes: the row decides what the scan
        excludes, so a runner that read node_modules behind a row that still
        excluded it would never see one."""
        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        target = _target_dir(tmp_path)
        for rel in (
            "src/a.js",
            "node_modules/x/index.js",
            ".git/c",
            "results/old.json",
        ):
            _plant(target, rel)
        out = tmp_path / "yara-x.json"
        flags = tool_exclusion_flags("yara-x", results_dir_name="results")

        rc = _run(rules, target, out, *flags)

        assert flags, "the yara-x row passes no --exclude-dir at all"
        assert rc == 1
        assert _matched(out, target) == ["node_modules/x/index.js", "src/a.js"]

    @skip_on_windows
    def test_a_symlinked_file_is_not_followed(self, tmp_path, capsys):
        """Reading vendored trees meets links: `.venv/bin/python` points at the
        system interpreter, `node_modules/.bin/*` back into the packages. A
        cloned repository chooses where its links point; read only real files,
        and say how many were passed over."""
        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        outside = tmp_path / "outside.txt"
        outside.write_bytes(MARKER)
        target = _target_dir(tmp_path)
        _plant(target, "node_modules/x/cli.js")
        (target / "node_modules" / ".bin").mkdir()
        (target / "node_modules" / ".bin" / "x").symlink_to(
            target / "node_modules" / "x" / "cli.js"
        )
        (target / "escape.txt").symlink_to(outside)
        out = tmp_path / "yara-x.json"

        rc = _run(rules, target, out)

        assert rc == 1
        assert _matched(out, target) == ["node_modules/x/cli.js"]
        assert "2 symlinks not followed" in capsys.readouterr().err

    def test_a_named_directory_is_pruned_at_any_depth(self, tmp_path):
        """#1235: a results directory inside the scanned tree was read back by
        every later scan. The scan names it with `--exclude-dir`."""
        target = _target_dir(tmp_path)
        for rel in ("results/old.json", "sub/results/old.json", "own.php"):
            _plant(target, rel)

        files, _ = yara_runner.iter_target_files(target, 10_000, frozenset({"results"}))
        control, _ = yara_runner.iter_target_files(target, 10_000)

        assert [f.relative_to(target).as_posix() for f in files] == ["own.php"]
        assert len(control) == 3, "without the name all three are read"

    def test_the_flag_repeats_and_reaches_the_walk(self, tmp_path, monkeypatch):
        seen: list[frozenset[str]] = []

        def walk(target, max_bytes, exclude_dirs=frozenset()):
            seen.append(exclude_dirs)
            return [], 0

        monkeypatch.setattr(yara_runner, "iter_target_files", walk)
        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        target = _target_dir(tmp_path)

        _run(
            rules,
            target,
            tmp_path / "o.json",
            "--exclude-dir",
            "results",
            "--exclude-dir",
            "out",
        )

        assert seen == [frozenset({"results", "out"})]


class TestExternals:
    """signature-base's rules read LOKI's five externals (`filename`,
    `filepath`, `extension`, `filetype`, `owner`), each set per file. A rule
    that names one would otherwise not compile, or compare against ""."""

    def test_externals_are_set_per_file(self, tmp_path):
        rules = _rules_dir(tmp_path, by_name=RULE_BY_FILENAME)
        target = _target_dir(tmp_path, **{"a.js": b"one", "b.js": b"two"})
        out = tmp_path / "yara-x.json"

        rc = _run(rules, target, out)

        assert rc == 1
        assert _matched(out, target) == ["a.js"]

    def test_the_values_are_lokis(self, tmp_path):
        """`filepath` is the file's directory (signature-base compares
        `filepath == "/var/log"`), `extension` keeps its dot in lower case
        (`extension == ".jpg"`), `owner` is the owning account's name."""
        _plant(tmp_path, "sub/Shell.PHP", b"<?php echo 1;")
        path = tmp_path / "sub" / "Shell.PHP"
        if sys.platform == "win32":
            owner = ""
        else:
            import pwd

            owner = pwd.getpwuid(path.stat().st_uid).pw_name

        assert yara_runner.loki_externals(path) == {
            "filename": "Shell.PHP",
            "filepath": str(tmp_path / "sub"),
            "extension": ".php",
            "filetype": "",
            "owner": owner,
        }

    @pytest.mark.parametrize(
        ("head", "label"),
        [
            (b"MZ\x90\x00", "EXE"),
            (b"\x7fELF\x02", "ELF"),
            (b"{\\rtf1\\ansi", "RTF"),
            (b"MDMP\x93\xa7", "MDMP"),
            (b"plain text", ""),
        ],
    )
    def test_filetype_is_read_from_the_first_bytes(self, tmp_path, head, label):
        """The binary entries of signature-base's own type table, the one LOKI
        reads. `not filetype == "EXE"` guards a rule that also requires `MZ`:
        with no label it would fire on every such executable."""
        path = tmp_path / "f.bin"
        path.write_bytes(head + b"\x00" * 16)

        assert yara_runner.loki_externals(path)["filetype"] == label


class TestSizeCap:
    def test_a_file_over_the_cap_is_counted_not_scanned(self, tmp_path, capsys):
        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        target = _target_dir(
            tmp_path, **{"small.txt": MARKER, "big.txt": MARKER + b"x" * 200}
        )
        out = tmp_path / "yara-x.json"

        rc = _run(rules, target, out, "--max-file-bytes", "100")

        assert rc == 1
        assert _matched(out, target) == ["small.txt"]
        assert "1 over the size cap" in capsys.readouterr().err


class TestAdapterContract:
    """The runner's output must be what the adapter actually parses.

    The old pairing never closed this loop: the scanner asked for `-r -w -s`
    (line-oriented text) while the adapter called safe_load_json_file and its
    comment cited a `--json-output` flag that never existed. Asserting the two
    halves agree is the only thing that keeps them agreeing.
    """

    def test_runner_output_parses_into_findings(self, tmp_path):
        from scripts.core.adapters.yara_x_adapter import YaraXAdapter

        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        target = _target_dir(tmp_path, **{"app.php": MARKER})
        out = tmp_path / "yara-x.json"

        assert _run(rules, target, out) == 1

        findings = YaraXAdapter().parse(out)

        assert len(findings) == 1, "the adapter could not read the runner's own output"
        assert findings[0].ruleId == "JMo_Test_Webshell"
        assert findings[0].severity == "HIGH"
        assert "app.php" in findings[0].location["path"]

    def test_the_author_reaches_the_finding(self, tmp_path):
        """DRL 1.1 requires a rule's author with its output (decision 5): in
        the finding's context and in the message the reporters show."""
        from scripts.core.adapters.yara_x_adapter import YaraXAdapter

        rules = _rules_dir(tmp_path, authored=RULE_AUTHORED)
        target = _target_dir(tmp_path, **{"app.php": MARKER})
        out = tmp_path / "yara-x.json"

        assert _run(rules, target, out) == 1

        (finding,) = YaraXAdapter().parse(out)

        assert finding.context["author"] == "Jane Q. Analyst"
        assert "Jane Q. Analyst" in finding.message
        assert finding.context["reference"] == "https://example.invalid/jmo-authored"


class _PlantedScanner:
    """A scanner that raises what yara-x does not: nothing the per-file
    handler catches."""

    def __init__(self, rules):
        pass

    def set_timeout(self, seconds):
        pass

    def set_global(self, name, value):
        pass

    def scan_file(self, path):
        raise RuntimeError("planted failure")


def _planted_engine():
    import yara_x

    class Engine:
        Compiler = yara_x.Compiler
        CompileError = yara_x.CompileError
        ScanError = yara_x.ScanError
        TimeoutError = yara_x.TimeoutError
        Scanner = _PlantedScanner

    return Engine


class TestCrash:
    """An exception the runner did not anticipate exited 1, which the row
    accepts as "matches found" (`ok_return_codes=(0, 1)`), over whatever
    `--output` already held (#1382). 2 is "did not scan"."""

    def _args(self, tmp_path: Path, out: Path) -> list[str]:
        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        target = _target_dir(tmp_path, **{"a.txt": b"hello"})
        return ["--rules", str(rules), "--target", str(target), "--output", str(out)]

    def test_an_unexpected_exception_exits_2_and_says_why(
        self, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.setattr(yara_runner, "_import_yara_x", _planted_engine)
        out = tmp_path / "yara-x.json"

        rc = yara_runner.main(self._args(tmp_path, out))

        assert rc == yara_runner.EXIT_ERROR
        assert not out.exists()
        err = capsys.readouterr().err
        assert "RuntimeError: planted failure" in err
        assert "nothing was scanned" in err

    def test_a_stale_output_is_gone_after_a_crashed_run(self, tmp_path, monkeypatch):
        """Else a crash on a re-used results directory reads as the previous
        scan's matches."""
        monkeypatch.setattr(yara_runner, "_import_yara_x", _planted_engine)
        out = tmp_path / "yara-x.json"
        out.write_bytes(b'[{"rule": "stale"}]')

        rc = yara_runner.main(self._args(tmp_path, out))

        assert rc == yara_runner.EXIT_ERROR
        assert not out.exists()

    def test_a_stale_output_is_gone_when_the_scan_stops_early(self, tmp_path):
        """The runner's anticipated failures left it too: a missing target
        exited 2 over the previous scan's file."""
        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        out = tmp_path / "yara-x.json"
        out.write_bytes(b'[{"rule": "stale"}]')

        rc = _run(rules, tmp_path / "no-such-repo", out)

        assert rc == yara_runner.EXIT_ERROR
        assert not out.exists()

    def test_an_output_that_cannot_be_removed_is_an_error(
        self, tmp_path, monkeypatch, capsys
    ):
        """A directory where the file should be: nothing is scanned over it."""
        out = tmp_path / "yara-x.json"
        out.mkdir()

        rc = yara_runner.main(self._args(tmp_path, out))

        assert rc == yara_runner.EXIT_ERROR
        assert "could not remove" in capsys.readouterr().err

    def test_a_real_process_crash_exits_2_and_removes_the_stale_output(self, tmp_path):
        """A real subprocess, nothing patched. An `--timeout` no u64 holds
        makes yara-x's `set_timeout` raise OverflowError (measured, 1.22.1),
        which is no per-file scan error: Python would exit 1 on it."""
        import subprocess

        out = tmp_path / "yara-x.json"
        out.write_bytes(b'[{"rule": "stale"}]')

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.core.yara_runner",
                *self._args(tmp_path, out),
                "--timeout",
                str(2**70),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            cwd=Path(__file__).resolve().parents[2],
        )

        assert result.returncode == yara_runner.EXIT_ERROR, result.stderr
        assert not out.exists()
        assert "OverflowError" in result.stderr
