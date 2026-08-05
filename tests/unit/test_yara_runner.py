"""Contracts for the yara runner.

The runner exists because ``yara-python`` is libyara plus bindings, not a CLI:
the compiled module exposes ``compile()``/``match()`` and has no ``main()`` and
no console script. The scanner used to build the *native C* yara command line
(``yara -r -w -s <rules> <repo>``), which the library can never satisfy, and
``find_tool`` papered over the gap by returning the pseudo-path ``python:yara``.

The tests that need real matching are skipped when ``yara`` is absent -
``yara-python`` is installed by ``jmo tools install``, not declared in
``pyproject.toml``, so CI does not have it. The tests that pin the *honest
failure* contracts deliberately do not need it, because those are exactly the
paths that must work on a machine without the tool.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.core import yara_runner

# A rule with no external module dependencies, so it compiles on any libyara.
#
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
        pytest.importorskip("yara")
        rules = _rules_dir(tmp_path, broken=RULE_BROKEN)
        target = _target_dir(tmp_path, **{"app.php": MARKER})
        out = tmp_path / "yara.json"

        rc = yara_runner.main(
            ["--rules", str(rules), "--target", str(target), "--output", str(out)]
        )

        assert rc not in (0, 1), (
            "zero rules compiled but the runner returned an accepted code, so "
            "the scan would be recorded as a completed clean malware scan"
        )
        assert "0" in capsys.readouterr().err

    def test_missing_rules_path_is_an_error(self, tmp_path):
        """A rules path that does not exist must not read as 'nothing to find'."""
        target = _target_dir(tmp_path, **{"a.txt": b"hello"})
        out = tmp_path / "yara.json"

        rc = yara_runner.main(
            [
                "--rules",
                str(tmp_path / "does-not-exist"),
                "--target",
                str(target),
                "--output",
                str(out),
            ]
        )

        assert rc not in (0, 1)

    def test_missing_target_is_an_error(self, tmp_path):
        """Scanning a path that is not there is a failure, not an empty result."""
        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        out = tmp_path / "yara.json"

        rc = yara_runner.main(
            [
                "--rules",
                str(rules),
                "--target",
                str(tmp_path / "no-such-repo"),
                "--output",
                str(out),
            ]
        )

        assert rc not in (0, 1)

    def test_absent_yara_module_is_reported_not_swallowed(
        self, tmp_path, monkeypatch, capsys
    ):
        """Without the library the runner must fail loudly and name the fix.

        This is the path a machine that never ran `jmo tools install yara`
        takes, and it must not resemble success in any way.
        """
        monkeypatch.setattr(yara_runner, "_import_yara", lambda: None)
        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        target = _target_dir(tmp_path, **{"a.txt": b"hello"})
        out = tmp_path / "yara.json"

        rc = yara_runner.main(
            ["--rules", str(rules), "--target", str(target), "--output", str(out)]
        )

        assert rc not in (0, 1)
        err = capsys.readouterr().err
        assert "yara" in err.lower()
        assert not out.exists(), "an output file was written for a scan that never ran"


class TestMatching:
    """Real libyara behaviour, exercised end to end."""

    def test_match_exits_1_and_records_the_file(self, tmp_path):
        """Exit 1 is 'findings', matching the scanner's ok_return_codes=(0, 1)."""
        pytest.importorskip("yara")
        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        target = _target_dir(
            tmp_path,
            **{"app.php": MARKER, "clean.txt": b"nothing here"},
        )
        out = tmp_path / "yara.json"

        rc = yara_runner.main(
            ["--rules", str(rules), "--target", str(target), "--output", str(out)]
        )

        assert rc == 1
        matches = json.loads(out.read_text(encoding="utf-8"))
        assert len(matches) == 1
        assert matches[0]["rule"] == "JMo_Test_Webshell"
        assert matches[0]["file"].endswith("app.php")
        assert matches[0]["meta"]["severity"] == "HIGH"

    def test_no_match_exits_0_with_an_empty_array(self, tmp_path):
        """A genuinely clean tree: exit 0, and a real (empty) artifact."""
        pytest.importorskip("yara")
        rules = _rules_dir(tmp_path, miss=RULE_MISS)
        target = _target_dir(tmp_path, **{"clean.txt": b"nothing to see"})
        out = tmp_path / "yara.json"

        rc = yara_runner.main(
            ["--rules", str(rules), "--target", str(target), "--output", str(out)]
        )

        assert rc == 0
        assert json.loads(out.read_text(encoding="utf-8")) == []

    def test_one_broken_rule_file_does_not_lose_the_others(self, tmp_path, capsys):
        """A third-party rule set will contain files this libyara cannot compile.

        310 rule files ship in the pinned bundle; some use modules a given build
        lacks. Compiling them as one unit means a single bad file silently costs
        every rule. Compile per file, skip what fails, and say how many.
        """
        pytest.importorskip("yara")
        rules = _rules_dir(tmp_path, hit=RULE_HIT, broken=RULE_BROKEN)
        target = _target_dir(tmp_path, **{"app.php": MARKER})
        out = tmp_path / "yara.json"

        rc = yara_runner.main(
            ["--rules", str(rules), "--target", str(target), "--output", str(out)]
        )

        assert rc == 1, "a broken sibling rule file suppressed a real detection"
        assert len(json.loads(out.read_text(encoding="utf-8"))) == 1
        assert "skipped" in capsys.readouterr().err.lower()

    def test_namespace_does_not_leak_local_filesystem_layout(self, tmp_path):
        """The namespace reaches every finding as a tag - keep paths out of it.

        libyara reports the namespace on each match and the adapter emits it as
        `namespace:<value>`. Keying compile() by absolute path (the obvious
        choice, since the keys must be unique) put the developer's full home
        directory into every finding, and from there into reports, the history
        database and any shared export. The relative stem is both safe and
        better signal: the pinned bundle is organised by category.
        """
        pytest.importorskip("yara")
        rules_root = tmp_path / "rules"
        (rules_root / "ransomware").mkdir(parents=True)
        (rules_root / "ransomware" / "probe.yar").write_bytes(RULE_HIT)
        target = _target_dir(tmp_path, **{"hit.txt": MARKER})
        out = tmp_path / "yara.json"

        rc = yara_runner.main(
            ["--rules", str(rules_root), "--target", str(target), "--output", str(out)]
        )

        assert rc == 1
        ns = json.loads(out.read_text(encoding="utf-8"))[0]["namespace"]
        assert ns == "ransomware/probe", ns
        assert str(tmp_path) not in ns

    def test_vendored_directories_are_pruned_during_traversal(self, tmp_path):
        """node_modules is third-party noise, and stat-ing it is what hung CI.

        Pruning must happen *during* the walk (os.walk + dirs[:] mutation), not
        by filtering paths afterwards: the post-filter form descended into pnpm
        symlink farms, which raised WinError 1920 on Windows and simply timed
        out on Linux. Same cause, two unrecognisable symptoms - commit ded93df.
        """
        pytest.importorskip("yara")
        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        target = _target_dir(tmp_path)
        vendored = target / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        (vendored / "bad.php").write_bytes(MARKER)
        (target / "own.php").write_bytes(MARKER)
        out = tmp_path / "yara.json"

        rc = yara_runner.main(
            ["--rules", str(rules), "--target", str(target), "--output", str(out)]
        )

        assert rc == 1
        matched = [m["file"] for m in json.loads(out.read_text(encoding="utf-8"))]
        assert len(matched) == 1
        assert "node_modules" not in matched[0]


class TestAdapterContract:
    """The runner's output must be what the adapter actually parses.

    The old pairing never closed this loop: the scanner asked for `-r -w -s`
    (line-oriented text) while the adapter called safe_load_json_file and its
    comment cited a `--json-output` flag. The string "json" does not appear
    anywhere in yara's CLI source, so that flag has never existed. Asserting the
    two halves agree is the only thing that keeps them agreeing.
    """

    def test_runner_output_parses_into_findings(self, tmp_path):
        pytest.importorskip("yara")
        from scripts.core.adapters.yara_adapter import YaraAdapter

        rules = _rules_dir(tmp_path, hit=RULE_HIT)
        target = _target_dir(tmp_path, **{"app.php": MARKER})
        out = tmp_path / "yara.json"

        assert (
            yara_runner.main(
                ["--rules", str(rules), "--target", str(target), "--output", str(out)]
            )
            == 1
        )

        findings = YaraAdapter().parse(out)

        assert len(findings) == 1, "the adapter could not read the runner's own output"
        assert findings[0].ruleId == "JMo_Test_Webshell"
        assert findings[0].severity == "HIGH"
        assert "app.php" in findings[0].location["path"]
