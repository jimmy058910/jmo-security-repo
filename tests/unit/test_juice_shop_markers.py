"""The juice-shop marker parser and the detection table built from it.

juice-shop marks each deliberately vulnerable line with an end-of-line comment,
``// vuln-code-snippet vuln-line <challenge>``. tests/integration/juice_shop_markers.py
reads those comments from a clone and grades a scan's findings against them. The
parser is checked here on files written in ``tmp_path`` with made-up challenge
names; nothing here is juice-shop text, and nothing the parser returns is line
text (a marked Terraform line in juice-shop holds a private key).
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
from pathlib import Path
from typing import Any

from tests.conftest import skip_on_windows
from tests.integration.juice_shop_markers import (
    MarkedLine,
    Marker,
    detection_table,
    parse_markers,
    recall_by_type,
    table_json,
)
from tests.integration.targets import JUICE_SHOP_COMMIT

GIT_TIMEOUT = 60


def tracked_repo(tmp_path: Path, files: dict[str, str | bytes]) -> Path:
    """Write ``files`` under a fresh git repository and stage them.

    ``git ls-files`` lists staged files, so no commit (and no identity) is needed.
    """
    root = tmp_path / "repo"
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode("utf-8") if isinstance(content, str) else content
        path.write_bytes(data)
    for args in (["init", "--quiet"], ["add", "-A"]):
        subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT,
        )
    return root


def finding(
    path: str,
    start: int,
    end: int | None = None,
    tool: str = "opengrep",
    detected_by: list[str] | None = None,
) -> dict[str, Any]:
    """A finding shaped like findings.json: location, tool and optional cluster."""
    location: dict[str, Any] = {"path": path, "startLine": start}
    if end is not None:
        location["endLine"] = end
    found: dict[str, Any] = {"location": location, "tool": {"name": tool}}
    if detected_by is not None:
        found["detected_by"] = [{"name": name} for name in detected_by]
    return found


class TestParseMarkers:
    def test_slash_slash_form_in_typescript_and_solidity(self, tmp_path: Path):
        root = tracked_repo(
            tmp_path,
            {
                "routes/handler.ts": (
                    "const a = 1\n"
                    "run(input) // vuln-code-snippet vuln-line fooBarChallenge\n"
                    "const b = 2\n"
                ),
                "contracts/Vault.sol": (
                    "pragma solidity ^0.8.0;\n"
                    "\n"
                    "call(x); // vuln-code-snippet vuln-line zedChallenge\n"
                ),
            },
        )
        assert parse_markers(root) == [
            Marker("contracts/Vault.sol", 3, "zedChallenge"),
            Marker("routes/handler.ts", 2, "fooBarChallenge"),
        ]

    def test_hash_form_in_yaml_and_terraform(self, tmp_path: Path):
        root = tracked_repo(
            tmp_path,
            {
                "data/questions.yml": (
                    "-\n  text: a\n  # vuln-code-snippet vuln-line yamlOneChallenge\n"
                ),
                "infra/main.tf": (
                    'resource "x" "y" {\n'
                    '  key = "placeholder"  # vuln-code-snippet vuln-line tfLeakChallenge\n'
                    "}\n"
                ),
            },
        )
        assert parse_markers(root) == [
            Marker("data/questions.yml", 3, "yamlOneChallenge"),
            Marker("infra/main.tf", 2, "tfLeakChallenge"),
        ]

    def test_a_line_naming_several_challenges_yields_one_marker_each(
        self, tmp_path: Path
    ):
        root = tracked_repo(
            tmp_path,
            {
                "a.ts": (
                    "check(x) // vuln-code-snippet vuln-line oneChallenge "
                    "twoChallenge threeChallenge\n"
                )
            },
        )
        assert parse_markers(root) == [
            Marker("a.ts", 1, "oneChallenge"),
            Marker("a.ts", 1, "threeChallenge"),
            Marker("a.ts", 1, "twoChallenge"),
        ]

    def test_other_directives_are_not_vulnerable_lines(self, tmp_path: Path):
        """Only vuln-line marks a vulnerable line; a snippet's start and end do not."""
        lines = [
            f"{prefix}ok() {token} vuln-code-snippet {kind} fooChallenge"
            for token in ("//", "#")
            for prefix in ("", "  ")
            for kind in (
                "start",
                "end",
                "neutral-line",
                "hide-line",
                "hide-start",
                "hide-end",
                "block",
            )
        ]
        root = tracked_repo(tmp_path, {"a.ts": "\n".join(lines) + "\n"})
        assert parse_markers(root) == []

    def test_code_that_merely_mentions_the_directive_is_not_a_marker(
        self, tmp_path: Path
    ):
        """A scanner of markers names the directive in a pattern; the pattern is not one."""
        lines = [
            "const finder = new RegExp(`vuln-code-snippet vuln-line.*${name}`)",
            "const strip = body.replace(/ *[/#]+ vuln-code-snippet vuln-line.*$/gm, '')",
            "// the vuln-code-snippet vuln-line comment marks a line",
            'const quoted = "// vuln-code-snippet vuln-line fooChallenge"; run()',
            "// vuln-code-snippet vuln-line",
        ]
        root = tracked_repo(tmp_path, {"lib/reader.ts": "\n".join(lines) + "\n"})
        assert parse_markers(root) == []

    def test_a_marker_carries_no_line_text(self, tmp_path: Path):
        """The marked line of the Terraform file holds a key; only its position may leave."""
        secret = "NOT-A-REAL-KEY-0123456789"
        root = tracked_repo(
            tmp_path,
            {
                "main.tf": (
                    f'key = "{secret}"  # vuln-code-snippet vuln-line keyChallenge\n'
                )
            },
        )
        markers = parse_markers(root)
        assert markers == [Marker("main.tf", 1, "keyChallenge")]
        assert {f.name for f in dataclasses.fields(Marker)} == {
            "file",
            "line",
            "challenge",
        }
        assert secret not in repr(markers)

    def test_line_numbers_count_newlines_only(self, tmp_path: Path):
        """A scanner counts lines by \\n; \\f, \\x1c and \\u2028 do not start a line."""
        text = "a\r\nb \f c\r\nd \x1c e   f\r\ng // vuln-code-snippet vuln-line oddChallenge\r\n"
        root = tracked_repo(tmp_path, {"odd.ts": text})
        assert parse_markers(root) == [Marker("odd.ts", 4, "oddChallenge")]

    def test_only_tracked_files_are_read(self, tmp_path: Path):
        root = tracked_repo(
            tmp_path, {"kept.ts": "x // vuln-code-snippet vuln-line keptChallenge\n"}
        )
        (root / "untracked.ts").write_text(
            "x // vuln-code-snippet vuln-line strayChallenge\n", encoding="utf-8"
        )
        assert parse_markers(root) == [Marker("kept.ts", 1, "keptChallenge")]

    def test_a_file_that_is_not_utf8_is_skipped(self, tmp_path: Path):
        root = tracked_repo(
            tmp_path,
            {
                "binary.dat": b"\xff\xfe // vuln-code-snippet vuln-line binChallenge\n",
                "good.ts": "x // vuln-code-snippet vuln-line goodChallenge\n",
            },
        )
        assert parse_markers(root) == [Marker("good.ts", 1, "goodChallenge")]

    @skip_on_windows
    def test_a_symlink_is_not_followed(self, tmp_path: Path):
        """A cloned repository chooses where its symlinks point; read only real files."""
        outside = tmp_path / "outside.ts"
        outside.write_text(
            "x // vuln-code-snippet vuln-line outsideChallenge\n", encoding="utf-8"
        )
        root = tracked_repo(
            tmp_path, {"real.ts": "x // vuln-code-snippet vuln-line realChallenge\n"}
        )
        (root / "link.ts").symlink_to(outside)
        subprocess.run(
            ["git", "add", "-A"],
            cwd=root,
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT,
        )
        assert parse_markers(root) == [Marker("real.ts", 1, "realChallenge")]


class TestDetectionTable:
    @staticmethod
    def table(
        findings: list[dict[str, Any]], line: int = 10, file: str = "app.ts"
    ) -> MarkedLine:
        (row,) = detection_table([Marker(file, line, "fooChallenge")], findings)
        return row

    def test_a_finding_on_the_exact_line_detects_it(self):
        row = self.table([finding("app.ts", 10)])
        assert row == MarkedLine("app.ts", 10, ("fooChallenge",), ("opengrep",))

    def test_a_line_inside_a_multi_line_range_is_detected(self):
        assert self.table([finding("app.ts", 5, 15)]).tools == ("opengrep",)

    def test_both_ends_of_the_range_are_inside_it(self):
        assert self.table([finding("app.ts", 10, 20)]).tools == ("opengrep",)
        assert self.table([finding("app.ts", 1, 10)]).tools == ("opengrep",)

    def test_a_line_outside_the_range_is_not_detected(self):
        assert self.table([finding("app.ts", 11, 20)]).tools == ()
        assert self.table([finding("app.ts", 1, 9)]).tools == ()

    def test_without_an_end_line_only_the_start_line_counts(self):
        assert self.table([finding("app.ts", 10)]).tools == ("opengrep",)
        assert self.table([finding("app.ts", 9)]).tools == ()
        assert self.table([finding("app.ts", 11)]).tools == ()

    def test_another_file_does_not_detect_it(self):
        assert self.table([finding("other.ts", 10)]).tools == ()

    def test_the_path_must_match_whole(self):
        """src/app.ts is not app.ts: a suffix match would credit the wrong file."""
        assert self.table([finding("src/app.ts", 10)]).tools == ()
        assert self.table([finding("app.ts.bak", 10)]).tools == ()

    def test_detected_by_adds_the_clustered_tools(self):
        """A cluster keeps one tool but lists every member; all of them detected it."""
        row = self.table(
            [
                finding(
                    "app.ts",
                    10,
                    tool="gitleaks",
                    detected_by=["gitleaks", "trufflehog"],
                )
            ]
        )
        assert row.tools == ("gitleaks", "trufflehog")

    def test_tools_are_the_union_over_every_finding_on_the_line(self):
        row = self.table(
            [
                finding("app.ts", 10, tool="opengrep"),
                finding("app.ts", 8, 12, tool="checkov"),
                finding("app.ts", 30, tool="trivy"),
            ]
        )
        assert row.tools == ("checkov", "opengrep")

    def test_a_finding_with_no_usable_location_is_ignored(self):
        findings: list[dict[str, Any]] = [
            {"tool": {"name": "syft"}},
            {"tool": {"name": "syft"}, "location": None},
            {"tool": {"name": "syft"}, "location": {"path": "app.ts"}},
            {"tool": {"name": "syft"}, "location": {"startLine": 10}},
        ]
        assert self.table(findings).tools == ()

    def test_every_marked_line_is_a_row_sorted_by_file_and_line(self):
        markers = [
            Marker("z.ts", 1, "lastChallenge"),
            Marker("a.ts", 7, "twoChallenge"),
            Marker("a.ts", 2, "oneChallenge"),
            Marker("a.ts", 7, "oneChallenge"),
        ]
        rows = detection_table(markers, [finding("a.ts", 7)])
        assert [(r.file, r.line, r.challenges, r.tools) for r in rows] == [
            ("a.ts", 2, ("oneChallenge",), ()),
            ("a.ts", 7, ("oneChallenge", "twoChallenge"), ("opengrep",)),
            ("z.ts", 1, ("lastChallenge",), ()),
        ]


class TestRecordedTable:
    ROWS = [
        MarkedLine("a.sol", 1, ("oneChallenge",), ()),
        MarkedLine("a.ts", 1, ("oneChallenge",), ("opengrep",)),
        MarkedLine("b.ts", 2, ("twoChallenge", "threeChallenge"), ()),
        MarkedLine("c.ts", 3, ("fourChallenge",), ("gitleaks", "trufflehog")),
    ]

    def test_recall_is_counted_in_lines_per_file_type(self):
        assert recall_by_type(self.ROWS) == {
            ".sol": {"marked": 1, "detected": 0},
            ".ts": {"marked": 3, "detected": 2},
        }

    def test_the_document_holds_positions_and_tools_and_nothing_else(self):
        raw = table_json(
            self.ROWS, ["gitleaks", "opengrep", "trufflehog"], "2026-10-30T00:00:00Z"
        )
        assert b"\r" not in raw and raw.endswith(b"}\n")
        document = json.loads(raw)
        assert document["metadata"]["tools_used"] == [
            "gitleaks",
            "opengrep",
            "trufflehog",
        ]
        assert document["lines"][2] == {
            "file": "b.ts",
            "line": 2,
            "challenges": ["twoChallenge", "threeChallenge"],
            "tools": [],
        }
        assert document["recall_total"] == {"marked": 4, "detected": 2}
        assert document["recall_by_type"][".ts"] == {"marked": 3, "detected": 2}

    def test_the_same_rows_render_the_same_bytes(self):
        args = (self.ROWS, ["opengrep"], "2026-10-30T00:00:00Z")
        assert table_json(*args) == table_json(*args)


def test_the_recorded_commit_is_the_pinned_one():
    """The document names the commit it was derived at: the one targets.py pins."""
    raw = table_json([], [], "2026-10-30T00:00:00Z")
    assert json.loads(raw)["metadata"]["commit"] == JUICE_SHOP_COMMIT
