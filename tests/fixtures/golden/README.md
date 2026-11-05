# Golden Test Fixtures

One real output per tool, what JMo's adapter reads from it, and how it was made.
`tests/adapters/test_adapter_golden.py` replays each through the adapter and fails
when the findings change. The samples they scan are in `tests/fixtures/samples/`.

## Structure

```text
golden/
├── <adapter>/              # the adapter name: osv_scanner, jmo_native, yara_x, ...
│   └── v<version>/         # the version that ran, not necessarily today's pin
│       ├── raw-output.json        # the tool's output, as the scan wrote it
│       ├── expected-findings.json # the adapter's findings from it
│       └── metadata.json          # tool, version, binary sha256, target, command, count
└── ...
```

## Capturing

`scripts/dev/generate_golden.py` runs `jmo scan --tools <tool>` on the tool's sample
(its `CAPTURES` table), in a HOME of its own, and keeps what the scan wrote. The
command is the descriptor's, never a copy kept in the script. It needs the tool
installed (`jmo tools install <tool>`), and runs on Linux or macOS.

```bash
python scripts/dev/generate_golden.py --tool shellcheck          # capture one
python scripts/dev/generate_golden.py --tool trivy --update      # replace a version
python scripts/dev/generate_golden.py --check                    # capture all again, write nothing
```

`--check` fails when a tool does not run or its output parses to no finding, and
reports a count that moved from the committed fixture's. The nightly runs it.

A capture changes two things in a tool's output, and its `metadata.json` says so:

- **The capture's working directory reads as `/golden`.** A file-fed tool names each
  file absolutely, so a fixture would otherwise carry the capturing machine's path.
- **trufflehog's credential fields are replaced.** Its target holds a key generated
  for the capture (no tracked sample holds one it reports), and no key enters the
  tree. The capture fails if the replacement changes a finding.

Four fixtures predate the script and are kept: gitleaks (juice-shop), osv-scanner
(NodeGoat, queried online), zizmor (this repository) and opengrep (four juice-shop
files). Each `metadata.json` names its target and the bare command that made it.
`--check` still captures those four tools on their samples, without comparing counts.
