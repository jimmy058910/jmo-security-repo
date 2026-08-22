#!/usr/bin/env python3
"""Run `jmo attest` and `jmo verify` end to end against artifacts they produced.

**Why this exists.** Both commands appear in **zero** workflow files (#948).
The unit suite is large -- 421 tests over `scripts/core/attestation/` plus the
two CLI commands -- and it exercises the library, but nothing runs the two
commands against each other's output. That is how chunk 19 found `jmo verify`
reporting "verified successfully" having compared **zero** digests, and passing
on a forged signature bundle it never opened. Green CI carried no information
about this surface, by construction rather than by oversight.

The sequence, from #948. **Steps 3-5 are the point:** step 2 on its own passes
against a verifier that returns 0 unconditionally, which is close to what the
shipped one did.

| # | action | expected exit |
|---|--------|--------------:|
| 1 | `jmo attest findings.json` | 0 |
| 2 | `jmo verify findings.json` | 0 |
| 3 | mutate one byte of the subject, verify again | 1 |
| 4 | verify against a *different* file's attestation | 1 |
| 5 | `jmo verify missing.json` | 2 |

Signing is deliberately out of scope: it needs an OIDC identity, which is the
one prerequisite chunk 19 recorded as genuinely unobtainable outside CI.

Run it locally exactly as CI does:

    python scripts/dev/attest_smoke.py

Exit codes: 0 every step behaved, 1 a step did not.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# `python -m scripts.cli.jmo` rather than the `jmo` console script, matching
# release.yml's `jmo validate` invocation: it does not depend on the venv's
# Scripts/ directory being on PATH, which differs between the runner OSes.
#
# Every step runs with cwd set to the temporary directory, not the repo, so
# the module has to resolve from the INSTALLED package and the subject paths
# have to resolve relative to the user's own directory. That is the shape a
# user invokes it in, and cwd-relative resolution is a measured hazard here.
JMO = [sys.executable, "-m", "scripts.cli.jmo"]

TIMEOUT_S = 120

FIXTURE = {
    "findings": [
        {
            "id": "0000eba9addb92a7",
            "severity": "HIGH",
            "title": "Attest smoke fixture",
            "tool": "bandit",
            "ruleId": "B101",
            "location": {"path": "smoke/app.py", "startLine": 1},
        }
    ],
    "summary": {"total": 1},
}


def _run(args: list[str], cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(
        JMO + args,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TIMEOUT_S,
    )
    return proc.returncode, (proc.stdout + proc.stderr)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="jmo-attest-smoke-"))
    failures: list[str] = []
    try:
        subject = tmp / "findings.json"
        subject.write_bytes(json.dumps(FIXTURE).encode("utf-8"))
        other = tmp / "other.json"
        other.write_bytes(b'{"findings": [], "summary": {"total": 0}}')

        steps = [
            ("attest the subject", ["attest", "findings.json"], 0),
            ("verify an untouched subject", ["verify", "findings.json"], 0),
        ]
        for label, args, expected in steps:
            rc, out = _run(args, tmp)
            ok = rc == expected
            print(
                f"{'ok  ' if ok else 'FAIL'} {label}: exit {rc} (expected {expected})"
            )
            if not ok:
                failures.append(
                    f"{label}: exit {rc}, expected {expected}\n{out[-800:]}"
                )

        # 3. One byte of the subject changes. The digest check must catch it.
        subject.write_bytes(subject.read_bytes().replace(b'"HIGH"', b'"LOWW"'))
        rc, out = _run(["verify", "findings.json"], tmp)
        ok = rc == 1
        print(
            f"{'ok  ' if ok else 'FAIL'} verify a tampered subject: exit {rc} (expected 1)"
        )
        if not ok:
            failures.append(
                f"tampered subject verified as clean: exit {rc}\n{out[-800:]}"
            )
        elif "TAMPER" not in out.upper():
            failures.append("tampered subject failed, but the output never says TAMPER")

        # 4. An attestation for a DIFFERENT file. Exit 1 alone is not enough
        #    here -- the failure must be the digest, not an unrelated parse
        #    error that would fail on a correct pairing too.
        rc, out = _run(["attest", "other.json"], tmp)
        if rc != 0:
            failures.append(
                f"could not attest the second file: exit {rc}\n{out[-800:]}"
            )
        subject.write_bytes(json.dumps(FIXTURE).encode("utf-8"))  # restore
        rc, out = _run(
            ["verify", "findings.json", "--attestation", "other.json.att.json"], tmp
        )
        ok = rc == 1 and "digest" in out.lower()
        print(
            f"{'ok  ' if ok else 'FAIL'} verify against another file's attestation: "
            f"exit {rc} (expected 1, on a digest mismatch)"
        )
        if not ok:
            failures.append(
                f"cross-attestation not rejected on the digest: exit {rc}\n{out[-800:]}"
            )

        # 5. A path that does not exist is a USAGE error, not a failed
        #    verification -- the exit-code contract added in chunk 18 says
        #    2 means nothing was verified. Collapsing 2 into 1 would make
        #    "your file is missing" indistinguishable from "your file is
        #    tampered", which is the difference a CI gate acts on.
        rc, out = _run(["verify", "no-such-file.json"], tmp)
        ok = rc == 2
        print(
            f"{'ok  ' if ok else 'FAIL'} verify a missing subject: exit {rc} (expected 2)"
        )
        if not ok:
            failures.append(f"missing subject did not exit 2: exit {rc}\n{out[-800:]}")

        print()
        if failures:
            for f in failures:
                print(f"FAIL {f}", file=sys.stderr)
            print(f"{len(failures)} step(s) failed.", file=sys.stderr)
            return 1
        print("attest/verify smoke: all steps behaved.")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
