#!/usr/bin/env python3
"""Fetch the four juice-shop files the rule-bundle guard scans.

    python scripts/dev/fetch_rule_fixture.py [--dest DIR]

`tests/integration/test_rule_bundle_fixture.py` keeps four findings in the
committed opengrep bundle firing (see docs/RULE_BUNDLE.md, swap step 4). Its
fixture is four files of juice-shop, an intentionally vulnerable application,
fetched by commit and checked against a sha256 each. They are never committed:
`lib/insecurity.ts` holds an RSA private key and `routes/login.ts` line 65 trips
gitleaks' `generic-api-key` (both measured), so the destination,
`tests/fixtures/rule_bundle/juice-shop/`, is listed in `.gitignore`.

A present file with the right hash is left alone. A file that is missing, or
whose hash is wrong, is fetched; the bytes are written to a temporary name
beside it and renamed only after they verify, so a bad download never replaces
a good file and never leaves one behind. A request that fails with a 5xx or a
timeout is made once more after a short wait, so a flaky raw.githubusercontent.com
does not redden the CI job; nothing else is retried.

Exit status: 0 when all four files are in place; 2 when one could not be fetched,
did not match its pin or could not be written (each is named on stderr, with the
expected and actual sha256 for a mismatch).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DEST = ROOT / "tests" / "fixtures" / "rule_bundle" / "juice-shop"

# juice-shop 2025-12-22. The paths and hashes are the plan's measured table.
COMMIT = "401393872069a1cedc8cdd26e89f2f8e05fe0dab"
FILES: dict[str, str] = {
    "routes/login.ts": "a75800151ddeda7b18ad683cd3c75fecadf48d23b507c5e531426285a1feb67a",
    "routes/search.ts": "0c23e746dfe31ec29aa6477e076a0a4d55d27afd90446e668b1dc10b88416967",
    "lib/insecurity.ts": "cc8eb6a6bc249de6c2616706a27123842dbfafb8b967595365f671be5e9ca7f0",
    "views/promotionVideo.pug": "d9c4ab0b3a96c832fbde18346f900df727ab20cd0d4ce229e7a8ef3d0bd0c285",
}
URL = "https://raw.githubusercontent.com/juice-shop/juice-shop/{commit}/{path}"
FETCH_TIMEOUT_S = 60
RETRY_DELAY_S = 2


def _get(url: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": "jmo-security rule fixture fetch"}
    )
    # The URL is built from the constants above, never from user input.
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_S) as response:  # nosec B310
        body: bytes = response.read()
    return body


def _transient(exc: OSError) -> bool:
    """A server error or a timeout: the failures a second request can cure."""
    if isinstance(exc, urllib.error.HTTPError):  # before URLError, its base
        return exc.code >= 500
    if isinstance(exc, urllib.error.URLError):
        return isinstance(exc.reason, TimeoutError)
    return isinstance(exc, TimeoutError)


def fetch_bytes(url: str) -> bytes:
    """The body of `url`, asked for twice at most; raises OSError (URLError, a
    timeout) or HTTPException."""
    try:
        return _get(url)
    except OSError as exc:
        if not _transient(exc):
            raise
    time.sleep(RETRY_DELAY_S)
    return _get(url)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _present(target: Path, expected: str) -> bool:
    try:
        return _sha256(target.read_bytes()) == expected
    except OSError:
        return False


def fetch_file(dest: Path, path: str, expected: str) -> str | None:
    """Put `path` in `dest` with the hash `expected`; None on success, else why not."""
    target = dest / path
    if _present(target, expected):
        return None
    url = URL.format(commit=COMMIT, path=path)
    try:
        data = fetch_bytes(url)
    except (OSError, http.client.HTTPException) as exc:  # URLError is an OSError
        return f"{path}: could not fetch {url}: {exc}"
    actual = _sha256(data)
    if actual != expected:
        return f"{path}: sha256 mismatch for {url}: expected {expected}, got {actual}"
    part = target.with_name(target.name + ".part")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        part.write_bytes(data)
        os.replace(part, target)
    except OSError as exc:
        with contextlib.suppress(OSError):
            part.unlink(missing_ok=True)
        return f"{path}: could not write {target}: {exc}"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fetch the juice-shop files the rule-bundle guard scans."
    )
    parser.add_argument(
        "--dest",
        type=Path,
        default=DEFAULT_DEST,
        help="where the files go (default %(default)s, which .gitignore lists)",
    )
    args = parser.parse_args(argv)

    problems = [
        problem
        for path, expected in FILES.items()
        if (problem := fetch_file(args.dest, path, expected))
    ]
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    return 2 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
