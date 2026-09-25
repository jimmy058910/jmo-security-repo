"""Clone the repositories a TSV lists, for `jmo scan --tsv FILE --dest DIR`.

Input: a TSV (or CSV) whose header has a `url` column, or a `full_name` column
of `owner/repo` values that become `https://github.com/<owner>/<repo>.git`.

Each repository lands at `<dest>/<owner>/<repo>`. A clone that is already there
is fetched and fast-forwarded, so a second run scans current code rather than
the first run's checkout.

Every row is untrusted input that reaches git, and `clone_or_update` is the one
way in: it refuses a URL outside the allowlist, a destination outside `--dest`,
and an existing directory that is not a clone of the row, before git runs.
"""

from __future__ import annotations

import csv
import logging
import os
import re
import subprocess  # nosec B404 - this module intentionally shells out to git
from pathlib import Path

logger = logging.getLogger(__name__)

#: Seconds any one git command may take. A clone of a large repository is
#: minutes, not hours; past this it is stuck (a prompt nobody can answer, a
#: stalled transfer) and the row fails instead of the scan hanging.
GIT_TIMEOUT = 1800

#: A host: letters, digits, `.` and `-`, starting with a letter or digit (a
#: leading `-` is an option to git or ssh).
_HOST = r"[A-Za-z0-9][A-Za-z0-9.-]*"

#: `https://`, `ssh://` or scp-form `git@host:`, printable ASCII only. No
#: `file://` and no bare paths: a TSV names remote repositories, and either
#: form would copy any local repository into --dest. An https userinfo may hold
#: a token, so it is any printable run without `/` or `@`. An ssh user and host
#: reach ssh itself, which can expand them into a `ProxyCommand` (the
#: CVE-2023-51385 class), so they get the host's alphabet.
_ALLOWED_URL = re.compile(
    rf"https://(?:[!-.0-?A-~]+@)?{_HOST}(?::[0-9]+)?/[!-~]+"
    rf"|ssh://(?:[A-Za-z0-9._-]+@)?{_HOST}(?::[0-9]+)?/[!-~]+"
    rf"|git@{_HOST}:[!-~]+"
)

_USERINFO = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://)[^/@]*@")


def redact(url: str) -> str:
    """The URL as it may be logged: userinfo, which can hold a token, hidden.

    git strips it from its own messages; ours have to as well. Any scheme, in
    any case: a refused `http://user:token@...` row is logged too.
    """
    return _USERINFO.sub(r"\1***@", url)


#: Programs git runs to ask for a password *before* it consults
#: `GIT_TERMINAL_PROMPT` (measured: with the prompt disabled and `GIT_ASKPASS`
#: set, as a VS Code terminal sets it, git still ran the askpass program).
_ASKPASS_VARS = ("GIT_ASKPASS", "SSH_ASKPASS")


def _git_env() -> dict[str, str]:
    """The environment git runs in: no https credential prompt of any kind.

    A credential helper still answers (that is how private repositories clone),
    but nothing asks: no askpass program, no terminal prompt, and Git
    Credential Manager told not to open its window.
    """
    env = {k: v for k, v in os.environ.items() if k.upper() not in _ASKPASS_VARS}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"
    return env


def run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Run one git command: bounded, and unable to wait on an https prompt.

    See `_git_env`; no stdin means nothing can answer a prompt git asks another
    way. Returns 124 on timeout, 127 if the binary is missing, 126 for any
    other OS error (a `cwd` that cannot be entered).
    """
    try:
        cp = subprocess.run(  # nosec B603 - list argv, shell=False
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            env=_git_env(),
            # git clone/fetch of arbitrary public repos echoes remote ref names
            # and commit subjects, which are UTF-8 and frequently non-ASCII.
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=GIT_TIMEOUT,
        )
    except FileNotFoundError as e:
        return 127, "", str(e)
    except OSError as e:
        return 126, "", str(e)
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {GIT_TIMEOUT} s"
    return cp.returncode, cp.stdout or "", cp.stderr or ""


def _last_line(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1] if lines else "no output"


def ensure_unshallowed(repo_dir: Path) -> str | None:
    """Unshallow a shallow clone, then fetch tags and prune.

    Returns why the repository could not be brought up to date, or None. The
    caller scans what this fetched, so a failed fetch has to stop it: the old
    checkout would be reported as if it were current.
    """
    rc, out, err = run(["git", "rev-parse", "--is-shallow-repository"], cwd=repo_dir)
    if rc != 0:
        return _last_line(err)
    if out.strip().lower() == "true":
        rc, _, err = run(["git", "fetch", "--unshallow"], cwd=repo_dir)
        if rc != 0:
            # Some setups require specifying the remote; try origin
            rc2, _, err2 = run(["git", "fetch", "origin", "--unshallow"], cwd=repo_dir)
            if rc2 != 0:
                logger.warning(
                    "Failed to unshallow %s: %s", repo_dir.name, _last_line(err2 or err)
                )
    rc, _, err = run(["git", "fetch", "--all", "--tags", "--prune"], cwd=repo_dir)
    return _last_line(err) if rc != 0 else None


def _folder(url: str) -> tuple[str, str]:
    """`<owner>`, `<repo>`: the last two segments of the host and its path.

    The scp form's path follows `host:`, and a trailing `/` is not a segment. A
    one-segment path makes the host the owner, without its userinfo, which
    would otherwise put a token in a folder name, and without its port.
    """
    if url.startswith("git@"):
        host, _, path = url[len("git@") :].partition(":")
    else:
        host, _, path = url.split("://", 1)[1].partition("/")
        host = host.rpartition("@")[2]
    parts = [host.split(":", 1)[0], *path.rstrip("/").split("/")]
    return parts[-2], parts[-1].removesuffix(".git")


def _not_a_clone_of(target: Path, url: str) -> str | None:
    """Why the existing `target` must not be updated in this row's name.

    `rev-parse --show-toplevel` rather than any git command that merely
    succeeds: from a plain directory inside another repository git walks up,
    and that repository was fetched and scanned under this row's name. It also
    names `dubious ownership`, where `git config` fails without a message.
    """
    rc, out, err = run(["git", "rev-parse", "--show-toplevel"], cwd=target)
    if rc != 0:
        return f"exists and is not a clone: {_last_line(err)}"
    if Path(out.strip()).resolve() != target:
        return f"exists and is not a clone (it is inside {out.strip()})"
    _rc, origin, _err = run(["git", "config", "--get", "remote.origin.url"], cwd=target)
    if origin.strip() != url:
        return (
            f"exists and is a clone of {redact(origin.strip()) or 'no origin'}, "
            f"not a clone of this row"
        )
    return None


def clone_or_update(url: str, dest_root: Path) -> tuple[Path | None, str | None]:
    """Clone `url` to `<dest_root>/<owner>/<repo>`, or bring that clone current.

    Returns `(path, None)`, or `(None, why)` naming why this row was refused or
    failed. In order, before git runs: the allowlist; the destination, which
    must resolve to exactly `<dest_root>/<owner>/<repo>` (checked before
    anything is created, since `mkdir` on a `..` or `\\` segment is itself an
    escape); and an existing directory there, which must be a clone of this URL.
    `--` ends git's options, so a row is never read as one.
    """
    if not _ALLOWED_URL.fullmatch(url):
        return None, "not an allowed clone URL (https://, ssh:// or git@host: only)"
    owner, repo = _folder(url)
    try:
        root = dest_root.resolve()
        target = (root / owner / repo).resolve()
    except (OSError, ValueError, RuntimeError) as exc:  # RuntimeError: a symlink loop
        return None, f"cannot be used as a folder name: {exc}"
    if target.parent.parent != root:
        return None, f"would clone outside --dest ({target})"

    # One row must never end the scan: every filesystem call here can raise
    # (a --dest that is a file, a folder name Windows refuses, no permission).
    try:
        exists = target.exists()
    except OSError as exc:
        return None, f"cannot be read: {exc}"
    if exists:
        why = _not_a_clone_of(target, url)
        if why:
            return None, why
        logger.info("Updating existing clone %s", target)
        why = ensure_unshallowed(target)
        if why:
            return None, f"could not update the existing clone: {why}"
        rc, _, err = run(["git", "merge", "--ff-only"], cwd=target)
        if rc != 0:
            return None, (
                f"could not fast-forward the existing clone: {_last_line(err)}; "
                f"delete {target} to clone it again"
            )
        return target, None

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return None, f"cannot create {target.parent}: {exc}"
    logger.info("Cloning %s into %s", redact(url), target)
    rc, _, err = run(["git", "clone", "--", url, str(target)])
    if rc != 0:
        return None, f"clone failed: {_last_line(err)}"
    return target, None


def parse_tsv(tsv_path: Path) -> list[str]:
    """Parse TSV file to extract repository URLs from 'url' or 'full_name' columns.

    Reads TSV file with CSV sniffer to auto-detect delimiter (tab/comma/semicolon),
    extracts repository URLs from 'url' column, or constructs URLs from 'full_name'
    column if 'url' not present.

    Args:
        tsv_path (Path): Path to TSV/CSV file with header row

    Returns:
        list[str]: List of repository URLs (e.g., ["https://github.com/owner/repo.git", ...])

    Raises:
        RuntimeError: If TSV has no header row or missing both 'url' and 'full_name' columns

    Note:
        TSV header must contain 'url' OR 'full_name' column (case-insensitive).
        If 'url' present, uses it directly; if only 'full_name', constructs GitHub URL.
        Auto-detects delimiter by sniffing first 4KB of file (supports tab, comma, semicolon).
        Skips rows with blank url/full_name values.

    """
    urls: list[str] = []
    # utf-8-sig: a spreadsheet's export starts with a BOM, which read as plain
    # utf-8 becomes part of the first column's name ("﻿url").
    with tsv_path.open("r", encoding="utf-8-sig") as f:
        # Sniff delimiter; default to tab.
        #
        # Sniffer raises `_csv.Error: Could not determine delimiter` on a
        # single-column file, because such a file contains no delimiter to find.
        # That is the *documented* minimal example in
        # docs/examples/scan_from_tsv.md -- a `full_name` header followed by one
        # `owner/repo` per line -- so following the docs produced an unhandled
        # traceback and exit 1. Tab is the intended default (this file is a TSV
        # reader and the empty-sample branch below already says so); a failed
        # sniff means "no delimiter present", which a single column satisfies.
        sample = f.read(4096)
        f.seek(0)
        dialect: type[csv.Dialect] | csv.Dialect = csv.excel_tab
        if sample:
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters="\t,;")
            except csv.Error:
                dialect = csv.excel_tab
        reader = csv.DictReader(f, dialect=dialect)
        cols = [c.strip().lower() for c in (reader.fieldnames or [])]
        if not cols:
            raise RuntimeError("TSV file has no header row")
        # Rows are keyed by the header as written; key them by what was matched,
        # or a `URL` column is found and then read as empty on every row.
        reader.fieldnames = cols
        use_url = "url" in cols
        use_full = "full_name" in cols
        if not use_url and not use_full:
            raise RuntimeError("TSV must include either 'url' or 'full_name' columns")
        for row in reader:
            u = (row.get("url") or "").strip() if use_url else ""
            if not u and use_full:
                fn = (row.get("full_name") or "").strip()
                if fn:
                    u = f"https://github.com/{fn}.git"
            if u:
                urls.append(u)
    return urls
