#!/usr/bin/env python3
"""Clone repositories listed in a TSV and emit a targets file for jmo scan.

Inputs
- --tsv: Path to a TSV file with a header containing either 'url' or 'full_name' columns.
  Example header: full_name	url	stars	language	description	created_at	updated_at	matched_by
  Rows may have blank description; this script only cares about url/full_name.

Outputs
- Clones repos under --dest (default: ./repos-tsv/<owner>/<repo>)
- Writes a newline-delimited list of absolute repo paths to --targets-out (default: results/targets.tsv.txt)

Behavior
- If a repo already exists, perform a fetch and ensure it is not shallow ("unshallowed")
- Prefer the 'url' column when present; otherwise construct https://github.com/<full_name>.git
- Limits cloning to --max (default: all)
"""

from __future__ import annotations

import argparse
import csv
import subprocess  # nosec B404 - this CLI intentionally shells out to git
import sys
from pathlib import Path


def log(msg: str, level: str = "INFO", human: bool = True) -> None:
    level = level.upper()
    if human:
        color = {
            "DEBUG": "\x1b[36m",
            "INFO": "\x1b[32m",
            "WARN": "\x1b[33m",
            "ERROR": "\x1b[31m",
        }.get(level, "")
        reset = "\x1b[0m"
        sys.stderr.write(f"{color}{level:5}{reset} {msg}\n")
    else:
        import json
        import datetime

        rec = {
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "level": level,
            "msg": msg,
        }
        sys.stderr.write(json.dumps(rec) + "\n")


def run(
    cmd: list[str], cwd: Path | None = None, ok_rcs: tuple[int, ...] = (0,)
) -> tuple[int, str, str]:
    try:
        cp = subprocess.run(  # nosec B603 - command is list-based, constructed by this tool; shell=False
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )
        rc = cp.returncode
        if rc not in ok_rcs:
            return rc, cp.stdout or "", cp.stderr or ""
        return rc, cp.stdout or "", cp.stderr or ""
    except FileNotFoundError as e:
        return 127, "", str(e)


def ensure_unshallowed(repo_dir: Path) -> None:
    """Ensure git repository is fully cloned (not shallow) with all history.

    Checks if repository is shallow-cloned and converts to full clone if needed.
    Also fetches all tags and prunes deleted remote branches for completeness.
    Used after cloning/updating repos to ensure security tools can analyze full history.

    Args:
        repo_dir (Path): Path to local git repository directory

    Returns:
        None (modifies repository in-place)

    Raises:
        None (logs warnings on failures but does not raise)

    Example:
        >>> repo = Path("repos-tsv/owner/myrepo")
        >>> ensure_unshallowed(repo)
        # Checks if shallow, runs `git fetch --unshallow`, fetches all tags

    Note:
        Some git configurations require specifying remote explicitly (origin).
        Falls back to `git fetch origin --unshallow` if standard unshallow fails.
        Logs warnings if unshallow fails but does not abort (allows partial results).

    """
    # Determine if shallow and unshallow if needed
    rc, out, err = run(["git", "rev-parse", "--is-shallow-repository"], cwd=repo_dir)
    if rc != 0:
        log(f"git rev-parse failed for {repo_dir.name}: {err.strip()}", "WARN")
        return
    shallow = out.strip().lower() == "true"
    if shallow:
        # Attempt to unshallow
        rc, _, err = run(["git", "fetch", "--unshallow"], cwd=repo_dir)
        if rc != 0:
            # Some setups require specifying the remote; try origin
            rc2, _, err2 = run(["git", "fetch", "origin", "--unshallow"], cwd=repo_dir)
            if rc2 != 0:
                log(
                    f"Failed to unshallow {repo_dir.name}: {err.strip() or err2.strip()}",
                    "WARN",
                )
        # Also fetch tags/prune to be thorough
    run(["git", "fetch", "--all", "--tags", "--prune"], cwd=repo_dir)


def clone_or_update(url: str, dest_root: Path) -> Path | None:
    """Clone new repository or update existing repository from remote URL.

    Derives stable local path <dest_root>/<owner>/<repo> from URL, clones if new,
    or updates (fetch + unshallow) if already exists. Ensures full git history
    is available for security scanning.

    Args:
        url (str): Git repository URL (e.g., https://github.com/owner/repo.git)
        dest_root (Path): Root directory for cloned repositories

    Returns:
        Path | None: Path to cloned/updated repository, or None if clone/update failed

    Raises:
        None (logs errors on failures but returns None instead of raising)

    Example:
        >>> url = "https://github.com/owner/myrepo.git"
        >>> dest = Path("repos-tsv")
        >>> repo_path = clone_or_update(url, dest)
        >>> print(repo_path)
        repos-tsv/owner/myrepo

    Note:
        Local path derived by parsing owner/repo from URL (strips .git suffix).
        If repository exists, runs `git fetch --all --tags --prune` before unshallowing.
        Returns None if clone fails or existing path is not a valid git repository.

    """
    # Derive a stable folder path like <dest_root>/<owner>/<repo>
    try:
        # Strip trailing .git for folder naming
        stem = url.split("//", 1)[-1]
        # stem like github.com/owner/repo(.git)
        parts = stem.split("/")
        owner, repo = parts[-2], parts[-1]
        if repo.endswith(".git"):
            repo = repo[:-4]
    except Exception:
        owner, repo = "misc", url.replace("://", "_").replace("/", "-")
    target = dest_root / owner / repo
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        log(f"Updating existing repo {owner}/{repo}")
        rc, _, err = run(["git", "remote", "-v"], cwd=target)
        if rc != 0:
            log(f"Not a git repo at {target}: {err.strip()}", "ERROR")
            return None
        run(["git", "fetch", "--all", "--tags", "--prune"], cwd=target)
        ensure_unshallowed(target)
        return target
    log(f"Cloning {owner}/{repo}")
    rc, _, err = run(["git", "clone", url, str(target)])
    if rc != 0:
        log(f"Clone failed for {url}: {err.strip()}", "ERROR")
        return None
    ensure_unshallowed(target)
    return target


def parse_tsv(tsv_path: Path, max_count: int | None) -> list[str]:
    """Parse TSV file to extract repository URLs from 'url' or 'full_name' columns.

    Reads TSV file with CSV sniffer to auto-detect delimiter (tab/comma/semicolon),
    extracts repository URLs from 'url' column, or constructs URLs from 'full_name'
    column if 'url' not present. Supports limiting results via max_count parameter.

    Args:
        tsv_path (Path): Path to TSV/CSV file with header row
        max_count (int | None): Optional limit on number of URLs to extract, or None for all

    Returns:
        list[str]: List of repository URLs (e.g., ["https://github.com/owner/repo.git", ...])

    Raises:
        RuntimeError: If TSV has no header row or missing both 'url' and 'full_name' columns

    Example:
        >>> tsv = Path("candidates.tsv")
        >>> urls = parse_tsv(tsv, max_count=10)
        >>> print(urls[0])
        https://github.com/owner/myrepo.git

    Note:
        TSV header must contain 'url' OR 'full_name' column (case-insensitive).
        If 'url' present, uses it directly; if only 'full_name', constructs GitHub URL.
        Auto-detects delimiter by sniffing first 4KB of file (supports tab, comma, semicolon).
        Skips rows with blank url/full_name values.

    """
    urls: list[str] = []
    with tsv_path.open("r", encoding="utf-8") as f:
        # Sniff delimiter; default to tab
        sample = f.read(4096)
        f.seek(0)
        dialect = (
            csv.Sniffer().sniff(sample, delimiters="\t,;") if sample else csv.excel_tab
        )
        reader = csv.DictReader(f, dialect=dialect)
        cols = [c.strip().lower() for c in (reader.fieldnames or [])]
        if not cols:
            raise RuntimeError("TSV file has no header row")
        use_url = "url" in cols
        use_full = "full_name" in cols
        if not use_url and not use_full:
            raise RuntimeError("TSV must include either 'url' or 'full_name' columns")
        for row in reader:
            if max_count and len(urls) >= max_count:
                break
            u = (row.get("url") or "").strip() if use_url else ""
            if not u and use_full:
                fn = (row.get("full_name") or "").strip()
                if fn:
                    u = f"https://github.com/{fn}.git"
            if u:
                urls.append(u)
    return urls


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Clone repos listed in a TSV and emit a jmo targets file"
    )
    ap.add_argument(
        "--tsv",
        required=True,
        help="Path to candidates.tsv with 'url' or 'full_name' header",
    )
    ap.add_argument(
        "--dest",
        default="repos-tsv",
        help="Destination directory to clone into (default: repos-tsv)",
    )
    ap.add_argument(
        "--targets-out",
        default=str(Path("results") / "targets.tsv.txt"),
        help="Path to write newline-delimited repo paths (default: results/targets.tsv.txt)",
    )
    ap.add_argument(
        "--max", type=int, default=None, help="Optional max number of repos to process"
    )
    ap.add_argument("--human-logs", action="store_true", help="Use human-friendly logs")
    args = ap.parse_args(argv)

    tsv_path = Path(args.tsv).expanduser().resolve()
    dest = Path(args.dest).expanduser().resolve()
    targets_out = Path(args.targets_out).expanduser().resolve()
    targets_out.parent.mkdir(parents=True, exist_ok=True)

    if not tsv_path.exists():
        log(f"TSV not found: {tsv_path}", "ERROR")
        return 2

    urls = parse_tsv(tsv_path, args.max)
    if not urls:
        log("No repository URLs found in TSV", "ERROR")
        return 2

    paths: list[Path] = []
    for url in urls:
        p = clone_or_update(url, dest)
        if p:
            paths.append(p)

    if not paths:
        log("No repositories cloned/updated successfully", "ERROR")
        return 1

    # Write absolute paths to targets file
    with targets_out.open("w", encoding="utf-8") as f:
        for p in paths:
            f.write(str(p) + "\n")
    log(f"Wrote targets file: {targets_out}")
    log(f"Cloned/updated {len(paths)} repos into {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
