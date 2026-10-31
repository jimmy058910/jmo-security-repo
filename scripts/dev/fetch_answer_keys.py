#!/usr/bin/env python3
"""Fetch the answer keys a test grades JMo against.

    python scripts/dev/fetch_answer_keys.py [key ...]      (default: every key)

An answer key is somebody else's file, pinned by commit and checked against a
sha256 each, kept in `$JMO_ANSWER_KEYS_DIR` or `~/.cache/jmo-answer-keys`, as
`<root>/<key>/<commit>/<path>`. Never inside the repository: sca-kitchen-sink's
lockfiles are vulnerable on purpose, so tracking them would raise Dependabot
alerts on JMo's own repository, and vibeproof's fixtures hold three Postgres
URIs that trufflehog finds. A test whose key is absent skips and names the
command above.

A file is written only after its bytes match the pin: they go to a temporary
name beside it and are renamed once they verify, so a bad download never
replaces a good file and never leaves one behind. A file already there with the
right hash is left alone.

To add a key: a pinned table, one function that takes an optional cache root and
returns the problems it met, and a line in `KEYS`.

Exit status: 0 when every key is in place; 2 when a file could not be fetched,
did not match its pin or could not be written, or a key is unknown (each is
named on stderr, with the expected and actual sha256 for a mismatch).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path, PureWindowsPath

ROOT = Path(__file__).resolve().parents[2]

# Run directly (`python scripts/dev/fetch_answer_keys.py`) and sys.path[0] is
# scripts/dev, not the repo root - so scripts.dev is not importable without
# this. Same bootstrap as scripts/dev/generate_baseline.py.
if __package__ in (None, ""):  # pragma: no cover - only on direct execution
    sys.path.insert(0, str(ROOT))

from scripts.dev.fetch_rule_fixture import fetch_bytes  # noqa: E402

ENV_VAR = "JMO_ANSWER_KEYS_DIR"

SCA_KITCHEN_SINK = "sca-kitchen-sink"
SCA_KITCHEN_SINK_COMMIT = "eeddfe4d92fddb749915a98a7b02956eae33af22"
SCA_KITCHEN_SINK_URL = (
    "https://raw.githubusercontent.com/QuackatronHQ/sca-kitchen-sink/{commit}/{path}"
)
# Every lockfile JMo reads that the repository holds, plus `API.deps.json`. The
# hashes were measured on the blobs at the commit above.
SCA_KITCHEN_SINK_FILES: dict[str, str] = {
    "javascript/bun/bun.lock": "f60e983fdbc743305f69481098d1126e5c8bfddf4ba1fc6bd13102039301e6b2",
    "javascript/npm/package-lock.json": "d902e7fe5d92a8d8c4d55aa46ca09bf9990cc6e70a5fedee240f6ca50afdc186",
    "javascript/pnpm/pnpm-lock.yaml": "9d0d14d563bcd233ffeddf3d5a894e6a545aafff99235bcde339304f8f07fbb5",
    "javascript/yarn/yarn.lock": "0f7c81d49b057808f9df6c688d09bd61b0279a6d582045d1e9b097768d6d6cad",
    "python/poetry/poetry.lock": "f8fcabd308d502096bd65822974adb24ac1d1be6abf7f393ae4d15fcda4e605b",
    "python/requirements/requirements.txt": "d338c871ed94be536d5cd7b901a345e67e9812762a6ba11dbad9a153f577ed6a",
    "python/uv/uv.lock": "1e00596a0c12e5a8b3d93274cf227e39aed36d881782e0c1733b34e73b868763",
    "golang/gomod/go.mod": "cb84d8f779bbac9664bbdadd5cc7a6591fc338339d2f08d7a0e784b19b36028b",
    "rust/cargo/Cargo.lock": "4ff080a86fc7b1113cfb41d8454497515d3767327fc0a0b09f7d4b3095f78f83",
    "php/composer/composer.lock": "cf772f5844d21f6dd771e40c5e2e515fcca943fe7721ab9cff9a00e7d5163622",
    "ruby/rubygems/Gemfile.lock": "6bd0ea1183d4d1b99d4591e6acd566f436bfe0c015996263c3298458b0ca16d7",
    "java/maven/pom.xml": "edaea3447b03a1e0c3edde7f01979ebca8267d577e22831a76900c26e5d285e7",
    "java/gradle/gradle.lockfile": "987bfcd33f406eb9301694de063dc4ba72b90ddd5f4c6d88a754f2409141ad21",
    "csharp/nuget/packages.lock.json": "01ab79293636104a01dd680fc0cda9f06ee489598bea0df5646fabee5b2c4f0d",
    "csharp/nuget/packages.config": "57be95d533bdb4ffe39c7957f6098a490d29ede41fca9106deb273e7603e9303",
    "csharp/API.deps.json": "400975c04be8a4e64d25f0403712417465071eb20726054d9e9f8ed091f35954",
}

VIBEPROOF = "vibeproof"
VIBEPROOF_COMMIT = "2c57bfae70ab9bb1e059f8522fe1603b613ac42a"
VIBEPROOF_URL = "https://raw.githubusercontent.com/humora2504/vibeproof/{commit}/{path}"
# humora2504/vibeproof (MIT): the fixtures its own test suite scans, a vulnerable
# project and a clean one. The hashes were measured on the blobs at the commit
# above. `vulnerable/env.fixture` and `clean/env.example.fixture` carry tokens in
# place of credentials; the test that reads them builds the real files.
VIBEPROOF_FILES: dict[str, str] = {
    "test/fixtures/.gitignore": "3ee3be110dc18537e0ce3a2f027c8235143e348b162d4825a8e0af42973cf757",
    "test/fixtures/clean/.gitignore": "18d08748340596f6fc068ee2304c4a3e34e58c207df214f491587ece87ab47b1",
    "test/fixtures/clean/env.example.fixture": "68022d12b3f58bffcf1c935a84ddd90adf64af14fb5a8753fbb1e85ffa30c8dd",
    "test/fixtures/clean/package.json": "f500958b6425dcaa338f4fdee28ee4d482b6e61c7a828dd24cff2f28cb20a3c4",
    "test/fixtures/clean/src/app/api/items/route.ts": "7651d37a392613ba5e0952ba8d628c97cbcf1d4076cdfe3101db825ad19b6525",
    "test/fixtures/clean/src/lib/server.ts": "e587c5d734c8a1cca41b69196032fe4c07dd20f559012a7e2511d907b5b67efa",
    "test/fixtures/clean/supabase/migrations/001_init.sql": "4fa94c8224fca29fc786516eb86c585dd3a9f6ad6057fc01f7af2bf2295a5c8c",
    "test/fixtures/vulnerable/.gitignore": "16d30e4462189fb14dd611bdb708c510630c576a1f35b9383e89a4352da36c97",
    "test/fixtures/vulnerable/env.fixture": "aea8e768ca79e30342d0636bc9cf2e42e7bdffe7a4838005e0bfd53b80faa880",
    "test/fixtures/vulnerable/firestore.rules": "cc6e6efc37538d8041a014b7b30ae5ee746490d84f6e8c0643de0e5068440a5d",
    "test/fixtures/vulnerable/package.json": "2e6fcb50347744a4a9c8bb0a69a3a28ac0f22a3397aa5c95f88ea9fdf73ab6c3",
    "test/fixtures/vulnerable/src/app/api/delete/route.ts": "13752f3f1ffff75a8c803064210ed5d27a1319fe782642b4b809dca35550cee8",
    "test/fixtures/vulnerable/src/lib/admin.ts": "359dd0fa7a39f99198960b0530d77e75aa469904532b025db903bd58035fbf10",
    "test/fixtures/vulnerable/supabase/migrations/001_init.sql": "365428d836db5f6dd43c0fb9360b80d8ef9135fb3fc1dcc18e0f150ba7e6bda9",
}


def answer_keys_dir() -> Path:
    """`$JMO_ANSWER_KEYS_DIR`, else `~/.cache/jmo-answer-keys`; an empty
    variable is no override."""
    override = os.environ.get(ENV_VAR)
    return Path(override) if override else Path.home() / ".cache" / "jmo-answer-keys"


def sca_kitchen_sink_dir(root: Path | None = None) -> Path:
    """Where the key's files are: `<root>/sca-kitchen-sink/<commit>`."""
    return (root or answer_keys_dir()) / SCA_KITCHEN_SINK / SCA_KITCHEN_SINK_COMMIT


def vibeproof_dir(root: Path | None = None) -> Path:
    """Where the key's files are: `<root>/vibeproof/<commit>`."""
    return (root or answer_keys_dir()) / VIBEPROOF / VIBEPROOF_COMMIT


def download(url: str) -> bytes:
    """The body of `url`. The one network call here, so a test replaces it.

    It is `fetch_rule_fixture.fetch_bytes`, which asks a second time after a 5xx
    or a timeout: raw.githubusercontent.com is flaky enough to have reddened CI.
    """
    return fetch_bytes(url)


def relative_path_problem(path: str) -> str | None:
    """Why `path` may not be joined under a key's directory, or None. It names
    a file below the directory on every platform: not empty, not absolute in
    either spelling, no drive, no `..` between either kind of separator."""
    if not path:
        return "empty path"
    portable = path.replace("\\", "/")
    if portable.startswith("/") or PureWindowsPath(path).drive:
        return "absolute path"
    if ".." in portable.split("/"):
        return "`..` in path"
    return None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _present(target: Path, expected: str) -> bool:
    try:
        return _sha256(target.read_bytes()) == expected
    except OSError:
        return False


def _fetch_file(dest: Path, path: str, expected: str, url: str) -> str | None:
    """Put `path` in `dest` with the hash `expected`; None on success, else why not."""
    refusal = relative_path_problem(path)
    if refusal:
        return f"{path!r}: refused, {refusal}"
    target = dest / path
    if _present(target, expected):
        return None
    try:
        data = download(url)
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


def _fetch_pinned(
    dest: Path, commit: str, url: str, files: Mapping[str, str]
) -> list[str]:
    problems = []
    for path, expected in files.items():
        problem = _fetch_file(
            dest, path, expected, url.format(commit=commit, path=path)
        )
        if problem:
            problems.append(problem)
    return problems


def sca_kitchen_sink(root: Path | None = None) -> list[str]:
    """QuackatronHQ/sca-kitchen-sink's lockfiles at the pinned commit; the
    problems met, none when every file is in place."""
    return _fetch_pinned(
        sca_kitchen_sink_dir(root),
        SCA_KITCHEN_SINK_COMMIT,
        SCA_KITCHEN_SINK_URL,
        SCA_KITCHEN_SINK_FILES,
    )


def vibeproof(root: Path | None = None) -> list[str]:
    """humora2504/vibeproof's test fixtures at the pinned commit; the problems
    met, none when every file is in place."""
    return _fetch_pinned(
        vibeproof_dir(root), VIBEPROOF_COMMIT, VIBEPROOF_URL, VIBEPROOF_FILES
    )


KEYS: dict[str, Callable[[], list[str]]] = {
    SCA_KITCHEN_SINK: sca_kitchen_sink,
    VIBEPROOF: vibeproof,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fetch the pinned answer keys the tests grade JMo against."
    )
    parser.add_argument(
        "keys",
        nargs="*",
        metavar="key",
        help=f"which keys (default all): {', '.join(KEYS)}",
    )
    args = parser.parse_args(argv)

    names = args.keys or list(KEYS)
    unknown = [name for name in names if name not in KEYS]
    for name in unknown:
        print(f"error: unknown key {name!r}; known: {', '.join(KEYS)}", file=sys.stderr)
    if unknown:
        return 2

    failed = False
    for name in names:
        problems = KEYS[name]()
        for problem in problems:
            print(f"error: {name}: {problem}", file=sys.stderr)
        failed = failed or bool(problems)
        if not problems:
            print(f"{name}: in place under {answer_keys_dir() / name}")
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
