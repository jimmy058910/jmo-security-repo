"""scripts/dev/fetch_answer_keys.py: the pinned answer keys, fetched and never committed.

An answer key is somebody else's file a test grades JMo against: the lockfiles of
QuackatronHQ/sca-kitchen-sink, which are vulnerable on purpose, so committing them would
raise Dependabot alerts on JMo's own repository, and the fixtures of
humora2504/vibeproof, in which trufflehog finds three Postgres URIs. They are fetched by
commit, checked against a sha256 each BEFORE a byte is written, and kept outside the
repository.
Every test here is offline: the one network call, `download`, is replaced (and the
one that checks its retry replaces `fetch_rule_fixture._get`, beneath it).
"""

from __future__ import annotations

import hashlib
import io
import re
import urllib.error
from pathlib import Path

import pytest

from scripts.dev import fetch_answer_keys as fak
from scripts.dev import fetch_rule_fixture as frf


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


GOOD = {
    "javascript/bun/bun.lock": b'{"lockfileVersion": 1}\n',
    "golang/gomod/go.mod": b"module example.com/app\n",
}
GOOD_VIBEPROOF = {
    "test/fixtures/vulnerable/firestore.rules": b"allow read, write: if true;\n",
    "test/fixtures/clean/package.json": b'{"name":"clean"}\n',
}


@pytest.fixture
def keys_dir(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "keys"
    monkeypatch.setenv(fak.ENV_VAR, str(root))
    return root


@pytest.fixture
def served(monkeypatch) -> list[str]:
    """Two stand-in files for each key with their true hashes, and a `download`
    that serves them; the list collects each URL asked for."""
    asked: list[str] = []
    monkeypatch.setattr(
        fak, "SCA_KITCHEN_SINK_FILES", {p: _sha(d) for p, d in GOOD.items()}
    )
    monkeypatch.setattr(
        fak, "VIBEPROOF_FILES", {p: _sha(d) for p, d in GOOD_VIBEPROOF.items()}
    )

    def download(url: str) -> bytes:
        asked.append(url)
        for path, data in {**GOOD, **GOOD_VIBEPROOF}.items():
            if url.endswith("/" + path):
                return data
        raise OSError(f"no such file: {url}")

    monkeypatch.setattr(fak, "download", download)
    return asked


def _landed(root: Path) -> Path:
    return root / "sca-kitchen-sink" / fak.SCA_KITCHEN_SINK_COMMIT


def _landed_vibeproof(root: Path) -> Path:
    return root / "vibeproof" / fak.VIBEPROOF_COMMIT


# --- where the keys live ---------------------------------------------------------


def test_the_env_variable_moves_the_cache(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("JMO_ANSWER_KEYS_DIR", str(tmp_path / "elsewhere"))

    assert fak.answer_keys_dir() == tmp_path / "elsewhere"


def test_with_no_variable_the_cache_is_under_the_home_directory(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.delenv("JMO_ANSWER_KEYS_DIR", raising=False)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    assert fak.answer_keys_dir() == tmp_path / ".cache" / "jmo-answer-keys"


def test_an_empty_variable_is_no_override(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("JMO_ANSWER_KEYS_DIR", "")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    assert fak.answer_keys_dir() == tmp_path / ".cache" / "jmo-answer-keys"


def test_a_key_lands_under_its_name_and_its_commit(keys_dir, served) -> None:
    assert fak.sca_kitchen_sink_dir() == _landed(keys_dir)

    assert fak.sca_kitchen_sink() == []

    for path, data in GOOD.items():
        assert (_landed(keys_dir) / path).read_bytes() == data


# --- what is fetched -------------------------------------------------------------


def test_each_file_is_asked_for_by_the_pinned_commit(keys_dir, served) -> None:
    fak.sca_kitchen_sink()

    assert sorted(served) == sorted(
        "https://raw.githubusercontent.com/QuackatronHQ/sca-kitchen-sink/"
        f"{fak.SCA_KITCHEN_SINK_COMMIT}/{path}"
        for path in GOOD
    )


def test_a_file_already_present_with_the_right_hash_is_not_fetched(
    keys_dir, served
) -> None:
    fak.sca_kitchen_sink()
    served.clear()

    assert fak.sca_kitchen_sink() == []
    assert served == []


def test_a_present_file_with_the_wrong_hash_is_fetched_again(keys_dir, served) -> None:
    target = _landed(keys_dir) / "golang/gomod/go.mod"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"module tampered\n")

    assert fak.sca_kitchen_sink() == []

    assert target.read_bytes() == GOOD["golang/gomod/go.mod"]


def test_a_download_is_written_byte_for_byte(keys_dir, monkeypatch) -> None:
    """CRLF and a missing final newline survive: a lockfile is hashed as it is."""
    data = b"line one\r\nline two, no newline at the end"
    monkeypatch.setattr(fak, "SCA_KITCHEN_SINK_FILES", {"a/b.lock": _sha(data)})
    monkeypatch.setattr(fak, "download", lambda url: data)

    assert fak.sca_kitchen_sink() == []

    assert (_landed(keys_dir) / "a/b.lock").read_bytes() == data


def test_a_server_error_is_asked_for_once_more(monkeypatch) -> None:
    """`download` is `fetch_rule_fixture.fetch_bytes`, so it keeps that script's
    one retry on a 5xx. The seam below it, `_get`, is the only thing replaced."""
    outcomes: list[object] = [
        urllib.error.HTTPError("https://x/y", 503, "unavailable", {}, io.BytesIO()),  # type: ignore[arg-type]
        b"body",
    ]
    asked: list[str] = []

    def get(url: str) -> bytes:
        asked.append(url)
        outcome = outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        assert isinstance(outcome, bytes)
        return outcome

    monkeypatch.setattr(frf, "_get", get)
    monkeypatch.setattr(frf, "RETRY_DELAY_S", 0)

    assert fak.download("https://x/y") == b"body"
    assert asked == ["https://x/y", "https://x/y"]


# --- what is refused -------------------------------------------------------------


def test_a_download_that_does_not_match_its_hash_is_not_written(
    keys_dir, served, monkeypatch
) -> None:
    monkeypatch.setattr(fak, "download", lambda url: b"<html>rate limited</html>")

    problems = fak.sca_kitchen_sink()

    assert len(problems) == len(GOOD)
    assert all("sha256 mismatch" in p for p in problems)
    # The expected and the actual hash are both on the line, with the file.
    assert "javascript/bun/bun.lock" in problems[0]
    assert _sha(GOOD["javascript/bun/bun.lock"]) in problems[0]
    assert _sha(b"<html>rate limited</html>") in problems[0]
    assert not _landed(keys_dir).exists()


def test_a_bad_download_leaves_what_was_there_alone(
    keys_dir, served, monkeypatch
) -> None:
    fak.sca_kitchen_sink()
    path = _landed(keys_dir) / "golang/gomod/go.mod"
    path.write_bytes(b"stale")  # forces a fetch
    monkeypatch.setattr(fak, "download", lambda url: b"wrong")

    assert fak.sca_kitchen_sink()

    # Nothing half-written, and no temporary file beside it.
    assert path.read_bytes() == b"stale"
    assert sorted(p.name for p in path.parent.iterdir()) == ["go.mod"]


@pytest.mark.parametrize(
    "path",
    [
        "../escape.lock",
        "a/../../escape.lock",
        "a/..",
        "/etc/passwd",
        "\\windows\\system32\\x.lock",
        "C:/windows/x.lock",
        "a\\..\\..\\x.lock",
        "",
    ],
)
def test_a_path_that_leaves_the_key_directory_is_refused(
    path, keys_dir, monkeypatch
) -> None:
    called: list[str] = []
    monkeypatch.setattr(fak, "SCA_KITCHEN_SINK_FILES", {path: _sha(b"x")})
    monkeypatch.setattr(fak, "download", lambda url: called.append(url) or b"x")

    problems = fak.sca_kitchen_sink()

    assert len(problems) == 1
    assert "refused" in problems[0]
    assert called == []  # not even asked for
    assert not (keys_dir.parent / "escape.lock").exists()
    assert not keys_dir.exists()


def test_a_failed_download_is_named_and_the_rest_still_land(
    keys_dir, served, monkeypatch
) -> None:
    def download(url: str) -> bytes:
        if url.endswith("go.mod"):
            raise OSError("connection reset")
        return GOOD["javascript/bun/bun.lock"]

    monkeypatch.setattr(fak, "download", download)

    problems = fak.sca_kitchen_sink()

    assert len(problems) == 1
    assert "golang/gomod/go.mod" in problems[0]
    assert "connection reset" in problems[0]
    assert (_landed(keys_dir) / "javascript/bun/bun.lock").is_file()


# --- the command line ------------------------------------------------------------


def test_the_command_with_no_name_fetches_every_key(keys_dir, served) -> None:
    assert fak.main([]) == 0

    for path in GOOD:
        assert (_landed(keys_dir) / path).is_file()
    for path in GOOD_VIBEPROOF:
        assert (_landed_vibeproof(keys_dir) / path).is_file()


def test_the_command_fetches_the_key_it_is_asked_for(keys_dir, served) -> None:
    assert fak.main(["sca-kitchen-sink"]) == 0

    assert (_landed(keys_dir) / "golang/gomod/go.mod").is_file()


def test_the_command_fetches_only_the_vibeproof_key_when_asked_for_it(
    keys_dir, served
) -> None:
    assert fak.main(["vibeproof"]) == 0

    for path in GOOD_VIBEPROOF:
        assert (_landed_vibeproof(keys_dir) / path).is_file()
    assert not _landed(keys_dir).exists()


def test_a_mismatch_makes_the_command_exit_non_zero_and_say_so(
    keys_dir, served, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(fak, "download", lambda url: b"wrong")

    assert fak.main(["sca-kitchen-sink"]) != 0

    assert "sha256 mismatch" in capsys.readouterr().err


def test_an_unknown_key_is_refused_naming_the_known_ones(
    keys_dir, served, capsys
) -> None:
    assert fak.main(["no-such-key"]) != 0

    err = capsys.readouterr().err
    assert "no-such-key" in err
    assert "sca-kitchen-sink" in err
    assert "vibeproof" in err
    assert served == []


# --- the vibeproof key -----------------------------------------------------------


def test_the_vibeproof_key_lands_under_its_name_and_its_commit(
    keys_dir, served
) -> None:
    assert fak.vibeproof_dir() == _landed_vibeproof(keys_dir)

    assert fak.vibeproof() == []

    for path, data in GOOD_VIBEPROOF.items():
        assert (_landed_vibeproof(keys_dir) / path).read_bytes() == data


def test_each_vibeproof_file_is_asked_for_by_the_pinned_commit(
    keys_dir, served
) -> None:
    fak.vibeproof()

    assert sorted(served) == sorted(
        "https://raw.githubusercontent.com/humora2504/vibeproof/"
        f"{fak.VIBEPROOF_COMMIT}/{path}"
        for path in GOOD_VIBEPROOF
    )


def test_a_vibeproof_download_that_does_not_match_its_hash_is_not_written(
    keys_dir, served, monkeypatch
) -> None:
    """The same verify-before-write as the other key: this one is registered on
    `_fetch_pinned` and not on a copy of it."""
    monkeypatch.setattr(fak, "download", lambda url: b"<html>rate limited</html>")

    problems = fak.vibeproof()

    assert len(problems) == len(GOOD_VIBEPROOF)
    assert all("sha256 mismatch" in p for p in problems)
    assert not _landed_vibeproof(keys_dir).exists()


def test_a_vibeproof_path_that_leaves_the_key_directory_is_refused(
    keys_dir, monkeypatch
) -> None:
    called: list[str] = []
    monkeypatch.setattr(fak, "VIBEPROOF_FILES", {"../escape.txt": _sha(b"x")})
    monkeypatch.setattr(fak, "download", lambda url: called.append(url) or b"x")

    problems = fak.vibeproof()

    assert len(problems) == 1
    assert "refused" in problems[0]
    assert called == []
    assert not keys_dir.exists()


# --- the pins --------------------------------------------------------------------


def test_the_pins_are_a_commit_and_a_sha256_per_file() -> None:
    assert re.fullmatch(r"[0-9a-f]{40}", fak.SCA_KITCHEN_SINK_COMMIT)
    assert fak.SCA_KITCHEN_SINK_FILES
    for path, digest in fak.SCA_KITCHEN_SINK_FILES.items():
        assert re.fullmatch(r"[0-9a-f]{64}", digest), path
        assert fak.relative_path_problem(path) is None, path


def test_sca_kitchen_sink_is_registered_under_the_name_the_command_takes() -> None:
    assert fak.KEYS["sca-kitchen-sink"] is fak.sca_kitchen_sink


def test_the_vibeproof_pins_are_a_commit_and_a_sha256_per_fixture_file() -> None:
    assert re.fullmatch(r"[0-9a-f]{40}", fak.VIBEPROOF_COMMIT)
    assert len(fak.VIBEPROOF_FILES) == 14
    for path, digest in fak.VIBEPROOF_FILES.items():
        assert re.fullmatch(r"[0-9a-f]{64}", digest), path
        assert fak.relative_path_problem(path) is None, path
        assert path.startswith("test/fixtures/"), path


def test_the_vibeproof_pins_hold_the_two_files_the_answer_key_test_materialises() -> (
    None
):
    """`tests/integration/test_native_answer_key.py` builds `.env` and
    `.env.example` from these two; without them it would have no `.env` to read."""
    assert "test/fixtures/vulnerable/env.fixture" in fak.VIBEPROOF_FILES
    assert "test/fixtures/clean/env.example.fixture" in fak.VIBEPROOF_FILES


def test_vibeproof_is_registered_under_the_name_the_command_takes() -> None:
    assert fak.KEYS["vibeproof"] is fak.vibeproof
