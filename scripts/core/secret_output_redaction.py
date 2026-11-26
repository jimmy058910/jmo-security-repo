"""Take the secrets out of the secret scanners' raw outputs once the report has read them.

The report and history never hold a secret: trufflehog's adapter drops `Raw` and
gitleaks' binding drops `region.snippet`. The raw outputs under
`results/individual-*/<target>/` did hold every one, the git-history files
included, and a results directory gets uploaded as a CI artifact (#1329).

A later `jmo report` reads these files again and reads the secret for two
things: the digest that pairs a secret's tree record with its history records
(`pair_history_with_tree`), and trufflehog's filter for pytest names its Lob
detector matches. So each secret is replaced by a stand-in of its own, a keyed
digest that is equal for equal secrets, and the Lob records the adapter drops
(no secret, a function name) are left as they are. One marker for every secret
would pair each with every other at its path and rule: the trap gitleaks' own
`--redact` sets (#1323).

The key is random, one per target folder and pass, so a stand-in cannot be
compared with another run's or guessed from a dictionary of likely secrets.
Equal secrets in one pass get one stand-in, which is all the pairing needs: a
tool's tree and history outputs come from one scan, and one pass rewrites both.

Unless one of them cannot be rewritten (locked, a full disk, the run stopped
between the two). Then the next pass would give the other file's secrets a new
key's stand-ins, and that secret's two findings would never pair again (#1593).
So before its first rewrite a pass saves its key in the folder (`KEY_FILE`),
and removes it once every output there is rewritten. A pass that finds a key
reuses it, and the report finishes such a pass before it reads the folder
(`has_unfinished_pass`). The key can confirm a guessed secret against a
stand-in, so it stays only while the folder holds a raw secret anyway.
Writing both files and then replacing both would not do: the second replace
can still fail, and undoing the first would put the secret back.

trivy's image scan finds secrets too. It masks each one itself, but copies the
image's build metadata, which can hold the secret it masked, so a trivy output
that found one loses that metadata (#1624). Nothing pairs on it, so it needs no
key.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import stat
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, TypeGuard

# The adapter's own reader flattens arrays at any depth; whatever it reads, the
# redaction has to reach.
from scripts.core.adapters.common import _flatten_to_dicts
from scripts.core.adapters.opengrep_adapter import (
    REDACTED,
    redact_results,
    secret_texts,
)
from scripts.core.adapters.trivy_adapter import redact_image_metadata
from scripts.core.adapters.trufflehog_adapter import (
    SECRET_BEARING_FIELDS,
    _is_pytest_name_matched_as_lob_key,
)

logger = logging.getLogger(__name__)

#: Every stand-in starts with this, so a second pass leaves it alone.
STAND_IN_PREFIX = "jmo-redacted:"

#: What `gitleaks --redact` writes as every snippet. It holds no secret, and
#: the gitleaks binding refuses to pair on it; a stand-in never equals it.
_GITLEAKS_REDACTED = "REDACTED"

StandIn = Callable[[str], str]


def _is_secret_text(value: object) -> TypeGuard[str]:
    return (
        isinstance(value, str) and bool(value) and not value.startswith(STAND_IN_PREFIX)
    )


def _redact_trufflehog_record(record: dict[str, Any], stand_in: StandIn) -> int:
    """Replace `Raw` with its stand-in and drop the other fields that can carry
    the secret (the ones the adapter keeps out of `raw`). Returns how many
    fields changed."""
    detector = str(record.get("DetectorName") or record.get("Detector") or "Unknown")
    if _is_pytest_name_matched_as_lob_key(detector, record.get("Raw")):
        return 0
    changed = 0
    if _is_secret_text(record.get("Raw")):
        record["Raw"] = stand_in(record["Raw"])
        changed += 1
    for field in sorted(SECRET_BEARING_FIELDS - {"Raw"}):
        if record.get(field):
            del record[field]
            changed += 1
    return changed


def _redact_trufflehog(text: str, stand_in: StandIn) -> tuple[str, int, int]:
    """trufflehog writes NDJSON. The file is read as the adapter reads it
    (`safe_load_ndjson_file`): whole when it is one JSON document, else line
    by line, and every record found in a document or line at any depth of
    arrays.

    Returns the new text, how many fields changed, and how many non-empty lines
    did not parse (left as they are, and named by the caller)."""
    try:
        document = json.loads(text)
    except ValueError:
        document = None
    if isinstance(document, (dict, list)):
        changed = sum(
            _redact_trufflehog_record(r, stand_in) for r in _flatten_to_dicts(document)
        )
        return json.dumps(document), changed, 0

    out: list[str] = []
    changed = unparsed = 0
    for line in text.splitlines(keepends=True):
        # As the adapter reads it: the line stripped of whitespace, which
        # includes the U+2028 or NEL that str.splitlines() also breaks at.
        body = line.strip()
        try:
            record = json.loads(body) if body else None
        except ValueError:
            record = None
            unparsed += 1
        n = sum(
            _redact_trufflehog_record(r, stand_in) for r in _flatten_to_dicts(record)
        )
        if n:
            changed += n
            line = json.dumps(record) + line[len(line.splitlines()[0]) :]
        out.append(line)
    return "".join(out), changed, unparsed


def _redact_snippets(node: Any, stand_in: StandIn) -> int:
    """Replace the text of every SARIF `snippet` under `node`: gitleaks writes
    the matched secret there."""
    changed = 0
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "snippet" and isinstance(value, dict):
                text = value.get("text")
                if _is_secret_text(text) and text != _GITLEAKS_REDACTED:
                    value["text"] = stand_in(text)
                    changed += 1
            else:
                changed += _redact_snippets(value, stand_in)
    elif isinstance(node, list):
        changed += sum(_redact_snippets(item, stand_in) for item in node)
    return changed


def _redact_gitleaks(text: str, stand_in: StandIn) -> tuple[str, int, int]:
    try:
        document = json.loads(text)
    except ValueError:
        return text, 0, 1
    changed = _redact_snippets(document, stand_in)
    return json.dumps(document, indent=1), changed, 0


#: By the tool an output belongs to: its name before the first dot, so
#: `trufflehog.git.json` is trufflehog's (`normalize_and_report.tool_of_output`).
_REDACTORS: dict[str, Callable[[str, StandIn], tuple[str, int, int]]] = {
    "trufflehog": _redact_trufflehog,
    "gitleaks": _redact_gitleaks,
}


def _replace(path: Path, data: bytes) -> None:
    """Write `data` over `path` in one step, keeping its mode: a reader never
    sees half a file, and a failure leaves the old one whole."""
    mode = stat.S_IMODE(path.stat().st_mode)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(name, mode)
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


#: A target folder's redaction key, kept while a pass there is unfinished
#: (#1593). Not `*.json`, so no adapter reads it as a tool's output.
KEY_FILE = ".jmo-redaction-key"
_KEY_BYTES = 32


def has_unfinished_pass(folder: Path) -> bool:
    """Whether a pass over `folder` stopped before it rewrote every output.
    False when the folder cannot be searched: Python 3.12's `is_file()` raises
    there, and the report goes on without its outputs, as it did before."""
    try:
        return (folder / KEY_FILE).is_file()
    except OSError:
        return False


def _stored_key(folder: Path) -> bytes | None:
    """The key an unfinished pass left in `folder`, or None. One that cannot be
    read or is not a key is named and treated as absent: its pass's stand-ins
    and the next one's then differ, as they did before #1593."""
    key_file = folder / KEY_FILE
    try:
        key = key_file.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as e:
        logger.warning(
            "%s could not be read, so a new key redacts this folder: %s: %s",
            key_file,
            type(e).__name__,
            e,
        )
        return None
    if len(key) != _KEY_BYTES:
        logger.warning(
            "%s is not a redaction key, so a new key redacts this folder", key_file
        )
        return None
    return key


def _save_key(folder: Path, key: bytes) -> bool:
    """Save `key` in `folder` before a pass rewrites anything there, readable
    by its owner alone (mkstemp's 0o600), and on disk before the first
    rewrite. False, named, when it cannot be: the pass still redacts."""
    key_file = folder / KEY_FILE
    name = None
    try:
        fd, name = tempfile.mkstemp(dir=folder, prefix=f"{KEY_FILE}.", suffix=".tmp")
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, key_file)
    except OSError as e:
        if name is not None:
            Path(name).unlink(missing_ok=True)
        logger.warning(
            "%s could not be saved, so if an output here is not rewritten, its "
            "secrets will not pair with the others: %s: %s",
            key_file,
            type(e).__name__,
            e,
        )
        return False
    return True


#: opengrep's debug log, beside its output in a target's folder
#: (`tool_descriptors.OPENGREP_LOG`): it records the text of every match.
OPENGREP_LOG = Path(".opengrep") / "semgrep.log"


def _spellings(secret: str) -> set[str]:
    """A secret as opengrep's log may write it: as is, and escaped as Python's
    repr and JSON escape it (a quote or backslash in it appears escaped)."""
    return {secret, repr(secret)[1:-1], json.dumps(secret)[1:-1]}


def _redact_opengrep_output(path: Path) -> int:
    """Redact `opengrep.json` as the adapter redacts its findings
    (`redact_results`), and replace the secrets it quoted in opengrep's log
    beside it (#1585). The log goes first: its secrets are found through the
    JSON, so a JSON rewritten before a log that then could not be would leave
    them there for good. Returns how many results changed."""
    try:
        document = json.loads(path.read_bytes().decode("utf-8", "ignore"))
    except (OSError, ValueError, RecursionError) as e:
        logger.warning(
            "%s could not be read, so it may still hold secrets: %s", path, e
        )
        return 0
    results = document.get("results") if isinstance(document, dict) else None
    if not isinstance(results, list):
        return 0
    redacted = redact_results(results)
    changed = sum(1 for old, new in zip(results, redacted, strict=True) if old != new)
    if not changed:
        return 0
    spellings = sorted(
        {s for secret in secret_texts(results) for s in _spellings(secret)},
        key=len,
        reverse=True,
    )
    log = path.parent / OPENGREP_LOG
    try:
        text = log.read_bytes().decode("utf-8", "surrogateescape")
    except FileNotFoundError:
        text = None
    except OSError as e:
        logger.warning(
            "%s could not be read, so it and %s may still hold secrets: %s",
            log,
            path.name,
            e,
        )
        return 0
    if text is not None:
        scrubbed = text
        for secret in spellings:
            scrubbed = scrubbed.replace(secret, REDACTED)
        if scrubbed != text:
            try:
                _replace(log, scrubbed.encode("utf-8", "surrogateescape"))
            except OSError as e:
                logger.warning(
                    "%s could not be rewritten, so it and %s may still hold "
                    "secrets: %s: %s",
                    log,
                    path.name,
                    type(e).__name__,
                    e,
                )
                return 0
    document["results"] = redacted
    try:
        _replace(path, json.dumps(document).encode("utf-8"))
    except OSError as e:
        logger.warning(
            "%s could not be rewritten, so it may still hold secrets: %s: %s",
            path,
            type(e).__name__,
            e,
        )
        return 0
    return changed


def _redact_trivy_output(path: Path) -> int:
    """Remove the image build metadata from a `trivy.json` that found a
    secret, as the adapter removes it from its findings (#1624): trivy masks
    the secret it matched but copies the commands and environment that set it.
    Returns how many fields went."""
    try:
        document = json.loads(path.read_bytes().decode("utf-8", "ignore"))
    except (OSError, ValueError, RecursionError) as e:
        logger.warning(
            "%s could not be read, so it may still hold secrets: %s", path, e
        )
        return 0
    removed = redact_image_metadata(document)
    if not removed:
        return 0
    try:
        _replace(path, json.dumps(document, indent=2).encode("utf-8"))
    except OSError as e:
        logger.warning(
            "%s could not be rewritten, so it may still hold secrets: %s: %s",
            path,
            type(e).__name__,
            e,
        )
        return 0
    return removed


def redact_secret_outputs(outputs: Iterable[Path]) -> int:
    """Replace the secrets in every trufflehog, gitleaks and opengrep output
    among `outputs` (opengrep's: the results of rules that match a secret's
    value, and its log), and remove the image build metadata from a trivy
    output that found a secret.

    Other outputs are skipped. A file already redacted is not rewritten. A file
    that cannot be read, parsed or rewritten is named at WARNING and left as it
    is: the report it belongs to still runs. Returns how many fields changed.
    """
    by_folder: dict[Path, list[Path]] = {}
    for path in outputs:
        by_folder.setdefault(path.parent, []).append(path)
    total = sum(_redact_folder(folder, paths) for folder, paths in by_folder.items())
    if total:
        logger.info(
            "Replaced %d secret field(s) in the secret scanners' raw outputs", total
        )
    return total


def _redact_folder(folder: Path, outputs: list[Path]) -> int:
    """One pass over the outputs of one target folder, under the key an
    unfinished pass left there or a new one (#1593)."""
    key = _stored_key(folder)
    saved = key is not None
    key = key or os.urandom(_KEY_BYTES)
    tried_to_save = saved
    # An output a later pass can still finish: one that could not be read or
    # rewritten. One that does not parse never will be, so it keeps no key.
    unfinished = False

    def stand_in(secret: str) -> str:
        digest = hmac.new(key, secret.encode("utf-8"), "sha256")
        return STAND_IN_PREFIX + digest.hexdigest()[:32]

    total = 0
    for path in outputs:
        tool = path.name.split(".", 1)[0]
        if tool == "opengrep":
            total += _redact_opengrep_output(path)
            continue
        if tool == "trivy":
            total += _redact_trivy_output(path)
            continue
        redact = _REDACTORS.get(tool)
        if redact is None:
            continue
        try:
            # Decoded as the adapter decodes it, dropping bytes that are not
            # UTF-8: what it reads is what has to be redacted.
            text = path.read_bytes().decode("utf-8", "ignore")
        except OSError as e:
            logger.warning(
                "%s could not be read, so it may still hold secrets: %s", path, e
            )
            unfinished = True
            continue
        if not text.strip():
            # A tool stopped after creating its file: nothing to hold.
            continue
        try:
            new_text, changed, unparsed = redact(text, stand_in)
        except RecursionError:
            # Nested deeper than Python's JSON reader goes; the adapter
            # cannot read it either.
            logger.warning(
                "%s is nested too deeply to read, so it may still hold secrets",
                path,
            )
            continue
        if unparsed:
            logger.warning(
                "%s: %d part(s) do not parse as JSON and are left as they are; "
                "they may still hold secrets",
                path,
                unparsed,
            )
        if not changed:
            continue
        if not tried_to_save:
            # Before the first rewrite, so a run stopped after it leaves the key.
            saved = _save_key(folder, key)
            tried_to_save = True
        try:
            _replace(path, new_text.encode("utf-8"))
        except OSError as e:
            logger.warning(
                "%s could not be rewritten, so it may still hold %d secret "
                "field(s): %s: %s",
                path,
                changed,
                type(e).__name__,
                e,
            )
            unfinished = True
            continue
        total += changed
    if saved and unfinished:
        logger.warning(
            "%s is kept until a report rewrites every output here, so their "
            "secrets keep pairing; it can confirm a guessed secret, so treat it "
            "as one",
            folder / KEY_FILE,
        )
    elif saved:
        try:
            (folder / KEY_FILE).unlink(missing_ok=True)
        except OSError as e:
            logger.warning(
                "%s could not be removed; it can confirm a guessed secret, so "
                "treat it as one: %s: %s",
                folder / KEY_FILE,
                type(e).__name__,
                e,
            )
    return total
