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

The key is random and lives for one pass, so a stand-in cannot be compared with
another run's or guessed from a dictionary of likely secrets. Equal secrets in
one pass get one stand-in, which is all the pairing needs: a tool's tree and
history outputs come from one scan, and one pass rewrites both.
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
    """trufflehog writes NDJSON; a JSON array is read too, as the adapter does.

    Returns the new text, how many fields changed, and how many non-empty lines
    did not parse (left as they are, and named by the caller)."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        document = None
    if isinstance(document, (dict, list)):
        records = document if isinstance(document, list) else [document]
        changed = sum(
            _redact_trufflehog_record(r, stand_in)
            for r in records
            if isinstance(r, dict)
        )
        return json.dumps(document), changed, 0

    out: list[str] = []
    changed = unparsed = 0
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        try:
            record = json.loads(body) if body.strip() else None
        except json.JSONDecodeError:
            record = None
            unparsed += 1
        if isinstance(record, dict):
            n = _redact_trufflehog_record(record, stand_in)
            if n:
                changed += n
                line = json.dumps(record) + line[len(body) :]
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
    except json.JSONDecodeError:
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


def redact_secret_outputs(outputs: Iterable[Path]) -> int:
    """Replace the secrets in every trufflehog and gitleaks output among `outputs`.

    Other outputs are skipped. A file already redacted is not rewritten. A file
    that cannot be read, parsed or rewritten is named at WARNING and left as it
    is: the report it belongs to still runs. Returns how many fields changed.
    """
    key = os.urandom(32)

    def stand_in(secret: str) -> str:
        digest = hmac.new(key, secret.encode("utf-8", "surrogateescape"), "sha256")
        return STAND_IN_PREFIX + digest.hexdigest()[:32]

    total = 0
    for path in outputs:
        redact = _REDACTORS.get(path.name.split(".", 1)[0])
        if redact is None:
            continue
        try:
            text = path.read_bytes().decode("utf-8", "surrogateescape")
        except OSError as e:
            logger.warning(
                "%s could not be read, so it may still hold secrets: %s", path, e
            )
            continue
        new_text, changed, unparsed = redact(text, stand_in)
        if unparsed:
            logger.warning(
                "%s: %d part(s) do not parse as JSON and are left as they are; "
                "they may still hold secrets",
                path,
                unparsed,
            )
        if not changed:
            continue
        try:
            _replace(path, new_text.encode("utf-8", "surrogateescape"))
        except OSError as e:
            logger.warning(
                "%s could not be rewritten, so it may still hold %d secret "
                "field(s): %s: %s",
                path,
                changed,
                type(e).__name__,
                e,
            )
            continue
        total += changed
    if total:
        logger.info(
            "Replaced %d secret field(s) in the secret scanners' raw outputs", total
        )
    return total
