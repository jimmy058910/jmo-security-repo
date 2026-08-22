#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import fnmatch
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from scripts.core.exceptions import ConfigurationException

# Configure logging
logger = logging.getLogger(__name__)

try:
    import yaml
except ImportError as e:
    logger.debug(f"Suppression support unavailable: {e}")
    yaml = None  # type: ignore[assignment]  # Fallback when yaml not installed

#: Keys that select which findings an entry applies to. An entry needs at
#: least one, or it would match every finding in the scan.
SELECTOR_KEYS = frozenset({"id", "path", "ruleId", "severity", "line"})

#: Keys that annotate an entry without affecting what it matches.
METADATA_KEYS = frozenset({"reason", "expires"})


def _normalize_path(value: str) -> str:
    """Reduce a path *or a pattern* to the comparable form used for matching.

    Separators are unified to ``/`` and leading separators are stripped, so a
    pattern written ``/iac/*`` still matches a path reported as ``iac/x.tf``.

    Why this is needed: ``location.path`` is not written uniformly. A single
    ``deep`` scan of one directory produced four spellings of the same file --
    ``iac/x.tf``, ``iac\\x.tf``, ``\\iac\\x.tf`` and an absolute
    ``C:\\...\\iac\\x.tf``. Comparing raw strings matched 37 of that file's 77
    findings.

    A drive letter is deliberately **not** stripped. Doing so is unnecessary --
    the suffix matching in :func:`_path_matches` already reaches
    ``iac/x.tf`` inside ``C:/work/repo/iac/x.tf`` -- and actively harmful,
    because this function is applied to the pattern too: stripping would
    rewrite the pattern ``C:/*`` to ``*`` and suppress the entire scan.
    """
    return value.replace("\\", "/").lstrip("/")


def _path_matches(path: str, pattern: str) -> bool:
    """Match a finding path against a suppression glob.

    The pattern is compared against the normalized path and against every
    suffix of it that starts at a separator, so one pattern covers all the
    spellings above without matching a partial path component
    (``iac/*`` does not capture ``my-iac/secret.tf``).

    ``fnmatchcase`` is used rather than ``fnmatch`` deliberately: ``fnmatch``
    applies ``os.path.normcase``, which lowercases on Windows and not on
    POSIX. Measured, the pattern ``IAC/*`` matched 101 findings on Windows and
    0 on POSIX -- a config committed to a repository would then suppress
    different findings on a developer's machine than in CI.
    """
    if not path or not pattern:
        return False
    target = _normalize_path(path)
    glob = _normalize_path(pattern)
    if not target or not glob:
        return False
    parts = target.split("/")
    return any(
        fnmatch.fnmatchcase("/".join(parts[i:]), glob) for i in range(len(parts))
    )


@dataclass
class Suppression:
    """One entry from ``jmo.suppress.yml``.

    An entry carries one or more *selectors* -- ``id``, ``path``, ``rule_id``,
    ``severity``, ``lines`` -- and matches a finding only when **every**
    selector it declares matches (logical AND). An entry declaring no selector
    matches nothing; ``load_suppressions`` rejects those at load time.
    """

    id: str = ""
    reason: str = ""
    expires: str | None = None  # ISO date or date object (YAML auto-parses dates)
    path: str | None = None
    rule_id: str | None = None
    severity: str | None = None
    lines: tuple[int, ...] = ()

    @property
    def key(self) -> str:
        """Stable identifier for this rule, used for reporting and de-duplication.

        An ``id`` entry keys on its id, so ``suppressions[finding_id]`` keeps
        working for callers that look a finding up directly. A selector entry
        keys on a rendering of its selectors.
        """
        if self.id:
            return self.id
        parts = []
        if self.path is not None:
            parts.append(f"path={self.path}")
        if self.rule_id is not None:
            parts.append(f"ruleId={self.rule_id}")
        if self.severity is not None:
            parts.append(f"severity={self.severity}")
        if self.lines:
            parts.append("line=" + ",".join(str(n) for n in self.lines))
        return " ".join(parts)

    def has_selector(self) -> bool:
        """True when this entry can match anything at all."""
        return bool(
            self.id
            or self.path is not None
            or self.rule_id is not None
            or self.severity is not None
            or self.lines
        )

    def matches(self, finding: dict) -> bool:
        """Check whether this entry applies to a finding.

        Every declared selector must match. Expiration is *not* considered
        here -- callers combine this with :meth:`is_active`.
        """
        if not self.has_selector():
            return False

        if self.id:
            fid = finding.get("id")
            if not isinstance(fid, str) or fid != self.id:
                return False

        location = finding.get("location") or {}

        if self.path is not None:
            if not _path_matches(str(location.get("path") or ""), self.path):
                return False

        if self.rule_id is not None:
            rule = finding.get("ruleId")
            if not isinstance(rule, str) or not fnmatch.fnmatchcase(rule, self.rule_id):
                return False

        if self.severity is not None:
            severity = str(finding.get("severity") or "")
            if severity.upper() != self.severity.upper():
                return False

        if self.lines:
            start = location.get("startLine")
            if not isinstance(start, int) or start not in self.lines:
                return False

        return True

    def is_active(self, now: dt.date | None = None) -> bool:
        """Check if suppression rule is currently active based on expiration date.

        Verifies that current date falls within the suppression's valid_until
        date (if specified). Expired suppressions are ignored.

        Args:
            now (dt.date | None): Current date for testing, or None for today

        Returns:
            bool: True if suppression is active, False if expired

        Example:
            >>> suppression = Suppression(id='fp-123', expires='2025-12-31')
            >>> suppression.is_active()
            True  # (if current date < 2025-12-31)
            >>> suppression.is_active(dt.date(2026, 1, 1))
            False  # (if checking future date > 2025-12-31)

        Note:
            If 'expires' not specified, suppression is always active.
            Date format: YYYY-MM-DD (ISO 8601).
            Invalid dates treated as never expires (returns True).

        """
        if not self.expires:
            return True
        try:
            # Handle both string and date object (YAML auto-parses dates like "2999-01-01")
            if isinstance(self.expires, dt.date):
                exp = self.expires
            elif isinstance(self.expires, str):
                exp = dt.date.fromisoformat(self.expires)
            else:
                # Unexpected type - treat as never expires
                logger.warning(
                    "Suppression %r has expires=%r of type %s, which is not a date; "
                    'treating it as never expiring. Quote it as "YYYY-MM-DD".',
                    self.key,
                    self.expires,
                    type(self.expires).__name__,
                )
                return True
        except (ValueError, TypeError) as e:
            # Invalid date format - treat as never expires
            logger.warning(
                "Suppression %r has an unparseable expires=%r (%s); treating it as "
                "never expiring. Use YYYY-MM-DD.",
                self.key,
                self.expires,
                e,
            )
            return True
        today = now or dt.date.today()
        return today <= exp


@dataclass
class SuppressionSummary:
    """Summary of suppression activity for debt visibility.

    Tracks what was suppressed during filtering to provide insight into
    suppression debt - the accumulation of suppressed findings that may
    need periodic review.

    Attributes:
        total_suppressed: Number of findings that were suppressed
        total_before_suppression: Total findings before suppression applied
        by_severity: Count of suppressed findings by severity level
        by_rule: Count of suppressed findings by suppression rule key
        suppressed_ids: List of finding IDs that were suppressed
        suppressed_by: Finding ID -> the rule key that suppressed it
    """

    total_suppressed: int = 0
    total_before_suppression: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_rule: dict[str, int] = field(default_factory=dict)
    suppressed_ids: list[str] = field(default_factory=list)
    suppressed_by: dict[str, str] = field(default_factory=dict)

    @property
    def suppression_percentage(self) -> float:
        """Percentage of findings that were suppressed."""
        if self.total_before_suppression == 0:
            return 0.0
        return (self.total_suppressed / self.total_before_suppression) * 100

    @property
    def debt_label(self) -> str:
        """Human-readable suppression debt summary.

        e.g., 'Suppression debt: 15 findings (3 HIGH, 8 MEDIUM, 4 LOW)'
        """
        if self.total_suppressed == 0:
            return "Suppression debt: 0 findings"
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        severity_parts = [
            f"{count} {sev}"
            for sev, count in sorted(
                self.by_severity.items(),
                key=lambda x: (
                    severity_order.index(x[0]) if x[0] in severity_order else 99
                ),
            )
        ]
        severity_str = f" ({', '.join(severity_parts)})" if severity_parts else ""
        return f"Suppression debt: {self.total_suppressed} findings{severity_str}"

    def to_dict(self) -> dict:
        """Serialize for JSON storage."""
        return {
            "total_suppressed": self.total_suppressed,
            "total_before_suppression": self.total_before_suppression,
            "suppression_percentage": round(self.suppression_percentage, 1),
            "by_severity": self.by_severity,
            "by_rule": self.by_rule,
        }


def _build_suppression(entry: dict) -> Suppression:
    """Turn one parsed YAML mapping into a Suppression."""
    raw_line = entry.get("line")
    if isinstance(raw_line, bool):  # bool is an int subclass; not a line number
        lines: tuple[int, ...] = ()
    elif isinstance(raw_line, int):
        lines = (raw_line,)
    elif isinstance(raw_line, (list, tuple)):
        lines = tuple(
            n for n in raw_line if isinstance(n, int) and not isinstance(n, bool)
        )
    else:
        lines = ()

    def _optional_str(key: str) -> str | None:
        value = entry.get(key)
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    return Suppression(
        id=str(entry.get("id") or "").strip(),
        reason=str(entry.get("reason") or ""),
        expires=entry.get("expires"),
        path=_optional_str("path"),
        rule_id=_optional_str("ruleId"),
        severity=_optional_str("severity"),
        lines=lines,
    )


def _read_entries(path: Path) -> list | None:
    """Read the entry list out of a suppression file.

    Returns None when nothing usable could be read; every such case is logged
    at WARNING or ERROR first. A malformed file never raises: it used to exit
    ``jmo report`` with a raw traceback *after* the whole scan had been
    parsed, and reporting no suppressions is the fail-safe direction (more
    findings are shown, never fewer).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.error(
            "Cannot read suppression file %s (%s); no suppressions applied", path, exc
        )
        return None

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        logger.error(
            "Suppression file %s is not valid YAML (%s); no suppressions applied",
            path,
            str(exc).replace("\n", " "),
        )
        return None

    if data is None:
        return []  # An empty file is a legitimate "no suppressions".

    if not isinstance(data, dict):
        logger.warning(
            "Suppression file %s should contain a mapping with a 'suppressions' key, "
            "but parsed as %s; no suppressions applied",
            path,
            type(data).__name__,
        )
        return None

    # 'suppressions' is preferred; 'suppress' is the legacy spelling.
    entries = data.get("suppressions")
    if entries is None:
        entries = data.get("suppress")

    if entries is None:
        if "suppressions" in data or "suppress" in data:
            logger.warning(
                "Suppression file %s has an empty 'suppressions' key; "
                "no suppressions applied",
                path,
            )
        return []

    if not isinstance(entries, list):
        logger.warning(
            "Suppression file %s: 'suppressions' should be a list of entries but is "
            "%s; no suppressions applied",
            path,
            type(entries).__name__,
        )
        return None

    return entries


def load_suppressions(path: str | None) -> dict[str, Suppression]:
    """Load suppressions from YAML file.

    Supports both 'suppressions' (recommended) and 'suppress' (backward compat) keys.

    Each entry selects findings with one or more of ``id``, ``path``,
    ``ruleId``, ``severity`` and ``line``; an entry matches only findings that
    satisfy **all** of the selectors it declares. ``path`` and ``ruleId`` are
    glob patterns; ``severity`` is compared case-insensitively; ``line``
    accepts an integer or a list of integers.

    Entries the engine cannot use are skipped and reported at WARNING rather
    than dropped silently -- an entry with no selector would otherwise match
    every finding, and a misspelled key would quietly suppress nothing.

    Args:
        path: Path to suppression YAML file (e.g., jmo.suppress.yml)

    Returns:
        Dict mapping rule keys to Suppression objects. An entry with an ``id``
        is keyed by that id, so ``result[finding_id]`` still resolves.

    """
    if not path:
        return {}
    p = Path(path)
    if not p.exists() or yaml is None:
        return {}

    entries = _read_entries(p)
    if not entries:
        return {}

    items: dict[str, Suppression] = {}
    for position, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            logger.warning(
                "Suppression entry %d in %s is %s, not a mapping; ignored",
                position,
                p,
                type(entry).__name__,
            )
            continue

        unknown = sorted(set(entry) - SELECTOR_KEYS - METADATA_KEYS)
        if unknown:
            logger.warning(
                "Suppression entry %d in %s has unrecognised key(s) %s; they select "
                "nothing and are ignored. Supported: %s",
                position,
                p,
                ", ".join(repr(k) for k in unknown),
                ", ".join(sorted(SELECTOR_KEYS | METADATA_KEYS)),
            )

        suppression = _build_suppression(entry)
        if not suppression.has_selector():
            logger.warning(
                "Suppression entry %d in %s declares no selector "
                "(one of %s is required); it suppresses nothing and is ignored",
                position,
                p,
                ", ".join(sorted(SELECTOR_KEYS)),
            )
            continue

        if suppression.key in items:
            logger.warning(
                "Suppression entry %d in %s duplicates an earlier entry (%r); "
                "the later one wins",
                position,
                p,
                suppression.key,
            )
        items[suppression.key] = suppression

    return items


#: Matches the top-level key that holds the entry list, on its own line.
#: A `# suppressions:` inside a comment cannot match -- `^` is followed by the
#: `#`, not by the word.
_ENTRY_LIST_KEY = re.compile(r"^(?:suppressions|suppress):", re.MULTILINE)

#: Matches the first block-sequence item, to learn the file's own indentation.
#: Mixing a 0-indented item into a 2-indented sequence is a YAML error, so the
#: writer copies what is already there rather than imposing a house style.
_FIRST_SEQUENCE_ITEM = re.compile(r"^([ \t]*)-[ \t]", re.MULTILINE)


def append_suppression(
    path: str | Path,
    *,
    finding_id: str,
    reason: str,
    expires: str | None = None,
) -> bool:
    """Append one id-keyed entry to a suppression config, byte-preserving.

    This is the **only writer** of ``jmo.suppress.yml``. The file was read-only
    for the product's whole life, and the shipped copy is ~5 KB of which most
    is explanatory comments -- a ``yaml.safe_dump`` round-trip would delete
    every one of them. So the existing bytes are never re-serialised: they are
    a prefix of the result, and the new entry is appended after them. YAML
    ignores comments, so a sequence item written past a trailing comment block
    still joins the sequence.

    The entry itself *is* rendered by the YAML dumper. Quoting a free-text
    ``reason`` by hand is how a comment carrying a newline and a ``- path: "*"``
    item becomes a second rule that mutes the entire scan.

    Nothing is written until the candidate has been parsed **by this module's
    own loader** and shown to contain the new rule with the previous ones
    intact. Chunk 8 found the shipped config loading to zero rules against a
    parser it did not match; a writer that cannot be read back is the same
    defect from the other side.

    Args:
        path: Path to the suppression config. Created if absent.
        finding_id: Exact finding fingerprint to suppress; becomes the entry's
            ``id`` selector and its key in :func:`load_suppressions`.
        reason: Free text recorded on the entry. Serialised, never interpolated.
        expires: Optional ``YYYY-MM-DD``. Honoured by :meth:`Suppression.is_active`.

    Returns:
        True when an entry was appended. **False when *finding_id* is already
        suppressed** -- nothing is written and that is not an error. Appending
        a duplicate would leave the loader's rule count unchanged while the
        file grew, so the file and the loader would disagree about how many
        rules exist.

    Raises:
        ConfigurationException: PyYAML is missing, the existing file cannot be
            parsed, or the result would not load back correctly. In every case
            the file on disk is left exactly as it was.
    """
    if yaml is None:
        raise ConfigurationException(
            "suppressions", "PyYAML is not installed, so nothing can be written"
        )

    p = Path(path)
    original = p.read_bytes() if p.exists() else b""

    if original and _read_entries(p) is None:
        # _read_entries has already logged why. It returns None for a file it
        # could not parse and [] for one that is legitimately empty; appending
        # to the first would produce a file that still loads to zero rules,
        # i.e. a write that reports success and suppresses nothing.
        raise ConfigurationException(
            "suppressions",
            "the existing file could not be parsed; it was left unchanged",
            p,
        )

    before = load_suppressions(str(p)) if original else {}
    if finding_id in before:
        return False

    text = original.decode("utf-8")
    newline = "\r\n" if "\r\n" in text else "\n"
    key_match = _ENTRY_LIST_KEY.search(text)
    item_match = _FIRST_SEQUENCE_ITEM.search(text, key_match.end() if key_match else 0)
    indent = item_match.group(1) if item_match else "  "

    entry: dict[str, str] = {"id": finding_id, "reason": reason}
    if expires:
        entry["expires"] = expires
    rendered = yaml.safe_dump(
        [entry],
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=10**6,  # never fold a long reason into a multi-line scalar
    )

    block = ""
    if not original:
        block += (
            "# JMo Security Suppression Configuration"
            + newline
            + "# Created automatically. See docs/USER_GUIDE.md"
            "#handling-false-positives" + newline + newline
        )
    if not key_match:
        block += "suppressions:" + newline
    block += "".join(indent + line + newline for line in rendered.splitlines())

    prefix = original
    if prefix and not prefix.endswith(newline.encode()):
        prefix += newline.encode()
    candidate = prefix + block.encode("utf-8")

    # Validate against the real loader before anything on disk changes, then
    # swap atomically. os.replace is atomic on Windows too, for one volume.
    tmp = p.with_name(p.name + ".jmo-write")
    try:
        tmp.write_bytes(candidate)
        after = load_suppressions(str(tmp))
        if finding_id not in after:
            # Reachable with real input, not merely defensive. Measured: a
            # config whose list is in FLOW style -- `suppressions: []`, the
            # most natural way to write an empty one -- cannot take a block
            # sequence item after it, so the candidate is invalid YAML.
            # Refusing leaves the user's file exactly as it was; the
            # alternative would be re-serialising it, which destroys every
            # comment in it.
            raise ConfigurationException(
                "suppressions",
                f"the appended entry for {finding_id!r} did not load back. "
                "This happens when the list is written in flow style "
                "(suppressions: [...]); rewrite it as a block list "
                "(one '- id:' item per line) and retry",
                p,
            )
        # A second post-condition -- `set(before) <= set(after)`, "no existing
        # rule was lost" -- was written here and REMOVED after mutation testing
        # showed no input can reach it. While the write is an append, an
        # existing rule can only vanish if the file stops parsing, and the
        # check above already refuses that. A guard no input can trigger reads
        # as protection and provides none; the invariant lives in
        # test_mark_resolved_leaves_the_pre_existing_rules_loading instead. If
        # this writer ever stops being append-only, put it back.
        os.replace(tmp, p)
    finally:
        # Missing after a successful replace; present after a refusal.
        tmp.unlink(missing_ok=True)

    logger.info("Suppression appended to %s for finding %s", p, finding_id)
    return True


def _first_active_match(
    finding: dict, suppressions: dict[str, Suppression]
) -> Suppression | None:
    """Return the first active suppression that applies to a finding."""
    for suppression in suppressions.values():
        if suppression.matches(finding) and suppression.is_active():
            return suppression
    return None


def filter_suppressed(
    findings: list[dict], suppressions: dict[str, Suppression]
) -> list[dict]:
    """Filter out suppressed findings based on suppression rules.

    Applies suppression rules from jmo.suppress.yml to findings list,
    removing active suppressed findings and returning only active findings.

    Args:
        findings (list[dict]): List of CommonFinding dictionaries
        suppressions (dict[str, Suppression]): Suppression rules keyed by rule key

    Returns:
        list[dict]: Active (non-suppressed) findings

    Example:
        >>> findings = [{'id': 'fp-123', 'ruleId': 'G101', ...}, {'id': 'real-456', ...}]
        >>> suppressions = {'fp-123': Suppression(id='fp-123', reason='False positive')}
        >>> active = filter_suppressed(findings, suppressions)
        >>> print(len(active))
        1
        >>> print(active[0]['id'])
        real-456

    Note:
        A finding is suppressed when an entry's selectors all match it and the
        entry has not expired.

    """
    return [f for f in findings if _first_active_match(f, suppressions) is None]


def filter_suppressed_with_summary(
    findings: list[dict], suppressions: dict[str, Suppression]
) -> tuple[list[dict], SuppressionSummary]:
    """Filter suppressed findings and return summary of what was suppressed.

    Like filter_suppressed() but also tracks suppression statistics for
    debt visibility. The filtering logic is identical.

    Args:
        findings (list[dict]): List of CommonFinding dictionaries
        suppressions (dict[str, Suppression]): Suppression rules keyed by rule key

    Returns:
        tuple[list[dict], SuppressionSummary]: Active (non-suppressed) findings
            and summary of what was suppressed

    Example:
        >>> findings = [{'id': 'fp-123', 'severity': 'HIGH'}, {'id': 'real-456'}]
        >>> suppressions = {'fp-123': Suppression(id='fp-123', reason='False positive')}
        >>> active, summary = filter_suppressed_with_summary(findings, suppressions)
        >>> print(len(active))
        1
        >>> print(summary.total_suppressed)
        1
        >>> print(summary.debt_label)
        Suppression debt: 1 findings (1 HIGH)

    """
    summary = SuppressionSummary(total_before_suppression=len(findings))
    active = []

    for f in findings:
        sup = _first_active_match(f, suppressions)
        if sup is not None:
            summary.total_suppressed += 1
            severity = f.get("severity", "UNKNOWN")
            summary.by_severity[severity] = summary.by_severity.get(severity, 0) + 1
            summary.by_rule[sup.key] = summary.by_rule.get(sup.key, 0) + 1
            sid = f.get("id")
            if sid and isinstance(sid, str):
                summary.suppressed_ids.append(sid)
                summary.suppressed_by[sid] = sup.key
            continue
        active.append(f)

    return active, summary
