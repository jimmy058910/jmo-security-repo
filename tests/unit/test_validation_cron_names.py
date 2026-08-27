"""`validate_cron_expression` must accept the named weekdays cron accepts (#927).

Three parsers saw the same string and disagreed: ``croniter`` (used at create
and validate) accepted ``0 2 * * MON``, GitHub Actions accepts it, POSIX cron
defines it -- and ``validate_cron_expression`` (used at install) refused it. So
``jmo schedule create --cron "0 2 * * MON"`` succeeded and ``jmo schedule
install`` then rejected the schedule it had just written.

The validator was the thing that was wrong, which is why chunk 17 deliberately
did NOT add a warning here: warning would have flagged an expression that works.

The over-acceptance in the other direction is real and stays rejected: croniter
takes 6-field expressions and ``@daily``, neither of which cron or GitHub
Actions accept, and neither of which this validator ever did.
"""

from __future__ import annotations

import pytest

from scripts.core.validation import validate_cron_expression

# POSIX cron defines names for the month and day-of-week fields only.
ACCEPT = [
    "0 2 * * *",
    "*/15 * * * *",
    "0 2 * * 1",
    "0 2 * * MON",
    "0 2 * * mon",  # cron is case-insensitive
    "0 2 * * Mon",
    "0 2 * * SUN",
    "0 2 * * SAT",
    "0 2 * * MON-FRI",
    "0 2 * * MON,WED,FRI",
    "0 2 * * MON-FRI/2",
    "0 2 * * MON,3",  # names and numbers may be mixed in one list
    "0 2 * JAN *",
    "0 2 * JAN-MAR *",
    "0 2 * JAN,JUL *",
    "0 2 * DEC MON",
]

REJECT = [
    "0 0 2 * * *",  # 6-field: croniter takes it, cron and GH Actions do not
    "@daily",  # croniter takes it, cron and GH Actions do not
    "0 2 * * NOTADAY",  # not a weekday name
    "0 2 * * MOO",  # three letters, still not a weekday
    "0 2 * FOO *",  # not a month name
    "0 2 * * MONDAY",  # cron takes exactly three letters
    "0 2 * * *; rm -rf /",  # the injection case this validator exists for
    "0 2 * * $(id)",
    "0 2 * * `id`",
    "MON 2 * * *",  # names are NOT legal in the minute field
    "0 MON * * *",  # ...nor the hour field
    "0 2 MON * *",  # ...nor day-of-month
    "",
    "0 2 * *",  # 4 fields
]


@pytest.mark.parametrize("expr", ACCEPT)
def test_accepted(expr: str):
    assert validate_cron_expression(expr) is True, f"rejected a valid cron: {expr!r}"


@pytest.mark.parametrize("expr", REJECT)
def test_rejected(expr: str):
    assert (
        validate_cron_expression(expr) is False
    ), f"accepted an invalid cron: {expr!r}"


def test_named_weekdays_are_the_specific_regression():
    """Named without parametrisation so a revert reads as itself in the log."""
    assert validate_cron_expression("0 2 * * MON") is True


def test_names_are_not_accepted_in_the_numeric_fields():
    """Widening month and day-of-week must not widen minute/hour/day-of-month.

    Without this, `re.IGNORECASE` plus a shared field pattern would be an easy
    way to "fix" #927 by accepting `MON 2 * * *`, which cron rejects.
    """
    for expr in ("MON 2 * * *", "0 MON * * *", "0 2 MON * *"):
        assert validate_cron_expression(expr) is False, expr


# --------------------------------------------------------------------------
# The cross-check the issue asked for
# --------------------------------------------------------------------------


def test_everything_this_validator_accepts_croniter_can_parse():
    """The validator must not drift into accepting what the backend cannot run.

    `jmo schedule` builds its next-run times with croniter, so an expression
    this validator waves through and croniter rejects would install a schedule
    that never fires.
    """
    croniter = pytest.importorskip("croniter").croniter

    unparseable = [e for e in ACCEPT if not croniter.is_valid(e)]
    assert not unparseable, (
        f"validate_cron_expression accepts expressions croniter cannot parse: "
        f"{unparseable}"
    )


def test_the_cross_check_can_actually_fail():
    """Positive control for the test above.

    A cross-check built on `croniter.is_valid` is worthless if that function
    returns True for everything. Pin something it must reject.
    """
    croniter = pytest.importorskip("croniter").croniter
    assert croniter.is_valid("0 2 * * NOTADAY") is False
