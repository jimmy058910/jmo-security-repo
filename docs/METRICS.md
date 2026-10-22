# Adoption metrics collection

Run from a checkout with Python 3.12+, Bash, curl and an authenticated GitHub CLI:

```bash
bash scripts/dev/collect_metrics.sh
```

The Bash entry point locates `collect_metrics.py` beside itself. Outputs always
go to the checkout's gitignored `metrics/`, even when launched from another
working directory. `JMO_METRICS_PYTHON` can select the intended Python executable;
otherwise the wrapper probes `python3`, then `python`. No additional Python
runtime packages or standalone jq are required.

`--date YYYY-MM-DD` (or the legacy positional date) labels the report. It does
not request historical API data. Default dates follow the host's local timezone;
timestamps inside results are UTC. Configure the scheduler's timezone explicitly.

## Sources and failure behavior

The five sources remain GitHub repository counts, GitHub traffic, GitHub clones,
PyPI recent downloads and Docker Hub counts. Every network operation is a read.
The collector checks `gh auth status --hostname github.com` first. Missing
dependencies or unsuccessful authentication stop collection. Once preflight
passes, each source is independent: command failure, timeout, invalid JSON or
missing/invalid required counts makes that source unavailable while the others
continue. Null, booleans, negative counts and numeric strings are not real zeroes.

Commands have a 60-second process timeout; curl also has 15-second connection
and 45-second request limits. There is one attempt per source, with no collector
retry loop. Provider stdout/stderr and exception details are not echoed on error,
because they can contain configuration or credentials. Error categories identify
failure or timeout without claiming a particular cause such as missing admin
permissions. Verify that cause separately as the intended service account.

| Collection status | Exit | Meaning |
|---|---|---|
| `complete` | 0 | All five sources validated. |
| `partial` | 0 | At least one validated source and at least one gap; report both. |
| `unavailable` | 1 | Fetches were attempted, but none produced usable counts. |
| `failed` | 1 | Preflight failed; the report records the reason. |
| `running` | Never a successful result | An unfinished run; do not use it as a digest or comparison baseline. |

Invalid CLI arguments exit 2 before collection. Lock/filesystem failures exit
1 with a JSON error on stderr and no success record on stdout. A prior file is
not evidence that this invocation succeeded.

## Output contract

On a finalized run, stdout is one JSON object containing `status`, `run_id`,
`date`, `collection` and `summary`. Use these returned paths, not an independently
calculated date. Read `collection-YYYY-MM-DD.json` as the authoritative record;
its embedded sources contain status, error, validated data and optional deltas.
Match its run ID and status to stdout, then match the summary's Run ID.

The per-source filenames and successful numeric field names are retained. Each
file now includes `_collection` with its run ID, observation time, status and
error. Failed sources overwrite earlier same-day results with an unavailable
marker and no old counts. After fatal preflight, older source files can remain;
their run IDs do not match and they must not be used. Fetch/parse errors never
publish partially downloaded JSON.

Files are written through a synced temporary file and atomic replacement. A
`running` collection record invalidates previous same-day success before fetches.
The matching summary and source files are published before the final collection
record. This is a commit-marker protocol, not a multi-file filesystem transaction:
readers accept only finalized records with matching run IDs. If a later write
fails, the record stays unfinished and the command fails. The next run may
replace that date's artifacts; copy them for investigation first if needed.

A `.collect_metrics.lock` prevents overlapping collectors in the same checkout.
An abrupt termination can leave it behind. Confirm that its process is no
longer running before removing it; age alone is not enough. Preserve the
unfinished evidence, then deliberately run once. Separate checkouts need a
scheduler-level ownership decision; this lock does not coordinate them.

## Comparisons and reporting

Use the closest earlier dated structured collection. The comparison states its
date and the number of days between report labels; it is not automatically a
week-over-week change. A missing source on either side means its delta is
unavailable. Do not reach further back to fill a recent gap. An invalid,
unreadable or unfinished prior collection suppresses all deltas and is named in
the report. Legacy Markdown summaries and unmarked JSON are not parsed as
numeric baselines; the first structured run has no comparison.

Report absolute change and percentage only where both counts are usable. A zero
baseline has no percentage change. PyPI downloads and GitHub traffic/clones use
rolling windows that can overlap; their differences are not new unique users
or installations. Repository counts and Docker pulls are snapshots; clone counts
can include CI activity. Preserve these limitations in any AI-written digest.

The scheduled digest remains information-only: it reads this run's artifacts and
writes its local report. It does not commit, push, send messages or mutate GitHub.
An exit-0 partial run must still lead with unavailable sources. An all-unavailable
or failed run must be reported as such, not as "nothing notable this week."
Use the collector's deltas rather than reconstructing missing numbers from prose.

## Verification and migration

Focused offline tests use fake command responses and disposable files:

```bash
python -m pytest tests/unit/test_collect_metrics.py
```

The tests cover complete/partial/unavailable results, malformed counts, history,
stale same-day data, failed writes, locks and an abruptly terminated process.
They do not prove live service access or guest filesystem behavior. Run the
owning project's required format/lint/test checks when integrating the change.

For a scheduled job, verify the intended account's GitHub authentication, Python,
Bash/curl, timezone, output permissions and report retention. Preserve metrics
history in backup scope. Test the installed entry point, trigger and reboot
behavior; keep one active collector. Claude Code can turn the structured result
into a digest using the intended subscription authentication. Claude Desktop is
not required. No scheduler, AI authentication or delivery mechanism is installed
by this collector.
