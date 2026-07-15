# Telemetry: Retire the Dead Gist Pipeline (A) + Serverless Replacement Design (B)

**Date:** 2026-07-04
**Status:** Part A — approved for execution (pending change-set sign-off). Part B — design only, NOT to be built now.
**Author:** metrics-digest follow-up (triggered by the weekly digest surfacing 226-day-stale telemetry)
**Related:** `.claude/routines/jmo-security-metrics-digest/`, `scripts/dev/collect_metrics.sh`, `scripts/core/telemetry.py`

---

## 0. Background — why we're here (root cause)

The weekly metrics digest reported a frozen telemetry total of **745 events**, newest **2025-11-19 (226 days stale)**, every event from a pre-release `0.7.0-dev`/`0.7.1` build. Investigation showed this is **not stale data — it's a pipeline that was never able to collect real-world data**:

- The client (`scripts/core/telemetry.py`) sends events by **`PATCH`ing a GitHub Gist** (`fc897ef9…`) owned by the maintainer.
- GitHub only permits the **gist owner** to PATCH a gist. A PyPI/Docker user cannot contribute an event — they'd need a token that owns the maintainer's gist.
- Two hard gates in `send_event` (`if not TELEMETRY_ENDPOINT or not _get_github_token(): return`) mean any real user silently no-ops. Only the maintainer's own machine, with `JMO_TELEMETRY_GIST_ID` + `JMO_TELEMETRY_GITHUB_TOKEN` (a `gist:write` PAT) set, ever wrote events.
- The design's own guide already lives in `dev-only/archive/` — the subsystem was effectively abandoned.

**Secondary integrity gap:** `show_telemetry_banner()` and `prompt_telemetry_opt_in()` tell users "JMo Security collects anonymous usage data → jmotools.com/privacy," but nothing is ever collected. The shipped tool advertises a capability it does not have.

**Decision (owner):** Do **A** completely now (retire honestly, zero new infra). Keep the five *working* external adoption sources (PyPI, Docker Hub, GitHub repo/traffic/clones). Write **B** (serverless replacement) as a spec, to build only if deep in-tool analytics later justifies the maintenance surface.

---

## Part A — Retire the telemetry pipeline

### A.1 Goals / non-goals

**Goals**
- Remove the dead gist-PATCH client and the misleading first-run banner / opt-in prompt from the shipped tool.
- Make the metrics collector run cleanly on the host (no standalone `jq`) and stop presenting telemetry as a live source.
- Keep the tool's behavior otherwise identical; keep test coverage ≥85%.

**Non-goals**
- No replacement telemetry backend (that's Part B).
- No change to the five working external metric sources.

### A.2 Change-set (by area)

Every telemetry function's only real consumers are telemetry itself, so removal is clean. `detect_ci_environment()` is used solely to populate the `scan.started` payload (attestation has its own private copy), so it goes too.

#### Code — delete whole modules

| File | Action |
|---|---|
| `scripts/core/telemetry.py` | **Delete.** Client, banner, `bucket_*`, `detect_ci_environment`, `is_telemetry_enabled`, anon-id/scan-count files. (Verify no non-telemetry consumer of `bucket_*` during impl — expected none.) |
| `scripts/cli/wizard_flows/telemetry_helper.py` | **Delete.** `prompt_telemetry_opt_in`, `save_telemetry_preference`, `send_wizard_telemetry`. |
| `scripts/dev/view_telemetry.sh` | **Delete.** Dev-only gist viewer. |

#### Code — edit call sites

| File | Lines (approx) | Action |
|---|---|---|
| `scripts/cli/jmo.py` | 31–37 import; 2779–2796 banner; 2870–2912 `scan.started` (incl. `detect_ci_environment()` at 2912); 3149–3154 `scan.completed` | Remove telemetry import + both `send_event` calls + banner block + start-time tracking used only for telemetry. |
| `scripts/cli/report_orchestrator.py` | 32–35 import; 271–293 `send_policy_evaluation_event`; 389–404 `report.generated` | Remove import + both event sends. Keep policy-eval timing only if used elsewhere (it isn't → remove). |
| `scripts/cli/wizard.py` | 53–54 import; 747–749 `JMO_TELEMETRY_SHOWN`; 871–887 banner; 1016/1037/1048/1167 `send_wizard_telemetry`; any `prompt_telemetry_opt_in`/`save_telemetry_preference` calls | Remove all telemetry imports/calls + banner dedup env. |
| `scripts/cli/wizard_generators.py` | 564, 641 | Remove generated `JMO_TELEMETRY_DISABLE=1` lines from emitted docker-compose/config templates. |

#### Config

| File | Action |
|---|---|
| `jmo.yml` | Remove the `telemetry:` block (≈L210–211). |

#### Tests (hold coverage ≥85%)

| File | Action |
|---|---|
| `tests/core/test_telemetry.py` | **Delete** (module gone). |
| `tests/unit/test_wizard_repo_telemetry.py` | **Delete** unless it also asserts non-telemetry wizard behavior (then trim). |
| `tests/unit/test_wizard_generators.py` | Remove `JMO_TELEMETRY_DISABLE` assertions. |
| `tests/cli/test_wizard_automation.py` | Remove telemetry mocks/assertions. |
| `tests/cli/test_report_orchestrator.py` | Remove telemetry mocks/assertions. |

#### Docs (user-facing)

| File | Action |
|---|---|
| `docs/TELEMETRY.md` (1123 lines) | Replace with a short stub: "Telemetry was removed in v1.0.x. JMo Security no longer collects usage data." (Avoids 404s from external links; states the privacy improvement.) |
| `docs/index.md`, `docs/FAQ.md`, `docs/USER_GUIDE.md`, `docs/brand/IDENTITY.md`, `DOCKER_HUB_README.md`, `docs/HISTORY_GUIDE.md`, `docs/examples/wizard-examples.md` | Remove telemetry banner / opt-out mentions and links. |
| `CHANGELOG.md` | Add a **Removed** entry: dead gist telemetry + banner; note privacy improvement. |

#### Collector + digest (fixes #1 jq-independence and #2 source-honesty)

| File | Action |
|---|---|
| `scripts/dev/collect_metrics.sh` | (a) Drop `jq` from `check_deps`; port the two `curl \| jq` blocks (PyPI summary print, Docker Hub) and all `generate_summary` `jq -r` extractions to `python -c` / `gh --jq`. (b) Remove `collect_telemetry` + its call + the telemetry section of `generate_summary`. |
| `.claude/routines/jmo-security-metrics-digest/SPEC.md` | Remove telemetry from "Context to load", Steps, and the output schema; digest now reports **five** sources. (Gitignored — local only.) |

### A.3 Out of scope (flag to owner — not in this repo)

- **`jmotools.com/privacy`** — lives on the Cloudflare-hosted site, not this repo. Must be updated to remove telemetry claims. **Owner action.**
- `.claude/skills/community-manager/references/memory-integration.md` and `dev-only/archive/*TELEMETRY*` — gitignored/archived; optional local cleanup.

### A.4 Test / verification strategy

- TDD-lean: delete telemetry tests first, adjust the shared tests, then remove code, iterating until green.
- `make fmt && make lint && make test` must pass; coverage stays ≥85% (removing tested-but-dead code lowers the denominator too — monitor).
- Grep-guard: after removal, `grep -ri "telemetry\|send_event\|JMO_TELEMETRY" scripts/ tests/ jmo.yml` returns only intentional remnants (e.g., CHANGELOG).
- Smoke: `jmo scan --help`, `jmo wizard` (non-interactive test path), `jmo report` run without import errors.

### A.5 Risk / reversibility

- Fully reversible via git; no data loss (the 745 gist events remain in the gist as an archived artifact, just no longer read).
- Main risk is a missed caller causing an ImportError — mitigated by the grep-guard + full test run + CLI smoke.

---

## Part B — Serverless telemetry (design only; build later if justified)

### B.1 Goal / non-goals

- **Goal:** if in-tool usage analytics (which scanners run, scan duration buckets, CLI/Docker/wizard mode, platform, version) becomes worth owning, collect it **honestly** on infrastructure the maintainer controls — at $0 hosting cost and minimal maintenance.
- **Non-goals:** PII, repo/path/finding data, IP storage, per-user tracking. Same privacy floor as today's (bucketed, anonymous) schema.

### B.2 Platform choice — **Cloudflare Workers + D1**

jmotools.com is **already entirely on Cloudflare** (apex + blog on CF, NS = `irma/pedro.ns.cloudflare.com`, blog on CF Pages; **no Vercel signals**). So a Worker adds **no new vendor**.

| | Cloudflare Workers | Vercel Hobby |
|---|---|---|
| Free tier | 100k req/day | 1M inv/month |
| Commercial-use clause | none | **prohibits commercial/branded use** (risk for jmotools.com) |
| Already in stack | **yes** | no |

→ **Cloudflare Workers.** Store events in **D1** (SQLite), not KV: KV free-tier write caps (~1k/day) and key-value shape are wrong for group-by aggregates; D1 is SQL with a far higher write allowance. *(Verify current free limits at build time.)*

### B.3 Architecture & data flow

```text
 jmo client (user machine)
    │  POST https://telemetry.jmotools.com/e   (anonymous bucketed JSON; NO token)
    ▼
 Cloudflare Worker  [ingest]
    │  validate schema+size, event-type allowlist, rate-limit; DISCARD client IP
    ▼
 Cloudflare D1 (SQLite)  ──  events table
    ▲
    │  GET https://telemetry.jmotools.com/stats?window=7d   (Bearer STATS_READ_TOKEN)
 Cloudflare Worker  [aggregate]
    ▲
    │
 collect_metrics.sh / weekly digest   (STATS_READ_TOKEN in env)
```

### B.4 Endpoints

- **`POST /e` (public write, no secret).** Body = existing bucketed event schema. Worker rejects: body > ~2 KB, unknown `event` (allowlist: `scan.started/completed`, `report.generated`, `wizard.completed`, `policy.evaluated`), malformed fields. Insert one D1 row; return `204`. A static non-secret header `X-JMo-Client: 1` trims trivial spam (not a credential).
- **`GET /stats` (read, Bearer `STATS_READ_TOKEN` CF secret).** Returns aggregates the digest needs: total events, counts by `event`, by `version`, last-7d / last-30d, and distinct `anonymous_id` (≈ active installs). Replaces `gh gist view` in the collector.

### B.5 Storage schema (D1)

```sql
CREATE TABLE events (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at  TEXT NOT NULL,   -- server ISO8601 (authoritative clock)
  event        TEXT NOT NULL,
  version      TEXT,
  platform     TEXT,
  python_version TEXT,
  anonymous_id TEXT,
  metadata     TEXT             -- JSON of bucketed fields
  -- NOTE: no ip column, by design
);
CREATE INDEX idx_events_received ON events(received_at);
CREATE INDEX idx_events_event    ON events(event);
```
Retention: a scheduled Worker cron purges rows older than ~400 days.

### B.6 Privacy model (the honest version)

- Client payload is **unchanged** from today's schema — already anonymous + bucketed (random UUID, no repo/path/finding/PII).
- Worker **must not persist `CF-Connecting-IP`**. Recommendation: store **nothing** location-derived initially (not even `CF-IPCountry`); revisit only if a real need appears. This makes "we don't collect IP addresses" **true for the first time**.
- The first-run notice becomes truthful (collection actually happens), so the banner can return — honestly.

### B.7 Client changes (when built)

- Replace `_send_event_async`'s gist PATCH with a single `POST /e` (`urllib`, 2 s timeout, fire-and-forget, silent-fail — same non-blocking guarantees).
- Drop `JMO_TELEMETRY_GIST_ID` / `JMO_TELEMETRY_GITHUB_TOKEN`. Endpoint is a constant; allow `JMO_TELEMETRY_ENDPOINT` override for tests.
- Keep opt-out (`JMO_TELEMETRY_DISABLE`, `telemetry.enabled: false`) and CI auto-disable.

### B.8 Decision needed — opt-in vs opt-out

Today's code contradicts itself (default-on `is_telemetry_enabled` vs a y/N-default-No wizard prompt). B must pick one:
- **Recommended: opt-out with an honest, one-time first-run banner.** Data is fully anonymous + bucketed; opt-out is normal for this class and yields usable volume. Reconcile the wizard to match (drop the conflicting opt-in prompt).
- Alternative: opt-in (stronger privacy posture, much lower volume — likely too sparse to be useful at current adoption).

### B.9 Abuse / integrity

- CF WAF rate-limit rule on `/e` (e.g., N/min/IP — IP used transiently for limiting, never stored).
- Body-size cap + schema/event allowlist in the Worker.
- Public-write means counts are **approximate** (spoofable); acceptable for product-direction signal, not billing.

### B.10 Cost & the real trade

- **Hosting: $0** at current and realistic near-term scale (far under CF free tiers).
- **Standing cost is maintenance, not money:** a Worker + D1 + secret + deploy pipeline + schema versioning + a privacy page kept truthful, owned for years. This — not the invoice — is what the solo-dev longevity bias weighs. Build only if the "which scanners do people run" question is worth that.

### B.11 Rollout (when built)

1. `telemetry-worker` (Wrangler + D1), deploy to `telemetry.jmotools.com`; add `STATS_READ_TOKEN` secret.
2. Update jmo client → `POST /e` (ships in a minor release).
3. Update `collect_metrics.sh` / digest → read `/stats`.
4. Update `jmotools.com/privacy` + re-add honest docs.
5. No backfill — fresh start; historical gist archived.

### B.12 Open questions

- Opt-in vs opt-out (recommend opt-out honest).
- Store coarse country or nothing (recommend nothing initially).
- Worker home: new repo vs existing jmotools infra.
- Subdomain: `telemetry.jmotools.com` vs `api.jmotools.com/telemetry`.

---

## Execution order (A)

1. Collector + digest SPEC (`collect_metrics.sh` jq-independence + drop telemetry) — self-contained, unblocks the routine immediately.
2. Delete telemetry modules + edit call sites; iterate tests to green.
3. Config + docs + CHANGELOG.
4. `make fmt && make lint && make test`; grep-guard; CLI smoke.
5. Open PR to `main` (per project PR-direct-to-main policy).
