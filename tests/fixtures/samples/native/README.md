# `jmo-native` fixture

Placeholder-only fixture for the `jmo-native` check pack
(`scripts/core/native_checks.py`). Every value here is a placeholder
(`placeholder`, `https://example.supabase.co`) — nothing shaped like a real
provider key, so neither Defender, the `detect-private-key` pre-commit hook,
TruffleHog CI nor GitHub push protection has anything to react to.

## Expected findings (8)

| # | Rule id | File | Line |
|---|---|---|---|
| 1 | `jmo.nextjs.public-env-holds-server-secret` | `.env.example` | 4 |
| 2 | `jmo.nextjs.public-env-holds-server-secret` | `app/dashboard/chat.tsx` | 6 |
| 3 | `jmo.ai.llm-api-key-in-browser-code` | `app/dashboard/chat.tsx` | 7 |
| 4 | `jmo.supabase.service-role-key-in-client-code` | `src/lib/supabase.ts` | 6 |
| 5 | `jmo.firebase.rules-open` | `firestore.rules` | 6 |
| 6 | `jmo.supabase.table-without-rls` | `supabase/migrations/20260101000000_init.sql` | 6 |
| 7 | `jmo.supabase.rls-without-policy` | `supabase/migrations/20260101000000_init.sql` | 8 |
| 8 | `jmo.supabase.table-without-rls` | `supabase/migrations/20260101000000_init.sql` | 12 |

## Negatives (4) — must produce nothing

| File | Why it is a negative |
|---|---|
| `app/api/admin/route.ts` (line 7 names the service_role key) | It is a server-only route (path contains `/api/`), which is where the key belongs. |
| `storage.rules` (line 6) | Both read and write require `request.auth != null`; the rule is closed. |
| `src/lib/supabase.ts` (line 1) | A *comment* naming `service_role` must never itself produce a finding — only code does. |
| `supabase/migrations/20260101000000_init.sql`, table `profiles` (lines 2-4) | Row Level Security is enabled and a policy exists. |

`supabase/migrations/20260101000000_init.sql` line 11 is a SQL comment
(`-- create table notes_in_a_comment ...`) naming a table; it must not produce
a finding either. The real `notes` table it sits beside, created on line 12
with no RLS, is finding #8 above.

## Why every value is a placeholder

`placeholder` and `https://example.supabase.co` are used everywhere a real
Supabase URL, anon key, or secret value would appear, so this fixture is
tracked and public without shipping anything that resembles a real credential.
