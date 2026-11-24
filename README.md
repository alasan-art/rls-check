# rls-check

**A free, offline checker for the most common security holes in Supabase apps built with Lovable, Bolt, Replit or Cursor.**

AI app builders get you most of the way to a working app. But many of these apps go live with the same few holes, and you can't see them in the app itself. This script finds them in your project folder and explains each one in plain English, with the fix.

- **Runs on your machine.** Nothing is uploaded, there's no login, and it makes no network calls.
- **Zero dependencies.** You only need Node.js 18 or newer.
- **It is not a full security review.** It catches the common mistakes, not everything.

## Quick start

```bash
git clone https://github.com/alasan-art/rls-check.git
node rls-check/rls-check.mjs ./your-project
```

For the database part, the checker needs your SQL. Most Lovable/Supabase projects already have `supabase/migrations/*.sql`. If yours doesn't, export the schema into the project folder:

```bash
supabase db dump --schema public > your-project/schema.sql
```

Other options:

```bash
node rls-check.mjs ./your-project --json   # machine-readable output
```

The exit code is `1` if anything HIGH is found, so you can use it in CI.

## Example output

```
rls-check v0.1.0 — 1 SQL files, 2 code/env files, 4 tables

[HIGH] RLS_OFF  invoices  (supabase/migrations/20260101_init.sql)
  Table "invoices" has row-level security OFF. Anyone with the public anon key can read and change every row.

[HIGH] OPEN_WRITE_POLICY  notes / Anyone can do anything  (supabase/migrations/20260101_init.sql)
  Policy "Anyone can do anything" on "notes" lets anyone read and change every row (condition is "true"). Tie it to auth.uid().
```

## What it checks

| Code | Level | Problem |
|---|---|---|
| `RLS_OFF` | HIGH | A public table without row-level security, so anyone can read and write it |
| `OPEN_WRITE_POLICY` | HIGH | An insert/update/delete/all policy whose condition is just `true` |
| `VIEW_BYPASSES_RLS` | HIGH | A view without `security_invoker = true`, so it skips RLS |
| `SERVICE_KEY_EXPOSED` | HIGH | A `service_role` key in your code or `.env` files |
| `SERVICE_KEY_PUBLIC_ENV` | HIGH | The service-role key in a browser variable (`VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, `EXPO_PUBLIC_`, `PUBLIC_`) |
| `STRIPE_SECRET_EXPOSED` | HIGH | A live Stripe secret key (`sk_live_…`) in your code |
| `STRIPE_WEBHOOK_UNVERIFIED` | HIGH | A Stripe webhook handler that never verifies the signature, so anyone can fake a "paid" event |
| `OPEN_READ_POLICY` | MEDIUM/LOW | A select policy whose condition is `true`, so every row is readable |
| `ANY_USER_POLICY` | MEDIUM | A policy that only checks `auth.role() = 'authenticated'`, so every user sees every other user's rows |
| `DEFINER_NO_SEARCH_PATH` | MEDIUM | A `SECURITY DEFINER` function without a fixed `search_path` |
| `RLS_NO_POLICIES` | INFO | RLS is on but there are no policies, the classic "my data disappeared" bug |

The checker reads `*.sql`, JS/TS/Vue/Svelte/Astro files and `.env*` files, but skips `.env.example`. It also skips `node_modules`, `dist`, `build`, `.next` and `.git`.

## If it finds something

- **An exposed key:** rotate it first. Changing the code is not enough, because the old key is already out. In Supabase go to Project Settings → API; in Stripe go to Developers → API keys.
- **RLS problems:** write policies that compare the row's owner column with `auth.uid()`. The [Supabase RLS guide](https://supabase.com/docs/guides/database/postgres/row-level-security) explains how.

## Known limits

- The SQL is read with pattern matching, not a full parser, so unusual SQL may be missed.
- It checks files only. Changes made in the Supabase dashboard are invisible unless you export a dump.
- Storage bucket policies and auth settings are not checked yet.

## Development

```bash
npm test
```

The demo apps in `fixtures/` are invented. The tests generate fake keys at runtime, so the repo contains no key-like strings.

Found a false alarm or a missed case? Please open an issue with a minimal SQL example.

## License

MIT
