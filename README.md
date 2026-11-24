# rls-check

**A free, offline checker for the most common security holes in Supabase apps built with Lovable, Bolt, Replit or Cursor.**

AI app builders get you most of the way to a working app. But many of these apps go live with the same few holes, and you can't see them in the app itself. This script finds them in your project folder and explains each one in plain English, with the fix.

- **Runs on your machine.** Nothing is uploaded, there's no login, and it makes no network calls.
- **Zero dependencies.** You only need Node.js 18 or newer.
- **It is not a full security review.** It catches the common mistakes, not everything.

## Use it in your browser (no install)

Open **https://alasan-art.github.io/rls-check/**, then drag in your project folder (or click *See an example*). The page runs entirely in your browser: its security policy blocks all network requests, so your files can't leave your computer.

## Quick start (command line)

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
rls-check v0.2.0 — 2 SQL files, 3 code/env files, 1 config files, 4 tables

[HIGH] RLS_OFF  invoices  (supabase/migrations/20260101_init.sql)
  Table "invoices" has row-level security OFF. Anyone with the public anon key can read and change every row.

[HIGH] OPEN_WRITE_POLICY  notes / Anyone can do anything  (supabase/migrations/20260101_init.sql)
  Policy "Anyone can do anything" on "notes" lets anyone read and change every row (condition is "true"). Tie it to auth.uid().
```

## What it checks

| Code | Level | Problem |
|---|---|---|
| `RLS_OFF` | HIGH | A table created in your migrations that never gets row-level security turned on (tables revoked from `anon`/`authenticated`, or enabled in an `EXECUTE format(...)` loop, are recognised) |
| `OPEN_WRITE_POLICY` | HIGH | An update/delete/all policy whose condition is just `true` |
| `OPEN_INSERT_POLICY` | MEDIUM | An insert policy with `with check (true)`: fine for a contact form, not for user-owned data |
| `VIEW_BYPASSES_RLS` | HIGH | A view without `security_invoker = true`, so it skips RLS |
| `SERVICE_KEY_EXPOSED` | HIGH | A `service_role` key in your code or `.env` files |
| `SERVICE_KEY_PUBLIC_ENV` | HIGH | The service-role key in a browser variable (`VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, `EXPO_PUBLIC_`, `PUBLIC_`) |
| `STRIPE_SECRET_EXPOSED` | HIGH | A live Stripe secret key (`sk_live_…`) in your code |
| `STRIPE_WEBHOOK_UNVERIFIED` | HIGH | A Stripe webhook handler that never verifies the signature, so anyone can fake a "paid" event |
| `SECRET_IN_PUBLIC_ENV` | HIGH | A paid API key (OpenAI, Anthropic, Gemini, Groq, Resend, SendGrid, Twilio, …) in a browser variable such as `VITE_OPENAI_API_KEY`: anyone can copy it and run up your bill |
| `AI_KEY_IN_BROWSER_CODE` | HIGH | An OpenAI / Anthropic / Groq / Replicate / xAI / Perplexity / SendGrid / Resend key written into front-end code |
| `AI_KEY_HARDCODED` | MEDIUM | The same kind of key written into server code (safer, but still saved in your repo) |
| `FUNCTION_NO_AUTH` | HIGH/MEDIUM | A Supabase Edge Function with `verify_jwt = false` and no visible caller check (user login, secret header, or a `_shared` auth helper). HIGH when it calls paid AI/email/SMS APIs, otherwise MEDIUM. Webhooks are excluded |
| `STORAGE_OPEN_WRITE` | HIGH/MEDIUM | A storage policy that lets people upload, overwrite or delete files without an owner check (HIGH if logged-out visitors can) |
| `STORAGE_BUCKET_PUBLIC` | MEDIUM | A public storage bucket: every file is viewable by link, which is bad for IDs, invoices and user uploads |
| `STORAGE_OPEN_READ` | LOW | A storage policy that lets logged-out visitors list and download files |
| `OPEN_READ_POLICY` | MEDIUM/LOW | A select policy whose condition is `true`, so every row is readable |
| `ANY_USER_POLICY` | MEDIUM | A policy that only checks "is logged in" (`auth.role() = 'authenticated'` or `auth.uid() is not null`), so every user sees every other user's rows |
| `DEFINER_NO_SEARCH_PATH` | MEDIUM | A `SECURITY DEFINER` function without a fixed `search_path` |
| `RLS_NO_POLICIES` | INFO | RLS is on and no policy lets app users in: safe for server-only tables, or the classic "my data disappeared" bug |
| `EMAIL_CONFIRM_OFF` | INFO | Email confirmation is off in `supabase/config.toml`; check it's on in your live project |

The checker reads `*.sql`, JS/TS/Vue/Svelte/Astro files, `.env*` files (but skips `.env.example`) and `supabase/config.toml`. It also skips `node_modules`, `dist`, `build`, `.next` and `.git`.

## If it finds something

- **An exposed key** (Supabase, Stripe, OpenAI, …): rotate it first. Changing the code is not enough, because the old key is already out. In Supabase go to Project Settings → API; in Stripe go to Developers → API keys.
- **RLS problems:** write policies that compare the row's owner column with `auth.uid()`. The [Supabase RLS guide](https://supabase.com/docs/guides/database/postgres/row-level-security) explains how.

## How accurate is it?

We tested v0.2 on 30 public open-source Supabase projects built with AI tools (about 2,300 tables). The first draft raised 836 HIGH warnings. After fixing every false-alarm pattern we found (service-role-only policies, policies inside `DO` blocks, views and functions fixed in later migrations, tables enabled in loops, secret-header and shared-helper auth in Edge Functions), it raises 192, and every one we hand-checked was real. Results are kept private, and no project was contacted or named.

## Known limits

- The SQL is read with pattern matching, not a full parser, so unusual SQL may be missed. The checker follows the final state across migrations (drops, renames, later fixes).
- It can't know whether something is *meant* to be public (a booking form, a public catalogue). MEDIUM and LOW warnings are things to look at, not proven bugs.
- It checks files only. Changes made in the Supabase dashboard are invisible unless you export a dump.
- Auth settings are only read from `supabase/config.toml`, which often differs from your live project's dashboard settings.
- "Browser code" vs "server code" is guessed from folder names (`supabase/functions`, `api`, `server`, …).

## Development

The checks live in `core.mjs`, which has no file-system or network code. `rls-check.mjs` (command line) and `index.html` + `page.mjs` (browser page) are thin front ends around it.

```bash
npm test
```

The demo apps in `fixtures/` are invented. The tests generate fake keys at runtime, so the repo contains no key-like strings.

Found a false alarm or a missed case? Please open an issue with a minimal SQL example.

## License

MIT
