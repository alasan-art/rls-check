# We checked 30 public Supabase apps built with AI tools. 21 had at least one high-risk hole.

In November 2026, researchers reported that more than 24,000 apps built with Lovable had a Supabase database that answered without a login ([Techzine](https://www.techzine.eu/news/security/145550/thousands-of-lovable-apps-are-leaking-personal-data/)). We wanted to know what the problems actually look like in the code. So we took 30 public GitHub projects built with AI app builders that use Supabase, 2,328 database tables in total, and read their migration files and server functions with [rls-check](https://alasan-art.github.io/rls-check/), a free checker that runs entirely in your browser.

We only read code that was already public. We ran nothing, attacked nothing and contacted nobody, and no project is named here.

## The numbers

- **21 of 30 projects (70%) have at least one high-risk problem.**
- **7 of 30 have a secret key in their public code**: the Supabase master key (service role), a live Stripe secret key, or an AI provider key.
- 192 high-risk findings in total, and every one we checked by hand was real.

| What we found | Findings | Projects |
|---|---|---|
| Table rule "everyone can change everything" (`using (true)` on business tables) | 71 | 9 of 30 |
| Server function anyone can call that spends money (AI, email, SMS) | 32 | 8 |
| Table with no row-level security at all | 28 | 6 |
| Upload bucket where strangers can upload or overwrite files | 18 | 5 |
| View that skips the table rules | 16 | 7 |
| Supabase service-role key in the code | 13 | 5 |
| Stripe webhook that doesn't check the signature | 7 | 3 |
| AI key in website code or a browser variable | 5 | 3 |
| Live Stripe secret key in the code | 2 | 2 |

The medium-risk findings were often more common. The biggest was **"only checks if someone is logged in"** (39 findings in 8 projects): a rule like `auth.uid() is not null` looks safe, but it lets every user read every other user's data.

## Five patterns that kept coming back

**1. `using (true)` is "everyone", not "the owner".**
AI builders often write it to make an error go away. On a table with orders, profiles or invoices, it means anyone with your public key can read or change all of them.
Fix: compare against the owner, for example `using (auth.uid() = user_id)`.

**2. "Logged in" is not "allowed".**
`auth.uid() is not null` only proves that *someone* signed in. Sign-up is usually open, so that's anyone.
Fix: the same owner check as above, or a role or team check.

**3. Server functions that spend your money with no login check.**
An edge function that calls OpenAI, sends email or sends SMS, without checking who is calling, can be run by anyone in a loop, and you pay for it.
Fix: check the user's token at the top, or require a secret header for server-to-server calls.

**4. Views quietly bypass row-level security.**
A Postgres view runs with its creator's rights by default, so a view over a protected table can show everything.
Fix: `alter view my_view set (security_invoker = on);`

**5. Keys that should never leave the server.**
The service-role key ignores every rule, and a live Stripe secret key can move money. Both turned up in public code.
Fix: rotate the key now (deleting it from the code isn't enough, because it stays in git history), then keep it in server-side secrets only.

## What this can't tell you

- We only read **files**. Anything switched on in the Supabase dashboard is invisible to us, so a few "no row-level security" findings may already be fixed there.
- Some open functions and tables are **public on purpose** (contact forms, booking forms). rls-check marks those as medium and says "check this is meant to be public".
- 30 projects is a small sample of public repositories. Private apps may look better or worse.
- Getting here took work. Our first version raised 836 high-risk warnings, and after fixing nine kinds of false alarm we were down to 192. The details are in the [README](../README.md#how-accurate-is-it).

## Check your own project

[rls-check](https://alasan-art.github.io/rls-check/) is free and open source. Drag in your project folder: it runs in your browser, sends nothing anywhere and needs no sign-up. There's also an example project, so you can see what a result looks like first.
