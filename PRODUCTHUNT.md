# Product Hunt Launch — supaguard

## Tagline (60 chars max)
Security audit for Supabase projects. One command.

## Description

**Hi Product Hunt 👋**

We built supaguard because we kept seeing the same security holes in every Supabase project — and AI was writing most of them.

Run this in any Supabase project:

```
npx supaguard
```

No install. No config. Scans your migrations, API routes, source files, and Edge Functions in under a second.

---

**The problem**

AI assistants generate working Supabase code fast. They also make the same security mistakes, consistently:

- `getSession()` for server-side auth gates (doesn't validate with Auth server — a forged cookie bypasses it)
- `user_metadata` for RBAC (user-writable — anyone can set their own role to "admin")
- `INSERT` policies with `USING` but no `WITH CHECK` (writes bypass ownership checks)
- `company_id` in the schema but not in any RLS policy (every tenant can read every other tenant's data)
- Service role keys committed to source
- `.env` files not in `.gitignore`

These aren't hypothetical — they're the patterns we see in production.

---

**What it checks**

- **RLS policies** — reads your full migration history, tracks tables through DROP/CREATE cycles, catches missing RLS, permissive policies, SECURITY DEFINER search-path injection, missing WITH CHECK, and tenant column gaps
- **Auth misuse** — getSession() as auth gate, createBrowserClient in server files, auth.admin in regular routes
- **API routes** — unprotected handlers, template literal SQL injection, mass assignment, IDOR
- **Storage** — public buckets, permissive storage.objects policies, dangerouslyAllowBrowser, long-lived signed URLs
- **Edge Functions** — Supabase client created without auth forwarding, wildcard CORS with authenticated operations
- **Secrets** — 20+ credential patterns across Stripe, OpenAI, AWS, GitHub, and more

---

**It doesn't just report — it fixes**

```
npx supaguard --fix
```

Generates a migration file with `ALTER TABLE … ENABLE ROW LEVEL SECURITY` and stub policies. Updates `.gitignore`. Then tells you what it couldn't auto-fix and why.

---

**It grades your project**

Every scan ends with a security grade (A–F) and a README badge:

```
npx supaguard --badge
```

```
[![supaguard: A](https://img.shields.io/badge/supabase--guard%3A+A-brightgreen?logo=supabase)]
```

---

**CI-ready**

```yaml
- uses: noblleai/supaguard@v1
  with:
    fail-on: critical
```

Outputs the grade, critical count, and a JSON results file as action outputs.

---

**Zero dependencies. 71 KB bundle. MIT.**

We open-sourced it because the Supabase community deserves a security tool as good as the platform.

Would love your feedback — especially if you find a common pattern we're missing.

— Team Noblle

---

## First comment (to post immediately after launch)

Hey everyone! We're the team at [Noblle](https://noblle.ai).

We built supaguard after noticing the same security patterns showing up across projects — almost always AI-generated code that looks correct but has subtle holes.

The one that surprises people most: `getSession()` vs `getUser()` for server-side auth. They look identical, run the same way, but `getSession()` never validates the JWT with the Auth server. A crafted cookie passes right through. Supabase's own docs flag this as the #1 mistake — and every AI assistant generates it.

**What we'd love help with:**
- Are there Supabase security patterns we're missing?
- Would a VS Code extension (inline squiggles on migrations) be useful?
- What would make you keep this in CI vs run it once and forget it?

The codebase is on GitHub — PRs welcome, especially for new secret patterns or framework-specific checks.

---

## Gallery images needed

1. Terminal screenshot: running `npx supaguard` on a project with findings
2. Terminal screenshot: `npx supaguard --fix` output
3. Grade badge examples (A through F)
4. GitHub Actions integration screenshot

---

## Topics / tags
supabase, security, devtools, open-source, postgres, nextjs, rls, database
