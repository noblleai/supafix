# supafix

**Security audit for Supabase projects — one command, zero install.**

[![npm](https://img.shields.io/npm/v/supafix?color=red&label=npm)](https://www.npmjs.com/package/supafix)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node ≥18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

```
npx supafix
```

AI writes your Supabase code. It makes the same security mistakes every time. `supafix` catches them in seconds — and fixes the ones it can.

---

## Demo

```
  supafix  v0.2.0
  ─────────────────────────────────────────────
  12 migrations · 8 tables · 24 route files · 3,102 source files  (411ms)

  ✖  RLS Policies
  ─────────────────────────────────────────────

  CRITICAL  "orders" has RLS enabled but no policies
            With RLS on and no policies Postgres denies all access.
            → supabase/migrations/20240801_orders.sql
            fix: CREATE POLICY "access" ON orders USING (auth.uid() IS NOT NULL);
            ✦ auto-fixable — run npx supafix --fix

  CRITICAL  "invoices" has tenant column(s) not enforced in any RLS policy
            Column [company_id] exists but is not referenced in any policy.
            Any authenticated user can read every tenant's invoices.
            → supabase/migrations/20240715_invoices.sql:12
            fix: Add USING (company_id = (...)) to your policies.

  CRITICAL  Policy "insert_post" on "posts" uses user_metadata for RBAC
            user_metadata is writable by the user — anyone can set role:"admin".
            → supabase/migrations/20240715_posts.sql:32
            fix: Replace auth.jwt() -> 'user_metadata' with auth.jwt() -> 'app_metadata'

  ✖  Auth Misuse
  ─────────────────────────────────────────────

  CRITICAL  getSession() used for server-side auth in app/api/posts/route.ts
            getSession() reads from cookies without re-validating with Auth.
            A crafted cookie bypasses this check entirely.
            → app/api/posts/route.ts:8
            fix: Use supabase.auth.getUser() — it validates on every call.

  ✖  Secrets & Credentials
  ─────────────────────────────────────────────

  CRITICAL  Stripe secret key found in source
            → lib/stripe.ts:3
            fix: Rotate immediately. Move to process.env.STRIPE_SECRET_KEY.

  ─────────────────────────────────────────────
  4 critical  ·  1 warning

  Security grade: F  (critical)
  1 issue can be auto-fixed — run npx supafix --fix

  Add this badge to your README:
  [![supafix](https://img.shields.io/badge/supabase--guard%3A+F+%E2%80%94+4+critical-red?logo=supabase&logoColor=white)](https://github.com/noblleai/supafix)
```

---

## What it checks

### RLS Policies
Reads every SQL migration and tracks your tables through the full migration history.

| Check | Severity |
|---|---|
| Table with no RLS enabled | `warning` |
| RLS enabled but no policies (all queries denied — usually a bug) | `critical` |
| `USING (true)` — unconditionally permissive policy | `warning` |
| Policy with no `auth.uid()` / `auth.jwt()` / `auth.role()` reference | `info` |
| `SECURITY DEFINER` function missing `SET search_path` (search-path injection) | `critical` |
| `user_metadata` used for RBAC (user-controlled — anyone can self-promote to admin) | `critical` |
| `INSERT`/`UPDATE` policy with `USING` but no `WITH CHECK` | `warning` |
| Table has `SELECT` policy but no `INSERT`/`UPDATE` policies | `warning` |
| **Tenant column (`org_id`, `company_id`, `tenant_id`…) not checked in any policy** | **`critical`** |

### Auth Misuse
Catches the most common common Supabase auth bugs.

| Check | Severity |
|---|---|
| `getSession()` used as server-side auth gate (doesn't validate with Auth server) | `critical` |
| `createBrowserClient` used in a server file (silently falls back to anon role) | `critical` |
| `supabase.auth.admin` used outside of `/admin/` or `/internal/` routes | `warning` |

### API Routes
Scans Next.js App Router, Pages Router, SvelteKit, and Nuxt route files.

| Check | Severity |
|---|---|
| Exported HTTP handler with no recognisable auth pattern | `warning` |
| Template literal in Supabase query method (SQL injection) | `critical` |
| Raw `req.json()` piped directly into `.insert()` / `.upsert()` (mass assignment) | `critical` |
| `.eq('id', params.id)` without an ownership check nearby (IDOR) | `info` |

### Storage Security

| Check | Severity |
|---|---|
| `public: true` bucket in migrations or application code | `critical` |
| `storage.objects` policy with `USING (true)` or `WITH CHECK (true)` | `critical` |
| `dangerouslyAllowBrowser: true` in Supabase client (service key exposed to browser) | `warning` |
| Signed URL with expiry > 7 days | `info` |

### Secrets & Credentials
Scans source files, config files, and `.env` files.

| Pattern | Severity |
|---|---|
| Stripe, OpenAI, Anthropic, GitHub, Slack, SendGrid, Twilio keys | `critical` |
| AWS Access Key ID / Secret Access Key | `critical` |
| PostgreSQL, MySQL, MongoDB, Redis connection strings with credentials | `critical` |
| Private key blocks (`-----BEGIN ... PRIVATE KEY-----`) | `critical` |
| Firebase / Google Cloud service account JSON | `critical` |
| Hardcoded JWT tokens | `critical` |
| Supabase service role key exposed as `NEXT_PUBLIC_` | `critical` |
| `.env` file not in `.gitignore` | `critical` |

---

## Usage

```bash
# Scan current directory
npx supafix

# Scan a monorepo app
npx supafix --cwd ./apps/web

# Auto-fix what can be fixed (generates migration, updates .gitignore)
npx supafix --fix

# Print a README badge for your security grade
npx supafix --badge

# Skip a category
npx supafix --no-secrets
npx supafix --no-rls

# CI-friendly: machine-readable JSON
npx supafix --json

# Pipe to jq
npx supafix --json | jq '.findings[] | select(.severity=="critical")'
```

### Options

| Flag | Description |
|---|---|
| `--cwd <path>` | Project root to scan (default: current directory) |
| `--no-rls` | Skip RLS checks |
| `--no-routes` | Skip route auth checks |
| `--no-storage` | Skip storage security checks |
| `--no-secrets` | Skip secret scanning |
| `--no-injection` | Skip injection / mass-assignment checks |
| `--fix` | Auto-fix RLS issues and `.gitignore` gaps |
| `--badge` | Print a README badge for your security grade |
| `--json` | Output JSON instead of the terminal report |
| `--version` | Print version |
| `--help` | Show help |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no issues found |
| `1` | Issues found |
| `2` | Fatal scanner error |

---

## Auto-fix

`--fix` applies the issues it can safely resolve and lists everything else:

```
  supafix  v0.2.0  --fix mode
  ─────────────────────────────────────────────

  Auto-fixed
  ─────────────────────────────────────────────

  ✔  Created supabase/migrations/20260622120000_supabase_guard_fixes.sql
     · Enable RLS on "orders"
     · Stub policy for "products" (needs customisation)

  ✔  Updated .gitignore
     · Added ".env.local"

  Needs manual attention  (3 issues)
  ─────────────────────────────────────────────
  ✖  getSession() used for server-side auth in app/api/posts/route.ts
  ✖  Stripe secret key found in source
  ✖  Policy "insert_post" uses user_metadata for RBAC

  Run npx supafix to verify.
  ⚠  Review the generated migration before running supabase db push.
```

**What `--fix` can resolve automatically:**
- Tables missing RLS → `ALTER TABLE … ENABLE ROW LEVEL SECURITY`
- Tables with RLS but no policies → stub policy with `auth.uid() IS NOT NULL`
- `.env` files not in `.gitignore` → adds them

**What requires manual action:**
- Rotate leaked secrets (must be done at the provider)
- Replace `getSession()` with `getUser()` in code
- Fix `user_metadata` RBAC policies
- Add ownership checks to write policies

---

## Security grade & badge

Every scan ends with a security grade. Run `--badge` to get a shields.io badge for your README:

```bash
npx supafix --badge
```

```markdown
[![supafix](https://img.shields.io/badge/supabase--guard%3A+A-brightgreen?logo=supabase&logoColor=white)](https://github.com/noblleai/supafix)
```

| Grade | Criteria |
|---|---|
| **A** | No findings |
| **B** | Warnings only (≤ 2) |
| **C** | Warnings only (3+) |
| **D** | 1–2 critical issues |
| **F** | 3+ critical issues |

---

## CI integration

**GitHub Actions**

```yaml
- name: Supabase security audit
  run: npx supafix --json | tee audit.json

- name: Upload audit results
  uses: actions/upload-artifact@v4
  with:
    name: security-audit
    path: audit.json
```

**Block the build on critical issues only**

```bash
npx supafix --json \
  | jq -e '.findings | map(select(.severity=="critical")) | length == 0'
```

---

## Config file (optional)

Create `supafix.config.json` at your project root:

```json
{
  "migrationDirs": ["db/migrations", "supabase/migrations"],
  "routeDirs":     ["src/app/api"],
  "ignore":        ["**/generated/**", "supabase/migrations/seed.sql"]
}
```

The `ignore` field supports exact paths, directory prefixes, and `*` / `**` globs. All fields are optional.

---

## Why these checks matter

### `getSession()` vs `getUser()`

This is [documented by Supabase](https://supabase.com/docs/guides/auth/server-side/nextjs) as the #1 server-side auth mistake. `getSession()` reads the JWT from the cookie and trusts it without re-validating with the Auth server. A forged or replayed cookie bypasses your auth gate entirely.

`getUser()` makes a network call to the Supabase Auth server on every invocation — it is the only safe option. AI assistants generate `getSession()` constantly because it looks identical and runs faster.

```ts
// ❌ Wrong — does not validate with Auth server
const { data: { session } } = await supabase.auth.getSession()
if (!session) return new Response('Unauthorized', { status: 401 })

// ✅ Correct — validates on every call
const { data: { user }, error } = await supabase.auth.getUser()
if (!user) return new Response('Unauthorized', { status: 401 })
```

### `user_metadata` for RBAC

`user_metadata` is writable by any authenticated user via `supabase.auth.updateUser()`. An RLS policy that checks `user_metadata.role` can be bypassed by any user in your system:

```sql
-- ❌ Wrong — any user can call updateUser({ data: { role: 'admin' } })
CREATE POLICY "admin_only" ON reports
  USING (auth.jwt() -> 'user_metadata' ->> 'role' = 'admin');

-- ✅ Correct — only writable server-side via the Admin API
CREATE POLICY "admin_only" ON reports
  USING (auth.jwt() -> 'app_metadata' ->> 'role' = 'admin');
```

### Missing `WITH CHECK`

`USING` controls which rows a user can **read**. `WITH CHECK` controls which rows a user can **write**. An `INSERT`/`UPDATE` policy with only `USING` does not restrict what gets written — ownership is bypassed.

```sql
-- ❌ Wrong — user can insert rows owned by anyone
CREATE POLICY "users_insert" ON posts FOR INSERT
  USING (auth.uid() = user_id);

-- ✅ Correct
CREATE POLICY "users_insert" ON posts FOR INSERT
  WITH CHECK (auth.uid() = user_id);
```

### Tenant column not in policies

If your table has a `company_id` or `org_id` column but no RLS policy checks it, every authenticated user can query every tenant's data — regardless of which company they belong to. This is the most common critical breach in multi-tenant SaaS apps built with Supabase.

```sql
-- ❌ Only checks the user, not the tenant
CREATE POLICY "user_access" ON invoices
  USING (auth.uid() = user_id);

-- ✅ Checks both — cross-tenant access impossible
CREATE POLICY "tenant_access" ON invoices
  USING (
    company_id = (SELECT company_id FROM user_profiles WHERE id = auth.uid())
  );
```

---

## Compatibility

| Framework | RLS | Routes | Auth checks | Storage |
|---|---|---|---|---|
| Next.js App Router | ✓ | ✓ | ✓ | ✓ |
| Next.js Pages Router | ✓ | ✓ | ✓ | ✓ |
| SvelteKit | ✓ | ✓ | — | ✓ |
| Nuxt | ✓ | ✓ | — | ✓ |
| Any (SQL migrations only) | ✓ | — | — | ✓ |

Auth library support: Supabase Auth, NextAuth / Auth.js, Clerk, Lucia.

---

## Contributing

Pull requests are welcome. The scanner is intentionally low false-positive — when in doubt, flag at `info` severity so the user can verify rather than generating noise at `critical`.

**Adding a secret pattern** — open `src/secrets.ts` and add to the `PATTERNS` array:

```ts
{
  name: 'Acme API key',
  re: /acme_sk_[A-Za-z0-9]{32}/,
  severity: 'critical',
  fix: 'Rotate at acme.com/settings. Move to process.env.ACME_API_KEY.',
},
```

**Adding an RLS check** — advanced policy checks live in `src/rls-advanced.ts`. Basic existence checks are in `src/rls.ts`. SQL is parsed by `splitStatements()` which handles dollar-quoting, block comments, and line comments.

**Running tests**

```bash
npm test      # 81 tests across 8 suites
```

---

Zero runtime dependencies. 71 KB bundle.

Built by [Noblle](https://noblle.ai).
