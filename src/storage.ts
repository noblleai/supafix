/**
 * Supabase Storage security scanner.
 *
 * Checks:
 *  1. Public storage buckets in SQL migrations
 *     → INSERT INTO storage.buckets (..., public, ...) VALUES (..., true, ...)
 *     → UPDATE storage.buckets SET public = true
 *     Any authenticated — or even unauthenticated — user can download every
 *     file in a public bucket. No RLS policy can restrict public bucket access.
 *
 *  2. Public storage buckets created in application code
 *     → supabase.storage.createBucket('x', { public: true })
 *     → supabase.storage.updateBucket('x', { public: true })
 *     Same risk as above, just created at runtime instead of migration time.
 *
 *  3. Permissive policies on storage.objects
 *     → CREATE POLICY ... ON storage.objects ... USING (true)
 *     → CREATE POLICY ... ON storage.objects ... WITH CHECK (true)
 *     For private buckets, these make ALL objects world-accessible or
 *     allow anyone to upload/overwrite files.
 *
 *  4. dangerouslyAllowBrowser: true in Supabase client creation
 *     → createClient(url, SERVICE_ROLE_KEY, { auth: { dangerouslyAllowBrowser: true } })
 *     This flag exists to suppress the library's own warning that you are
 *     about to use a service-role key in a browser context. Legitimate use
 *     is rare. Most of the time this is an AI shortcut to silence a warning
 *     without fixing the underlying problem (service role key exposed to browser).
 *
 *  5. Signed URLs with very long expiry
 *     → createSignedUrl('path', 999999999)
 *     Links shared for years cannot be revoked if the underlying file is deleted.
 *     Supabase signed URLs embed the bucket/path, so a long-lived URL for a
 *     "deleted" file may still resolve if the file is re-uploaded to the same path.
 */

import fs from 'fs';
import path from 'path';
import { walk, findDirs } from './walk.js';
import { splitStatements } from './rls.js';
import type { Finding } from './types.js';

const MIGRATION_DIRS = [
  'supabase/migrations', 'migrations', 'db/migrations',
  'database/migrations', 'prisma/migrations', 'drizzle',
];

const SOURCE_DIRS = [
  'app', 'src', 'components', 'lib', 'utils', 'server', 'api',
  'apps/web/app', 'apps/web/lib', 'apps/web/src',
];

// 7 days in seconds — anything over this is flagged as long-lived
const LONG_EXPIRY_THRESHOLD = 60 * 60 * 24 * 7;

export function scanStorage(
  root: string,
): { findings: Finding[] } {
  const findings: Finding[] = [];

  // ── SQL migrations ──────────────────────────────────────────────────────
  const migDirs = findDirs(root, MIGRATION_DIRS);
  const sqlFiles = migDirs.flatMap(d => walk(d, ['.sql'])).sort();

  for (const file of sqlFiles) {
    let sql: string;
    try { sql = fs.readFileSync(file, 'utf-8'); } catch { continue; }

    const rel = path.relative(root, file);
    const stmts = splitStatements(sql);

    for (const { stmt, line } of stmts) {
      const up = stmt.replace(/\s+/g, ' ');

      // 1. Public bucket via INSERT
      const insertBucket = detectPublicBucketInsert(up);
      if (insertBucket !== null) {
        findings.push({
          severity: 'critical',
          category: 'storage',
          title: `Storage bucket "${insertBucket}" created as public`,
          detail:
            'Public buckets bypass ALL RLS policies — every file is downloadable by anyone with the bucket URL, with no authentication required. Use private buckets and signed URLs or Supabase Storage policies.',
          file: rel,
          line,
          fix: `Change public: false (or omit the column) and create an authenticated download policy:\n  CREATE POLICY "auth download" ON storage.objects FOR SELECT USING (auth.uid() IS NOT NULL);`,
        });
      }

      // 1b. Public bucket via UPDATE
      if (/UPDATE\s+storage\.buckets/i.test(up) && /SET[^;]*\bpublic\s*=\s*true\b/i.test(up)) {
        const where = up.match(/WHERE\s+(?:id|name)\s*=\s*'([^']+)'/i);
        const name = where ? where[1] : 'unknown';
        findings.push({
          severity: 'critical',
          category: 'storage',
          title: `Storage bucket "${name}" updated to public`,
          detail:
            'Public buckets are world-readable — no authentication required. This UPDATE makes ALL existing and future files in the bucket accessible without any credentials.',
          file: rel,
          line,
          fix: `Use UPDATE storage.buckets SET public = false WHERE id = '${name}'; and control access via storage policies.`,
        });
      }

      // 3. Permissive storage.objects policies
      if (/ON\s+storage\.objects/i.test(up) && /USING\s*\(\s*true\s*\)/i.test(up)) {
        findings.push({
          severity: 'critical',
          category: 'storage',
          title: `storage.objects policy allows unrestricted access`,
          detail:
            'A storage policy with USING (true) grants every request — authenticated or anonymous — read access to all files. This is equivalent to making the bucket public.',
          file: rel,
          line,
          fix: `Restrict the policy: USING (auth.uid() IS NOT NULL) for authenticated access, or USING (auth.uid() = owner) for owner-only.`,
        });
      }

      if (/ON\s+storage\.objects/i.test(up) && /WITH\s+CHECK\s*\(\s*true\s*\)/i.test(up)) {
        findings.push({
          severity: 'critical',
          category: 'storage',
          title: `storage.objects policy allows unrestricted uploads`,
          detail:
            'WITH CHECK (true) lets any request — including anonymous — upload, overwrite, or delete any file in the bucket. Attackers can replace profile images, documents, or assets.',
          file: rel,
          line,
          fix: `Replace: WITH CHECK (auth.uid() IS NOT NULL) — ensures uploads require authentication.`,
        });
      }
    }
  }

  // ── Application source code ─────────────────────────────────────────────
  const srcDirs = findDirs(root, SOURCE_DIRS);
  const srcFiles = srcDirs.flatMap(d => walk(d, ['.ts', '.tsx', '.js', '.jsx']));

  for (const file of srcFiles) {
    const rel = path.relative(root, file);
    if (/\.(spec|test)\.[jt]sx?$/.test(file)) continue;

    let content: string;
    try { content = fs.readFileSync(file, 'utf-8'); } catch { continue; }

    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // 2. createBucket / updateBucket with public: true
      // The options object is often multi-line, so look ahead up to 8 lines.
      if (/\.(?:storage\.)?(?:createBucket|updateBucket)\s*\(/.test(line)) {
        const windowEnd = Math.min(lines.length, i + 8);
        const window = lines.slice(i, windowEnd).join('\n');
        if (/\bpublic\s*:\s*true\b/.test(window)) {
          const isCreate = line.includes('createBucket');
          const nameMatch = line.match(/(?:createBucket|updateBucket)\s*\(\s*['"`]([^'"`]+)['"`]/);
          const name = nameMatch ? nameMatch[1] : 'unknown';
          findings.push({
            severity: 'critical',
            category: 'storage',
            title: `Bucket "${name}" ${isCreate ? 'created' : 'updated'} as public in code`,
            detail:
              'public: true makes all files in this bucket downloadable by anyone — no auth token needed, no RLS checked. Use signed URLs for controlled access to private files.',
            file: rel,
            line: i + 1,
            fix: `Remove public: true and use supabase.storage.createSignedUrl() to grant time-limited access.`,
          });
        }
      }

      // 4. dangerouslyAllowBrowser: true
      if (/dangerouslyAllowBrowser\s*:\s*true\b/.test(line)) {
        findings.push({
          severity: 'warning',
          category: 'storage',
          title: `dangerouslyAllowBrowser: true in ${rel}`,
          detail:
            'This flag suppresses Supabase\'s built-in warning that you are using a server-only key (service role) in a browser context. It does not make it safe — it disables the safety check. In almost all cases this means a service role key is being exposed to the client.',
          file: rel,
          line: i + 1,
          fix: `Use the anon key in browser clients. Only use the service role key in server-side code (API routes, server actions, Edge Functions).`,
        });
      }

      // 5. Signed URLs with very long expiry
      const signedUrlMatch = line.match(/createSignedUrl\s*\([^,]+,\s*(\d+)/);
      if (signedUrlMatch) {
        const expiry = parseInt(signedUrlMatch[1], 10);
        if (expiry > LONG_EXPIRY_THRESHOLD) {
          const days = Math.round(expiry / 86400);
          findings.push({
            severity: 'info',
            category: 'storage',
            title: `Signed URL with ${days}-day expiry in ${rel}`,
            detail:
              `Signed URLs valid for ${days} days cannot be revoked once shared. If the file moves or the user loses access, the link remains valid until it expires naturally.`,
            file: rel,
            line: i + 1,
            fix: `Use shorter expiry times (max 1 hour for sensitive files, 24 hours for general use). For long-lived access, re-sign on each request.`,
          });
        }
      }
    }
  }

  return { findings };
}

// ─── SQL helpers ──────────────────────────────────────────────────────────────

function detectPublicBucketInsert(stmt: string): string | null {
  if (!/INSERT\s+INTO\s+storage\.buckets/i.test(stmt)) return null;

  // Extract column list: INSERT INTO storage.buckets (col1, col2, ...) VALUES (...)
  const colMatch = stmt.match(/\(([^)]+)\)\s*VALUES/i);
  if (!colMatch) {
    // No explicit column list — positional insert, too ambiguous to flag accurately
    return null;
  }

  const cols = colMatch[1]
    .split(',')
    .map(c => c.trim().replace(/["`]/g, '').toLowerCase());

  const publicIdx = cols.indexOf('public');
  if (publicIdx === -1) return null;

  // Extract first VALUES tuple
  const valMatch = stmt.match(/VALUES\s*\(([^)]+)\)/i);
  if (!valMatch) return null;

  const vals = splitSQLValues(valMatch[1]);
  const publicVal = vals[publicIdx]?.trim().toUpperCase();

  if (publicVal !== 'TRUE' && publicVal !== "'TRUE'" && publicVal !== '1') return null;

  // Extract bucket name from id or name column
  const nameIdx = cols.indexOf('name');
  const idIdx = cols.indexOf('id');
  const idx = nameIdx >= 0 ? nameIdx : idIdx >= 0 ? idIdx : -1;
  const bucketName = idx >= 0 ? stripQuotes(vals[idx]) : 'unknown';

  return bucketName;
}

function splitSQLValues(valStr: string): string[] {
  const vals: string[] = [];
  let cur = '';
  let inStr = false;
  let depth = 0;

  for (const ch of valStr) {
    if (ch === "'" && !inStr) {
      inStr = true; cur += ch;
    } else if (ch === "'" && inStr) {
      inStr = false; cur += ch;
    } else if (!inStr && ch === '(') {
      depth++; cur += ch;
    } else if (!inStr && ch === ')') {
      depth--; cur += ch;
    } else if (!inStr && depth === 0 && ch === ',') {
      vals.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) vals.push(cur.trim());
  return vals;
}

function stripQuotes(s: string): string {
  return s.trim().replace(/^['"`]|['"`]$/g, '');
}
