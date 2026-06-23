/**
 * Auth misuse scanner — catches common Supabase auth misuse patterns.
 *
 * Checks:
 *  1. getSession() used for server-side auth
 *     → getSession() reads the session from the local storage / cookie and
 *       does NOT re-validate it with the Supabase Auth server. A forged
 *       cookie passes this check. getUser() makes a network call to Auth
 *       and is the only safe check. (Supabase docs explicitly warn about this.)
 *
 *  2. createBrowserClient used in server/API files
 *     → createBrowserClient uses the anon key and reads the session from
 *       browser storage. In a server file (route, server action, server
 *       component) it silently falls back to the anon role, bypassing RLS.
 *       Use createServerClient instead.
 *
 *  3. supabase.auth.admin used outside of clearly-intended admin files
 *     → auth.admin methods use the service role and bypass RLS entirely.
 *       Fine in isolated admin scripts; dangerous when dropped into
 *       a regular API route.
 */

import fs from 'fs';
import path from 'path';
import { walk, findDirs } from './walk.js';
import type { Finding } from './types.js';

const ROUTE_DIRS = [
  'app/api', 'src/app/api', 'apps/web/app/api',
  'pages/api', 'src/pages/api',
];

const SERVER_COMPONENT_PATTERNS = [
  /app\/(?!.*\(.*client.*\)).*\.tsx?$/,
  /\.server\.[jt]sx?$/,
];

const PUBLIC_PATTERNS = [/\/webhook/i, /\/callback/i, /\/health/i, /\/ping/i, /\/cron\//i];

export function scanAuth(
  root: string,
  extraDirs: string[] = [],
): { findings: Finding[] } {
  const dirs = findDirs(root, [...ROUTE_DIRS, ...extraDirs]);
  if (dirs.length === 0) return { findings: [] };

  const routeFiles = dirs.flatMap(d =>
    walk(d, ['.ts', '.tsx', '.js', '.jsx']).filter(f =>
      path.basename(f).startsWith('route.') ||
      d.includes('pages/api'),
    ),
  );

  const findings: Finding[] = [];

  for (const file of routeFiles) {
    const rel = path.relative(root, file);
    if (PUBLIC_PATTERNS.some(p => p.test(rel))) continue;

    let content: string;
    try { content = fs.readFileSync(file, 'utf-8'); } catch { continue; }

    // Skip 'use client' files — browser context, rules don't apply
    if (/^\s*['"]use client['"]/m.test(content)) continue;

    const lines = content.split('\n');

    // ── 1. getSession() for auth verification ────────────────────────────
    // Flag when getSession() result is used as the auth gate (if !session return 401).
    // Pattern: call to getSession + a truthiness check on session within a few lines.
    for (let i = 0; i < lines.length; i++) {
      if (!/\.auth\.getSession\s*\(/.test(lines[i])) continue;

      // Look ahead up to 6 lines for the auth gate pattern
      const window = lines.slice(i, i + 6).join('\n');
      const isUsedAsGate =
        /if\s*\(.*!.*session/i.test(window) ||
        /if\s*\(!session/i.test(window) ||
        /session\s*==\s*null/.test(window) ||
        /\?\?\s*null/.test(window);

      if (isUsedAsGate) {
        findings.push({
          severity: 'critical',
          category: 'routes',
          title: `getSession() used for server-side auth in ${rel}`,
          detail:
            'getSession() reads from cookies without re-validating with the Auth server. A crafted cookie bypasses this check entirely. Use supabase.auth.getUser() — it validates with Auth on every call.',
          file: rel,
          line: i + 1,
          fix: `Replace: const { data: { session } } = await supabase.auth.getSession()
  With:    const { data: { user }, error } = await supabase.auth.getUser()`,
        });
        break; // one finding per file
      }
    }

    // ── 2. createBrowserClient in server file ────────────────────────────
    if (
      content.includes('createBrowserClient') &&
      /from\s+['"]@supabase\/ssr['"]/.test(content)
    ) {
      const lineIdx = lines.findIndex(l => l.includes('createBrowserClient'));
      findings.push({
        severity: 'critical',
        category: 'routes',
        title: `createBrowserClient used in server file ${rel}`,
        detail:
          'createBrowserClient reads auth state from browser storage and uses the anon key in server context, where no browser storage exists. The client silently falls back to the anon role, bypassing your RLS policies.',
        file: rel,
        line: lineIdx + 1,
        fix: `Replace createBrowserClient with createServerClient from @supabase/ssr`,
      });
    }

    // ── 3. auth.admin in non-admin routes ────────────────────────────────
    if (
      /supabase\.auth\.admin\b/.test(content) &&
      !/\/admin\//i.test(rel) &&
      !/\/internal\//i.test(rel)
    ) {
      const lineIdx = lines.findIndex(l => /supabase\.auth\.admin\b/.test(l));
      findings.push({
        severity: 'warning',
        category: 'routes',
        title: `supabase.auth.admin used in ${rel}`,
        detail:
          'auth.admin methods use the service role key and bypass RLS entirely. Verify this is intentional and not a shortcut that bypasses what should be a user-scoped operation.',
        file: rel,
        line: lineIdx + 1,
        fix: 'Use the user-scoped Supabase client unless this is an explicitly privileged admin operation.',
      });
    }
  }

  return { findings };
}
