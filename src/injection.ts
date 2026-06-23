/**
 * Injection and mass-assignment scanner — catches AI patterns that introduce
 * SQL injection and privilege-escalation through unsafe data handling.
 *
 * Checks:
 *  1. Template literals in Supabase query calls
 *     → .rpc('fn', { query: `SELECT * FROM ${table}` })  ← SQL injection
 *     → .from('x').select(`${userInput}`)                ← column injection
 *     AI builds "dynamic" queries with template literals constantly.
 *
 *  2. Mass assignment — raw req.body / req.json() piped directly into insert/upsert
 *     → supabase.from('users').insert(await req.json())
 *     An attacker can add extra fields (role, is_admin, company_id) that
 *     bypass intended access controls. Always allowlist fields explicitly.
 *
 *  3. Unvalidated ID from params passed to .eq() without ownership check
 *     → .from('orders').select('*').eq('id', params.id)   with no user check
 *     This is IDOR (Insecure Direct Object Reference). Classic AI pattern:
 *     fetch by primary key without verifying the caller owns the record.
 *     (Flagged as INFO due to higher false-positive rate — RLS may cover this.)
 */

import fs from 'fs';
import path from 'path';
import { walk, findDirs } from './walk.js';
import type { Finding } from './types.js';

const SOURCE_DIRS = [
  'app', 'src', 'components', 'lib', 'utils', 'server', 'api',
  'apps/web/app', 'apps/web/lib', 'apps/web/src',
];

// Template literals passed into Supabase query-execution methods
const TEMPLATE_INJECTION_PATTERNS: Array<{ re: RegExp; desc: string }> = [
  {
    re: /\.rpc\s*\(\s*['"]\w+['"]\s*,\s*\{[^}]*`[^`]*\$\{/,
    desc: 'Template literal in .rpc() argument',
  },
  {
    re: /\.from\s*\([^)]+\)\s*\.(?:select|insert|update)\s*\(\s*`[^`]*\$\{/,
    desc: 'Template literal in Supabase query method',
  },
  {
    re: /supabase\.rpc\s*\(\s*`[^`]*\$\{/,
    desc: 'Template literal as RPC function name',
  },
];

// Mass-assignment patterns
const MASS_ASSIGN_PATTERNS: Array<{ re: RegExp; desc: string }> = [
  {
    re: /\.(?:insert|upsert)\s*\(\s*await\s+req(?:uest)?\.json\s*\(\s*\)\s*[,)]/,
    desc: 'Direct req.json() passed to insert/upsert',
  },
  {
    re: /\.(?:insert|upsert)\s*\(\s*body\s*[,)]/,
    desc: 'Raw body variable passed to insert/upsert',
  },
  {
    re: /\.(?:insert|upsert)\s*\(\s*\{[^}]*\.\.\.\s*(?:body|data|payload|input|req(?:uest)?\.body)[^}]*\}/,
    desc: 'Spread of request body into insert/upsert',
  },
  {
    re: /\.(?:insert|upsert)\s*\(\s*\{[^}]*\.\.\.\s*(?:await\s+)?req(?:uest)?\.json\s*\(\s*\)/,
    desc: 'Spread of req.json() into insert/upsert',
  },
];

// IDOR pattern: .eq('id', params.id) or .eq('id', searchParams.get) without a user ownership check nearby
const IDOR_PATTERN = /\.eq\s*\(\s*['"]id['"]\s*,\s*(?:params\.|searchParams\.)/;
const OWNERSHIP_CHECK = /\.eq\s*\(\s*['"](?:user_id|owner_id|created_by|author_id|account_id|company_id)['"]/;

export function scanInjection(
  root: string,
  extraDirs: string[] = [],
): { findings: Finding[] } {
  const dirs = findDirs(root, [...SOURCE_DIRS, ...extraDirs]);
  const files = dirs.flatMap(d => walk(d, ['.ts', '.tsx', '.js', '.jsx']));

  const findings: Finding[] = [];

  for (const file of files) {
    const rel = path.relative(root, file);

    // Skip test files and non-route library code for IDOR (too noisy in helpers)
    const isRoute = rel.includes('/api/') && path.basename(file).startsWith('route.');

    let content: string;
    try { content = fs.readFileSync(file, 'utf-8'); } catch { continue; }

    // Skip 'use client' — browser context, server-side injection doesn't apply
    if (/^\s*['"]use client['"]/m.test(content)) continue;

    const lines = content.split('\n');

    // ── 1. Template literal injection ────────────────────────────────────
    for (let i = 0; i < lines.length; i++) {
      for (const { re, desc } of TEMPLATE_INJECTION_PATTERNS) {
        if (re.test(lines[i])) {
          findings.push({
            severity: 'critical',
            category: 'injection',
            title: `SQL injection risk: ${desc}`,
            detail:
              'Template literals in Supabase query methods allow user-controlled values to escape the query structure. Use parameterised filters (.eq(), .filter(), .contains()) or Supabase RPC with properly typed parameters.',
            file: rel,
            line: i + 1,
            fix: 'Replace template literals with Supabase\'s chainable filter API: .eq("column", value)',
          });
          break;
        }
      }
    }

    // ── 2. Mass assignment ────────────────────────────────────────────────
    for (let i = 0; i < lines.length; i++) {
      for (const { re, desc } of MASS_ASSIGN_PATTERNS) {
        if (re.test(lines[i])) {
          findings.push({
            severity: 'critical',
            category: 'routes',
            title: `Mass assignment: ${desc} in ${rel}`,
            detail:
              'Piping the raw request body directly into a DB write lets an attacker add fields like role, is_admin, or company_id. Always destructure and allowlist the exact fields you expect.',
            file: rel,
            line: i + 1,
            fix: `const { title, content } = await req.json()  // allowlist fields explicitly
await supabase.from('posts').insert({ title, content, user_id: user.id })`,
          });
          break;
        }
      }
    }

    // ── 3. IDOR (route files only, INFO severity) ─────────────────────────
    if (isRoute) {
      for (let i = 0; i < lines.length; i++) {
        if (!IDOR_PATTERN.test(lines[i])) continue;

        // Check a window of ±8 lines for an ownership check
        const windowStart = Math.max(0, i - 8);
        const windowEnd = Math.min(lines.length, i + 8);
        const window = lines.slice(windowStart, windowEnd).join('\n');

        if (!OWNERSHIP_CHECK.test(window)) {
          findings.push({
            severity: 'info',
            category: 'routes',
            title: `Possible IDOR: fetch by ID without ownership check in ${rel}`,
            detail:
              'Fetching a record by primary key without also checking user_id / company_id allows any authenticated user to read or modify any row by guessing its ID. RLS may cover this — verify.',
            file: rel,
            line: i + 1,
            fix: `Chain .eq('user_id', user.id) after your .eq('id', ...) filter, or rely on RLS with auth.uid() = user_id in the policy.`,
          });
        }
      }
    }
  }

  return { findings };
}
