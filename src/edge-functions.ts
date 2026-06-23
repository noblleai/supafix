/**
 * Supabase Edge Function security scanner.
 *
 * Scans supabase/functions/ for common security mistakes.
 *
 * Checks:
 *  1. Supabase client created without forwarding the Authorization header
 *     → The client falls back to anon/service-role, bypassing per-user RLS.
 *     → The correct pattern passes the request's JWT via global.headers.
 *
 *  2. Wildcard CORS with authenticated DB operations
 *     → 'Access-Control-Allow-Origin': '*' paired with auth-dependent logic
 *       can allow cross-origin credential theft via CORS-based attacks.
 *
 *  3. Service role key hardcoded (not from Deno.env)
 *     → Edge function source is readable; hardcoded keys are exposed.
 *
 *  4. No user verification at all
 *     → Function accesses the DB but never calls auth.getUser() — runs
 *       entirely as anon even when it appears to be user-scoped.
 */

import fs from 'fs';
import path from 'path';
import type { Finding } from './types.js';

const EDGE_FUNCTION_DIRS = ['supabase/functions'];

export function scanEdgeFunctions(root: string): { findings: Finding[] } {
  const findings: Finding[] = [];

  const fnDirs = EDGE_FUNCTION_DIRS
    .map(d => path.join(root, d))
    .filter(d => { try { return fs.statSync(d).isDirectory(); } catch { return false; } });

  if (fnDirs.length === 0) return { findings };

  // Walk one level deep: supabase/functions/<name>/index.ts
  for (const fnRoot of fnDirs) {
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(fnRoot, { withFileTypes: true }); } catch { continue; }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const fnName = entry.name;
      if (fnName.startsWith('_') || fnName === 'node_modules') continue;

      const candidates = ['index.ts', 'index.js', 'main.ts', 'main.js'];
      for (const candidate of candidates) {
        const file = path.join(fnRoot, fnName, candidate);
        try { fs.accessSync(file); } catch { continue; }

        let content: string;
        try { content = fs.readFileSync(file, 'utf-8'); } catch { continue; }

        const rel = path.relative(root, file);
        const lines = content.split('\n');

        scanFunction(rel, content, lines, findings);
        break; // only scan the first match per function dir
      }
    }
  }

  return { findings };
}

function scanFunction(
  rel: string,
  content: string,
  lines: string[],
  findings: Finding[],
): void {
  const hasCreateClient = /\bcreateClient\s*\(/.test(content);
  const hasDbAccess = /\.from\s*\(|\.rpc\s*\(|supabase\.\w/.test(content);

  if (!hasCreateClient || !hasDbAccess) return;

  // ── 1. createClient without auth header forwarding ─────────────────────
  // The correct pattern includes global: { headers: { Authorization: ... } }
  const hasAuthForwarding =
    /Authorization.*req(?:uest)?\.headers/i.test(content) ||
    /headers.*Authorization/i.test(content);

  const usesServiceRole =
    /SUPABASE_SERVICE_ROLE_KEY/.test(content) ||
    /service_role/.test(content);

  if (!hasAuthForwarding && !usesServiceRole) {
    const lineIdx = lines.findIndex(l => /\bcreateClient\s*\(/.test(l));
    findings.push({
      severity: 'critical',
      category: 'auth',
      title: `Edge function "${path.dirname(rel).split('/').pop()}" creates Supabase client without auth forwarding`,
      detail:
        'createClient() without forwarding the Authorization header runs every DB operation as the anon role, bypassing per-user RLS. User A can read User B\'s data.',
      file: rel,
      line: lineIdx >= 0 ? lineIdx + 1 : undefined,
      fix: `Pass the request JWT:\n  const supabase = createClient(url, key, {\n    global: { headers: { Authorization: req.headers.get('Authorization')! } },\n  })`,
    });
  }

  // ── 2. Wildcard CORS paired with authenticated operations ───────────────
  const hasWildcardCors =
    /'Access-Control-Allow-Origin'\s*[,:]\s*['"]\*['"]/.test(content) ||
    /"Access-Control-Allow-Origin"\s*[,:]\s*['"]\*['"]/.test(content);
  const hasAuthOp =
    /auth\.getUser\s*\(|getSession\s*\(|Authorization/.test(content);

  if (hasWildcardCors && hasAuthOp) {
    const lineIdx = lines.findIndex(
      l => /Access-Control-Allow-Origin/.test(l) && /\*/.test(l),
    );
    findings.push({
      severity: 'warning',
      category: 'auth',
      title: `Edge function "${path.dirname(rel).split('/').pop()}" uses wildcard CORS with authenticated operations`,
      detail:
        'Access-Control-Allow-Origin: * allows any origin to make credentialed requests to this function. Restrict to your application\'s origin for functions that perform auth-gated operations.',
      file: rel,
      line: lineIdx >= 0 ? lineIdx + 1 : undefined,
      fix: `Replace '*' with your app origin, e.g. 'https://yourapp.com'. Use '*' only for fully public, stateless endpoints.`,
    });
  }

  // ── 3. Hardcoded service role key ───────────────────────────────────────
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;
    if (/Deno\.env\.get\(/.test(line)) continue; // safe — from environment

    // Real service role keys are long JWTs starting with eyJ
    if (/eyJ[A-Za-z0-9\-_]{60,}\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/.test(line)) {
      findings.push({
        severity: 'critical',
        category: 'secrets',
        title: `Hardcoded JWT token in edge function "${path.dirname(rel).split('/').pop()}"`,
        detail:
          'A JWT token (possibly a service role key) is hardcoded in the edge function source. Edge function source is stored in your repository and visible to anyone with repo access.',
        file: rel,
        line: i + 1,
        fix: `Use Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') and set the secret via: supabase secrets set SUPABASE_SERVICE_ROLE_KEY=<value>`,
      });
      break;
    }
  }

  // ── 4. No user identity verification ───────────────────────────────────
  const hasUserCheck =
    /auth\.getUser\s*\(/.test(content) ||
    /auth\.getSession\s*\(/.test(content) ||
    /verifyJwt/i.test(content);

  if (!hasUserCheck && hasDbAccess && !usesServiceRole) {
    findings.push({
      severity: 'info',
      category: 'auth',
      title: `Edge function "${path.dirname(rel).split('/').pop()}" performs DB operations without verifying user identity`,
      detail:
        'No auth.getUser() call detected. If this function is not intentionally public, add identity verification. Forwarding the Authorization header alone does not block unauthenticated calls — RLS must also be enabled.',
      file: rel,
      fix: `Add: const { data: { user }, error } = await supabase.auth.getUser()\n  if (!user) return new Response('Unauthorized', { status: 401 })`,
    });
  }
}
