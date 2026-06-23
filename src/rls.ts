import fs from 'fs';
import path from 'path';
import { walk, findDirs } from './walk.js';
import type { Finding, ScanStats } from './types.js';

interface TableState {
  name: string;
  rlsEnabled: boolean;
  policies: PolicyState[];
  file: string;
}

interface PolicyState {
  name: string;
  table: string;
  using: string;
  file: string;
  line: number;
}

// Candidate locations for migration files in any Supabase project
const MIGRATION_DIRS = [
  'supabase/migrations',
  'migrations',
  'db/migrations',
  'database/migrations',
  'prisma/migrations',
  'drizzle',
];

// Tables managed by Supabase itself — skip them
const MANAGED_PREFIXES = ['pg_', '_realtime', '_analytics', 'auth.', 'storage.', 'realtime.', 'extensions.'];
const MANAGED_NAMES = new Set([
  'schema_migrations', 'spatial_ref_sys', 'geography_columns', 'geometry_columns',
]);

export function scanRLS(
  root: string,
  extraDirs: string[] = [],
): { findings: Finding[]; stats: Partial<ScanStats> } {
  const dirs = findDirs(root, [...MIGRATION_DIRS, ...extraDirs]);
  if (dirs.length === 0) return { findings: [], stats: { migrationFiles: 0 } };

  const files = dirs.flatMap(d => walk(d, ['.sql'])).sort();
  const tables = new Map<string, TableState>();

  for (const file of files) {
    let sql: string;
    try {
      sql = fs.readFileSync(file, 'utf-8');
    } catch {
      continue;
    }

    const stmts = splitStatements(sql);

    for (const { stmt, line } of stmts) {
      const up = stmt.replace(/\s+/g, ' ').toUpperCase().trimStart();

      if (up.startsWith('CREATE') && /TABLE\s/.test(up)) {
        const name = extractTableName(stmt);
        if (name && !isManaged(name)) {
          if (!tables.has(name)) {
            tables.set(name, { name, rlsEnabled: false, policies: [], file });
          }
        }
      } else if (up.startsWith('DROP') && /TABLE\s/.test(up)) {
        // Respect DROP TABLE — remove from tracking (table no longer exists)
        const names = extractDropTableNames(stmt);
        for (const n of names) tables.delete(n);
      } else if (up.includes('ENABLE ROW LEVEL SECURITY')) {
        const name = extractAlterTableName(stmt);
        if (name && !isManaged(name)) {
          if (!tables.has(name)) {
            tables.set(name, { name, rlsEnabled: false, policies: [], file });
          }
          tables.get(name)!.rlsEnabled = true;
        }
      } else if (up.startsWith('DROP') && up.includes('POLICY')) {
        // DROP POLICY ... ON table — handled implicitly; CREATE POLICY below replaces it
      } else if (up.startsWith('CREATE') && up.includes('POLICY')) {
        const p = extractPolicy(stmt, file, line);
        if (p && !isManaged(p.table)) {
          if (!tables.has(p.table)) {
            tables.set(p.table, { name: p.table, rlsEnabled: false, policies: [], file });
          }
          const existing = tables.get(p.table)!.policies;
          // Replace policy with same name (migration may redefine it)
          const idx = existing.findIndex(e => e.name === p.name);
          if (idx >= 0) existing[idx] = p;
          else existing.push(p);
        }
      }
    }
  }

  const findings: Finding[] = [];

  for (const t of tables.values()) {
    const rel = relPath(root, t.file);

    if (!t.rlsEnabled && t.policies.length === 0) {
      findings.push({
        severity: 'warning',
        category: 'rls',
        title: `"${t.name}" has no Row Level Security`,
        detail: 'Any role with SELECT privilege can read every row. Enable RLS and add policies.',
        file: rel,
        fix: `ALTER TABLE ${t.name} ENABLE ROW LEVEL SECURITY;`,
      });
      continue;
    }

    if (t.rlsEnabled && t.policies.length === 0) {
      findings.push({
        severity: 'critical',
        category: 'rls',
        title: `"${t.name}" has RLS enabled but no policies`,
        detail: 'With RLS on and no policies Postgres denies all access — including your application. This is almost certainly a bug.',
        file: rel,
        fix: `CREATE POLICY "access" ON ${t.name} USING (auth.uid() IS NOT NULL);`,
      });
      continue;
    }

    for (const p of t.policies) {
      const rel2 = relPath(root, p.file);

      if (isUnconditional(p.using)) {
        findings.push({
          severity: 'warning',
          category: 'rls',
          title: `Policy "${p.name}" on "${t.name}" is unconditionally permissive`,
          detail: 'USING (true) grants every row to every user. Row-level security is effectively disabled for this operation.',
          file: rel2,
          line: p.line,
          fix: `Replace USING (true) with a condition such as USING (auth.uid() = user_id)`,
        });
      } else if (p.using && !hasAuthCheck(p.using)) {
        findings.push({
          severity: 'info',
          category: 'rls',
          title: `Policy "${p.name}" on "${t.name}" has no auth function in USING`,
          detail: 'The USING clause does not reference auth.uid(), auth.jwt(), or auth.role(). Verify this is intentional.',
          file: rel2,
          line: p.line,
        });
      }
    }
  }

  const policiesTotal = [...tables.values()].reduce((s, t) => s + t.policies.length, 0);

  return {
    findings,
    stats: { migrationFiles: files.length, tables: tables.size, policies: policiesTotal },
  };
}

// ─── SQL parsing helpers ──────────────────────────────────────────────────────

export function splitStatements(sql: string): Array<{ stmt: string; line: number }> {
  const out: Array<{ stmt: string; line: number }> = [];
  let buf = '';
  let i = 0;
  let line = 1;
  let stmtLine = 1;

  while (i < sql.length) {
    const ch = sql[i];

    // Track line numbers
    if (ch === '\n') line++;

    // Line comment
    if (ch === '-' && sql[i + 1] === '-') {
      while (i < sql.length && sql[i] !== '\n') i++;
      buf += ' ';
      continue;
    }

    // Block comment
    if (ch === '/' && sql[i + 1] === '*') {
      i += 2;
      while (i < sql.length && !(sql[i] === '*' && sql[i + 1] === '/')) {
        if (sql[i] === '\n') line++;
        buf += ' ';
        i++;
      }
      i += 2;
      buf += ' ';
      continue;
    }

    // Dollar quoting: $tag$ ... $tag$
    if (ch === '$') {
      let j = i + 1;
      while (j < sql.length && sql[j] !== '$' && /\w/.test(sql[j])) j++;
      if (j < sql.length && sql[j] === '$') {
        const tag = sql.slice(i, j + 1);
        const close = sql.indexOf(tag, j + 1);
        if (close !== -1) {
          const content = sql.slice(i, close + tag.length);
          for (const c of content) if (c === '\n') line++;
          buf += content;
          i = close + tag.length;
          continue;
        }
      }
    }

    // Single-quoted string
    if (ch === "'") {
      let j = i + 1;
      while (j < sql.length) {
        if (sql[j] === "'" && sql[j + 1] === "'") { j += 2; }
        else if (sql[j] === "'") { j++; break; }
        else { if (sql[j] === '\n') line++; j++; }
      }
      buf += sql.slice(i, j);
      i = j;
      continue;
    }

    // Statement end
    if (ch === ';') {
      const s = buf.trim();
      if (s) out.push({ stmt: s, line: stmtLine });
      buf = '';
      stmtLine = line + 1;
      i++;
      continue;
    }

    buf += ch;
    i++;
  }

  const s = buf.trim();
  if (s) out.push({ stmt: s, line: stmtLine });
  return out;
}

function extractIdentifier(raw: string): string {
  return raw.replace(/^"(.+)"$/, '$1').replace(/^'(.+)'$/, '$1').toLowerCase();
}

function parseQualifiedName(token: string): string {
  const parts = token.split('.');
  return extractIdentifier(parts[parts.length - 1]);
}

function extractTableName(stmt: string): string | null {
  const m = stmt.match(
    /CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:"[^"]+"|[\w$]+)(?:\.(?:"[^"]+"|[\w$]+))?)/i,
  );
  return m ? parseQualifiedName(m[1]) : null;
}

function extractAlterTableName(stmt: string): string | null {
  const m = stmt.match(
    /ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?((?:"[^"]+"|[\w$]+)(?:\.(?:"[^"]+"|[\w$]+))?)/i,
  );
  return m ? parseQualifiedName(m[1]) : null;
}

function extractDropTableNames(stmt: string): string[] {
  const m = stmt.match(
    /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([\s\S]+?)(?:\s+(?:CASCADE|RESTRICT))?$/i,
  );
  if (!m) return [];
  return m[1].split(',').map(t => parseQualifiedName(t.trim().split(/\s/)[0]));
}

function extractPolicy(stmt: string, file: string, line: number): PolicyState | null {
  const m = stmt.match(
    /CREATE\s+(?:OR\s+REPLACE\s+)?POLICY\s+(?:"([^"]+)"|([\w$]+))\s+ON\s+((?:"[^"]+"|[\w$]+)(?:\.(?:"[^"]+"|[\w$]+))?)/i,
  );
  if (!m) return null;

  const name = m[1] ?? m[2] ?? 'unnamed';
  const table = parseQualifiedName(m[3]);
  const using = extractBalancedClause(stmt, 'USING') ?? '';

  return { name, table, using, file, line };
}

export function extractBalancedClause(stmt: string, keyword: string): string | null {
  const re = new RegExp(`\\b${keyword}\\s*\\(`, 'i');
  const m = re.exec(stmt);
  if (!m) return null;

  let depth = 1;
  let i = m.index + m[0].length;
  const start = i;

  while (i < stmt.length && depth > 0) {
    if (stmt[i] === '(') depth++;
    else if (stmt[i] === ')') depth--;
    i++;
  }

  return stmt.slice(start, i - 1).trim();
}

function isManaged(name: string): boolean {
  if (MANAGED_NAMES.has(name)) return true;
  return MANAGED_PREFIXES.some(p => name.startsWith(p.replace('.', '')));
}

function isUnconditional(expr: string): boolean {
  const norm = expr.replace(/\s+/g, ' ').toLowerCase().trim();
  return norm === 'true' || norm === '1=1' || norm === '1 = 1';
}

function hasAuthCheck(expr: string): boolean {
  return (
    /auth\.(uid|jwt|role|email)\s*\(/i.test(expr) ||
    /current_setting\s*\(/i.test(expr) ||
    /current_user\b/i.test(expr) ||
    /request\.jwt\b/i.test(expr)
  );
}

function relPath(root: string, file: string): string {
  return path.relative(root, file);
}
