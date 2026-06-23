/**
 * Advanced RLS checks — catches policy mistakes that basic
 * existence checks miss.
 *
 * Checks:
 *  1. SECURITY DEFINER functions without SET search_path
 *     → search-path injection: attacker shadows a table in a schema that
 *       gets searched before public, function queries their table instead.
 *
 *  2. user_metadata used for RBAC in RLS policies
 *     → user_metadata is user-controlled via supabase.auth.updateUser().
 *       An attacker can set their own role to 'admin'. Use app_metadata
 *       (only writable via the service-role Admin API) for RBAC.
 *
 *  3. Policies covering INSERT / UPDATE / ALL with no WITH CHECK clause
 *     → USING controls which rows are visible (SELECT). WITH CHECK controls
 *       which rows can be written. developers often forget WITH CHECK, so
 *       a user who can read a row can also write anything to it.
 *
 *  4. Tables where SELECT is covered but INSERT/UPDATE/DELETE are not
 *     → Common mistake: write one SELECT policy and call it done.
 *       Unauthenticated writes are still possible.
 */

import fs from 'fs';
import path from 'path';
import { walk, findDirs } from './walk.js';
import { splitStatements, extractBalancedClause } from './rls.js';
import type { Finding, ScanStats } from './types.js';

const MIGRATION_DIRS = [
  'supabase/migrations',
  'migrations',
  'db/migrations',
  'database/migrations',
  'prisma/migrations',
  'drizzle',
];

interface PolicyRecord {
  name: string;
  table: string;
  command: string; // ALL SELECT INSERT UPDATE DELETE
  hasUsing: boolean;
  hasCheck: boolean;
  using: string;
  fullText: string;
  file: string;
  line: number;
}

interface TableRecord {
  columns: string[];
  file: string;
}

// Columns that indicate a multi-tenant schema — if present but not in any policy, data isolation is broken
const TENANT_COLUMNS = new Set([
  'org_id', 'organization_id', 'company_id', 'tenant_id',
  'workspace_id', 'team_id', 'account_id', 'project_id',
]);

export function scanRLSAdvanced(
  root: string,
  extraDirs: string[] = [],
): { findings: Finding[]; stats: Partial<ScanStats> } {
  const dirs = findDirs(root, [...MIGRATION_DIRS, ...extraDirs]);
  if (dirs.length === 0) return { findings: [], stats: {} };

  const files = dirs.flatMap(d => walk(d, ['.sql'])).sort();
  const findings: Finding[] = [];

  // table → set of operations covered by at least one policy
  const tableCoverage = new Map<string, Set<string>>();
  const policies: PolicyRecord[] = [];
  const tableRecords = new Map<string, TableRecord>();

  for (const file of files) {
    let sql: string;
    try { sql = fs.readFileSync(file, 'utf-8'); } catch { continue; }

    const stmts = splitStatements(sql);

    for (const { stmt, line } of stmts) {
      const up = stmt.replace(/\s+/g, ' ').toUpperCase().trimStart();

      // ── 0. Track table columns for multi-tenant check ────────────────────
      if (up.startsWith('CREATE') && /TABLE\s/.test(up)) {
        const nameMatch = stmt.match(
          /CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:"[^"]+"|[\w$]+)(?:\.(?:"[^"]+"|[\w$]+))?)/i,
        );
        if (nameMatch) {
          const tableName = parseQualifiedName(nameMatch[1]);
          const columns = extractColumnNames(stmt);
          tableRecords.set(tableName, { columns, file });
        }
      }

      // ── 1. SECURITY DEFINER without SET search_path ──────────────────────
      if (up.includes('SECURITY DEFINER') && !up.includes('SET SEARCH_PATH')) {
        const nameMatch = stmt.match(
          /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w."]+)/i,
        );
        const fnName = nameMatch ? nameMatch[1] : 'unknown function';
        findings.push({
          severity: 'critical',
          category: 'rls',
          title: `SECURITY DEFINER function "${fnName}" missing SET search_path`,
          detail:
            'Without SET search_path an attacker who can create objects in any searched schema can shadow your tables and redirect the function\'s queries to their own data.',
          file: path.relative(root, file),
          line,
          fix: `ALTER FUNCTION ${fnName}(...) SET search_path = public, pg_temp;`,
        });
      }

      // ── 2 + 3. Policy analysis ────────────────────────────────────────────
      if (up.startsWith('CREATE') && up.includes('POLICY')) {
        const p = parsePolicy(stmt, file, line);
        if (!p) continue;

        // Track per-table coverage
        if (!tableCoverage.has(p.table)) tableCoverage.set(p.table, new Set());
        const ops = p.command === 'ALL'
          ? ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
          : [p.command];
        for (const op of ops) tableCoverage.get(p.table)!.add(op);

        // 2. user_metadata for RBAC
        const fullPolicyText = stmt;
        if (/user_metadata/i.test(fullPolicyText) && /role|admin|permission/i.test(fullPolicyText)) {
          findings.push({
            severity: 'critical',
            category: 'rls',
            title: `Policy "${p.name}" on "${p.table}" uses user_metadata for RBAC`,
            detail:
              'user_metadata is writable by the user via supabase.auth.updateUser(). An attacker can set their own role to "admin". Use app_metadata instead — it is only writable via the Admin API (service role).',
            file: path.relative(root, file),
            line,
            fix: `Replace auth.jwt() -> 'user_metadata' with auth.jwt() -> 'app_metadata'`,
          });
        }

        // 3. Missing WITH CHECK on write operations
        const isWriteOp = ['ALL', 'INSERT', 'UPDATE'].includes(p.command);
        if (isWriteOp && p.hasUsing && !p.hasCheck) {
          findings.push({
            severity: 'warning',
            category: 'rls',
            title: `Policy "${p.name}" on "${p.table}" has no WITH CHECK`,
            detail:
              `USING controls which rows are visible. WITH CHECK controls which rows can be written. Without it, a user who can read a row can write anything — new rows bypass ownership checks entirely.`,
            file: path.relative(root, file),
            line,
            fix: `Add WITH CHECK (${p.using || 'auth.uid() = user_id'}) to match your USING clause.`,
          });
        }

        policies.push(p);
      }

      // Handle DROP TABLE
      if (up.startsWith('DROP') && /TABLE\s/.test(up)) {
        const m = stmt.match(
          /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([\s\S]+?)(?:\s+(?:CASCADE|RESTRICT))?$/i,
        );
        if (m) {
          for (const t of m[1].split(',').map(s => parseQualifiedName(s.trim().split(/\s/)[0]))) {
            tableRecords.delete(t);
          }
        }
      }

      // Handle DROP POLICY
      if (up.startsWith('DROP') && up.includes('POLICY')) {
        const m = stmt.match(/ON\s+([\w."]+)/i);
        if (m) {
          const table = parseQualifiedName(m[1]);
          const nameM = stmt.match(/DROP\s+POLICY\s+(?:IF\s+EXISTS\s+)?(?:"([^"]+)"|([\w]+))/i);
          const policyName = nameM ? (nameM[1] ?? nameM[2]) : null;
          if (policyName) {
            const idx = policies.findIndex(p => p.name === policyName && p.table === table);
            if (idx >= 0) {
              // Remove coverage for this policy's operations
              const removed = policies.splice(idx, 1)[0];
              const ops = removed.command === 'ALL'
                ? ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
                : [removed.command];
              const remaining = policies.filter(p => p.table === table);
              for (const op of ops) {
                const stillCovered = remaining.some(p =>
                  p.command === 'ALL' || p.command === op,
                );
                if (!stillCovered) tableCoverage.get(table)?.delete(op);
              }
            }
          }
        }
      }
    }
  }

  // ── 4. Multi-tenant isolation ────────────────────────────────────────────
  // Tables with org_id / company_id / tenant_id columns where no RLS policy
  // references that column — any authenticated user can read other tenants' rows.
  for (const [table, record] of tableRecords) {
    const tenantCols = record.columns.filter(col => TENANT_COLUMNS.has(col));
    if (tenantCols.length === 0) continue;

    const tablePolicies = policies.filter(p => p.table === table);
    if (tablePolicies.length === 0) continue; // caught by basic scanner

    const allPolicyText = tablePolicies.map(p => p.fullText).join(' ').toLowerCase();
    const uncheckedCols = tenantCols.filter(col => !allPolicyText.includes(col));

    if (uncheckedCols.length > 0) {
      const last = [...tablePolicies].pop()!;
      findings.push({
        severity: 'critical',
        category: 'rls',
        title: `"${table}" has tenant column(s) not enforced in any RLS policy`,
        detail:
          `Column(s) [${uncheckedCols.join(', ')}] exist but are not referenced in any policy. ` +
          `Any authenticated user can read or modify every tenant's data by querying directly.`,
        file: path.relative(root, last.file),
        line: last.line,
        fix: `Add USING (${uncheckedCols[0]} = (SELECT ${uncheckedCols[0]} FROM user_profiles WHERE id = auth.uid())) to your policies.`,
      });
    }
  }

  // ── 5. Incomplete operation coverage ─────────────────────────────────────
  // Only flag tables that have SOME policies (bare tables with no policies
  // are caught by the basic rls scanner). We want: "you wrote a SELECT policy
  // but forgot INSERT/UPDATE/DELETE."
  for (const [table, covered] of tableCoverage) {
    if (covered.size === 0) continue;
    if (covered.has('SELECT') && !covered.has('INSERT') && !covered.has('UPDATE')) {
      // Find the file from the last policy on this table
      const last = [...policies].reverse().find(p => p.table === table);
      findings.push({
        severity: 'warning',
        category: 'rls',
        title: `"${table}" has SELECT policy but no INSERT/UPDATE policies`,
        detail:
          'Read access is controlled, but writes are unrestricted. Any authenticated user can insert or update rows without passing the ownership check.',
        file: last ? path.relative(root, last.file) : undefined,
        fix: `Add FOR INSERT WITH CHECK (...)  and  FOR UPDATE USING (...) WITH CHECK (...) policies.`,
      });
    }
  }

  return { findings, stats: {} };
}

// ─── helpers ──────────────────────────────────────────────────────────────────

function parseQualifiedName(token: string): string {
  const parts = token.trim().split('.');
  return parts[parts.length - 1].replace(/^"(.+)"$/, '$1').toLowerCase();
}

function parsePolicy(
  stmt: string,
  file: string,
  line: number,
): PolicyRecord | null {
  const header = stmt.match(
    /CREATE\s+(?:OR\s+REPLACE\s+)?POLICY\s+(?:"([^"]+)"|([\w$]+))\s+ON\s+((?:"[^"]+"|[\w$]+)(?:\.(?:"[^"]+"|[\w$]+))?)/i,
  );
  if (!header) return null;

  const name = header[1] ?? header[2] ?? 'unnamed';
  const table = parseQualifiedName(header[3]);

  const forMatch = stmt.match(/\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b/i);
  const command = (forMatch?.[1] ?? 'ALL').toUpperCase();

  const using = extractBalancedClause(stmt, 'USING') ?? '';
  const withCheckRaw = extractBalancedClause(stmt, 'WITH CHECK') ??
    (stmt.toUpperCase().includes('WITH CHECK') ? '' : null);

  return {
    name,
    table,
    command,
    hasUsing: !!using,
    hasCheck: withCheckRaw !== null,
    using,
    fullText: stmt,
    file,
    line,
  };
}

function extractColumnNames(createTableStmt: string): string[] {
  // Extract the body between the outer parens of CREATE TABLE x (...)
  const bodyMatch = createTableStmt.match(/CREATE[^(]+\(([^]+)\)\s*(?:INHERITS|WITH|TABLESPACE|;|$)/i);
  if (!bodyMatch) return [];

  const body = bodyMatch[1];
  const cols: string[] = [];

  // Split on commas, being careful not to split inside nested parens
  const parts: string[] = [];
  let depth = 0;
  let cur = '';
  for (const ch of body) {
    if (ch === '(') { depth++; cur += ch; }
    else if (ch === ')') { depth--; cur += ch; }
    else if (ch === ',' && depth === 0) { parts.push(cur.trim()); cur = ''; }
    else { cur += ch; }
  }
  if (cur.trim()) parts.push(cur.trim());

  for (const part of parts) {
    // Skip constraint definitions: PRIMARY KEY, UNIQUE, FOREIGN KEY, CHECK, CONSTRAINT
    if (/^\s*(?:PRIMARY\s+KEY|UNIQUE|FOREIGN\s+KEY|CHECK|CONSTRAINT)\b/i.test(part)) continue;
    // Column name is the first identifier token
    const m = part.match(/^\s*"?(\w+)"?\s+\w/);
    if (m) cols.push(m[1].toLowerCase());
  }

  return cols;
}
