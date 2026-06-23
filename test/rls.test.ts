import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanRLS } from '../src/rls';

function tmpProject(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-rls-'));
  const migrDir = path.join(dir, 'supabase', 'migrations');
  fs.mkdirSync(migrDir, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(migrDir, name), content);
  }
  return dir;
}

describe('RLS scanner', () => {
  it('no findings on a clean table', () => {
    const dir = tmpProject({
      '001_init.sql': `
        CREATE TABLE posts (id uuid PRIMARY KEY, user_id uuid);
        ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "owner" ON posts FOR ALL USING (auth.uid() = user_id);
      `,
    });
    const { findings } = scanRLS(dir);
    assert.equal(findings.length, 0);
  });

  it('warns when table has no RLS', () => {
    const dir = tmpProject({
      '001_init.sql': `CREATE TABLE orders (id uuid PRIMARY KEY);`,
    });
    const { findings } = scanRLS(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'warning');
    assert.match(findings[0].title, /orders/);
  });

  it('critical when RLS enabled but no policies', () => {
    const dir = tmpProject({
      '001_init.sql': `
        CREATE TABLE payments (id uuid PRIMARY KEY);
        ALTER TABLE payments ENABLE ROW LEVEL SECURITY;
      `,
    });
    const { findings } = scanRLS(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
    assert.match(findings[0].title, /payments/);
  });

  it('warns on USING (true) policy', () => {
    const dir = tmpProject({
      '001_init.sql': `
        CREATE TABLE items (id uuid PRIMARY KEY);
        ALTER TABLE items ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "allow_all" ON items FOR ALL USING (true);
      `,
    });
    const { findings } = scanRLS(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'warning');
    assert.match(findings[0].title, /unconditionally permissive/);
  });

  it('no false positive on auth.uid() policy', () => {
    const dir = tmpProject({
      '001_init.sql': `
        CREATE TABLE notes (id uuid, user_id uuid);
        ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "owner" ON notes USING (auth.uid() = user_id);
      `,
    });
    const { findings } = scanRLS(dir);
    assert.equal(findings.length, 0);
  });

  it('handles schema-qualified table names', () => {
    const dir = tmpProject({
      '001_init.sql': `
        CREATE TABLE public.invoices (id uuid PRIMARY KEY);
        ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "access" ON public.invoices USING (auth.uid() IS NOT NULL);
      `,
    });
    const { findings } = scanRLS(dir);
    assert.equal(findings.length, 0);
  });

  it('handles IF NOT EXISTS tables', () => {
    const dir = tmpProject({
      '001_init.sql': `
        CREATE TABLE IF NOT EXISTS tickets (id uuid PRIMARY KEY);
        ALTER TABLE tickets ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "p" ON tickets USING (auth.uid() IS NOT NULL);
      `,
    });
    const { findings } = scanRLS(dir);
    assert.equal(findings.length, 0);
  });

  it('handles DROP TABLE removing tracking', () => {
    const dir = tmpProject({
      '001_init.sql': `CREATE TABLE temp_data (id uuid);`,
      '002_drop.sql': `DROP TABLE temp_data;`,
    });
    const { findings } = scanRLS(dir);
    assert.equal(findings.length, 0);
  });

  it('handles dollar-quoted functions without splitting statements', () => {
    const dir = tmpProject({
      '001_init.sql': `
        CREATE OR REPLACE FUNCTION get_user_id()
        RETURNS uuid LANGUAGE sql STABLE AS $$
          SELECT auth.uid();
        $$;

        CREATE TABLE widgets (id uuid, owner uuid);
        ALTER TABLE widgets ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "owner" ON widgets USING (auth.uid() = owner);
      `,
    });
    const { findings } = scanRLS(dir);
    assert.equal(findings.length, 0);
  });

  it('handles multi-migration projects, later migration fixes earlier gap', () => {
    const dir = tmpProject({
      '001_init.sql': `
        CREATE TABLE projects (id uuid PRIMARY KEY);
        ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
      `,
      '002_rls.sql': `
        CREATE POLICY "tenant" ON projects
          FOR ALL USING (
            company_id IN (
              SELECT company_id FROM user_profiles WHERE id = auth.uid()
            )
          );
      `,
    });
    const { findings } = scanRLS(dir);
    assert.equal(findings.length, 0);
  });

  it('handles DROP POLICY then CREATE POLICY replacement', () => {
    const dir = tmpProject({
      '001_init.sql': `
        CREATE TABLE docs (id uuid, user_id uuid);
        ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "access" ON docs USING (true);
      `,
      '002_fix.sql': `
        DROP POLICY IF EXISTS "access" ON docs;
        CREATE POLICY "access" ON docs USING (auth.uid() = user_id);
      `,
    });
    const { findings } = scanRLS(dir);
    // After replacement the policy is correct — no findings
    assert.equal(findings.length, 0);
  });

  it('returns stats', () => {
    const dir = tmpProject({
      '001_init.sql': `
        CREATE TABLE t1 (id uuid);
        ALTER TABLE t1 ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "p" ON t1 USING (auth.uid() IS NOT NULL);
      `,
    });
    const { stats } = scanRLS(dir);
    assert.equal(stats.migrationFiles, 1);
    assert.equal(stats.tables, 1);
    assert.equal(stats.policies, 1);
  });
});
