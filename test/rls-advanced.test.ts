import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanRLSAdvanced } from '../src/rls-advanced';

function tmpProject(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-rls-adv-'));
  const migrDir = path.join(dir, 'supabase', 'migrations');
  fs.mkdirSync(migrDir, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(migrDir, name), content);
  }
  return dir;
}

describe('RLS advanced scanner', () => {
  // ── SECURITY DEFINER ──────────────────────────────────────────────────
  it('flags SECURITY DEFINER without SET search_path', () => {
    const dir = tmpProject({
      '001.sql': `
        CREATE FUNCTION get_company_data(cid uuid)
        RETURNS TABLE(id uuid, name text)
        LANGUAGE sql STABLE SECURITY DEFINER
        AS $$ SELECT id, name FROM companies WHERE id = cid $$;
      `,
    });
    const { findings } = scanRLSAdvanced(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
    assert.match(findings[0].title, /search_path/);
  });

  it('no finding when SECURITY DEFINER has SET search_path', () => {
    const dir = tmpProject({
      '001.sql': `
        CREATE FUNCTION safe_fn() RETURNS void LANGUAGE sql
        SECURITY DEFINER SET search_path = public, pg_temp
        AS $$ SELECT 1 $$;
      `,
    });
    const { findings } = scanRLSAdvanced(dir);
    assert.equal(findings.filter(f => f.title.includes('search_path')).length, 0);
  });

  // ── user_metadata RBAC ────────────────────────────────────────────────
  it('flags user_metadata used for role check in RLS', () => {
    const dir = tmpProject({
      '001.sql': `
        CREATE TABLE reports (id uuid);
        ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "admin_only" ON reports
          USING ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
      `,
    });
    const { findings } = scanRLSAdvanced(dir);
    const hit = findings.find(f => f.title.includes('user_metadata'));
    assert.ok(hit, 'should find user_metadata finding');
    assert.equal(hit!.severity, 'critical');
  });

  it('no finding when using app_metadata for role check', () => {
    const dir = tmpProject({
      '001.sql': `
        CREATE TABLE reports (id uuid);
        ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "admin_only" ON reports
          USING ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
      `,
    });
    const { findings } = scanRLSAdvanced(dir);
    assert.equal(findings.filter(f => f.title.includes('user_metadata')).length, 0);
  });

  // ── Missing WITH CHECK ────────────────────────────────────────────────
  it('flags ALL policy with USING but no WITH CHECK', () => {
    const dir = tmpProject({
      '001.sql': `
        CREATE TABLE posts (id uuid, user_id uuid);
        ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "owner" ON posts FOR ALL USING (auth.uid() = user_id);
      `,
    });
    const { findings } = scanRLSAdvanced(dir);
    const hit = findings.find(f => f.title.includes('WITH CHECK'));
    assert.ok(hit, 'should flag missing WITH CHECK');
    assert.equal(hit!.severity, 'warning');
  });

  it('no finding when WITH CHECK is present', () => {
    const dir = tmpProject({
      '001.sql': `
        CREATE TABLE posts (id uuid, user_id uuid);
        ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "owner" ON posts FOR ALL
          USING (auth.uid() = user_id)
          WITH CHECK (auth.uid() = user_id);
      `,
    });
    const { findings } = scanRLSAdvanced(dir);
    assert.equal(findings.filter(f => f.title.includes('WITH CHECK')).length, 0);
  });

  it('no finding for SELECT-only policy (WITH CHECK not required)', () => {
    const dir = tmpProject({
      '001.sql': `
        CREATE TABLE articles (id uuid, user_id uuid);
        ALTER TABLE articles ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "read" ON articles FOR SELECT USING (auth.uid() = user_id);
      `,
    });
    const { findings } = scanRLSAdvanced(dir);
    assert.equal(findings.filter(f => f.title.includes('WITH CHECK')).length, 0);
  });

  // ── Incomplete operation coverage ─────────────────────────────────────
  it('flags table with SELECT but no INSERT/UPDATE', () => {
    const dir = tmpProject({
      '001.sql': `
        CREATE TABLE orders (id uuid, user_id uuid);
        ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "read" ON orders FOR SELECT USING (auth.uid() = user_id);
      `,
    });
    const { findings } = scanRLSAdvanced(dir);
    const hit = findings.find(f => f.title.includes('no INSERT/UPDATE'));
    assert.ok(hit, 'should flag incomplete operation coverage');
  });

  it('no finding when FOR ALL policy covers all operations', () => {
    const dir = tmpProject({
      '001.sql': `
        CREATE TABLE orders (id uuid, user_id uuid);
        ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
        CREATE POLICY "all_ops" ON orders FOR ALL
          USING (auth.uid() = user_id)
          WITH CHECK (auth.uid() = user_id);
      `,
    });
    const { findings } = scanRLSAdvanced(dir);
    assert.equal(findings.filter(f => f.title.includes('no INSERT/UPDATE')).length, 0);
  });
});
