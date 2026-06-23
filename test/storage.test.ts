import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanStorage } from '../src/storage';

function tmpProject(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-storage-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

function migrationProject(sql: Record<string, string>): string {
  const files: Record<string, string> = {};
  for (const [name, content] of Object.entries(sql)) {
    files[`supabase/migrations/${name}`] = content;
  }
  return tmpProject(files);
}

describe('Storage scanner', () => {
  // ── Public bucket via SQL INSERT ─────────────────────────────────────
  it('flags INSERT with public = true', () => {
    const dir = migrationProject({
      '001_buckets.sql': `
        INSERT INTO storage.buckets (id, name, public)
        VALUES ('avatars', 'avatars', true);
      `,
    });
    const { findings } = scanStorage(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
    assert.match(findings[0].title, /avatars.*public/i);
  });

  it('flags INSERT with columns in different order', () => {
    const dir = migrationProject({
      '001.sql': `
        INSERT INTO storage.buckets (id, public, name)
        VALUES ('docs', TRUE, 'docs');
      `,
    });
    const { findings } = scanStorage(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
  });

  it('no finding when public = false', () => {
    const dir = migrationProject({
      '001.sql': `
        INSERT INTO storage.buckets (id, name, public)
        VALUES ('private-docs', 'private-docs', false);
      `,
    });
    const { findings } = scanStorage(dir);
    assert.equal(findings.filter(f => f.title.includes('public')).length, 0);
  });

  it('no finding when public column is absent', () => {
    const dir = migrationProject({
      '001.sql': `
        INSERT INTO storage.buckets (id, name)
        VALUES ('uploads', 'uploads');
      `,
    });
    const { findings } = scanStorage(dir);
    assert.equal(findings.length, 0);
  });

  // ── Public bucket via SQL UPDATE ─────────────────────────────────────
  it('flags UPDATE storage.buckets SET public = true', () => {
    const dir = migrationProject({
      '002.sql': `
        UPDATE storage.buckets SET public = true WHERE id = 'documents';
      `,
    });
    const { findings } = scanStorage(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
    assert.match(findings[0].title, /documents/);
  });

  // ── Permissive storage.objects policy ────────────────────────────────
  it('flags USING (true) on storage.objects', () => {
    const dir = migrationProject({
      '003.sql': `
        CREATE POLICY "Public Read" ON storage.objects FOR SELECT
        USING (true);
      `,
    });
    const { findings } = scanStorage(dir);
    const hit = findings.find(f => f.title.includes('unrestricted access'));
    assert.ok(hit, 'should flag permissive storage policy');
    assert.equal(hit!.severity, 'critical');
  });

  it('flags WITH CHECK (true) on storage.objects', () => {
    const dir = migrationProject({
      '003.sql': `
        CREATE POLICY "Anyone Upload" ON storage.objects FOR INSERT
        WITH CHECK (true);
      `,
    });
    const { findings } = scanStorage(dir);
    const hit = findings.find(f => f.title.includes('unrestricted uploads'));
    assert.ok(hit);
    assert.equal(hit!.severity, 'critical');
  });

  it('no finding for authenticated storage policy', () => {
    const dir = migrationProject({
      '003.sql': `
        CREATE POLICY "Auth only" ON storage.objects FOR SELECT
        USING (auth.uid() IS NOT NULL);
      `,
    });
    const { findings } = scanStorage(dir);
    assert.equal(findings.length, 0);
  });

  // ── createBucket in code ─────────────────────────────────────────────
  it('flags createBucket with public: true in code', () => {
    const dir = tmpProject({
      'src/setup/storage.ts': `
        await supabase.storage.createBucket('profile-pics', {
          public: true,
          allowedMimeTypes: ['image/*'],
        })
      `,
    });
    const { findings } = scanStorage(dir);
    const hit = findings.find(f => f.title.includes('profile-pics'));
    assert.ok(hit);
    assert.equal(hit!.severity, 'critical');
  });

  it('no finding for createBucket with public: false', () => {
    const dir = tmpProject({
      'src/setup/storage.ts': `
        await supabase.storage.createBucket('private-files', { public: false })
      `,
    });
    const { findings } = scanStorage(dir);
    assert.equal(findings.length, 0);
  });

  // ── dangerouslyAllowBrowser ──────────────────────────────────────────
  it('flags dangerouslyAllowBrowser: true', () => {
    const dir = tmpProject({
      'src/lib/supabase.ts': `
        export const supabase = createClient(url, serviceKey, {
          auth: { dangerouslyAllowBrowser: true }
        })
      `,
    });
    const { findings } = scanStorage(dir);
    const hit = findings.find(f => f.title.includes('dangerouslyAllowBrowser'));
    assert.ok(hit);
    assert.equal(hit!.severity, 'warning');
  });

  // ── Long-lived signed URL ────────────────────────────────────────────
  it('flags signed URL with very long expiry', () => {
    const dir = tmpProject({
      'src/lib/files.ts': `
        const { data } = await supabase.storage
          .from('documents')
          .createSignedUrl('report.pdf', 31536000) // 1 year
      `,
    });
    const { findings } = scanStorage(dir);
    const hit = findings.find(f => f.title.includes('day expiry'));
    assert.ok(hit);
    assert.equal(hit!.severity, 'info');
  });

  it('no finding for short signed URL expiry', () => {
    const dir = tmpProject({
      'src/lib/files.ts': `
        const { data } = await supabase.storage
          .from('documents')
          .createSignedUrl('report.pdf', 3600) // 1 hour
      `,
    });
    const { findings } = scanStorage(dir);
    assert.equal(findings.filter(f => f.title.includes('expiry')).length, 0);
  });
});
