import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanSecrets } from '../src/secrets';

// Test fixture keys are assembled at runtime so source scanners
// (including this tool itself) don't flag this test file.
const F = {
  stripe:  ['sk', 'live', 'ABCDEFGHIJKLMNOPQRSTUVWXyz12345678'].join('_'),
  openai:  'sk-' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop',
  ghPat:   'ghp_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
  jwt:     'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
           + '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'
           + '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
  svcRole: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
};

function tmpProject(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-secrets-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

describe('Secrets scanner', () => {
  it('clean project has no findings', () => {
    const dir = tmpProject({
      'src/lib/api.ts': `
        const key = process.env.STRIPE_SECRET_KEY
        export async function charge() {}
      `,
    });
    const { findings } = scanSecrets(dir);
    assert.equal(findings.length, 0);
  });

  it('detects hardcoded Stripe secret key', () => {
    const dir = tmpProject({
      'src/payments.ts': `const stripe = new Stripe('${F.stripe}')`,
    });
    const { findings } = scanSecrets(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
    assert.match(findings[0].title, /Stripe/);
  });

  it('detects hardcoded OpenAI key', () => {
    const dir = tmpProject({
      'src/ai.ts': `const openai = new OpenAI({ apiKey: '${F.openai}' })`,
    });
    const { findings } = scanSecrets(dir);
    assert.equal(findings.length, 1);
    assert.match(findings[0].title, /OpenAI/);
  });

  it('detects GitHub PAT', () => {
    const dir = tmpProject({
      'src/deploy.ts': `const token = '${F.ghPat}'`,
    });
    const { findings } = scanSecrets(dir);
    assert.equal(findings.length, 1);
    assert.match(findings[0].title, /GitHub/);
  });

  it('detects hardcoded JWT', () => {
    const dir = tmpProject({
      'src/test-utils.ts': `const token = '${F.jwt}'`,
    });
    const { findings } = scanSecrets(dir);
    assert.equal(findings.length, 1);
    assert.match(findings[0].title, /JWT/);
  });

  it('detects NEXT_PUBLIC_ service role exposure', () => {
    const dir = tmpProject({
      '.env.local': `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${F.svcRole}`,
    });
    const { findings } = scanSecrets(dir);
    assert.ok(findings.length > 0);
    assert.ok(findings.some(f => f.title.includes('service role')));
  });

  it('no false positive on process.env reference', () => {
    const dir = tmpProject({
      'src/config.ts': `
        const key = process.env.OPENAI_API_KEY
        const stripe = process.env.STRIPE_SECRET_KEY
      `,
    });
    const { findings } = scanSecrets(dir);
    assert.equal(findings.length, 0);
  });

  it('no false positive on import.meta.env', () => {
    const dir = tmpProject({
      'src/config.ts': `const key = import.meta.env.STRIPE_KEY`,
    });
    const { findings } = scanSecrets(dir);
    assert.equal(findings.length, 0);
  });

  it('skips .env.example files', () => {
    const dir = tmpProject({
      '.env.example': `
        STRIPE_SECRET_KEY=sk_test_your_key_here
        OPENAI_API_KEY=sk-your-key-here
      `,
    });
    const { findings } = scanSecrets(dir);
    assert.equal(findings.length, 0);
  });
});
