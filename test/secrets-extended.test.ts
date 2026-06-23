import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanSecrets } from '../src/secrets';

// Test fixture credentials assembled at runtime so source scanners
// (including this tool itself) don't flag this test file.
const F = {
  awsKeyId:    'AKIA' + 'IOSFODNN7EXAMPLE',
  awsSecret:   'wJalrXUtnFEMI' + '/K7MDENG/bPxRfiCYEXAMPLEKEY',
  sendgrid:    'SG.' + 'abcdefghijklmnopqrstuv.' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQR',
  twilioSid:   'AC' + '1234567890abcdef1234567890abcdef',
  pgConn:      'postgresql://myuser:secretpassword@db.example.com:5432/mydb',
  mongoConn:   'mongodb+srv://admin:p%40ssword@cluster0.example.mongodb.net/mydb',
  redisConn:   'redis://:mysecretpassword@redis.example.com:6379',
};

function tmpProject(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-sec2-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

describe('Extended secrets scanner', () => {
  // ── AWS ───────────────────────────────────────────────────────────────
  it('detects AWS Access Key ID', () => {
    const dir = tmpProject({
      'src/lib/aws.ts': `
        const accessKeyId = '${F.awsKeyId}'
      `,
    });
    const { findings } = scanSecrets(dir);
    const hit = findings.find(f => f.title.includes('AWS Access Key'));
    assert.ok(hit);
    assert.equal(hit!.severity, 'critical');
  });

  it('detects AWS Secret Access Key', () => {
    const dir = tmpProject({
      'src/lib/aws.ts': `
        const aws_secret_access_key = '${F.awsSecret}'
      `,
    });
    const { findings } = scanSecrets(dir);
    const hit = findings.find(f => f.title.includes('AWS Secret'));
    assert.ok(hit);
    assert.equal(hit!.severity, 'critical');
  });

  // ── SendGrid ──────────────────────────────────────────────────────────
  it('detects SendGrid API key', () => {
    const dir = tmpProject({
      'src/lib/email.ts': `
        const apiKey = '${F.sendgrid}'
      `,
    });
    const { findings } = scanSecrets(dir);
    const hit = findings.find(f => f.title.includes('SendGrid'));
    assert.ok(hit);
    assert.equal(hit!.severity, 'critical');
  });

  // ── Twilio ────────────────────────────────────────────────────────────
  it('detects Twilio Account SID', () => {
    const dir = tmpProject({
      'src/lib/sms.ts': `
        const accountSid = '${F.twilioSid}'
      `,
    });
    const { findings } = scanSecrets(dir);
    const hit = findings.find(f => f.title.includes('Twilio Account SID'));
    assert.ok(hit);
  });

  it('detects Twilio Auth Token', () => {
    const dir = tmpProject({
      'src/lib/sms.ts': `
        const TWILIO_AUTH_TOKEN = '1234567890abcdef1234567890abcdef'
      `,
    });
    const { findings } = scanSecrets(dir);
    const hit = findings.find(f => f.title.includes('Twilio Auth Token'));
    assert.ok(hit);
    assert.equal(hit!.severity, 'critical');
  });

  // ── Database connection strings ───────────────────────────────────────
  it('detects PostgreSQL connection string with password', () => {
    const dir = tmpProject({
      'src/lib/db.ts': `
        const connectionString = '${F.pgConn}'
      `,
    });
    const { findings } = scanSecrets(dir);
    const hit = findings.find(f => f.title.includes('PostgreSQL'));
    assert.ok(hit);
    assert.equal(hit!.severity, 'critical');
  });

  it('detects MongoDB Atlas connection string', () => {
    const dir = tmpProject({
      'src/lib/mongo.ts': `
        const uri = '${F.mongoConn}'
      `,
    });
    const { findings } = scanSecrets(dir);
    const hit = findings.find(f => f.title.includes('MongoDB'));
    assert.ok(hit);
  });

  it('detects Redis URL with password', () => {
    const dir = tmpProject({
      'src/lib/cache.ts': `
        const redisUrl = '${F.redisConn}'
      `,
    });
    const { findings } = scanSecrets(dir);
    const hit = findings.find(f => f.title.includes('Redis'));
    assert.ok(hit);
  });

  // ── Firebase service account ──────────────────────────────────────────
  it('detects Firebase service account in JSON file', () => {
    const dir = tmpProject({
      'firebase-admin.json': `{
        "type": "service_account",
        "project_id": "my-project",
        "private_key_id": "abc123",
        "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIE...\\n-----END PRIVATE KEY-----\\n"
      }`,
    });
    const { findings } = scanSecrets(dir);
    const hit = findings.find(f => f.title.includes('Firebase') || f.title.includes('service account'));
    assert.ok(hit, 'should find Firebase service account');
  });

  // ── .env gitignore check ──────────────────────────────────────────────
  it('flags .env not in .gitignore', () => {
    const dir = tmpProject({
      '.gitignore': 'node_modules\n.next\n',
      '.env': 'DATABASE_URL=postgres://user:pass@host/db\n',
    });
    const { findings } = scanSecrets(dir);
    const hit = findings.find(f => f.title.includes('.env') && f.title.includes('gitignore'));
    assert.ok(hit, 'should flag .env not gitignored');
    assert.equal(hit!.severity, 'critical');
  });

  it('no finding when .env is properly gitignored', () => {
    const dir = tmpProject({
      '.gitignore': 'node_modules\n.next\n.env\n',
      '.env': 'DATABASE_URL=postgres://user:pass@host/db\n',
    });
    const { findings } = scanSecrets(dir);
    assert.equal(findings.filter(f => f.title.includes('.env') && f.title.includes('gitignore')).length, 0);
  });

  it('no gitignore finding when .env wildcard covers it', () => {
    const dir = tmpProject({
      '.gitignore': 'node_modules\n.env*\n',
      '.env': 'SECRET=xxx\n',
      '.env.local': 'SECRET=yyy\n',
    });
    const { findings } = scanSecrets(dir);
    assert.equal(findings.filter(f => f.title.includes('gitignore')).length, 0);
  });

  // ── No false positives ────────────────────────────────────────────────
  it('no finding when AWS key ID is in process.env', () => {
    const dir = tmpProject({
      'src/lib/aws.ts': `
        const accessKeyId = process.env.AWS_ACCESS_KEY_ID
      `,
    });
    const { findings } = scanSecrets(dir);
    assert.equal(findings.filter(f => f.title.includes('AWS')).length, 0);
  });

  it('no finding for template literal variable', () => {
    const dir = tmpProject({
      'src/lib/db.ts': `
        const url = \`postgresql://\${user}:\${pass}@\${host}/\${db}\`
      `,
    });
    const { findings } = scanSecrets(dir);
    assert.equal(findings.filter(f => f.title.includes('PostgreSQL')).length, 0);
  });

  it('skips package.json for API key patterns', () => {
    const dir = tmpProject({
      'package.json': JSON.stringify({
        name: 'my-app', version: '1.0.0',
        scripts: { build: 'next build' },
      }, null, 2),
    });
    const { findings } = scanSecrets(dir);
    assert.equal(findings.length, 0);
  });
});
