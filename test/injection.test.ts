import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanInjection } from '../src/injection';

function tmpProject(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-inj-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

describe('Injection & mass-assignment scanner', () => {
  // ── Template literal injection ────────────────────────────────────────
  it('flags template literal in .rpc() argument', () => {
    const dir = tmpProject({
      'src/lib/db.ts': `
        async function getRows(table: string) {
          return supabase.rpc('query', { sql: \`SELECT * FROM \${table}\` })
        }
      `,
    });
    const { findings } = scanInjection(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
    assert.match(findings[0].title, /SQL injection/);
  });

  it('flags template literal in .from().select()', () => {
    const dir = tmpProject({
      'src/lib/data.ts': `
        const { data } = await supabase.from('posts').select(\`id, \${extraField}\`)
      `,
    });
    const { findings } = scanInjection(dir);
    assert.equal(findings.length, 1);
    assert.match(findings[0].title, /SQL injection/);
  });

  it('no finding for normal string in .select()', () => {
    const dir = tmpProject({
      'src/lib/data.ts': `
        const { data } = await supabase.from('posts').select('id, title, body')
      `,
    });
    const { findings } = scanInjection(dir);
    assert.equal(findings.length, 0);
  });

  it('no finding in client components', () => {
    const dir = tmpProject({
      'src/components/Feed.tsx': `
        'use client'
        const { data } = await supabase.from('posts').select(\`id, \${col}\`)
      `,
    });
    const { findings } = scanInjection(dir);
    assert.equal(findings.length, 0);
  });

  // ── Mass assignment ───────────────────────────────────────────────────
  it('flags direct req.json() piped into insert', () => {
    const dir = tmpProject({
      'src/lib/handler.ts': `
        export async function createPost(req: Request) {
          const { data } = await supabase.from('posts').insert(await req.json())
          return data
        }
      `,
    });
    const { findings } = scanInjection(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
    assert.match(findings[0].title, /Mass assignment/);
  });

  it('flags spread of body into insert', () => {
    const dir = tmpProject({
      'src/lib/handler.ts': `
        const body = await req.json()
        await supabase.from('users').insert({ ...body, created_at: new Date() })
      `,
    });
    const { findings } = scanInjection(dir);
    const hit = findings.find(f => f.title.includes('Mass assignment'));
    assert.ok(hit, 'should flag body spread');
  });

  it('no finding when fields are explicitly destructured', () => {
    const dir = tmpProject({
      'src/lib/handler.ts': `
        const { title, content } = await req.json()
        await supabase.from('posts').insert({ title, content, user_id: user.id })
      `,
    });
    const { findings } = scanInjection(dir);
    assert.equal(findings.filter(f => f.title.includes('Mass assignment')).length, 0);
  });

  // ── IDOR ──────────────────────────────────────────────────────────────
  it('flags .eq("id", params.id) without ownership check in route', () => {
    const dir = tmpProject({
      'app/api/orders/[id]/route.ts': `
        export const GET = async (req: Request, { params }: { params: { id: string } }) => {
          const { data } = await supabase.from('orders').select('*').eq('id', params.id)
          return Response.json(data)
        }
      `,
    });
    const { findings } = scanInjection(dir);
    const hit = findings.find(f => f.title.includes('IDOR'));
    assert.ok(hit, 'should flag IDOR');
    assert.equal(hit!.severity, 'info');
  });

  it('no finding when ownership check is present', () => {
    const dir = tmpProject({
      'app/api/orders/[id]/route.ts': `
        export const GET = async (req: Request, { params }: any) => {
          const { data } = await supabase
            .from('orders')
            .select('*')
            .eq('id', params.id)
            .eq('user_id', user.id)
          return Response.json(data)
        }
      `,
    });
    const { findings } = scanInjection(dir);
    assert.equal(findings.filter(f => f.title.includes('IDOR')).length, 0);
  });
});
