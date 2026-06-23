import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanAuth } from '../src/auth';

function tmpProject(routes: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-auth-'));
  for (const [rel, content] of Object.entries(routes)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

describe('Auth misuse scanner', () => {
  // ── getSession() for auth ──────────────────────────────────────────────
  it('flags getSession() used as auth gate in route', () => {
    const dir = tmpProject({
      'app/api/data/route.ts': `
        import { createServerClient } from '@supabase/ssr'
        export const GET = async (req: Request) => {
          const supabase = createServerClient(url, key, { cookies })
          const { data: { session } } = await supabase.auth.getSession()
          if (!session) return new Response('Unauthorized', { status: 401 })
          return Response.json({ ok: true })
        }
      `,
    });
    const { findings } = scanAuth(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
    assert.match(findings[0].title, /getSession/);
  });

  it('no finding when using getUser() for auth', () => {
    const dir = tmpProject({
      'app/api/data/route.ts': `
        export const GET = async (req: Request) => {
          const { data: { user }, error } = await supabase.auth.getUser()
          if (!user) return new Response('Unauthorized', { status: 401 })
          return Response.json({ ok: true })
        }
      `,
    });
    const { findings } = scanAuth(dir);
    assert.equal(findings.filter(f => f.title.includes('getSession')).length, 0);
  });

  // ── createBrowserClient in server ──────────────────────────────────────
  it('flags createBrowserClient in API route', () => {
    const dir = tmpProject({
      'app/api/items/route.ts': `
        import { createBrowserClient } from '@supabase/ssr'
        export const GET = async (req: Request) => {
          const supabase = createBrowserClient(url, anonKey)
          return Response.json({ ok: true })
        }
      `,
    });
    const { findings } = scanAuth(dir);
    const hit = findings.find(f => f.title.includes('createBrowserClient'));
    assert.ok(hit, 'should flag createBrowserClient');
    assert.equal(hit!.severity, 'critical');
  });

  it('no finding for createBrowserClient in client component', () => {
    const dir = tmpProject({
      'app/api/client-thing/route.ts': `
        'use client'
        import { createBrowserClient } from '@supabase/ssr'
        const supabase = createBrowserClient(url, anonKey)
      `,
    });
    const { findings } = scanAuth(dir);
    assert.equal(findings.filter(f => f.title.includes('createBrowserClient')).length, 0);
  });

  // ── auth.admin outside admin routes ───────────────────────────────────
  it('flags supabase.auth.admin in a non-admin route', () => {
    const dir = tmpProject({
      'app/api/users/route.ts': `
        export const DELETE = async (req: Request) => {
          const { data } = await supabase.auth.admin.deleteUser(userId)
          return Response.json({ ok: true })
        }
      `,
    });
    const { findings } = scanAuth(dir);
    const hit = findings.find(f => f.title.includes('auth.admin'));
    assert.ok(hit);
    assert.equal(hit!.severity, 'warning');
  });

  it('no finding for auth.admin inside /admin/ route', () => {
    const dir = tmpProject({
      'app/api/admin/users/route.ts': `
        export const DELETE = async (req: Request) => {
          await supabase.auth.admin.deleteUser(userId)
          return Response.json({ ok: true })
        }
      `,
    });
    const { findings } = scanAuth(dir);
    assert.equal(findings.filter(f => f.title.includes('auth.admin')).length, 0);
  });
});
