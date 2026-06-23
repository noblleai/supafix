import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanRoutes } from '../src/routes';

function tmpProject(routes: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-routes-'));
  for (const [relPath, content] of Object.entries(routes)) {
    const full = path.join(dir, relPath);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

describe('Routes scanner', () => {
  it('no finding when handler uses supabase auth', () => {
    const dir = tmpProject({
      'app/api/items/route.ts': `
        import { createClient } from '@/lib/supabase/server'
        export const GET = async (req: Request) => {
          const supabase = createClient()
          const { data: { user } } = await supabase.auth.getUser()
          if (!user) return new Response('Unauthorized', { status: 401 })
          return Response.json({ ok: true })
        }
      `,
    });
    const { findings } = scanRoutes(dir);
    assert.equal(findings.length, 0);
  });

  it('warns on bare export with no auth', () => {
    const dir = tmpProject({
      'app/api/data/route.ts': `
        export const GET = async (req: Request) => {
          return Response.json({ data: 'public?' })
        }
      `,
    });
    const { findings } = scanRoutes(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'warning');
    assert.match(findings[0].title, /GET/);
  });

  it('no finding for wrapped handler (withAuth pattern)', () => {
    const dir = tmpProject({
      'app/api/users/route.ts': `
        import { withAuth } from '@/lib/middleware'
        export const GET = withAuth(async (req, { user }) => {
          return Response.json({ user })
        })
      `,
    });
    const { findings } = scanRoutes(dir);
    assert.equal(findings.length, 0);
  });

  it('skips webhook routes automatically', () => {
    const dir = tmpProject({
      'app/api/webhooks/stripe/route.ts': `
        export const POST = async (req: Request) => {
          return new Response('ok')
        }
      `,
    });
    const { findings } = scanRoutes(dir);
    assert.equal(findings.length, 0);
  });

  it('skips auth callback routes', () => {
    const dir = tmpProject({
      'app/api/auth/callback/route.ts': `
        export const GET = async (req: Request) => {
          return new Response('ok')
        }
      `,
    });
    const { findings } = scanRoutes(dir);
    assert.equal(findings.length, 0);
  });

  it('no finding for next-auth getServerSession', () => {
    const dir = tmpProject({
      'app/api/profile/route.ts': `
        import { getServerSession } from 'next-auth'
        export const GET = async (req: Request) => {
          const session = await getServerSession()
          if (!session) return new Response('Unauthorized', { status: 401 })
          return Response.json(session)
        }
      `,
    });
    const { findings } = scanRoutes(dir);
    assert.equal(findings.length, 0);
  });

  it('no finding for Clerk auth()', () => {
    const dir = tmpProject({
      'app/api/tasks/route.ts': `
        import { auth } from '@clerk/nextjs/server'
        export const GET = async (req: Request) => {
          const { userId } = auth()
          if (!userId) return new Response('Unauthorized', { status: 401 })
          return Response.json({ ok: true })
        }
      `,
    });
    const { findings } = scanRoutes(dir);
    assert.equal(findings.length, 0);
  });

  it('returns stats', () => {
    const dir = tmpProject({
      'app/api/a/route.ts': `export const GET = async () => Response.json({})`,
      'app/api/b/route.ts': `export const POST = async () => Response.json({})`,
    });
    const { stats } = scanRoutes(dir);
    assert.ok((stats.routeFiles ?? 0) >= 2);
    assert.ok((stats.handlers ?? 0) >= 2);
  });
});
