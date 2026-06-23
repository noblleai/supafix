import fs from 'fs';
import path from 'path';
import { walk, findDirs } from './walk.js';
import type { Finding, ScanStats } from './types.js';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;

// Candidate API route directories — covers Next.js App Router, Pages Router, SvelteKit, Nuxt
const ROUTE_DIRS = [
  'app/api',
  'src/app/api',
  'apps/web/app/api',
  'pages/api',
  'src/pages/api',
  'src/routes',
  'routes',
  'api',
];

// Patterns that make a route file explicitly public (webhooks, health checks, etc.)
const PUBLIC_PATTERNS = [
  /\/webhook/i,
  /\/webhooks/i,
  /\/callback/i,
  /\/health/i,
  /\/ping/i,
  /\/openapi/i,
  /\/cron\//i,
  /\/auth\//i,
  /\/oauth/i,
];

// Patterns that indicate auth is present somewhere in the file
// Generic enough to cover Next-Auth, Supabase, Clerk, Auth.js, Lucia, etc.
const AUTH_INDICATORS = [
  /getServerSession/,
  /getSession/,
  /getUser\s*\(/,
  /verifyJwt/i,
  /verifyToken/i,
  /requireAuth/i,
  /withAuth\s*\(/,
  /authenticate\s*\(/,
  /\.auth\.(getUser|getSession|admin\.getUserById)/,
  /currentUser\s*\(/,
  /auth\(\)/,                   // Clerk
  /validateRequest\s*\(/,       // Lucia
  /getToken\s*\(/,              // next-auth
  /jwt\.verify\s*\(/,
  /Bearer\s/,
  /Authorization/,
];

export function scanRoutes(
  root: string,
  extraDirs: string[] = [],
): { findings: Finding[]; stats: Partial<ScanStats> } {
  const dirs = findDirs(root, [...ROUTE_DIRS, ...extraDirs]);
  if (dirs.length === 0) return { findings: [], stats: { routeFiles: 0, handlers: 0 } };

  // Only look at files named route.ts/js (Next.js App Router) or *.ts in pages/api
  const files = dirs.flatMap(d => {
    const isAppRouter = d.includes('/api');
    if (isAppRouter) {
      return walk(d, ['.ts', '.js', '.tsx', '.jsx']).filter(f =>
        path.basename(f).startsWith('route.'),
      );
    }
    return walk(d, ['.ts', '.js', '.tsx', '.jsx']);
  });

  const findings: Finding[] = [];
  let handlers = 0;

  for (const file of files) {
    const rel = path.relative(root, file);

    if (PUBLIC_PATTERNS.some(p => p.test(rel))) continue;

    let content: string;
    try {
      content = fs.readFileSync(file, 'utf-8');
    } catch {
      continue;
    }

    const lines = content.split('\n');
    const fileHasAuth = AUTH_INDICATORS.some(p => p.test(content));

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const method of METHODS) {
        if (!isBareExport(line, method)) continue;
        handlers++;

        // If the file contains any auth indicator, consider it protected.
        // Only flag when we see zero auth signals in the entire file.
        if (!fileHasAuth) {
          findings.push({
            severity: 'warning',
            category: 'routes',
            title: `${method} handler in ${rel} has no auth`,
            detail: 'No authentication pattern detected. If this route is intentionally public, add it to the ignore list.',
            file: rel,
            line: i + 1,
            fix: `Protect with your auth library, e.g. const { data: { user } } = await supabase.auth.getUser(token)`,
          });
          break; // one finding per file is enough
        }
      }
    }
  }

  return {
    findings,
    stats: { routeFiles: files.length, handlers },
  };
}

function isBareExport(line: string, method: string): boolean {
  // export const GET = async (
  // export async function GET(
  return (
    new RegExp(`export\\s+const\\s+${method}\\s*=\\s*async`).test(line) ||
    new RegExp(`export\\s+async\\s+function\\s+${method}\\s*\\(`).test(line)
  );
}
