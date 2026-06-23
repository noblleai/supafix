import path from 'path';
import { scanRLS } from './rls.js';
import { scanRLSAdvanced } from './rls-advanced.js';
import { scanRoutes } from './routes.js';
import { scanAuth } from './auth.js';
import { scanInjection } from './injection.js';
import { scanStorage } from './storage.js';
import { scanSecrets } from './secrets.js';
import { scanEdgeFunctions } from './edge-functions.js';
import { printReport, printBadge, printJson, computeGrade } from './report.js';
import { applyFixes, printFixReport } from './fix.js';
import type { ScanResult, ScanStats, Finding } from './types.js';

const HELP = `
  supaguard — security audit for Supabase projects

  Usage
    npx supaguard [options]

  Options
    --cwd <path>      Project root to scan (default: current directory)
    --no-rls          Skip RLS policy checks
    --no-routes       Skip API route auth checks
    --no-storage      Skip storage security checks
    --no-secrets      Skip secret / credential scanning
    --no-injection    Skip injection / mass-assignment checks
    --no-edge         Skip Edge Function checks
    --fix             Auto-fix what can be fixed (generates migration, updates .gitignore)
    --badge           Print a README badge for your security grade and exit
    --json            Machine-readable JSON output
    --version         Print version
    --help            Show this help

  Config
    Create supaguard.config.json in your project root:
    {
      "migrationDirs": ["supabase/migrations"],
      "routeDirs":     ["app/api"],
      "ignore":        ["**/generated/**", "supabase/migrations/old_seed.sql"]
    }

  Exit codes
    0   Clean
    1   Issues found
    2   Fatal error

  Examples
    npx supaguard
    npx supaguard --cwd ./apps/web --no-secrets
    npx supaguard --fix
    npx supaguard --badge
    npx supaguard --json | jq '.findings[] | select(.severity=="critical")'
`;

interface Config {
  migrationDirs: string[];
  routeDirs: string[];
  ignore: string[];
}

function loadProjectConfig(cwd: string): Partial<Config> {
  for (const name of ['supaguard.config.json', '.supaguard.json']) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      return require(path.join(cwd, name)) as Partial<Config>;
    } catch { /* not found */ }
  }
  return {};
}

function matchesIgnorePattern(file: string, pattern: string): boolean {
  if (file === pattern) return true;
  // Directory prefix
  const dirPattern = pattern.endsWith('/') ? pattern : pattern + '/';
  if (file.startsWith(dirPattern)) return true;
  // Simple glob → regex (supports ** and *)
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const regexStr = escaped
    .replace(/\\\*\\\*/g, '.*')
    .replace(/\\\*/g, '[^/]*')
    .replace(/\\\?/g, '[^/]');
  try {
    return new RegExp(`^${regexStr}$`).test(file);
  } catch {
    return false;
  }
}

// Mark findings that can be auto-fixed
function markAutoFixable(findings: Finding[]): Finding[] {
  return findings.map(f => {
    const fixable =
      (f.category === 'rls' && f.title.includes('no Row Level Security')) ||
      (f.category === 'rls' && f.title.includes('no policies')) ||
      (f.category === 'secrets' && f.title.includes('not in .gitignore'));
    return fixable ? { ...f, autoFixable: true } : f;
  });
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(HELP + '\n');
    process.exit(0);
  }

  if (argv.includes('--version') || argv.includes('-v')) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      process.stdout.write((require('../package.json') as { version: string }).version + '\n');
    } catch { process.stdout.write('0.2.0\n'); }
    process.exit(0);
  }

  const cwdIdx = argv.indexOf('--cwd');
  const cwd = cwdIdx !== -1 ? path.resolve(argv[cwdIdx + 1]) : process.cwd();

  const noRls       = argv.includes('--no-rls');
  const noRoutes    = argv.includes('--no-routes');
  const noStorage   = argv.includes('--no-storage');
  const noSecrets   = argv.includes('--no-secrets');
  const noInjection = argv.includes('--no-injection');
  const noEdge      = argv.includes('--no-edge');
  const json        = argv.includes('--json');
  const fix         = argv.includes('--fix');
  const badge       = argv.includes('--badge');

  const cfg = loadProjectConfig(cwd);
  const ignorePatterns = cfg.ignore ?? [];

  const stats: ScanStats = {
    migrationFiles: 0, tables: 0, policies: 0,
    routeFiles: 0, handlers: 0, sourceFiles: 0, linesScanned: 0,
  };
  const findings: ScanResult['findings'] = [];
  const t0 = Date.now();

  if (!noRls) {
    const r = scanRLS(cwd, cfg.migrationDirs ?? []);
    findings.push(...r.findings);
    Object.assign(stats, r.stats);
  }

  if (!noRls) {
    const r = scanRLSAdvanced(cwd, cfg.migrationDirs ?? []);
    findings.push(...r.findings);
  }

  if (!noStorage) {
    const r = scanStorage(cwd);
    findings.push(...r.findings);
  }

  if (!noRoutes) {
    const r = scanRoutes(cwd, cfg.routeDirs ?? []);
    findings.push(...r.findings);
    Object.assign(stats, r.stats);
  }

  if (!noRoutes) {
    const r = scanAuth(cwd, cfg.routeDirs ?? []);
    findings.push(...r.findings);
  }

  if (!noInjection) {
    const r = scanInjection(cwd, []);
    findings.push(...r.findings);
  }

  if (!noSecrets) {
    const r = scanSecrets(cwd, []);
    findings.push(...r.findings);
    Object.assign(stats, r.stats);
  }

  if (!noEdge) {
    const r = scanEdgeFunctions(cwd);
    findings.push(...r.findings);
  }

  // Deduplicate by file+line+title
  const seen = new Set<string>();
  let deduped = findings.filter(f => {
    const key = `${f.file}:${f.line}:${f.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Apply ignore patterns
  if (ignorePatterns.length > 0) {
    deduped = deduped.filter(f =>
      !f.file || !ignorePatterns.some(p => matchesIgnorePattern(f.file!, p)),
    );
  }

  // Mark auto-fixable
  deduped = markAutoFixable(deduped);

  const grade = computeGrade(deduped);
  const result: ScanResult = { findings: deduped, stats, ms: Date.now() - t0, grade };

  // ── --badge: just print the badge and exit ────────────────────────────────
  if (badge) {
    printBadge(deduped);
    process.exit(deduped.length > 0 ? 1 : 0);
  }

  // ── --fix: apply auto-fixes then print what happened ─────────────────────
  if (fix) {
    process.stdout.write('\n');
    process.stdout.write(`  supaguard  v${getVersion()}  --fix mode\n`);
    process.stdout.write('  ─────────────────────────────────────────────\n');
    const { fixed, unfixable } = applyFixes(cwd, deduped);
    printFixReport(fixed, unfixable);
    process.exit(deduped.length > 0 ? 1 : 0);
  }

  if (json) printJson(result);
  else printReport(result);

  process.exit(deduped.length > 0 ? 1 : 0);
}

function getVersion(): string {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return (require('../package.json') as { version: string }).version;
  } catch { return '0.2.0'; }
}

main().catch(err => {
  process.stderr.write(`Fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(2);
});
