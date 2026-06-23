import fs from 'fs';
import path from 'path';
import { walk, findDirs } from './walk.js';
import type { Finding, ScanStats } from './types.js';

interface Pattern {
  name: string;
  re: RegExp;
  severity: Finding['severity'];
  fix: string;
}

const PATTERNS: Pattern[] = [
  // ── API Keys ────────────────────────────────────────────────────────────
  {
    name: 'Stripe secret key',
    re: /sk_(live|test)_[A-Za-z0-9]{24,}/,
    severity: 'critical',
    fix: 'Rotate immediately at dashboard.stripe.com. Move to process.env.STRIPE_SECRET_KEY.',
  },
  {
    name: 'OpenAI API key',
    re: /sk-(?:proj-)?[A-Za-z0-9]{40,}/,
    severity: 'critical',
    fix: 'Rotate at platform.openai.com/api-keys. Move to process.env.OPENAI_API_KEY.',
  },
  {
    name: 'Anthropic API key',
    re: /sk-ant-[A-Za-z0-9\-_]{80,}/,
    severity: 'critical',
    fix: 'Rotate at console.anthropic.com. Move to process.env.ANTHROPIC_API_KEY.',
  },
  {
    name: 'GitHub personal access token',
    re: /ghp_[A-Za-z0-9]{36}/,
    severity: 'critical',
    fix: 'Revoke immediately at github.com/settings/tokens. Never commit tokens.',
  },
  {
    name: 'GitHub OAuth app secret',
    re: /ghs_[A-Za-z0-9]{36}/,
    severity: 'critical',
    fix: 'Revoke and regenerate at github.com/settings/developers.',
  },
  {
    name: 'GitHub Actions token',
    re: /gha_[A-Za-z0-9]{36}/,
    severity: 'critical',
    fix: 'GitHub Actions tokens are short-lived, but should never appear in source.',
  },
  {
    name: 'Slack bot token',
    re: /xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+/,
    severity: 'critical',
    fix: 'Revoke in Slack app settings. Move to environment variables.',
  },
  {
    name: 'Slack OAuth token',
    re: /xoxp-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]+/,
    severity: 'critical',
    fix: 'Revoke in Slack app settings. Move to environment variables.',
  },
  {
    name: 'SendGrid API key',
    re: /SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{22,}/,
    severity: 'critical',
    fix: 'Rotate at app.sendgrid.com/settings/api_keys. Move to process.env.SENDGRID_API_KEY.',
  },
  {
    name: 'Twilio Account SID',
    re: /\bAC[0-9a-f]{32}\b/,
    severity: 'warning',
    fix: 'Account SIDs are semi-public but should not be committed. Move to process.env.TWILIO_ACCOUNT_SID.',
  },
  {
    name: 'Twilio Auth Token',
    re: /(?:twilio[_\-.]?(?:auth[_\-.]?)?token|TWILIO[_\-.]?AUTH[_\-.]?TOKEN)\s*[=:]\s*['"]?[0-9a-f]{32}['"]?/i,
    severity: 'critical',
    fix: 'Rotate at console.twilio.com. Move to process.env.TWILIO_AUTH_TOKEN.',
  },
  // ── Cloud Providers ─────────────────────────────────────────────────────
  {
    name: 'AWS Access Key ID',
    re: /\bAKIA[0-9A-Z]{16}\b/,
    severity: 'critical',
    fix: 'Deactivate at aws.amazon.com/iam and rotate. Move to environment variables or IAM roles.',
  },
  {
    name: 'AWS Secret Access Key',
    re: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|aws[-_.]secret)\s*[=:]\s*['"]?[0-9a-zA-Z/+=]{40}['"]?/i,
    severity: 'critical',
    fix: 'Deactivate at aws.amazon.com/iam. Use IAM roles for EC2/Lambda instead of static keys.',
  },
  // ── Supabase-specific ───────────────────────────────────────────────────
  {
    name: 'Supabase service role key exposed to browser',
    re: /NEXT_PUBLIC_[A-Z_]*SERVICE_ROLE[A-Z_]*/,
    severity: 'critical',
    fix: 'NEXT_PUBLIC_ variables are embedded in client bundles. Service role keys bypass RLS entirely — never expose them to the browser.',
  },
  // ── Connection Strings ──────────────────────────────────────────────────
  {
    name: 'PostgreSQL connection string with credentials',
    re: /postgres(?:ql)?:\/\/[^:\/\s@"']{1,}:[^@\/\s"']{1,}@[^\/\s"']+/,
    severity: 'critical',
    fix: 'Move to DATABASE_URL environment variable. Rotate the database password.',
  },
  {
    name: 'MySQL connection string with credentials',
    re: /mysql(?:2)?:\/\/[^:\/\s@"']{1,}:[^@\/\s"']{1,}@[^\/\s"']+/,
    severity: 'critical',
    fix: 'Move to DATABASE_URL environment variable. Rotate the database password.',
  },
  {
    name: 'MongoDB connection string with credentials',
    re: /mongodb(?:\+srv)?:\/\/[^:\/\s@"']{1,}:[^@\/\s"']{1,}@[^\/\s"']+/,
    severity: 'critical',
    fix: 'Move to MONGODB_URI environment variable. Rotate the credentials.',
  },
  {
    name: 'Redis connection string with credentials',
    re: /rediss?:\/\/:[^@\/\s"']{1,}@[^\/\s"']+/,
    severity: 'critical',
    fix: 'Move to REDIS_URL environment variable. Rotate the Redis password.',
  },
  {
    name: 'Basic auth credentials in URL',
    re: /https?:\/\/[^:\/\s@"']{1,}:[^@\/\s"']{6,}@(?!localhost|127\.0\.0\.1)/,
    severity: 'critical',
    fix: 'Embed credentials in environment variables, not URLs.',
  },
  // ── Cryptographic Material ──────────────────────────────────────────────
  {
    name: 'Private key block',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    severity: 'critical',
    fix: 'Never commit private keys. Use a secrets manager or environment variable.',
  },
  {
    name: 'Firebase service account private key',
    re: /-----BEGIN PRIVATE KEY-----[\\n\s]+[A-Za-z0-9+/=\\n\s]{50,}/,
    severity: 'critical',
    fix: 'Revoke this service account key at console.firebase.google.com. Use workload identity federation instead.',
  },
  {
    name: 'Hardcoded JWT token',
    re: /eyJ[A-Za-z0-9\-_]{30,}\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/,
    severity: 'critical',
    fix: 'Remove this token from source. If it is a real token, revoke it — it may still be valid.',
  },
];

// Patterns only meaningful in JSON / config files (too noisy in code)
const JSON_PATTERNS: Pattern[] = [
  {
    name: 'Firebase service account credential',
    re: /"type"\s*:\s*"service_account"/,
    severity: 'critical',
    fix: 'Never commit Firebase service account JSON. Use environment variables or Google Cloud Workload Identity.',
  },
  {
    name: 'Google Cloud service account key',
    re: /"private_key_id"\s*:/,
    severity: 'critical',
    fix: 'Revoke this key at console.cloud.google.com/iam-admin/serviceaccounts and use workload identity.',
  },
];

const SOURCE_DIRS = [
  'app', 'src', 'components', 'lib', 'utils', 'server', 'api',
  'apps/web/app', 'apps/web/lib', 'apps/web/src',
];

const CODE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];
const CONFIG_EXTENSIONS = ['.json', '.yaml', '.yml', '.toml', '.config.js'];

const SKIP_FILES = new Set([
  '.env.example', '.env.sample', '.env.template', '.env.test',
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'tsconfig.json', 'tsconfig.base.json',
]);

const SKIP_CONFIG_DIRS = [
  'node_modules', '.git', '.next', 'dist', 'build', '.turbo', 'coverage',
];

// .env files with real values (not examples)
const ENV_FILES_TO_CHECK = [
  '.env', '.env.local', '.env.production', '.env.development', '.env.staging',
];

export function scanSecrets(
  root: string,
  extraDirs: string[] = [],
): { findings: Finding[]; stats: Partial<ScanStats> } {
  const dirs = findDirs(root, [...SOURCE_DIRS, ...extraDirs]);
  const codeFiles = dirs.flatMap(d => walk(d, CODE_EXTENSIONS));

  // Config/JSON files from common locations (not recursive into node_modules)
  const configFiles = collectConfigFiles(root);

  // .env files at project root
  const envFiles = ENV_FILES_TO_CHECK
    .map(f => path.join(root, f))
    .filter(f => {
      try { fs.accessSync(f); return true; } catch { return false; }
    })
    .filter(f => !SKIP_FILES.has(path.basename(f)));

  const findings: Finding[] = [];
  let linesScanned = 0;

  // ── Code files ────────────────────────────────────────────────────────
  for (const file of codeFiles) {
    const rel = path.relative(root, file);
    if (/\.(spec|test)\.[jt]sx?$/.test(file) || rel.includes('__fixtures__')) continue;

    let content: string;
    try { content = fs.readFileSync(file, 'utf-8'); } catch { continue; }

    const lines = content.split('\n');
    linesScanned += lines.length;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (shouldSkipLine(line)) continue;

      for (const p of PATTERNS) {
        if (p.re.test(line)) {
          findings.push({
            severity: p.severity,
            category: 'secrets',
            title: `${p.name} found in source`,
            detail: 'A hardcoded credential was found. Treat any committed secret as compromised — bots scan public repos in minutes.',
            file: rel,
            line: i + 1,
            fix: p.fix,
          });
          break;
        }
      }
    }
  }

  // ── Config / JSON / YAML files ─────────────────────────────────────────
  for (const file of configFiles) {
    const rel = path.relative(root, file);
    if (SKIP_FILES.has(path.basename(file))) continue;
    if (/\.(spec|test)\./.test(file)) continue;

    let content: string;
    try { content = fs.readFileSync(file, 'utf-8'); } catch { continue; }

    const lines = content.split('\n');
    linesScanned += lines.length;

    const allPatterns = [...PATTERNS, ...JSON_PATTERNS];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // For JSON/YAML we skip process.env references but not comment skipping (# is valid YAML)
      if (line.includes('process.env.') || line.includes('import.meta.env.')) continue;

      for (const p of allPatterns) {
        if (p.re.test(line)) {
          findings.push({
            severity: p.severity,
            category: 'secrets',
            title: `${p.name} found in ${path.extname(file)} file`,
            detail: 'A hardcoded credential was found in a config file. Config files are often committed accidentally.',
            file: rel,
            line: i + 1,
            fix: p.fix,
          });
          break;
        }
      }
    }
  }

  // ── .env files ─────────────────────────────────────────────────────────
  for (const file of envFiles) {
    const rel = path.relative(root, file);

    let content: string;
    try { content = fs.readFileSync(file, 'utf-8'); } catch { continue; }

    const lines = content.split('\n');
    linesScanned += lines.length;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim().startsWith('#')) continue;

      for (const p of PATTERNS) {
        if (p.re.test(line)) {
          findings.push({
            severity: p.severity,
            category: 'secrets',
            title: `${p.name} found in ${path.basename(file)}`,
            detail: `.env files containing real secrets must be in .gitignore. If this file is tracked by git, the secret is already in your history.`,
            file: rel,
            line: i + 1,
            fix: p.fix,
          });
          break;
        }
      }
    }
  }

  // ── .gitignore check ───────────────────────────────────────────────────
  const gitignoreFindings = checkEnvGitignore(root);
  findings.push(...gitignoreFindings);

  const allFiles = [...codeFiles, ...configFiles, ...envFiles];
  return {
    findings,
    stats: { sourceFiles: allFiles.length, linesScanned },
  };
}

// ─── helpers ─────────────────────────────────────────────────────────────────

function shouldSkipLine(line: string): boolean {
  const t = line.trim();
  return (
    t.startsWith('//') ||
    t.startsWith('#') ||
    t.startsWith('*') ||
    line.includes('process.env.') ||
    line.includes('import.meta.env.') ||
    line.includes('${') // template literal — value comes from a variable
  );
}

function collectConfigFiles(root: string): string[] {
  const results: string[] = [];

  function recurse(dir: string, depth: number): void {
    if (depth > 6) return;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

    for (const entry of entries) {
      const name = entry.name;
      if (SKIP_CONFIG_DIRS.some(d => name === d)) continue;

      const full = path.join(dir, name);
      if (entry.isDirectory()) {
        recurse(full, depth + 1);
      } else if (entry.isFile()) {
        const ext = path.extname(name);
        if (CONFIG_EXTENSIONS.includes(ext) || CONFIG_EXTENSIONS.some(e => name.endsWith(e))) {
          results.push(full);
        }
      }
    }
  }

  recurse(root, 0);
  return results;
}

function checkEnvGitignore(root: string): Finding[] {
  const findings: Finding[] = [];
  const gitignorePath = path.join(root, '.gitignore');

  let gitignore = '';
  try { gitignore = fs.readFileSync(gitignorePath, 'utf-8'); } catch { return findings; }

  const isIgnored = (pattern: string): boolean =>
    gitignore.split('\n').some(line => {
      const l = line.trim();
      return l === pattern || l === `/${pattern}` || l === `*.env` || l === `.env*`;
    });

  for (const envFile of ENV_FILES_TO_CHECK) {
    const fullPath = path.join(root, envFile);
    let exists = false;
    try { fs.accessSync(fullPath); exists = true; } catch { /* not found */ }
    if (!exists) continue;

    if (!isIgnored(envFile)) {
      findings.push({
        severity: 'critical',
        category: 'secrets',
        title: `${envFile} exists but is not in .gitignore`,
        detail:
          `${envFile} is not listed in .gitignore. If it contains real secrets and gets committed, those secrets are in your git history permanently — even if the file is later removed.`,
        file: envFile,
        fix: `Add "${envFile}" to your .gitignore. Audit git history for any previous commits of this file.`,
      });
    }
  }

  return findings;
}
