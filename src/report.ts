import type { ScanResult, Finding, Grade } from './types.js';

const NO_COLOR = !!process.env.NO_COLOR || process.env.TERM === 'dumb';

const c = {
  red:    (s: string) => NO_COLOR ? s : `\x1b[31m${s}\x1b[0m`,
  yellow: (s: string) => NO_COLOR ? s : `\x1b[33m${s}\x1b[0m`,
  green:  (s: string) => NO_COLOR ? s : `\x1b[32m${s}\x1b[0m`,
  cyan:   (s: string) => NO_COLOR ? s : `\x1b[36m${s}\x1b[0m`,
  bold:   (s: string) => NO_COLOR ? s : `\x1b[1m${s}\x1b[0m`,
  dim:    (s: string) => NO_COLOR ? s : `\x1b[2m${s}\x1b[0m`,
  white:  (s: string) => NO_COLOR ? s : `\x1b[97m${s}\x1b[0m`,
};

function badge(severity: Finding['severity']): string {
  switch (severity) {
    case 'critical': return c.red(c.bold('CRITICAL'));
    case 'warning':  return c.yellow(c.bold('WARNING '));
    case 'info':     return c.cyan(c.bold('INFO    '));
  }
}

function sectionIcon(severity: Finding['severity']): string {
  switch (severity) {
    case 'critical': return c.red('✖');
    case 'warning':  return c.yellow('⚠');
    case 'info':     return c.cyan('·');
  }
}

export function computeGrade(findings: Finding[]): Grade {
  const critical = findings.filter(f => f.severity === 'critical').length;
  const warnings  = findings.filter(f => f.severity === 'warning').length;
  if (critical === 0 && warnings === 0) return 'A';
  if (critical === 0 && warnings <= 2)  return 'B';
  if (critical === 0)                   return 'C';
  if (critical <= 2)                    return 'D';
  return 'F';
}

function gradeColor(grade: Grade): string {
  switch (grade) {
    case 'A': return 'brightgreen';
    case 'B': return 'green';
    case 'C': return 'yellow';
    case 'D': return 'orange';
    case 'F': return 'red';
  }
}

function gradeLabel(grade: Grade): string {
  switch (grade) {
    case 'A': return 'passing';
    case 'B': return 'good';
    case 'C': return 'needs work';
    case 'D': return 'at risk';
    case 'F': return 'critical';
  }
}

function colorGrade(grade: Grade): string {
  switch (grade) {
    case 'A': return c.green(c.bold(grade));
    case 'B': return c.green(c.bold(grade));
    case 'C': return c.yellow(c.bold(grade));
    case 'D': return c.red(c.bold(grade));
    case 'F': return c.red(c.bold(grade));
  }
}

export function badgeUrl(findings: Finding[]): string {
  const grade = computeGrade(findings);
  const critical = findings.filter(f => f.severity === 'critical').length;
  const color = gradeColor(grade);
  const label = critical > 0
    ? `supabase--guard%3A+${grade}+%E2%80%94+${critical}+critical`
    : `supabase--guard%3A+${grade}`;
  return `https://img.shields.io/badge/${label}-${color}?logo=supabase&logoColor=white`;
}

export function badgeMarkdown(findings: Finding[]): string {
  return `[![supafix](${badgeUrl(findings)})](https://github.com/noblleai/supafix)`;
}

export function printReport(result: ScanResult): void {
  const { findings, stats, ms, grade } = result;

  process.stdout.write('\n');
  process.stdout.write(c.bold('  supafix') + c.dim('  v' + getVersion()) + '\n');
  process.stdout.write(c.dim('  ─────────────────────────────────────────────\n'));

  const statParts: string[] = [];
  if (stats.migrationFiles)  statParts.push(`${stats.migrationFiles} migrations`);
  if (stats.tables)          statParts.push(`${stats.tables} tables`);
  if (stats.routeFiles)      statParts.push(`${stats.routeFiles} route files`);
  if (stats.sourceFiles)     statParts.push(`${stats.sourceFiles} source files`);
  process.stdout.write(c.dim(`  ${statParts.join(' · ')}  (${ms}ms)\n`));
  process.stdout.write('\n');

  if (findings.length === 0) {
    process.stdout.write(c.green(c.bold('  ✔  Clean — no issues found.\n')));
    process.stdout.write('\n');
    process.stdout.write(`  Security grade: ${colorGrade(grade)}  ${c.dim('(' + gradeLabel(grade) + ')')}\n`);
    process.stdout.write('\n');
    process.stdout.write(c.dim('  Add this badge to your README:\n'));
    process.stdout.write(`  ${badgeMarkdown(findings)}\n`);
    process.stdout.write('\n');
    return;
  }

  const categories: Array<{ key: Finding['category']; label: string }> = [
    { key: 'rls',       label: 'RLS Policies' },
    { key: 'storage',   label: 'Storage Security' },
    { key: 'auth',      label: 'Auth Misuse' },
    { key: 'injection', label: 'Injection / Mass Assignment' },
    { key: 'routes',    label: 'API Routes' },
    { key: 'secrets',   label: 'Secrets & Credentials' },
  ];

  for (const { key, label } of categories) {
    const group = findings.filter(f => f.category === key);
    if (group.length === 0) continue;

    const worstSeverity = group.some(f => f.severity === 'critical') ? 'critical'
      : group.some(f => f.severity === 'warning') ? 'warning'
      : 'info';

    process.stdout.write(`  ${sectionIcon(worstSeverity)}  ${c.bold(label)}\n`);
    process.stdout.write(c.dim('  ─────────────────────────────────────────────\n'));

    for (const f of group) {
      process.stdout.write('\n');
      process.stdout.write(`  ${badge(f.severity)}  ${c.white(f.title)}\n`);
      process.stdout.write(`            ${c.dim(f.detail)}\n`);

      if (f.file) {
        const loc = f.line ? `${f.file}:${f.line}` : f.file;
        process.stdout.write(`            ${c.dim('→')} ${c.cyan(loc)}\n`);
      }

      if (f.fix) {
        process.stdout.write(`            ${c.dim('fix:')} ${f.fix}\n`);
      }

      if (f.autoFixable) {
        process.stdout.write(`            ${c.green('✦')} ${c.dim('auto-fixable — run')} npx supafix --fix\n`);
      }
    }

    process.stdout.write('\n');
  }

  const critical = findings.filter(f => f.severity === 'critical').length;
  const warnings  = findings.filter(f => f.severity === 'warning').length;
  const info      = findings.filter(f => f.severity === 'info').length;
  const autoFix   = findings.filter(f => f.autoFixable).length;

  process.stdout.write(c.dim('  ─────────────────────────────────────────────\n'));

  const summary: string[] = [];
  if (critical) summary.push(c.red(`${critical} critical`));
  if (warnings)  summary.push(c.yellow(`${warnings} warnings`));
  if (info)      summary.push(c.cyan(`${info} info`));
  process.stdout.write(`  ${summary.join('  ·  ')}\n\n`);

  process.stdout.write(`  Security grade: ${colorGrade(grade)}  ${c.dim('(' + gradeLabel(grade) + ')')}\n`);
  if (autoFix > 0) {
    process.stdout.write(c.dim(`  ${autoFix} issue${autoFix > 1 ? 's' : ''} can be auto-fixed — run `) + 'npx supafix --fix\n');
  }
  process.stdout.write('\n');
  process.stdout.write(c.dim('  Add this badge to your README:\n'));
  process.stdout.write(`  ${badgeMarkdown(findings)}\n`);
  process.stdout.write('\n');
}

export function printBadge(findings: Finding[]): void {
  process.stdout.write(badgeMarkdown(findings) + '\n');
}

export function printJson(result: ScanResult): void {
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
}

function getVersion(): string {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return (require('../package.json') as { version: string }).version;
  } catch {
    return '0.2.0';
  }
}
