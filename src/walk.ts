import fs from 'fs';
import path from 'path';

const SKIP = new Set([
  'node_modules', '.git', '.next', 'dist', 'build', '.turbo',
  'coverage', '.cache', 'out', '.svelte-kit', '.nuxt',
]);

export function walk(dir: string, exts: string[]): string[] {
  const results: string[] = [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (!SKIP.has(e.name)) results.push(...walk(path.join(dir, e.name), exts));
    } else if (exts.some(x => e.name.endsWith(x))) {
      results.push(path.join(dir, e.name));
    }
  }
  return results;
}

export function findDirs(root: string, candidates: string[]): string[] {
  return candidates
    .map(d => path.join(root, d))
    .filter(d => fs.existsSync(d) && fs.statSync(d).isDirectory());
}
