#!/usr/bin/env node
// rls-check v0.2.0 — offline security check for Supabase apps built with Lovable / Bolt / Replit / Cursor.
// Reads a project folder only. No network, no Supabase login, no dependencies.
// Usage: node rls-check.mjs <project-folder> [--json]
// Exit code: 1 if any HIGH finding, else 0.
// The checks live in core.mjs (shared with the browser page index.html).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { VERSION, SKIP_DIRS, isWanted, scanFiles } from './core.mjs';
export { analyzeSql, analyzeCode, analyzeConfig, scanFiles } from './core.mjs';

function walk(dir, out = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.isFile()) out.push(p);
  }
  return out;
}

export function scanProject(root) {
  const files = walk(root).map(f => path.relative(root, f)).filter(isWanted)
    .map(rel => ({ file: rel, text: fs.readFileSync(path.join(root, rel), 'utf8') }));
  return scanFiles(files);
}

function main() {
  const args = process.argv.slice(2);
  const json = args.includes('--json');
  const root = args.find(a => !a.startsWith('--'));
  if (!root) { console.error('Usage: node rls-check.mjs <project-folder> [--json]'); process.exit(2); }
  const r = scanProject(path.resolve(root));
  if (json) { console.log(JSON.stringify(r, null, 2)); }
  else {
    console.log(`rls-check v${VERSION} — ${r.sqlFiles} SQL files, ${r.codeFiles} code/env files, ${r.configs} config files, ${r.tables.length} tables`);
    if (r.sqlFiles === 0) console.log('Note: no .sql files found. Export your schema (supabase db dump --schema public) into the folder for the RLS part.');
    if (r.findings.length === 0) console.log('No problems found by these checks. (This is not a full security review.)');
    for (const f of r.findings) console.log(`\n[${f.level}] ${f.code}  ${f.item}  (${f.where})\n  ${f.text}`);
    const counts = r.findings.reduce((c, f) => (c[f.level] = (c[f.level] || 0) + 1, c), {});
    console.log(`\nSummary: ${['HIGH', 'MEDIUM', 'LOW', 'INFO'].map(l => `${l} ${counts[l] || 0}`).join(' · ')}`);
  }
  process.exit(r.findings.some(f => f.level === 'HIGH') ? 1 : 0);
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) main();
