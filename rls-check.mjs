#!/usr/bin/env node
// rls-check v0.1.0 — offline security check for Supabase apps built with Lovable / Bolt / Replit / Cursor.
// Reads a project folder only. No network, no Supabase login, no dependencies.
// Usage: node rls-check.mjs <project-folder> [--json]
// Exit code: 1 if any HIGH finding, else 0.

import fs from 'node:fs';
import path from 'node:path';

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.vercel', '.output', 'coverage']);
const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro']);

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

function stripSqlComments(sql) {
  return sql.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/--[^\n]*/g, ' ');
}

// Split on ; that are outside quotes and $tag$ ... $tag$ bodies
function splitStatements(sql) {
  const out = [];
  let cur = '', i = 0, inQuote = false, dollar = null;
  while (i < sql.length) {
    const ch = sql[i];
    if (dollar) {
      if (sql.startsWith(dollar, i)) { cur += dollar; i += dollar.length; dollar = null; continue; }
    } else if (inQuote) {
      if (ch === "'") inQuote = false;
    } else if (ch === "'") inQuote = true;
    else if (ch === '$') {
      const m = sql.slice(i).match(/^\$[A-Za-z_]*\$/);
      if (m) { dollar = m[0]; cur += dollar; i += dollar.length; continue; }
    } else if (ch === ';') { out.push(cur); cur = ''; i++; continue; }
    cur += ch; i++;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

// Normalise "public"."todos" / public.todos / todos -> todos (null if another schema)
function tableName(raw) {
  const parts = raw.replace(/"/g, '').split('.');
  if (parts.length === 2) return parts[0].toLowerCase() === 'public' ? parts[1].toLowerCase() : null;
  return parts[0].toLowerCase();
}

// Extract the balanced (...) after a keyword starting at index i
function balanced(s, i) {
  const start = s.indexOf('(', i);
  if (start < 0) return null;
  let depth = 0;
  for (let k = start; k < s.length; k++) {
    if (s[k] === '(') depth++;
    else if (s[k] === ')') { depth--; if (depth === 0) return s.slice(start + 1, k).trim(); }
  }
  return null;
}

export function analyzeSql(files) {
  // files: [{file, sql}] in apply order
  const tables = new Map(); // name -> {file, rls:false, policies:[]}
  const findings = [];
  const ID = '((?:"[^"]+"|[\\w]+)(?:\\.(?:"[^"]+"|[\\w]+))?)';

  for (const { file, sql: rawSql } of files) {
    const sql = stripSqlComments(rawSql);
    const stmts = splitStatements(sql);
    for (const st of stmts) {
      const s = st.trim();
      if (!s) continue;
      let m;
      if ((m = s.match(new RegExp(`^create\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?${ID}`, 'i')))) {
        const t = tableName(m[1]);
        if (t && !tables.has(t)) tables.set(t, { file, rls: false, policies: [] });
      } else if ((m = s.match(new RegExp(`^alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?${ID}\\s+(enable|disable)\\s+row\\s+level\\s+security`, 'i')))) {
        const t = tableName(m[1]);
        if (t) {
          if (!tables.has(t)) tables.set(t, { file, rls: false, policies: [] });
          tables.get(t).rls = m[2].toLowerCase() === 'enable';
        }
      } else if ((m = s.match(new RegExp(`^create\\s+policy\\s+("[^"]+"|\\w+)\\s+on\\s+${ID}`, 'i')))) {
        const t = tableName(m[2]);
        if (!t) continue;
        const cmd = (s.match(/\bfor\s+(all|select|insert|update|delete)\b/i)?.[1] || 'all').toLowerCase();
        const roles = (s.match(/\bto\s+([\w\s,"]+?)(?=\s+(?:using|with\s+check)\b|$)/i)?.[1] || 'public')
          .toLowerCase().replace(/"/g, '').split(',').map(r => r.trim());
        const ui = s.search(/\busing\s*\(/i);
        const ci = s.search(/\bwith\s+check\s*\(/i);
        const using = ui >= 0 ? balanced(s, ui) : null;
        const check = ci >= 0 ? balanced(s, ci) : null;
        if (!tables.has(t)) tables.set(t, { file, rls: false, policies: [] });
        tables.get(t).policies.push({ name: m[1].replace(/"/g, ''), cmd, roles, using, check, file });
      } else if ((m = s.match(new RegExp(`^drop\\s+policy\\s+(?:if\\s+exists\\s+)?("[^"]+"|\\w+)\\s+on\\s+${ID}`, 'i')))) {
        const t = tableName(m[2]);
        const name = m[1].replace(/"/g, '');
        if (t && tables.has(t)) tables.get(t).policies = tables.get(t).policies.filter(p => p.name !== name);
      } else if ((m = s.match(new RegExp(`^create\\s+(?:or\\s+replace\\s+)?(?:materialized\\s+)?view\\s+${ID}([\\s\\S]*?)\\bas\\b`, 'i')))) {
        const v = tableName(m[1]);
        if (v && !/security_invoker\s*=\s*(true|on)/i.test(m[2])) {
          findings.push({ level: 'HIGH', code: 'VIEW_BYPASSES_RLS', where: file, item: v,
            text: `View "${v}" runs with the owner's rights and skips RLS. Add WITH (security_invoker = true) or revoke access for anon/authenticated.` });
        }
      } else if ((m = s.match(new RegExp(`^create\\s+(?:or\\s+replace\\s+)?function\\s+${ID}`, 'i')))) {
        const f = tableName(m[1]);
        if (f && /\bsecurity\s+definer\b/i.test(s) && !/\bset\s+search_path\b/i.test(s)) {
          findings.push({ level: 'MEDIUM', code: 'DEFINER_NO_SEARCH_PATH', where: file, item: f,
            text: `Function "${f}" is SECURITY DEFINER without a fixed search_path. Add SET search_path = '' (or public) so it cannot be hijacked.` });
        }
      }
    }
  }

  const isTrue = e => e != null && /^\(*\s*true\s*\)*$/i.test(e);
  const anonish = roles => roles.some(r => r === 'public' || r === 'anon');

  for (const [t, info] of tables) {
    if (!info.rls) {
      findings.push({ level: 'HIGH', code: 'RLS_OFF', where: info.file, item: t,
        text: `Table "${t}" has row-level security OFF. Anyone with the public anon key can read and change every row.` });
      continue;
    }
    if (info.policies.length === 0) {
      findings.push({ level: 'INFO', code: 'RLS_NO_POLICIES', where: info.file, item: t,
        text: `Table "${t}" has RLS on but no policies, so the app cannot read it (often the "data disappeared" bug).` });
    }
    for (const p of info.policies) {
      const writes = p.cmd !== 'select';
      const openUsing = isTrue(p.using);
      const openCheck = isTrue(p.check);
      if (writes && (openUsing || openCheck)) {
        findings.push({ level: 'HIGH', code: 'OPEN_WRITE_POLICY', where: p.file, item: `${t} / ${p.name}`,
          text: `Policy "${p.name}" on "${t}" lets ${anonish(p.roles) ? 'anyone' : 'any logged-in user'} ${p.cmd === 'all' ? 'read and change' : p.cmd} every row (condition is "true"). Tie it to auth.uid().` });
      } else if (!writes && openUsing) {
        findings.push({ level: anonish(p.roles) ? 'MEDIUM' : 'LOW', code: 'OPEN_READ_POLICY', where: p.file, item: `${t} / ${p.name}`,
          text: `Policy "${p.name}" makes every row of "${t}" readable by ${anonish(p.roles) ? 'anyone, even logged out' : 'every logged-in user'}. Fine only if this data is meant to be public.` });
      }
      if (/auth\.role\(\)\s*=\s*'authenticated'/i.test(`${p.using || ''} ${p.check || ''}`)) {
        findings.push({ level: 'MEDIUM', code: 'ANY_USER_POLICY', where: p.file, item: `${t} / ${p.name}`,
          text: `Policy "${p.name}" only checks "is logged in", so every user sees/changes every other user's rows. Compare with auth.uid() instead.` });
      }
    }
  }
  return { tables: [...tables.keys()], findings };
}

function decodeJwtRole(tok) {
  try {
    const payload = JSON.parse(Buffer.from(tok.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    return payload.role || null;
  } catch { return null; }
}

export function analyzeCode(files) {
  // files: [{file, text}]
  const findings = [];
  const JWT = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
  for (const { file, text } of files) {
    const base = path.basename(file);
    for (const tok of text.match(JWT) || []) {
      if (decodeJwtRole(tok) === 'service_role') {
        findings.push({ level: 'HIGH', code: 'SERVICE_KEY_EXPOSED', where: file, item: base,
          text: `A Supabase service_role key is in "${base}". It bypasses all RLS. Rotate it in Supabase now and move it to a server-only secret.` });
      }
    }
    if (/\b(VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)\w*SERVICE_ROLE\w*/.test(text)) {
      findings.push({ level: 'HIGH', code: 'SERVICE_KEY_PUBLIC_ENV', where: file, item: base,
        text: `"${base}" puts the service_role key in a public (browser) env variable. Browsers can read it.` });
    }
    if (/\bsk_live_[A-Za-z0-9]{10,}/.test(text)) {
      findings.push({ level: 'HIGH', code: 'STRIPE_SECRET_EXPOSED', where: file, item: base,
        text: `A live Stripe secret key is in "${base}". Roll it in the Stripe dashboard and keep it server-side.` });
    }
    const ext = path.extname(file);
    if (CODE_EXT.has(ext) && /stripe/i.test(text) && /webhook/i.test(text) &&
        /(checkout\.session\.completed|invoice\.paid|payment_intent\.succeeded|customer\.subscription)/.test(text) &&
        !/constructEvent(Async)?\s*\(/.test(text)) {
      findings.push({ level: 'HIGH', code: 'STRIPE_WEBHOOK_UNVERIFIED', where: file, item: base,
        text: `"${base}" handles Stripe webhook events without verifying the signature (stripe.webhooks.constructEvent). Anyone can fake a "paid" event.` });
    }
  }
  return { findings };
}

export function scanProject(root) {
  const all = walk(root);
  const sqlFiles = all.filter(f => f.endsWith('.sql')).sort()
    .map(f => ({ file: path.relative(root, f), sql: fs.readFileSync(f, 'utf8') }));
  const codeFiles = all.filter(f => {
    const b = path.basename(f);
    return CODE_EXT.has(path.extname(f)) || (/^\.env/.test(b) && !/example|sample|template/i.test(b));
  }).map(f => ({ file: path.relative(root, f), text: fs.readFileSync(f, 'utf8') }));
  const a = analyzeSql(sqlFiles);
  const b = analyzeCode(codeFiles);
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
  const findings = [...a.findings, ...b.findings].sort((x, y) => order[x.level] - order[y.level]);
  return { sqlFiles: sqlFiles.length, codeFiles: codeFiles.length, tables: a.tables, findings };
}

function main() {
  const args = process.argv.slice(2);
  const json = args.includes('--json');
  const root = args.find(a => !a.startsWith('--'));
  if (!root) { console.error('Usage: node rls-check.mjs <project-folder> [--json]'); process.exit(2); }
  const r = scanProject(path.resolve(root));
  if (json) { console.log(JSON.stringify(r, null, 2)); }
  else {
    console.log(`rls-check v0.1.0 — ${r.sqlFiles} SQL files, ${r.codeFiles} code/env files, ${r.tables.length} tables`);
    if (r.sqlFiles === 0) console.log('Note: no .sql files found. Export your schema (supabase db dump --schema public) into the folder for the RLS part.');
    if (r.findings.length === 0) console.log('No problems found by these checks. (This is not a full security review.)');
    for (const f of r.findings) console.log(`\n[${f.level}] ${f.code}  ${f.item}  (${f.where})\n  ${f.text}`);
    const counts = r.findings.reduce((c, f) => (c[f.level] = (c[f.level] || 0) + 1, c), {});
    console.log(`\nSummary: ${['HIGH', 'MEDIUM', 'LOW', 'INFO'].map(l => `${l} ${counts[l] || 0}`).join(' · ')}`);
  }
  process.exit(r.findings.some(f => f.level === 'HIGH') ? 1 : 0);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
