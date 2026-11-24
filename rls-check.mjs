#!/usr/bin/env node
// rls-check v0.2.0 — offline security check for Supabase apps built with Lovable / Bolt / Replit / Cursor.
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
  const buckets = [];          // public buckets
  const storagePolicies = [];  // policies on storage.objects
  const ID = '((?:"[^"]+"|[\\w]+)(?:\\.(?:"[^"]+"|[\\w]+))?)';

  for (const { file, sql: rawSql } of files) {
    const sql = stripSqlComments(rawSql);
    const stmts = splitStatements(sql);
    for (const st of stmts) {
      const s = st.trim();
      if (!s) continue;
      let m;
      if (/^insert\s+into\s+"?storage"?\."?buckets"?/i.test(s)) {
        // insert into storage.buckets (id, name, public) values ('docs', 'docs', true), (...)
        const cols = (s.match(/buckets"?\s*\(([^)]*)\)/i)?.[1] || '').split(',').map(c => c.trim().replace(/"/g, '').toLowerCase());
        const vi = s.search(/\bvalues\b/i);
        const rows = vi >= 0 ? [...s.slice(vi).matchAll(/\(([^()]*)\)/g)].map(r => r[1].split(',').map(v => v.trim().replace(/^'|'$/g, ''))) : [];
        const ip = cols.indexOf('public'), ii = cols.indexOf('id') >= 0 ? cols.indexOf('id') : cols.indexOf('name');
        for (const r of rows) {
          if (ip >= 0 && /^true$/i.test(r[ip] || '')) buckets.push({ id: r[ii] || '?', file });
        }
        continue;
      }
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
        const cmd = (s.match(/\bfor\s+(all|select|insert|update|delete)\b/i)?.[1] || 'all').toLowerCase();
        const roles = (s.match(/\bto\s+([\w\s,"]+?)(?=\s+(?:using|with\s+check)\b|$)/i)?.[1] || 'public')
          .toLowerCase().replace(/"/g, '').split(',').map(r => r.trim());
        const ui = s.search(/\busing\s*\(/i);
        const ci = s.search(/\bwith\s+check\s*\(/i);
        const using = ui >= 0 ? balanced(s, ui) : null;
        const check = ci >= 0 ? balanced(s, ci) : null;
        if (/^"?storage"?\."?objects"?$/i.test(m[2])) {
          storagePolicies.push({ name: m[1].replace(/"/g, ''), cmd, roles, using, check, file });
          continue;
        }
        if (!t) continue;
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
  // Storage (uploaded files)
  for (const b of buckets) {
    findings.push({ level: 'MEDIUM', code: 'STORAGE_BUCKET_PUBLIC', where: b.file, item: b.id,
      text: `Storage bucket "${b.id}" is public: anyone with a file's link can open it, no login needed. Fine for product photos; not for IDs, invoices, contracts or user uploads. Set public = false and use signed URLs.` });
  }
  const ownerCheck = e => /auth\.uid\(\)|auth\.jwt\(\)|storage\.foldername/i.test(e || '');
  for (const p of storagePolicies) {
    const cond = `${p.using || ''} ${p.check || ''}`;
    if (p.cmd !== 'select' && !ownerCheck(cond)) {
      findings.push({ level: 'HIGH', code: 'STORAGE_OPEN_WRITE', where: p.file, item: `storage / ${p.name}`,
        text: `Storage policy "${p.name}" lets ${anonish(p.roles) ? 'anyone' : 'any logged-in user'} ${p.cmd === 'all' ? 'upload, overwrite and delete' : p.cmd} files without checking who owns them. Add a check such as (storage.foldername(name))[1] = auth.uid()::text.` });
    } else if (p.cmd === 'select' && anonish(p.roles) && !ownerCheck(cond)) {
      findings.push({ level: 'MEDIUM', code: 'STORAGE_OPEN_READ', where: p.file, item: `storage / ${p.name}`,
        text: `Storage policy "${p.name}" lets anyone, even logged out, list and download the files it covers. Fine only for public files.` });
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

const AI_KEYS = [
  [/\bsk-ant-[A-Za-z0-9_-]{20,}/, 'Anthropic'],
  [/\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/, 'OpenAI'],
  [/\bgsk_[A-Za-z0-9]{30,}/, 'Groq'],
  [/\br8_[A-Za-z0-9]{30,}/, 'Replicate'],
  [/\bxai-[A-Za-z0-9]{30,}/, 'xAI'],
  [/\bpplx-[A-Za-z0-9]{30,}/, 'Perplexity'],
  [/\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/, 'SendGrid'],
  [/\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/, 'Resend'],
];

// Server-side code: Supabase edge functions, API routes, server folders, *.server.* files
function isBrowserFile(file) {
  const p = file.split(path.sep).join('/');
  if (/(^|\/)\.env/.test(p)) return false;
  return !/(^|\/)(supabase\/functions|netlify\/functions|api|server|backend|functions|pages\/api|app\/api)\//.test(p) &&
         !/\.server\.[jt]sx?$/.test(p);
}

// Minimal reader for supabase/config.toml: sections + key = value
export function analyzeConfig(configs, functionCode) {
  // configs: [{file, text}]; functionCode: Map(name -> concatenated code of supabase/functions/<name>/)
  const findings = [];
  for (const { file, text } of configs) {
    let section = '';
    for (const line of text.split('\n')) {
      const l = line.replace(/#.*$/, '').trim();
      const sec = l.match(/^\[([^\]]+)\]$/);
      if (sec) { section = sec[1].trim(); continue; }
      const kv = l.match(/^([\w.]+)\s*=\s*(.+)$/);
      if (!kv) continue;
      const key = kv[1], val = kv[2].trim().replace(/^"|"$/g, '');
      const fn = section.match(/^functions\.("?)([\w-]+)\1$/);
      if (fn && key === 'verify_jwt' && val === 'false') {
        const name = fn[2];
        const code = functionCode.get(name) || '';
        const isWebhook = /webhook|stripe|callback|hook/i.test(name) || /constructEvent|svix|x-signature|stripe-signature/i.test(code);
        const ownAuth = /auth\.getUser\s*\(|getUser\s*\(|verifyJwt|jwtVerify|getClaims\s*\(|req\.headers\.get\(\s*['"]authorization['"]\s*\)/i.test(code);
        if (!isWebhook && !ownAuth) {
          findings.push({ level: 'HIGH', code: 'FUNCTION_NO_AUTH', where: file, item: name,
            text: `Server function "${name}" has the login check switched off (verify_jwt = false) and its code doesn't check the user itself. Anyone on the internet can call it${/openai|anthropic|gemini|resend|stripe|service_role|SERVICE_ROLE/i.test(code) ? ', and it uses paid services or admin rights' : ''}. Set verify_jwt = true, or check the user with supabase.auth.getUser().` });
        }
      }
      if (section === 'auth.email' && key === 'enable_confirmations' && val === 'false') {
        findings.push({ level: 'INFO', code: 'EMAIL_CONFIRM_OFF', where: file, item: 'auth.email',
          text: `Email confirmation is off in this config (common for local testing). Make sure it is ON in your live project (Authentication → Sign In / Providers → Email), otherwise anyone can sign up with someone else's email address.` });
      }
    }
  }
  return { findings };
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
    // Paid API keys in browser-visible env variables (someone else runs up your bill)
    const pubEnv = new Set();
    for (const mm of text.matchAll(/\b((?:VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)\w*?(OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GROQ|MISTRAL|REPLICATE|ELEVENLABS|PERPLEXITY|DEEPSEEK|XAI|RESEND|SENDGRID|MAILGUN|TWILIO|STRIPE_SECRET)\w*)/g)) {
      if (/PUBLISHABLE|PUBLIC_KEY|SITE_KEY/.test(mm[1])) continue;
      pubEnv.add(mm[1]);
    }
    for (const name of pubEnv) {
      findings.push({ level: 'HIGH', code: 'SECRET_IN_PUBLIC_ENV', where: file, item: name,
        text: `"${name}" is a browser-visible variable (the prefix ships it to every visitor). Anyone can copy this key and run up your bill or send email as you. Move the call into a server function and rotate the key.` });
    }
    // Hard-coded paid API keys
    const browser = isBrowserFile(file);
    for (const [re, label] of AI_KEYS) {
      if (re.test(text)) {
        findings.push({ level: browser ? 'HIGH' : 'MEDIUM', code: browser ? 'AI_KEY_IN_BROWSER_CODE' : 'AI_KEY_HARDCODED', where: file, item: `${label} key in ${base}`,
          text: browser
            ? `A ${label} API key is written into "${base}", which ends up in the browser. Anyone can copy it and use your paid account. Rotate it now and call ${label} from a server function instead.`
            : `A ${label} API key is written into "${base}" (server code, but saved in the repo). Rotate it and load it from a secret/env variable instead.` });
      }
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
  const configs = all.filter(f => path.basename(f) === 'config.toml' && /supabase/.test(f))
    .map(f => ({ file: path.relative(root, f), text: fs.readFileSync(f, 'utf8') }));
  const functionCode = new Map();
  for (const cf of codeFiles) {
    const m = cf.file.split(path.sep).join('/').match(/supabase\/functions\/([\w-]+)\//);
    if (m) functionCode.set(m[1], (functionCode.get(m[1]) || '') + '\n' + cf.text);
  }
  const a = analyzeSql(sqlFiles);
  const b = analyzeCode(codeFiles);
  const c = analyzeConfig(configs, functionCode);
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
  const findings = [...a.findings, ...b.findings, ...c.findings].sort((x, y) => order[x.level] - order[y.level]);
  return { sqlFiles: sqlFiles.length, codeFiles: codeFiles.length, configs: configs.length, tables: a.tables, findings };
}

function main() {
  const args = process.argv.slice(2);
  const json = args.includes('--json');
  const root = args.find(a => !a.startsWith('--'));
  if (!root) { console.error('Usage: node rls-check.mjs <project-folder> [--json]'); process.exit(2); }
  const r = scanProject(path.resolve(root));
  if (json) { console.log(JSON.stringify(r, null, 2)); }
  else {
    console.log(`rls-check v0.2.0 — ${r.sqlFiles} SQL files, ${r.codeFiles} code/env files, ${r.configs} config files, ${r.tables.length} tables`);
    if (r.sqlFiles === 0) console.log('Note: no .sql files found. Export your schema (supabase db dump --schema public) into the folder for the RLS part.');
    if (r.findings.length === 0) console.log('No problems found by these checks. (This is not a full security review.)');
    for (const f of r.findings) console.log(`\n[${f.level}] ${f.code}  ${f.item}  (${f.where})\n  ${f.text}`);
    const counts = r.findings.reduce((c, f) => (c[f.level] = (c[f.level] || 0) + 1, c), {});
    console.log(`\nSummary: ${['HIGH', 'MEDIUM', 'LOW', 'INFO'].map(l => `${l} ${counts[l] || 0}`).join(' · ')}`);
  }
  process.exit(r.findings.some(f => f.level === 'HIGH') ? 1 : 0);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
