// rls-check core v0.2.0 — shared by the command line (rls-check.mjs) and the browser page (index.html).
// Pure functions only: no file system, no network. Input is a list of {file, text}.

export const VERSION = '0.2.1';
export const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.vercel', '.output', 'coverage']);
export const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro']);

const basename = f => f.split(/[\\/]/).pop();
const extname = f => { const b = basename(f); const i = b.lastIndexOf('.'); return i > 0 ? b.slice(i) : ''; };
function decodeBase64Url(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(b64);
  return new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0)));
}

// Which files the checker wants to read (both front ends use this to skip everything else)
export function isWanted(file) {
  const p = file.split('\\').join('/');
  if (p.split('/').some(seg => SKIP_DIRS.has(seg))) return false;
  const b = basename(p);
  if (b.endsWith('.sql')) return true;
  if (b === 'config.toml' && /supabase/.test(p)) return true;
  if (/^\.env/.test(b)) return !/example|sample|template/i.test(b);
  return CODE_EXT.has(extname(b));
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
  // files: [{file, sql}] in apply order. Tracks the FINAL state after all migrations.
  const tables = new Map();    // name -> {file, created, rls, policies:[]}
  const views = new Map();     // name -> {file, invoker}
  const funcs = new Map();     // name -> {file, definer, path}
  const buckets = new Map();   // id -> {file, public}
  let storagePolicies = [];    // policies on storage.objects
  const findings = [];
  const ID = '((?:"[^"]+"|[\\w]+)(?:\\.(?:"[^"]+"|[\\w]+))?)';
  const PRIV = new Set(['service_role', 'postgres', 'supabase_admin', 'supabase_auth_admin', 'supabase_storage_admin']);
  const tbl = (t, file) => { if (!tables.has(t)) tables.set(t, { file, created: false, rls: false, policies: [] }); return tables.get(t); };
  const isStorageObjects = raw => /^"?storage"?\."?objects"?$/i.test(raw);

  // Statements inside DO $$ ... $$ blocks (e.g. "if not exists ... then create policy ...; end if;")
  function expandDo(s) {
    const m = s.match(/^do\s*(\$[A-Za-z_]*\$)([\s\S]*)\1/i);
    if (!m) return [s];
    return splitStatements(m[2]).map(x => x.trim()
      .replace(/^(?:(?:declare\b[\s\S]*?\bbegin|begin|else|elsif\b[\s\S]*?\bthen|end\s+if|end\s+loop|end|if\b[\s\S]*?\bthen|loop)\s+)+/i, '')
      .trim()).filter(Boolean);
  }

  const dynRls = new Set();     // tables named in a file that enables RLS with EXECUTE format(... %I ...)
  for (const { file, sql: rawSql } of files) {
    const sql = stripSqlComments(rawSql);
    if (/execute\s+format\s*\(\s*'[^']*enable\s+row\s+level\s+security/i.test(sql)) {
      if (/pg_tables|information_schema\.tables|pg_class/i.test(sql)) {
        for (const [, x] of tables) if (x.created) x.rls = true; // loop over every existing table
      }
      for (const [, w] of sql.matchAll(/'([A-Za-z_][\w]*)'/g)) dynRls.add(w.toLowerCase());
    }
    const stmts = splitStatements(sql).flatMap(x => expandDo(x.trim()));
    for (const st of stmts) {
      const s = st.trim();
      if (!s) continue;
      let m;
      if (/^insert\s+into\s+"?storage"?\."?buckets"?/i.test(s)) {
        // insert into storage.buckets (id, name, public) values ('docs', 'docs', true), (...)
        const cols = (s.match(/buckets"?\s*\(([^)]*)\)/i)?.[1] || '').split(',').map(c => c.trim().replace(/"/g, '').toLowerCase());
        const vi = s.search(/\bvalues\b/i);
        const oc = s.search(/\bon\s+conflict\b/i);
        const valuesPart = vi >= 0 ? s.slice(vi, oc > vi ? oc : undefined) : '';
        const rows = [...valuesPart.matchAll(/\(([^()]*)\)/g)].map(r => r[1].split(',').map(v => v.trim().replace(/^'|'$/g, '')));
        const ip = cols.indexOf('public'), ii = cols.indexOf('id') >= 0 ? cols.indexOf('id') : cols.indexOf('name');
        const upsertPublic = oc >= 0 && /set[\s\S]*public\s*=\s*(excluded\.public|true)/i.test(s.slice(oc));
        for (const r of rows) {
          const id = r[ii] || '?';
          const pub = ip >= 0 && /^true$/i.test(r[ip] || '');
          if (!buckets.has(id) || upsertPublic || oc < 0) buckets.set(id, { file, public: pub });
        }
        continue;
      }
      if ((m = s.match(/^update\s+"?storage"?\."?buckets"?\s+set\s+[\s\S]*?\bpublic\s*=\s*(true|false)[\s\S]*?where\s+[\s\S]*?(?:id|name)\s*=\s*'([^']+)'/i))) {
        buckets.set(m[2], { file, public: m[1].toLowerCase() === 'true' });
        continue;
      }
      if ((m = s.match(new RegExp(`^create\\s+(?:unlogged\\s+)?table\\s+(?:if\\s+not\\s+exists\\s+)?${ID}`, 'i')))) {
        const t = tableName(m[1]);
        if (t && !/\bpartition\s+of\b/i.test(s)) { const x = tbl(t, file); if (!x.created) { x.created = true; x.file = file; } }
      } else if ((m = s.match(new RegExp(`^drop\\s+table\\s+(?:if\\s+exists\\s+)?${ID}`, 'i')))) {
        for (const raw of s.replace(/^drop\s+table\s+(?:if\s+exists\s+)?/i, '').replace(/\s+(cascade|restrict)\s*$/i, '').split(',')) {
          const t = tableName(raw.trim()); if (t) tables.delete(t);
        }
      } else if ((m = s.match(new RegExp(`^alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?${ID}\\s+rename\\s+to\\s+("?[\\w]+"?)`, 'i')))) {
        const a = tableName(m[1]), b = tableName(m[2]);
        if (a && b && tables.has(a)) { tables.set(b, tables.get(a)); tables.delete(a); }
      } else if ((m = s.match(new RegExp(`^alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?${ID}\\s+(enable|disable)\\s+row\\s+level\\s+security`, 'i')))) {
        const t = tableName(m[1]);
        if (t) tbl(t, file).rls = m[2].toLowerCase() === 'enable';
      } else if ((m = s.match(new RegExp(`^create\\s+policy\\s+("[^"]+"|\\w+)\\s+on\\s+${ID}`, 'i')))) {
        const t = tableName(m[2]);
        const cmd = (s.match(/\bfor\s+(all|select|insert|update|delete)\b/i)?.[1] || 'all').toLowerCase();
        const roles = (s.match(/\bto\s+([\w\s,"]+?)(?=\s+(?:using|with\s+check)\b|$)/i)?.[1] || 'public')
          .toLowerCase().replace(/"/g, '').split(',').map(r => r.trim());
        const ui = s.search(/\busing\s*\(/i);
        const ci = s.search(/\bwith\s+check\s*\(/i);
        const using = ui >= 0 ? balanced(s, ui) : null;
        const check = ci >= 0 ? balanced(s, ci) : null;
        const pol = { name: m[1].replace(/"/g, ''), cmd, roles, using, check, file, privileged: roles.every(r => PRIV.has(r)) };
        if (isStorageObjects(m[2])) { storagePolicies = storagePolicies.filter(p => p.name !== pol.name); storagePolicies.push(pol); continue; }
        if (!t) continue;
        const x = tbl(t, file);
        x.policies = x.policies.filter(p => p.name !== pol.name);
        x.policies.push(pol);
      } else if ((m = s.match(new RegExp(`^drop\\s+policy\\s+(?:if\\s+exists\\s+)?("[^"]+"|\\w+)\\s+on\\s+${ID}`, 'i')))) {
        const name = m[1].replace(/"/g, '');
        if (isStorageObjects(m[2])) { storagePolicies = storagePolicies.filter(p => p.name !== name); continue; }
        const t = tableName(m[2]);
        if (t && tables.has(t)) tables.get(t).policies = tables.get(t).policies.filter(p => p.name !== name);
      } else if ((m = s.match(new RegExp(`^create\\s+(?:or\\s+replace\\s+)?(materialized\\s+)?view\\s+(?:if\\s+not\\s+exists\\s+)?${ID}([\\s\\S]*?)\\bas\\b`, 'i')))) {
        const v = tableName(m[2]);
        if (v) views.set(v, { file, invoker: /security_invoker\s*=\s*'?(true|on|1)'?/i.test(m[3]), materialized: !!m[1], revoked: false });
      } else if ((m = s.match(new RegExp(`^alter\\s+(?:materialized\\s+)?view\\s+(?:if\\s+exists\\s+)?${ID}\\s+set\\s*\\(([^)]*)\\)`, 'i')))) {
        const v = tableName(m[1]);
        if (v && views.has(v) && /security_invoker\s*=\s*'?(true|on|1)'?/i.test(m[2])) views.get(v).invoker = true;
      } else if ((m = s.match(new RegExp(`^drop\\s+(?:materialized\\s+)?view\\s+(?:if\\s+exists\\s+)?${ID}`, 'i')))) {
        const v = tableName(m[1]); if (v) views.delete(v);
      } else if ((m = s.match(new RegExp(`^revoke\\s+[\\s\\S]*?\\bon\\s+(?:table\\s+)?${ID}\\s+from\\s+([\\s\\S]+)$`, 'i')))) {
        const who = m[2].toLowerCase();
        if (/\banon\b/.test(who) && /\bauthenticated\b/.test(who)) {
          const list = s.replace(/^revoke\s+[\s\S]*?\bon\s+(?:table\s+)?/i, '').replace(/\s+from\s+[\s\S]+$/i, '');
          for (const raw of list.split(',')) {
            const v = tableName(raw.trim());
            if (!v) continue;
            if (views.has(v)) views.get(v).revoked = true;
            if (tables.has(v)) tables.get(v).revoked = true;
          }
        }
      } else if ((m = s.match(new RegExp(`^create\\s+(?:or\\s+replace\\s+)?function\\s+${ID}`, 'i')))) {
        const f = tableName(m[1]);
        if (f) funcs.set(f, { file, definer: /\bsecurity\s+definer\b/i.test(s), path: /\bset\s+search_path\b/i.test(s) });
      } else if ((m = s.match(new RegExp(`^alter\\s+function\\s+${ID}[\\s\\S]*?\\bset\\s+search_path\\b`, 'i')))) {
        const f = tableName(m[1]); if (f && funcs.has(f)) funcs.get(f).path = true;
      } else if ((m = s.match(new RegExp(`^drop\\s+function\\s+(?:if\\s+exists\\s+)?${ID}`, 'i')))) {
        const f = tableName(m[1]); if (f) funcs.delete(f);
      }
    }
  }

  const isTrue = e => e != null && /^\(*\s*true\s*\)*$/i.test(e);
  const anonish = roles => roles.some(r => r === 'public' || r === 'anon');

  for (const [v, info] of views) {
    if (!info.invoker && !info.revoked) {
      findings.push({ level: 'HIGH', code: 'VIEW_BYPASSES_RLS', where: info.file, item: v,
        text: `View "${v}" runs with its owner's rights, so it skips the RLS rules of the tables it reads. If it shows private data, add WITH (security_invoker = true) or revoke access from anon/authenticated.` });
    }
  }
  for (const [f, info] of funcs) {
    if (info.definer && !info.path) {
      findings.push({ level: 'MEDIUM', code: 'DEFINER_NO_SEARCH_PATH', where: info.file, item: f,
        text: `Function "${f}" is SECURITY DEFINER without a fixed search_path. Add SET search_path = '' (or public) so it cannot be hijacked.` });
    }
  }

  for (const [t, info] of tables) {
    if (!info.created) continue; // table not created in these files (dashboard or other schema): we can't judge it
    if (!info.rls && (dynRls.has(t) || info.revoked)) continue; // enabled in a loop, or API roles have no access
    if (!info.rls) {
      findings.push({ level: 'HIGH', code: 'RLS_OFF', where: info.file, item: t,
        text: `Table "${t}" never gets row-level security turned on in these files. Unless you switched it on in the dashboard, anyone with the public anon key can read and change every row.` });
      continue;
    }
    const usable = info.policies.filter(p => !p.privileged);
    if (usable.length === 0) {
      findings.push({ level: 'INFO', code: 'RLS_NO_POLICIES', where: info.file, item: t,
        text: `Table "${t}" is locked: RLS is on and no policy lets app users in, so only server code (service_role) can use it. That's safe if intended; if the app should show this data, it's the classic "my data disappeared" bug.` });
    }
    for (const p of usable) {
      const openUsing = isTrue(p.using);
      const openCheck = isTrue(p.check);
      if (p.cmd === 'insert' && openCheck) {
        findings.push({ level: 'MEDIUM', code: 'OPEN_INSERT_POLICY', where: p.file, item: `${t} / ${p.name}`,
          text: `Policy "${p.name}" lets ${anonish(p.roles) ? 'anyone, even logged out,' : 'any logged-in user'} add rows to "${t}" with no checks. Fine for a contact or sign-up form (watch for spam); not for data that should belong to a user.` });
      } else if (p.cmd !== 'select' && p.cmd !== 'insert' && (openUsing || openCheck)) {
        findings.push({ level: 'HIGH', code: 'OPEN_WRITE_POLICY', where: p.file, item: `${t} / ${p.name}`,
          text: `Policy "${p.name}" on "${t}" lets ${anonish(p.roles) ? 'anyone' : 'any logged-in user'} ${p.cmd === 'all' ? 'read and change' : p.cmd} every row (condition is "true"). Tie it to auth.uid().` });
      } else if (p.cmd === 'select' && openUsing) {
        findings.push({ level: anonish(p.roles) ? 'MEDIUM' : 'LOW', code: 'OPEN_READ_POLICY', where: p.file, item: `${t} / ${p.name}`,
          text: `Policy "${p.name}" makes every row of "${t}" readable by ${anonish(p.roles) ? 'anyone, even logged out' : 'every logged-in user'}. Fine only if this data is meant to be public.` });
      }
      const condAll = `${p.using || ''} ${p.check || ''}`;
      if (/auth\.role\(\)\s*=\s*'authenticated'/i.test(condAll) ||
          (/auth\.uid\(\)\s+is\s+not\s+null/i.test(condAll) && !/auth\.uid\(\)\s*(=|in\b)|=\s*auth\.uid\(\)|auth\.jwt\(\)|has_role|is_admin|is_member|exists\s*\(/i.test(condAll.replace(/auth\.uid\(\)\s+is\s+not\s+null/gi, '')))) {
        findings.push({ level: 'MEDIUM', code: 'ANY_USER_POLICY', where: p.file, item: `${t} / ${p.name}`,
          text: `Policy "${p.name}" only checks "is logged in", so every user sees/changes every other user's rows. Compare with auth.uid() instead.` });
      }
    }
  }
  // Storage (uploaded files)
  for (const [id, b] of buckets) {
    if (!b.public) continue;
    findings.push({ level: 'MEDIUM', code: 'STORAGE_BUCKET_PUBLIC', where: b.file, item: id,
      text: `Storage bucket "${id}" is public: anyone with a file's link can open it, no login needed. Fine for product photos and logos; not for IDs, invoices, contracts or private uploads. Set public = false and use signed URLs.` });
  }
  const ownerCheck = e => /auth\.uid\(\)|auth\.jwt\(\)|storage\.foldername|owner\s*=|owner_id|is_admin|has_role/i.test((e || '').replace(/auth\.uid\(\)\s+is\s+not\s+null/gi, ''));
  for (const p of storagePolicies) {
    if (p.privileged) continue;
    const cond = `${p.using || ''} ${p.check || ''}`;
    if (p.cmd !== 'select' && !ownerCheck(cond)) {
      findings.push({ level: anonish(p.roles) ? 'HIGH' : 'MEDIUM', code: 'STORAGE_OPEN_WRITE', where: p.file, item: `storage / ${p.name}`,
        text: `Storage policy "${p.name}" lets ${anonish(p.roles) ? 'anyone, even logged out,' : 'any logged-in user'} ${p.cmd === 'all' ? 'upload, overwrite and delete' : p.cmd} files without checking who owns them. Add a check such as (storage.foldername(name))[1] = auth.uid()::text.` });
    } else if (p.cmd === 'select' && anonish(p.roles) && !ownerCheck(cond)) {
      findings.push({ level: 'LOW', code: 'STORAGE_OPEN_READ', where: p.file, item: `storage / ${p.name}`,
        text: `Storage policy "${p.name}" lets anyone, even logged out, list and download the files it covers. Fine only for public files.` });
    }
  }
  return { tables: [...tables.keys()].filter(t => tables.get(t).created), findings };
}

function decodeJwtRole(tok) {
  try {
    const payload = JSON.parse(decodeBase64Url(tok.split('.')[1]));
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
  const p = file.split('\\').join('/');
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
        const isWebhook = /webhook|stripe|callback|hook|inbound|ipn|twilio-(voice|sms|status)/i.test(name) || /constructEvent|svix|x-signature|stripe-signature|x-twilio-signature|validateRequest|x-hub-signature/i.test(code);
        // Own protection: user login check, or a shared secret / signature header compared in code
        const userCheck = /auth\.getUser\s*\(|\bgetUser\s*\(|verifyJwt|jwtVerify|jwt\.verify|getClaims\s*\(|\brequire(Auth|User|Staff|Admin|Role|Member)\w*\s*\(|\b(auth|staff|admin)Gate\s*\(|\bwithAuth\s*\(|\bverify(Auth|User|Token|Request)\w*\s*\(|\bassert(Auth|Admin|User)\w*\s*\(/i.test(code);
        const headerRead = /headers\.get\(\s*(?:['"`](?!x-forwarded-for|x-real-ip|content-type|origin|user-agent|accept|referer|cf-connecting-ip)[\w-]+['"`]|[A-Za-z_]\w*)\s*\)\s*[!=]==?/i.test(code) ||
          /headers\.get\(\s*['"`](authorization|x-[\w-]*(key|secret|token|auth|signature)[\w-]*|apikey)['"`]\s*\)/i.test(code);
        const rejects = /\b40[13]\b|unauthori[sz]ed|forbidden/i.test(code);
        const secretCompare = /(SECRET|TOKEN|API_KEY|CRON)[\w]*['"`]\s*\)/.test(code) && /[!=]==?/.test(code);
        const ownAuth = userCheck || (headerRead && rejects) || (secretCompare && rejects);
        if (!isWebhook && !ownAuth) {
          const costly = /api\.openai\.com|openai|anthropic|generativelanguage|gemini|groq|replicate|elevenlabs|resend|sendgrid|mailgun|postmark|twilio|messagebird|vonage|perplexity|deepseek|api\.x\.ai/i.test(code);
          const admin = /SERVICE_ROLE|service_role/.test(code);
          const writes = /\.(insert|update|upsert|delete)\s*\(|\.rpc\s*\(/.test(code);
          findings.push({ level: costly ? 'HIGH' : 'MEDIUM', code: 'FUNCTION_NO_AUTH', where: file, item: name,
            text: `Server function "${name}" has the login check switched off (verify_jwt = false) and its code doesn't check the caller in any way we can see, so anyone on the internet can call it${costly ? ' and make it spend money on AI, email or SMS services' : admin && writes ? '. It changes data with admin rights' : writes ? '. It changes data' : ''}. If it isn't meant to be public (like a booking form or a tracking link), set verify_jwt = true, check the user with supabase.auth.getUser(), or require a secret header.` });
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
    const base = basename(file);
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
    const ext = extname(file);
    if (CODE_EXT.has(ext) && /stripe/i.test(text) && /webhook/i.test(text) &&
        /(checkout\.session\.completed|invoice\.paid|payment_intent\.succeeded|customer\.subscription)/.test(text) &&
        !/constructEvent(Async)?\s*\(/.test(text)) {
      findings.push({ level: 'HIGH', code: 'STRIPE_WEBHOOK_UNVERIFIED', where: file, item: base,
        text: `"${base}" handles Stripe webhook events without verifying the signature (stripe.webhooks.constructEvent). Anyone can fake a "paid" event.` });
    }
  }
  return { findings };
}

// files: [{file: 'relative/path', text}] for the whole project (unwanted files are ignored)
export function scanFiles(files) {
  const norm = files.map(f => ({ file: f.file.split('\\').join('/'), text: f.text })).filter(f => isWanted(f.file));
  const sqlFiles = norm.filter(f => f.file.endsWith('.sql')).sort((a, b) => a.file < b.file ? -1 : a.file > b.file ? 1 : 0)
    .map(f => ({ file: f.file, sql: f.text }));
  const codeFiles = norm.filter(f => {
    const b = basename(f.file);
    return CODE_EXT.has(extname(f.file)) || (/^\.env/.test(b) && !/example|sample|template/i.test(b));
  });
  const configs = norm.filter(f => basename(f.file) === 'config.toml' && /supabase/.test(f.file));
  const functionCode = new Map();
  const shared = new Map(); // supabase/functions/_shared/<file> -> text
  for (const cf of codeFiles) {
    const m = cf.file.match(/supabase\/functions\/([\w-]+)\//);
    if (!m) continue;
    if (m[1].startsWith('_')) shared.set(basename(cf.file).replace(/\.[jt]sx?$/, ''), cf.text);
    functionCode.set(m[1], (functionCode.get(m[1]) || '') + '\n' + cf.text);
  }
  // Add shared helper files a function imports (e.g. ../_shared/auth.ts), one level deep
  for (const [name, code] of functionCode) {
    if (name.startsWith('_')) continue;
    let extra = '';
    for (const [, f] of code.matchAll(/_[\w-]+\/(?:[\w.-]+\/)*([\w.-]+?)(?:\.[jt]sx?)?['"]/g)) extra += '\n' + (shared.get(f) || '');
    if (extra) functionCode.set(name, code + extra);
  }
  const a = analyzeSql(sqlFiles);
  const b = analyzeCode(codeFiles);
  const c = analyzeConfig(configs, functionCode);
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
  const findings = [...a.findings, ...b.findings, ...c.findings].sort((x, y) => order[x.level] - order[y.level]);
  return { sqlFiles: sqlFiles.length, codeFiles: codeFiles.length, configs: configs.length, tables: a.tables, findings };
}
