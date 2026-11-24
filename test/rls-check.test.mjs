import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject, analyzeSql } from '../rls-check.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const codes = r => r.findings.map(f => `${f.level}:${f.code}:${f.item}`);

// Fake JWTs are generated at test time so no key-like strings live in the repo.
const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const fakeJwt = role => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', ref: 'demoexample', role, iat: 1700000000 })}.${b64({ fake: 'signature-for-tests' })}`;

// Fake API key shaped like an OpenAI project key, built at runtime
const fakeOpenAiKey = () => 'sk-' + 'proj-' + 'x'.repeat(8) + 'FAKEKEYFORTESTS' + '0'.repeat(24);

function copyFixture(name, role) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `rls-check-${name}-`));
  fs.cpSync(path.join(here, '../fixtures', name), dir, { recursive: true });
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'src/supabaseClient.ts'),
    `import { createClient } from '@supabase/supabase-js';\nexport const supabase = createClient('https://demoexample.supabase.co', '${fakeJwt(role)}');\n`);
  if (name === 'broken-app') {
    fs.writeFileSync(path.join(dir, 'src/ai.ts'), `export const openaiKey = '${fakeOpenAiKey()}';\n`);
  }
  return dir;
}

test('broken app: finds the typical AI-built mistakes', () => {
  const dir = copyFixture('broken-app', 'service_role');
  try {
    const r = scanProject(dir);
    const c = codes(r);
    assert.ok(c.includes('HIGH:RLS_OFF:invoices'));
    assert.ok(c.includes('HIGH:OPEN_WRITE_POLICY:notes / Anyone can do anything'));
    assert.ok(c.includes('MEDIUM:ANY_USER_POLICY:profiles / logged in can read profiles'));
    assert.ok(c.includes('INFO:RLS_NO_POLICIES:audit_log'));
    assert.ok(c.includes('HIGH:VIEW_BYPASSES_RLS:invoice_totals'));
    assert.ok(c.includes('MEDIUM:DEFINER_NO_SEARCH_PATH:make_admin'));
    assert.ok(c.some(x => x.startsWith('HIGH:SERVICE_KEY_EXPOSED')));
    assert.ok(c.some(x => x.startsWith('HIGH:SERVICE_KEY_PUBLIC_ENV')));
    assert.ok(c.some(x => x.startsWith('HIGH:STRIPE_WEBHOOK_UNVERIFIED')));
    assert.equal(r.tables.length, 4);
    // v0.2 checks
    assert.ok(c.includes('HIGH:SECRET_IN_PUBLIC_ENV:VITE_OPENAI_API_KEY'), 'paid key in browser env');
    assert.ok(c.includes('HIGH:AI_KEY_IN_BROWSER_CODE:OpenAI key in ai.ts'), 'hard-coded key in browser code');
    assert.ok(c.includes('HIGH:FUNCTION_NO_AUTH:generate-report'), 'open server function');
    assert.ok(!c.some(x => x.includes('FUNCTION_NO_AUTH:stripe-webhook')), 'webhooks are allowed to skip JWT');
    assert.ok(c.includes('MEDIUM:STORAGE_BUCKET_PUBLIC:passports'));
    assert.ok(!c.some(x => x.includes('STORAGE_BUCKET_PUBLIC:logos')), 'private bucket not flagged');
    assert.ok(c.includes('HIGH:STORAGE_OPEN_WRITE:storage / upload passports'));
    assert.ok(c.includes('LOW:STORAGE_OPEN_READ:storage / read passports'));
    assert.ok(c.includes('INFO:EMAIL_CONFIRM_OFF:auth.email'));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('clean app: no findings (anon key is fine)', () => {
  const dir = copyFixture('clean-app', 'anon');
  try { assert.deepEqual(codes(scanProject(dir)), []); }
  finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('dropping a bad policy removes the finding', () => {
  const r = analyzeSql([{ file: 'a.sql', sql: `create table t (id int); alter table t enable row level security;
    create policy p on t for all using (true); drop policy p on t;
    create policy q on t for select to authenticated using (auth.uid() = id);` }]);
  assert.deepEqual(r.findings.map(f => f.code), []);
});

test('server-side key is MEDIUM, Anthropic key is not double-counted as OpenAI', async () => {
  const { analyzeCode } = await import('../rls-check.mjs');
  const ant = 'sk-' + 'ant-' + 'api03-' + 'F'.repeat(40);
  const r = analyzeCode([{ file: path.join('supabase', 'functions', 'chat', 'index.ts'), text: `const k = '${ant}';` }]);
  assert.deepEqual(r.findings.map(f => `${f.level}:${f.code}:${f.item}`), ['MEDIUM:AI_KEY_HARDCODED:Anthropic key in index.ts']);
});

test('publishable keys in public env are fine', async () => {
  const { analyzeCode } = await import('../rls-check.mjs');
  const r = analyzeCode([{ file: '.env', text: 'VITE_STRIPE_PUBLISHABLE_KEY=x\nNEXT_PUBLIC_SUPABASE_ANON_KEY=y\n' }]);
  assert.deepEqual(r.findings, []);
});

// Patterns found in real public projects (accuracy test, 24 Nov 2026)
test('real-world patterns: no false alarms', async () => {
  const { analyzeSql } = await import('../rls-check.mjs');
  const sql = `
    create table public.jobs (id int); alter table public.jobs enable row level security;
    create policy "service role full access" on public.jobs for all to service_role using (true) with check (true);
    do $$ begin
      if not exists (select 1 from pg_policies where policyname = 'own jobs') then
        create policy "own jobs" on public.jobs for select to authenticated using (auth.uid() = id::uuid);
      end if;
    end $$;
    create policy "q" on public.made_in_dashboard for select to authenticated using (auth.uid() = owner);
    create view public.v1 as select * from public.jobs;
    alter view public.v1 set (security_invoker = on);
    create function public.f() returns int language sql security definer as $f$ select 1 $f$;
    alter function public.f() set search_path = '';
    create table public.old (id int); drop table public.old;
    insert into storage.buckets (id, name, public) values ('docs', 'docs', true);
    update storage.buckets set public = false where id = 'docs';`;
  const r = analyzeSql([{ file: 'a.sql', sql }]);
  assert.deepEqual(r.findings.map(f => `${f.code}:${f.item}`), []);
});

test('real-world patterns: still caught', async () => {
  const { analyzeSql } = await import('../rls-check.mjs');
  const sql = `
    create table public.leads (id int); alter table public.leads enable row level security;
    create policy "anon insert" on public.leads for insert to anon with check (true);
    do $$ begin
      create policy "open update" on public.leads for update using (true);
    end $$;
    create table public.logs (id int);`;
  const c = analyzeSql([{ file: 'a.sql', sql }]).findings.map(f => `${f.level}:${f.code}:${f.item}`);
  assert.ok(c.includes('MEDIUM:OPEN_INSERT_POLICY:leads / anon insert'));
  assert.ok(c.includes('HIGH:OPEN_WRITE_POLICY:leads / open update'), 'policy inside DO block');
  assert.ok(c.includes('HIGH:RLS_OFF:logs'));
});

test('server function protected by a secret header is not flagged', async () => {
  const { analyzeConfig } = await import('../rls-check.mjs');
  const code = `const expected = Deno.env.get('INTERNAL_FUNCTION_SECRET');
    if (!expected || req.headers.get('x-internal-secret') !== expected) return json(401, {});
    await supabase.from('x').insert({});`;
  const open = `const ip = req.headers.get('x-forwarded-for'); return new Response(ip);`;
  const r = analyzeConfig([{ file: 'supabase/config.toml', text: '[functions.cron-job]\nverify_jwt = false\n[functions.whoami]\nverify_jwt = false\n' }],
    new Map([['cron-job', code], ['whoami', open]]));
  assert.deepEqual(r.findings.map(f => `${f.level}:${f.code}:${f.item}`), ['MEDIUM:FUNCTION_NO_AUTH:whoami']);
});

test('RLS enabled in a loop, or table revoked from API roles, is not RLS_OFF', async () => {
  const { analyzeSql } = await import('../rls-check.mjs');
  const sql = `create table public.a (id int); create table public.b (id int); create table public.c (id int);
    do $$ declare t text; begin
      foreach t in array array['a','b'] loop
        execute format('alter table public.%I enable row level security', t);
      end loop; end $$;
    revoke all on public.c from public, anon, authenticated;`;
  const r = analyzeSql([{ file: 'a.sql', sql }]);
  assert.deepEqual(r.findings.filter(f => f.code === 'RLS_OFF'), []);
});

test('"auth.uid() is not null" means any logged-in user, not the owner', async () => {
  const { analyzeSql } = await import('../rls-check.mjs');
  const sql = `create table public.notes (id int, owner uuid); alter table public.notes enable row level security;
    create policy "logged in" on public.notes for select using (auth.uid() is not null);
    create policy "own" on public.notes for update using (auth.uid() is not null and owner = auth.uid());
    create policy "upload" on storage.objects for insert with check (bucket_id = 'docs' and auth.uid() is not null);`;
  const c = analyzeSql([{ file: 'a.sql', sql }]).findings.map(f => `${f.code}:${f.item}`);
  assert.ok(c.includes('ANY_USER_POLICY:notes / logged in'));
  assert.ok(!c.includes('ANY_USER_POLICY:notes / own'));
  assert.ok(c.includes('STORAGE_OPEN_WRITE:storage / upload'));
});
