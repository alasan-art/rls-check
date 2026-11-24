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
    assert.ok(c.includes('MEDIUM:STORAGE_OPEN_READ:storage / read passports'));
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
