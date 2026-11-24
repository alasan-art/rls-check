// Browser front end for rls-check. Reads files locally with the File API; makes no network requests.
import { VERSION, SKIP_DIRS, isWanted, scanFiles } from './core.mjs';

const $ = id => document.getElementById(id);
const MAX_FILE = 2 * 1024 * 1024; // skip files over 2 MB (bundles, data dumps)
const LABEL = { HIGH: 'High risk', MEDIUM: 'Medium', LOW: 'Low', INFO: 'Info' };
let lastReport = '';

// "Get it fixed" offer, shown under high-risk results. It stays hidden while FIX_URL is empty,
// so the page never points to a listing that isn't live yet. Set FIX_URL to the live listing.
// A normal link: clicking it opens the listing; this page still sends nothing anywhere.
const FIX_URL = '';

$('ver').textContent = 'v' + VERSION;

function setStatus(msg) { $('status').textContent = msg; }

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Remove the top folder name so paths look like "supabase/migrations/x.sql"
function stripTop(paths) {
  const tops = new Set(paths.map(p => p.split('/')[0]));
  return tops.size === 1 && paths.every(p => p.includes('/')) ? paths.map(p => p.slice(p.indexOf('/') + 1)) : paths;
}

async function readFiles(list) {
  // list: [{path, file: File}]
  const wanted = list.filter(x => isWanted(x.path) && x.file.size <= MAX_FILE);
  const out = [];
  for (const x of wanted) out.push({ file: x.path, text: await x.file.text() });
  return out;
}

function render(r, sourceLabel) {
  const counts = r.findings.reduce((c, f) => (c[f.level] = (c[f.level] || 0) + 1, c), {});
  const pills = ['HIGH', 'MEDIUM', 'LOW', 'INFO'].filter(l => counts[l])
    .map(l => `<span class="pill ${l}">${counts[l]} ${esc(LABEL[l].toLowerCase())}</span>`).join('');
  $('summary').innerHTML = r.findings.length
    ? pills
    : `<span class="pill OK">No problems found by these checks</span>`;
  const fix = $('fix');
  if (FIX_URL && counts.HIGH) {
    $('fixLink').href = FIX_URL;
    $('fixCount').textContent = counts.HIGH === 1 ? '1 high-risk problem' : `${counts.HIGH} high-risk problems`;
    fix.hidden = false;
  } else fix.hidden = true;
  const notes = [];
  if (r.sqlFiles === 0) notes.push('No .sql files were found, so the database rules were not checked. Make sure the folder contains supabase/migrations, or paste your SQL.');
  $('list').innerHTML =
    notes.map(n => `<p class="note">${esc(n)}</p>`).join('') +
    r.findings.map(f => `
      <article class="finding ${f.level}">
        <div class="top">
          <span class="tag ${f.level}">${esc(LABEL[f.level])}</span>
          <span class="item">${esc(f.item)}</span>
          <span class="where">${esc(f.where)}</span>
        </div>
        <p class="text">${esc(f.text)}</p>
      </article>`).join('');
  $('results').hidden = false;
  setStatus(`Checked ${sourceLabel}: ${r.sqlFiles} SQL files, ${r.codeFiles} code files, ${r.configs} config files, ${r.tables.length} tables.`);
  lastReport = [
    `rls-check v${VERSION} report (${sourceLabel})`,
    `Summary: ${['HIGH', 'MEDIUM', 'LOW', 'INFO'].map(l => `${l} ${counts[l] || 0}`).join(' · ')}`,
    ...notes,
    ...r.findings.map(f => `\n[${f.level}] ${f.code}  ${f.item}  (${f.where})\n  ${f.text}`),
    '\nNot a full security review. Settings changed in the Supabase dashboard are not visible to this check.',
  ].join('\n');
  $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function runOn(list, label) {
  try {
    setStatus('Reading files…');
    const files = await readFiles(list);
    if (!files.length) { setStatus('No files the check can read were found in that folder (looked for .sql, code, .env and supabase/config.toml).'); return; }
    setStatus(`Checking ${files.length} files…`);
    render(scanFiles(files), label);
  } catch (e) {
    setStatus('Something went wrong while reading the files: ' + e.message);
  }
}

// Folder picker
$('folder').addEventListener('change', e => {
  const files = [...e.target.files];
  if (!files.length) return;
  const paths = stripTop(files.map(f => f.webkitRelativePath || f.name));
  const top = (files[0].webkitRelativePath || '').split('/')[0] || 'your folder';
  runOn(files.map((f, i) => ({ path: paths[i], file: f })), `"${top}"`);
  e.target.value = '';
});
$('folderBtn').addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('folder').click(); } });

// Drag and drop (folders are walked, skipping node_modules etc. early)
function walkEntry(entry, prefix, out) {
  return new Promise(resolve => {
    if (entry.isFile) {
      entry.file(f => { out.push({ path: prefix + entry.name, file: f }); resolve(); }, () => resolve());
    } else if (entry.isDirectory) {
      if (SKIP_DIRS.has(entry.name)) return resolve();
      const reader = entry.createReader();
      const all = [];
      const readBatch = () => reader.readEntries(async batch => {
        if (!batch.length) {
          for (const child of all) await walkEntry(child, prefix + entry.name + '/', out);
          return resolve();
        }
        all.push(...batch); readBatch();
      }, () => resolve());
      readBatch();
    } else resolve();
  });
}
const drop = $('drop');
['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', async e => {
  const items = [...(e.dataTransfer.items || [])].map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  const out = [];
  setStatus('Reading folder…');
  for (const entry of items) await walkEntry(entry, '', out);
  if (!out.length && e.dataTransfer.files.length) for (const f of e.dataTransfer.files) out.push({ path: f.name, file: f });
  const paths = stripTop(out.map(x => x.path));
  runOn(out.map((x, i) => ({ path: paths[i], file: x.file })), items.length === 1 ? `"${items[0].name}"` : 'dropped files');
});

// Pasted SQL
$('sqlBtn').addEventListener('click', () => {
  const sql = $('sql').value.trim();
  if (!sql) { setStatus('Paste some SQL first.'); return; }
  render(scanFiles([{ file: 'pasted.sql', text: sql }]), 'pasted SQL');
});

// Built-in example (an invented app with typical mistakes)
const DEMO = [
  { file: 'supabase/migrations/20260101_init.sql', text: `create table public.profiles (id uuid primary key, full_name text);
create table public.invoices (id bigint primary key, user_id uuid, amount numeric);
create table public.notes (id bigint primary key, owner uuid, body text);
alter table public.profiles enable row level security;
alter table public.notes enable row level security;
create policy "Anyone can do anything" on public.notes for all using (true) with check (true);
create policy "logged in can read profiles" on public.profiles for select using (auth.role() = 'authenticated');
insert into storage.buckets (id, name, public) values ('passports', 'passports', true);
create policy "upload passports" on storage.objects for insert to anon with check (bucket_id = 'passports');` },
  { file: 'supabase/config.toml', text: `[functions.generate-report]\nverify_jwt = false\n` },
  { file: 'supabase/functions/generate-report/index.ts', text: `Deno.serve(async (req) => {
  const { prompt } = await req.json();
  const r = await fetch('https://api.openai.com/v1/chat/completions', { method: 'POST',
    headers: { Authorization: 'Bearer ' + Deno.env.get('OPENAI_API_KEY') }, body: JSON.stringify({ prompt }) });
  return new Response(await r.text());
});` },
  { file: 'supabase/functions/stripe-webhook/index.ts', text: `// stripe webhook: trusts the request body without checking the signature
Deno.serve(async (req) => {
  const event = await req.json();
  if (event.type === 'checkout.session.completed') { /* mark user as paid */ }
  return new Response('ok');
});` },
  { file: '.env', text: 'VITE_SUPABASE_URL=https://example.supabase.co\nVITE_OPENAI_API_KEY=placeholder\n' },
];
$('demoBtn').addEventListener('click', () => render(scanFiles(DEMO), 'the example app (invented, with typical mistakes)'));

// Copy report
$('copyBtn').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(lastReport); setStatus('Report copied. You can paste it into an email or a message to your developer.'); }
  catch { setStatus('Copy did not work in this browser. Select the results and copy them by hand.'); }
});
