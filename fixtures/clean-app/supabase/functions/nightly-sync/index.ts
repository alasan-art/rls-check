import { machineAuthError } from '../_shared/cronAuth.ts';
Deno.serve(async (req) => {
  const err = machineAuthError(req, 'SYNC_SECRET', 'x-sync-key');
  if (err) return err;
  // ... await supabase.from('items').upsert(rows)
  return new Response('ok');
});
