import { createClient } from 'npm:@supabase/supabase-js@2';
Deno.serve(async (req) => {
  const supabase = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_ANON_KEY')!, {
    global: { headers: { Authorization: req.headers.get('Authorization')! } },
  });
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response('Unauthorized', { status: 401 });
  const key = Deno.env.get('OPENAI_API_KEY'); // server-side secret, fine
  return new Response(JSON.stringify({ ok: true, user: user.id, hasKey: !!key }));
});
