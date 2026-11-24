// invented demo: webhook trusts the body without signature check
Deno.serve(async (req) => {
  const event = await req.json(); // stripe webhook
  if (event.type === 'checkout.session.completed') {
    // mark user as paid
  }
  return new Response('ok');
});
