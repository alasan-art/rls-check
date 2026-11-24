import Stripe from 'npm:stripe@17';
const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY')!);
Deno.serve(async (req) => {
  const body = await req.text();
  const event = await stripe.webhooks.constructEventAsync(body, req.headers.get('stripe-signature')!, Deno.env.get('STRIPE_WEBHOOK_SECRET')!);
  if (event.type === 'checkout.session.completed') { /* mark paid */ }
  return new Response('ok');
});
