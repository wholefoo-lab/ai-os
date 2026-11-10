// Every pre-existing stripe-adjacent suite stubs `stripe: {}` via vm (test-audit-repairs.js,
// test-review-followup.js) — none imports the real package. This suite does, so a stripe-node
// major bump (e.g. 22.x -> 23.x) that changes webhook signing/verification or Checkout.Session
// shape actually gets caught, not just the routing code around it (server.js:735).
const stripe = require('stripe')('sk_test_dummykeyfortesting');
const { assert, done } = require('./test-util');

const secret = 'whsec_testsecret';
const payload = JSON.stringify({
  id: 'evt_test_123',
  object: 'event',
  type: 'checkout.session.completed',
  data: {
    object: {
      id: 'cs_test_123',
      object: 'checkout.session',
      customer_details: { email: 'buyer@example.com' },
      amount_total: 1999,
      metadata: { plan: 'pro' },
      payment_status: 'paid',
    },
  },
});

const header = stripe.webhooks.generateTestHeaderString({ payload, secret });
const event = stripe.webhooks.constructEvent(payload, header, secret);

assert(event.type === 'checkout.session.completed', 'constructEvent recovers the event type after a signed round-trip');
assert(event.data.object.amount_total === 1999, 'amount_total survives verification unchanged');
assert(event.data.object.payment_status === 'paid', 'payment_status survives verification unchanged');
assert(event.data.object.customer_details.email === 'buyer@example.com', 'customer_details survives verification unchanged');
assert(event.data.object.metadata.plan === 'pro', 'metadata survives verification unchanged');

let rejected = false;
try {
  stripe.webhooks.constructEvent(payload, header, 'whsec_wrongsecret');
} catch (e) {
  rejected = e && /signature/i.test(e.message || '');
}
assert(rejected, 'a signature made with the wrong secret is rejected, not silently accepted');

done();
