# TraitX Decision SDK — Node.js / TypeScript

Turns a TraitX risk evaluation into one of three answers: **allow**, **challenge**,
**deny**. Requires Node 18+ (for built-in `fetch`).

Wire contract and decision algorithm: [`SPEC.md`](SPEC.md).

---

## Install

```bash
npm install @traitx/sdk
```

From this repository:

```bash
npm install && npm run build
```

---

## 1 · Browser: get a `requestId`

The public key goes in the browser. The private key never does.

```html
<script type="module">
  import { createCollector } from '@traitx/sdk/browser';

  const collector = createCollector({
    publicKey: 'trx_116d72cb0e…',
    apiEndpoint: 'https://traitx.allytech.sa',
  });

  document.querySelector('#login').addEventListener('submit', async (event) => {
    event.preventDefault();
    const { requestId } = await collector.identify();

    await fetch('/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-TraitX-Request-Id': requestId,
      },
      body: JSON.stringify({ email: email.value, password: password.value }),
    });
  });
</script>
```

`createCollector` throws if you hand it a `trx_pvk_` key — that guard exists
because shipping the private key to a browser hands risk-API access for the whole
tenant to anyone who opens devtools.

## 2 · Server: evaluate and enforce

```ts
import { TraitXClient, Action } from '@traitx/sdk';

const traitx = new TraitXClient({
  baseUrl: process.env.TRAITX_BASE_URL!,          // https://traitx.allytech.sa
  apiKey: process.env.TRAITX_PRIVATE_KEY!,        // trx_pvk_…
  applicationId: process.env.TRAITX_APPLICATION_ID,
  timeoutMs: 2500,
  failureMode: Action.Allow,                      // TraitX down → do not block logins
});

app.post('/api/login', async (req, res) => {
  const user = await authenticate(req.body.email, req.body.password);
  if (!user) return res.status(401).json({ error: 'invalid credentials' });

  const decision = await traitx.evaluateLogin({
    requestId: req.headers['x-traitx-request-id'] as string,
    user: { id: user.id, email: user.email, registeredAt: user.createdAt },
    session: { id: req.sessionID, createdAt: new Date() },
    context: TraitXClient.contextFromRequest(req),
  });

  if (decision.isDenied()) {
    await auditFraudBlock(user.id, decision);
    return res.status(403).json({ error: 'access denied' });
  }

  if (decision.requiresChallenge()) {
    await sendOtp(user);
    return res.status(200).json({ next: 'otp', reason: decision.signals });
  }

  return res.json({ token: issueToken(user) });
});
```

Construct the client **once per process**. The circuit breaker state lives on the
instance, so a client per request never opens and buys you nothing.

## 3 · Close the loop on a challenge

Tell the chain how the step-up went, so `$challenge` policies can react:

```ts
await traitx.reportChallengeOutcome({
  requestId,
  user: { id: user.id },
  passed: otpWasCorrect,
});
```

---

## Transactions

Transaction attributes go at the event root — that is where policy triggers look
for them:

```ts
const decision = await traitx.evaluateTransaction({
  requestId,
  amount: 5000,
  currency: 'SAR',
  payeeId: 'payee_88213',
  user: { id: user.id, email: user.email },
  context: TraitXClient.contextFromRequest(req),
  attributes: {
    'merchant.mcc': '5967',        // a dotted key is a literal key name
    'payment.channel': 'mada',
    'counterparty.country': 'SA',
  },
});
```

---

## Reading a decision

```ts
decision.action            // 'allow' | 'challenge' | 'deny'  ← act on this
decision.reason            // 'policy_match' | 'shadow' | 'score_threshold' | …
decision.score             // 0–100
decision.riskLevel         // 'low' | 'medium' | 'high' | 'critical'
decision.signals           // ['bot_behavior', 'tor_ip', …]
decision.matchedPolicies   // [{ id, name, action, passThrough }]
decision.enforced          // false when the deciding policy is shadow-mode
decision.observedAction    // what the chain would have done
decision.degraded          // true when TraitX was unreachable or rejected the call
decision.latencyMs
decision.raw               // full response body

decision.isAllowed()
decision.requiresChallenge()
decision.isDenied()
decision.hasDeviceContext()   // false → IP enrichment missing, IP policies unreachable
```

Branch on `isAllowed()`, never on `!isDenied()` — the latter lets challenges
through unchallenged, which is the most common way this integration goes wrong.

### Shadow mode

A policy deployed with `pass_through: true` evaluates and logs but does not
enforce. The SDK returns `allow` with `enforced: false` and `observedAction` set
to what would have happened. Log the pair to size a policy before you turn it on:

```ts
if (!decision.enforced && decision.observedAction !== Action.Allow) {
  metrics.increment('traitx.shadow', { would: decision.observedAction });
}
```

---

## Failure behaviour

`evaluate()` does not throw for network or API problems. It returns a decision
with `degraded: true` and the configured fallback action:

| Situation | Config | Default |
| --- | --- | --- |
| Timeout, connection error, 5xx, 429, open breaker | `failureMode` | `allow` |
| 401 / 400 / 403 — bad key or bad payload | `clientErrorMode` | `allow` |

Both default to `allow` deliberately: a rotated key must not lock every customer
out of checkout. Set them to `Action.Challenge` or `Action.Deny` if your risk
appetite says otherwise — that is a business decision, so the SDK makes you state
it.

`ValidationError` **is** thrown, for events the SDK refuses to send (missing
`requestId`, `$before_all` as a type). Those are bugs in calling code and should
fail in your tests.

---

## Express middleware

```ts
import { traitxMiddleware } from '@traitx/sdk';

app.use(traitxMiddleware({ client: traitx }));

app.post('/api/transfer', async (req, res) => {
  const decision = await req.traitx.evaluate({
    type: EventType.Transaction,
    user: { id: req.user.id },
    attributes: { amount: req.body.amount, currency: 'SAR' },
  });
  // …
});
```

The middleware fills in the end user's IP and headers and finds the collector
`requestId`. It never blocks on its own — enforcement belongs in the route that
knows what the user was trying to do.

---

## Management API (optional)

Policies and lists are administrative and authenticate with a **portal JWT**, not
the private key. These calls throw on failure.

```ts
traitx.management.withToken(process.env.TRAITX_PORTAL_JWT!);

// Assert at boot that what you rely on is actually live.
const audit = await traitx.management.auditPolicies();
console.log(`${audit.live.length} live, ${audit.shadow.length} shadow, ${audit.disabled.length} off`);

// Blocklist a device after a confirmed chargeback.
await traitx.management.addListEntry(BLOCKED_DEVICES_LIST_ID, {
  value: visitorId,
  comment: `chargeback ${caseId}`,
  expiresAt: new Date(Date.now() + 90 * 24 * 3600 * 1000),
});
```

---

## Self-check

```bash
npm run build
TRAITX_BASE_URL=https://traitx.allytech.sa \
TRAITX_PRIVATE_KEY=trx_pvk_… \
TRAITX_APPLICATION_ID=ccf2d2a0-… \
node scripts/doctor.js req_abc123
```

Confirms the key class, connectivity, application scoping, whether IP enrichment
reached the event, and whether the chain returns an action.

## Tests

```bash
npm run build && npm test
```

`test/conformance.test.js` runs [`conformance/vectors.json`](conformance/vectors.json),
the shared fixture every language binding must satisfy.
