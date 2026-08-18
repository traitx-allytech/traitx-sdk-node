/**
 * Transport, serialisation and client behaviour. Uses a stub fetch, so it makes
 * no network calls.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  TraitXClient,
  Action,
  EventType,
  ValidationError,
  ConfigurationError,
  serializeEvent,
  contextFromRequest,
} = require('../dist/index.js');

const BASE = { baseUrl: 'https://traitx.example/', apiKey: 'trx_pvk_test_key_abcd' };

function stubFetch(responses) {
  const calls = [];
  const queue = Array.isArray(responses) ? [...responses] : [responses];
  const impl = async (url, init) => {
    calls.push({ url, init });
    const next = queue.length > 1 ? queue.shift() : queue[0];
    if (typeof next === 'function') return next(url, init);
    return {
      status: next.status ?? 200,
      headers: new Map(Object.entries(next.headers ?? {})),
      text: async () => JSON.stringify(next.body ?? {}),
    };
  };
  // Transport reads response.headers.get(); Map provides it.
  return { impl, calls };
}

function client(overrides = {}, responses = { status: 200, body: { score: 5 } }) {
  const { impl, calls } = stubFetch(responses);
  return {
    calls,
    traitx: new TraitXClient({ ...BASE, fetchImpl: impl, maxRetries: 0, ...overrides }),
  };
}

// -- configuration ----------------------------------------------------------

test('rejects a public collector key', () => {
  assert.throws(
    () => new TraitXClient({ ...BASE, apiKey: 'trx_116d72cb0e2f', fetchImpl: async () => {} }),
    ConfigurationError,
  );
});

test('rejects a non-absolute base url', () => {
  assert.throws(
    () => new TraitXClient({ ...BASE, baseUrl: 'traitx.example', fetchImpl: async () => {} }),
    ConfigurationError,
  );
});

test('rejects challenge threshold above deny threshold', () => {
  assert.throws(
    () => new TraitXClient({ ...BASE, thresholds: { challenge: 90, deny: 50 }, fetchImpl: async () => {} }),
    ConfigurationError,
  );
});

test('trims a trailing slash from the base url', () => {
  const { traitx } = client();
  assert.equal(traitx.config.baseUrl, 'https://traitx.example');
});

// -- request shape ----------------------------------------------------------

test('posts to /api/v1/risk with the private key header', async () => {
  const { traitx, calls } = client({ applicationId: 'app-123' });

  await traitx.evaluateLogin({ requestId: 'req_1', user: { id: 'u1' } });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://traitx.example/api/v1/risk');
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.headers['X-API-Key'], 'trx_pvk_test_key_abcd');
  assert.equal(calls[0].init.headers['X-Application-ID'], 'app-123');
  assert.equal(calls[0].init.headers['Content-Type'], 'application/json');
  assert.match(calls[0].init.headers['User-Agent'], /^traitx-sdk-node\//);
});

test('serialises headers as pairs and attributes at the root', () => {
  const payload = serializeEvent({
    requestId: 'req_2',
    type: EventType.Transaction,
    context: { ip: '66.118.160.25', headers: [['User-Agent', 'curl/8'], ['Accept-Language', 'ar-SA']] },
    user: { id: 'u1', email: 'a@b.c', firstName: 'Sara', address: { countryCode: 'SA' } },
    attributes: { amount: 5000, 'merchant.mcc': '5967' },
  });

  assert.deepEqual(payload.context.headers, [['User-Agent', 'curl/8'], ['Accept-Language', 'ar-SA']]);
  assert.equal(payload.amount, 5000);
  assert.equal(payload['merchant.mcc'], '5967');
  assert.equal(payload.user.first_name, 'Sara');
  assert.equal(payload.user.address.country_code, 'SA');
  assert.equal(payload.type, '$transaction');
  assert.equal(payload.status, '$succeeded');
  assert.ok(payload.created_at.endsWith('Z'));
});

test('transaction helper puts amount, currency and payee at the root', async () => {
  const { traitx, calls } = client();
  await traitx.evaluateTransaction({
    requestId: 'req_3',
    amount: 1200,
    currency: 'SAR',
    payeeId: 'payee_9',
  });
  const body = JSON.parse(calls[0].init.body);
  assert.equal(body.amount, 1200);
  assert.equal(body.currency, 'SAR');
  assert.equal(body.payee_id, 'payee_9');
  assert.equal(body.type, '$transaction');
});

test('challenge outcome maps passed to event status', async () => {
  const { traitx, calls } = client();
  await traitx.reportChallengeOutcome({ requestId: 'req_4', passed: false });
  const body = JSON.parse(calls[0].init.body);
  assert.equal(body.type, '$challenge');
  assert.equal(body.status, '$failed');
});

// -- validation -------------------------------------------------------------

test('rejects a missing requestId', async () => {
  const { traitx } = client();
  await assert.rejects(() => traitx.evaluateLogin({ user: { id: 'u1' } }), ValidationError);
});

test('rejects a chain hook used as an event type', async () => {
  const { traitx } = client();
  await assert.rejects(
    () => traitx.evaluate({ requestId: 'req_5', type: '$before_all' }),
    (error) => error instanceof ValidationError && /chain hook/.test(error.message),
  );
});

test('rejects an attribute that collides with a reserved field', () => {
  assert.throws(
    () => serializeEvent({ requestId: 'r', type: '$login', attributes: { user: {} } }),
    ValidationError,
  );
});

// -- degradation ------------------------------------------------------------

test('a thrown fetch degrades to failureMode instead of throwing', async () => {
  const { traitx } = client({ failureMode: Action.Challenge }, () => {
    throw new Error('ECONNREFUSED');
  });

  const decision = await traitx.evaluateLogin({ requestId: 'req_6' });

  assert.equal(decision.action, Action.Challenge);
  assert.equal(decision.reason, 'degraded');
  assert.equal(decision.degraded, true);
  assert.match(decision.error, /ECONNREFUSED/);
});

test('a 401 degrades to clientErrorMode and reports the api message', async () => {
  const { traitx } = client({}, {
    status: 401,
    body: { error: 'Unauthorized', message: 'Invalid or expired API key' },
  });

  const decision = await traitx.evaluateLogin({ requestId: 'req_7' });

  assert.equal(decision.action, Action.Allow);
  assert.equal(decision.reason, 'client_error');
  assert.match(decision.error, /Invalid or expired API key/);
});

test('retries a 503 then succeeds', async () => {
  let seen = 0;
  const { impl, calls } = stubFetch(async () => {
    seen += 1;
    if (seen === 1) {
      return { status: 503, headers: new Map(), text: async () => '{"error":"nope"}' };
    }
    return {
      status: 200,
      headers: new Map(),
      text: async () => JSON.stringify({ score: 90, policy: { action: 'deny' } }),
    };
  });

  const traitx = new TraitXClient({ ...BASE, fetchImpl: impl, maxRetries: 2, retryBackoffMs: 1 });
  const decision = await traitx.evaluateLogin({ requestId: 'req_8' });

  assert.equal(calls.length, 2);
  assert.equal(decision.action, Action.Deny);
  assert.equal(decision.degraded, false);
});

test('does not retry a 400', async () => {
  const { impl, calls } = stubFetch({ status: 400, body: { error: 'Bad Request' } });
  const traitx = new TraitXClient({ ...BASE, fetchImpl: impl, maxRetries: 3, retryBackoffMs: 1 });

  await traitx.evaluateLogin({ requestId: 'req_9' });

  assert.equal(calls.length, 1);
});

test('the breaker opens after repeated transport failures and short-circuits', async () => {
  let attempts = 0;
  const impl = async () => {
    attempts += 1;
    throw new Error('ECONNREFUSED');
  };
  const traitx = new TraitXClient({
    ...BASE,
    fetchImpl: impl,
    maxRetries: 0,
    breaker: { failureThreshold: 2, resetAfterMs: 60_000 },
  });

  await traitx.evaluateLogin({ requestId: 'a' });
  await traitx.evaluateLogin({ requestId: 'b' });
  assert.equal(attempts, 2);
  assert.equal(traitx.breakerState, 'open');

  const third = await traitx.evaluateLogin({ requestId: 'c' });
  assert.equal(attempts, 2, 'the third call must not touch the network');
  assert.equal(third.error, 'circuit breaker open');
  assert.equal(third.latencyMs, 0);
});

test('a successful call resets the breaker counter', async () => {
  let fail = true;
  const impl = async () => {
    if (fail) throw new Error('ECONNREFUSED');
    return { status: 200, headers: new Map(), text: async () => '{"score":1}' };
  };
  const traitx = new TraitXClient({
    ...BASE,
    fetchImpl: impl,
    maxRetries: 0,
    breaker: { failureThreshold: 3, resetAfterMs: 60_000 },
  });

  await traitx.evaluateLogin({ requestId: 'a' });
  fail = false;
  await traitx.evaluateLogin({ requestId: 'b' });
  fail = true;
  await traitx.evaluateLogin({ requestId: 'c' });

  assert.equal(traitx.breakerState, 'closed');
});

// -- hooks and helpers ------------------------------------------------------

test('onDecision can replace the decision', async () => {
  const { traitx } = client({
    onDecision: (decision) =>
      decision.score > 0 ? Object.assign(Object.create(Object.getPrototypeOf(decision)), decision, {
        action: Action.Deny,
      }) : undefined,
  }, { status: 200, body: { score: 3 } });

  const decision = await traitx.evaluateLogin({ requestId: 'req_10' });
  assert.equal(decision.action, Action.Deny);
});

test('contextFromRequest prefers the first X-Forwarded-For hop', () => {
  const context = contextFromRequest({
    headers: {
      'x-forwarded-for': '66.118.160.25, 10.0.0.1',
      'user-agent': 'Mozilla/5.0',
      'accept-language': 'ar-SA',
    },
    socket: { remoteAddress: '10.0.0.1' },
  });

  assert.equal(context.ip, '66.118.160.25');
  assert.deepEqual(
    context.headers.find(([name]) => name === 'User-Agent'),
    ['User-Agent', 'Mozilla/5.0'],
  );
});

test('management calls refuse to run without a portal token', async () => {
  const { traitx } = client();
  await assert.rejects(() => traitx.management.listPolicies(), /portal JWT/);
});

test('management calls send a bearer token and omit the api key', async () => {
  const { impl, calls } = stubFetch({ status: 200, body: { policies: [] } });
  const traitx = new TraitXClient({ ...BASE, fetchImpl: impl, applicationId: 'app-1' });

  traitx.management.withToken('jwt-abc');
  await traitx.management.listPolicies();

  assert.equal(calls[0].init.headers.Authorization, 'Bearer jwt-abc');
  assert.equal(calls[0].init.headers['X-API-Key'], undefined);
  assert.match(calls[0].url, /application_id=app-1/);
});

test('auditPolicies splits live, shadow and disabled policies', async () => {
  const { impl } = stubFetch({
    status: 200,
    body: {
      policies: [
        { name: 'live', enabled: true, pass_through: false },
        { name: 'shadow', enabled: true, pass_through: true },
        { name: 'off', enabled: false, pass_through: false },
      ],
    },
  });
  const traitx = new TraitXClient({ ...BASE, fetchImpl: impl });
  traitx.management.withToken('jwt');

  const audit = await traitx.management.auditPolicies();

  assert.deepEqual(audit.live, ['live']);
  assert.deepEqual(audit.shadow, ['shadow']);
  assert.deepEqual(audit.disabled, ['off']);
  assert.equal(audit.total, 3);
});
