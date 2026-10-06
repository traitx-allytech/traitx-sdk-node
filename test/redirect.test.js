/**
 * Redirect policy (SDK-01): the transport must never follow a redirect on its
 * own, because `fetch` would forward `X-API-Key` / `Authorization` to whatever
 * host the `Location` header names.
 *
 * Covers cross-host, port change, HTTPS→HTTP downgrade, same-origin, and the
 * management JWT path — each with a stub fetch — plus one end-to-end check
 * against two loopback HTTP servers using the real global fetch.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { TraitXClient, Action, ApiError } = require('../dist/index.js');
const { isSameOrigin } = require('../dist/http.js');

const BASE = { baseUrl: 'https://traitx.example', apiKey: 'trx_pvk_test_key_abcd' };

function redirectingFetch(status, location) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    return {
      status,
      headers: new Map(location === null ? [] : [['location', location]]),
      text: async () => '',
    };
  };
  return { impl, calls };
}

async function evaluateVia(impl, overrides = {}) {
  const client = new TraitXClient({ ...BASE, fetchImpl: impl, maxRetries: 2, ...overrides });
  return client.evaluateLogin({ requestId: 'req_1', user: { id: 'u1' } });
}

test('fetch is called with redirect: "manual"', async () => {
  const { impl, calls } = redirectingFetch(302, 'https://evil.example/collect');
  await evaluateVia(impl);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.redirect, 'manual');
});

test('cross-host 302 is not followed; decision degrades to failureMode', async () => {
  const { impl, calls } = redirectingFetch(302, 'https://evil.example/api/v1/risk');
  const decision = await evaluateVia(impl, { failureMode: Action.Deny });
  assert.equal(calls.length, 1, 'no second request to the redirect target');
  assert.equal(decision.degraded, true);
  assert.equal(decision.action, Action.Deny);
  assert.match(decision.error, /cross-origin/);
  assert.match(decision.error, /evil\.example/);
});

test('port-change redirect is not followed', async () => {
  const { impl, calls } = redirectingFetch(307, 'https://traitx.example:8443/api/v1/risk');
  const decision = await evaluateVia(impl);
  assert.equal(calls.length, 1);
  assert.equal(decision.degraded, true);
  assert.match(decision.error, /cross-origin/);
});

test('HTTPS→HTTP downgrade redirect is not followed', async () => {
  const { impl, calls } = redirectingFetch(301, 'http://traitx.example/api/v1/risk');
  const decision = await evaluateVia(impl);
  assert.equal(calls.length, 1);
  assert.equal(decision.degraded, true);
  assert.match(decision.error, /cross-origin/);
});

test('same-origin redirect is also not followed (no retry loop, no credential replay)', async () => {
  const { impl, calls } = redirectingFetch(308, '/api/v1/risk/');
  const decision = await evaluateVia(impl);
  assert.equal(calls.length, 1, 'a redirect must not be retried');
  assert.equal(decision.degraded, true);
  assert.match(decision.error, /same-origin/);
});

test('redirect without Location is reported, not retried', async () => {
  const { impl, calls } = redirectingFetch(302, null);
  const decision = await evaluateVia(impl);
  assert.equal(calls.length, 1);
  assert.equal(decision.degraded, true);
  assert.match(decision.error, /no Location/);
});

test('management JWT is not forwarded on a cross-host redirect', async () => {
  const { impl, calls } = redirectingFetch(302, 'https://evil.example/api/v1/policies');
  const client = new TraitXClient({ ...BASE, fetchImpl: impl, maxRetries: 0 });
  await assert.rejects(
    () => client.management.withToken('eyJ.jwt.token').listPolicies('app-1'),
    (error) => error instanceof ApiError && /cross-origin/.test(error.message),
  );
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.headers.Authorization, 'Bearer eyJ.jwt.token');
  assert.equal(calls[0].init.redirect, 'manual');
});

test('isSameOrigin: scheme, host and port must all match', () => {
  assert.equal(isSameOrigin('https://a.example/x', 'https://a.example/y'), true);
  assert.equal(isSameOrigin('https://a.example/x', '/y'), true);
  assert.equal(isSameOrigin('https://a.example/x', 'https://b.example/x'), false);
  assert.equal(isSameOrigin('https://a.example/x', 'https://a.example:8443/x'), false);
  assert.equal(isSameOrigin('https://a.example/x', 'http://a.example/x'), false);
  assert.equal(isSameOrigin('https://a.example/x', 'not a url'), true, 'relative path, same origin');
  assert.equal(isSameOrigin('not a url', 'https://a.example/x'), false);
});

// -- end to end with the real fetch and two loopback servers ----------------

function listen(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

test('real fetch: 302 from one loopback server to another never reaches the target', async (t) => {
  if (typeof fetch !== 'function') {
    t.skip('global fetch unavailable');
    return;
  }
  const targetHits = [];
  const target = await listen((req, res) => {
    targetHits.push(req.headers);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"score":1}');
  });
  const targetPort = target.address().port;
  const origin = await listen((req, res) => {
    res.writeHead(302, { location: `http://localhost:${targetPort}/api/v1/risk` });
    res.end();
  });
  t.after(() => {
    origin.close();
    target.close();
  });

  const client = new TraitXClient({
    baseUrl: `http://127.0.0.1:${origin.address().port}`,
    apiKey: 'trx_pvk_test_key_abcd',
    maxRetries: 1,
  });
  const decision = await client.evaluateLogin({ requestId: 'req_1', user: { id: 'u1' } });

  assert.equal(targetHits.length, 0, 'the redirect target must never see the request');
  assert.equal(decision.degraded, true);
  assert.match(decision.error, /cross-origin/);
});
