/**
 * Runs sdk/conformance/vectors.json against the Node decision engine.
 *
 *   npm run build && npm test
 *
 * Every language SDK ships the equivalent of this file. If a vector fails here
 * but passes elsewhere, the bindings have drifted.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { resolveDecision, resolveConfig, Action } = require('../dist/index.js');

// Walk up looking for the shared fixture, so this passes whether the SDK sits in
// the monorepo (sdk/node) or at the root of its own repository.
function locateVectors() {
  let dir = __dirname;
  for (let i = 0; i < 6; i += 1) {
    const candidate = path.join(dir, 'conformance', 'vectors.json');
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('could not find conformance/vectors.json');
}

const vectorsPath = locateVectors();
const suite = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));

function configFor(overrides) {
  return resolveConfig({
    baseUrl: 'https://example.test',
    apiKey: 'trx_pvk_conformance_key_0000',
    ...suite.defaults.config,
    ...overrides,
    thresholds: { ...suite.defaults.config.thresholds, ...(overrides.thresholds ?? {}) },
    fetchImpl: async () => {
      throw new Error('the decision engine must not perform I/O');
    },
  });
}

function outcomeFor(http) {
  if (http.transportError) {
    return { statusCode: 0, latencyMs: 3, transportError: http.transportError };
  }
  if (http.rawBody !== undefined) {
    // A body that is not decodable JSON reaches the engine as `body: undefined`.
    return { statusCode: http.status, latencyMs: 3, body: undefined };
  }
  const retryable = http.status >= 500 || http.status === 429 || http.status === 408;
  return {
    statusCode: http.status,
    latencyMs: 3,
    body: http.body,
    ...(retryable ? { transportError: `risk api returned HTTP ${http.status}` } : {}),
  };
}

for (const vector of suite.vectors) {
  test(vector.name, () => {
    const config = configFor(vector.config ?? {});
    const decision = resolveDecision(outcomeFor(vector.http), config, 'req_conformance');
    const want = vector.expect;

    assert.equal(decision.action, want.action, 'action');

    if ('observedAction' in want) {
      assert.equal(decision.observedAction, want.observedAction, 'observedAction');
    }
    if ('enforced' in want) assert.equal(decision.enforced, want.enforced, 'enforced');
    if ('reason' in want) assert.equal(decision.reason, want.reason, 'reason');
    if ('score' in want) assert.equal(decision.score, want.score, 'score');
    if ('riskLevel' in want) assert.equal(decision.riskLevel, want.riskLevel, 'riskLevel');
    if ('degraded' in want) assert.equal(decision.degraded, want.degraded, 'degraded');
    if ('statusCode' in want) assert.equal(decision.statusCode, want.statusCode, 'statusCode');
    if ('matchedCount' in want) {
      assert.equal(decision.matchedPolicies.length, want.matchedCount, 'matchedPolicies.length');
    }
    if ('firstMatchedId' in want) {
      assert.equal(decision.matchedPolicies[0].id, want.firstMatchedId, 'matchedPolicies[0].id');
    }
    if ('firstMatchedName' in want) {
      assert.equal(decision.matchedPolicies[0].name, want.firstMatchedName, 'matchedPolicies[0].name');
    }
    if ('hasError' in want) {
      assert.equal(Boolean(decision.error), want.hasError, 'error present');
    }
    if ('hasDeviceContext' in want) {
      assert.equal(decision.hasDeviceContext(), want.hasDeviceContext, 'hasDeviceContext()');
    }

    // Invariants that hold for every vector.
    assert.ok(Object.values(Action).includes(decision.action), 'action is a valid Action');
    assert.equal(
      decision.isAllowed(),
      decision.action === Action.Allow,
      'isAllowed() agrees with action',
    );
    assert.ok(
      !(decision.isAllowed() && decision.isDenied()),
      'a decision cannot be both allowed and denied',
    );
  });
}

test('vector file covers every reason code', () => {
  const seen = new Set(suite.vectors.map((v) => v.expect.reason).filter(Boolean));
  for (const reason of [
    'policy_match',
    'shadow',
    'score_threshold',
    'signal_override',
    'no_match',
    'degraded',
    'client_error',
  ]) {
    assert.ok(seen.has(reason), `no vector exercises reason "${reason}"`);
  }
});
