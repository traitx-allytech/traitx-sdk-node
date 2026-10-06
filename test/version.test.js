/**
 * The reported version must match the packaged version.
 *
 * SDK_VERSION goes out in the User-Agent on every risk call, so if it drifts
 * from package.json support reads the wrong SDK version off a client's traffic.
 * 1.0.1 shipped with that drift; this test exists so it cannot recur.
 * `npm run sync-version` fixes it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { SDK_VERSION, TraitXClient } = require('../dist/index.js');

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));

test('SDK_VERSION matches package.json version', () => {
  assert.equal(SDK_VERSION, pkg.version, 'run `npm run sync-version`');
});

test('src/config.ts constant matches package.json (source of truth for the build)', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'config.ts'), 'utf8');
  const match = source.match(/export const SDK_VERSION = '([^']*)';/);
  assert.ok(match, 'SDK_VERSION declaration not found');
  assert.equal(match[1], pkg.version);
});

test('default User-Agent carries the package version', async () => {
  let seen;
  const client = new TraitXClient({
    baseUrl: 'https://traitx.example',
    apiKey: 'trx_pvk_test_key_abcd',
    maxRetries: 0,
    fetchImpl: async (_url, init) => {
      seen = init.headers;
      return { status: 200, headers: new Map(), text: async () => '{"score":1}' };
    },
  });
  await client.evaluateLogin({ requestId: 'req_1', user: { id: 'u1' } });
  assert.equal(seen['User-Agent'], `traitx-sdk-node/${pkg.version}`);
});
