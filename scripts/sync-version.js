#!/usr/bin/env node
/**
 * Keep `SDK_VERSION` in src/config.ts equal to package.json's version.
 *
 * SDK_VERSION goes out in the User-Agent on every risk call; 1.0.1 shipped
 * with the constant still at 1.0.0. `npm version` runs this via the `version`
 * lifecycle script, and test/version.test.js fails if the two ever drift.
 *
 *   node scripts/sync-version.js          # rewrite src/config.ts
 *   node scripts/sync-version.js --check  # exit 1 if out of sync
 */

const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const configPath = path.join(root, 'src', 'config.ts');
const source = fs.readFileSync(configPath, 'utf8');

const pattern = /export const SDK_VERSION = '([^']*)';/;
const match = source.match(pattern);
if (!match) {
  console.error('sync-version: SDK_VERSION declaration not found in src/config.ts');
  process.exit(2);
}

if (match[1] === pkg.version) {
  console.log(`sync-version: SDK_VERSION already ${pkg.version}`);
  process.exit(0);
}

if (process.argv.includes('--check')) {
  console.error(`sync-version: SDK_VERSION is ${match[1]} but package.json is ${pkg.version}`);
  process.exit(1);
}

fs.writeFileSync(configPath, source.replace(pattern, `export const SDK_VERSION = '${pkg.version}';`));
console.log(`sync-version: SDK_VERSION ${match[1]} -> ${pkg.version}`);
