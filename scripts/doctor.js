#!/usr/bin/env node
/**
 * Integration self-check. Run it once after wiring the SDK up:
 *
 *   TRAITX_BASE_URL=https://traitx.allytech.sa \
 *   TRAITX_PRIVATE_KEY=trx_pvk_… \
 *   TRAITX_APPLICATION_ID=ccf2d2a0-… \
 *   node scripts/doctor.js [collector-request-id]
 *
 * Pass a real `requestId` from your browser collector to also verify that the
 * key is accepted, that IP enrichment is attached, and that the policy chain
 * returns an action. Without one, only connectivity and configuration are
 * checked. See SPEC.md §13.
 */

const { TraitXClient } = require('../dist/index.js');

async function main() {
  const baseUrl = process.env.TRAITX_BASE_URL;
  const apiKey = process.env.TRAITX_PRIVATE_KEY;

  if (!baseUrl || !apiKey) {
    console.error('set TRAITX_BASE_URL and TRAITX_PRIVATE_KEY');
    process.exit(2);
  }

  const client = new TraitXClient({
    baseUrl,
    apiKey,
    applicationId: process.env.TRAITX_APPLICATION_ID,
    timeoutMs: Number(process.env.TRAITX_TIMEOUT_MS ?? 5000),
  });

  const report = await client.doctor(process.argv[2]);

  for (const finding of report.findings) {
    console.log(`${finding.ok ? 'ok  ' : 'FAIL'}  ${finding.check.padEnd(32)} ${finding.detail}`);
  }

  console.log(`\n${report.ok ? 'All checks passed.' : 'Some checks failed — see above.'}`);
  process.exit(report.ok ? 0 : 1);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
