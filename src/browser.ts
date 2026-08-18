/**
 * Browser-side helper.
 *
 * This is the ONLY part of the SDK that belongs in a browser bundle, and it
 * carries the **public** key only. It wraps the TraitX collector so your
 * frontend does one thing: obtain a `requestId` and hand it to your own backend.
 *
 *   import { createCollector } from '@traitx/sdk/browser';
 *
 *   const collector = createCollector({
 *     publicKey: 'trx_…',
 *     apiEndpoint: 'https://traitx.allytech.sa',
 *     sdkUrl: 'https://traitx.allytech.sa/traitx.esm.js',
 *   });
 *
 *   const { requestId } = await collector.identify();
 *   await fetch('/api/login', {
 *     method: 'POST',
 *     headers: { 'Content-Type': 'application/json', 'X-TraitX-Request-Id': requestId },
 *     body: JSON.stringify({ email, password }),
 *   });
 *
 * The decision itself is never made here. A browser can be modified, so a
 * client-side "allow" is worth nothing.
 */

export interface CollectorOptions {
  /** Public collector key, `trx_…`. Safe to ship. */
  publicKey: string;
  /** Tenant deployment that ingests fingerprints. */
  apiEndpoint: string;
  /** Where the collector ESM bundle lives. Defaults to `${apiEndpoint}/traitx.esm.js`. */
  sdkUrl?: string;
  /** Milliseconds to wait for collection before giving up. Default 4000. */
  timeoutMs?: number;
  debug?: boolean;
}

export interface Identity {
  /** Pass this to your backend — it is what the Risk API keys on. */
  requestId: string;
  /** Stable device identifier across sessions. */
  visitorId?: string;
  sessionId?: string;
  /** 0–1 completeness of the collected signals. */
  confidence?: number;
}

interface CollectorAgent {
  get(options?: { skipCache?: boolean }): Promise<Record<string, any>>;
}

export interface Collector {
  /** Collect and submit a fingerprint, returning the ids your backend needs. */
  identify(options?: { skipCache?: boolean }): Promise<Identity>;
  /** Underlying collector agent, once loaded. */
  agent(): Promise<CollectorAgent>;
}

/**
 * A guard, not a nicety: the private key must never reach a browser. If you see
 * this throw, a server secret has leaked into a client bundle.
 */
function assertPublicKey(key: string): void {
  if (!key || typeof key !== 'string') {
    throw new Error('publicKey is required');
  }
  if (key.startsWith('trx_pvk_')) {
    throw new Error(
      'refusing to use a PRIVATE key (trx_pvk_…) in the browser. It grants risk-API access ' +
        'for the whole tenant. Use the public collector key (trx_…) here and keep the ' +
        'private key on your server.',
    );
  }
}

export function createCollector(options: CollectorOptions): Collector {
  assertPublicKey(options.publicKey);
  if (!options.apiEndpoint) throw new Error('apiEndpoint is required');

  const endpoint = options.apiEndpoint.replace(/\/+$/, '');
  const sdkUrl = options.sdkUrl ?? `${endpoint}/traitx.esm.js`;
  const timeoutMs = options.timeoutMs ?? 4000;

  let agentPromise: Promise<CollectorAgent> | undefined;

  async function loadAgent(): Promise<CollectorAgent> {
    // Dynamic import, not a <script> tag: the collector is an ES module and does
    // not attach itself to `window`.
    const mod: any = await import(/* webpackIgnore: true */ /* @vite-ignore */ sdkUrl);
    const load = mod.load ?? mod.default?.load;
    if (typeof load !== 'function') {
      throw new Error(`collector at ${sdkUrl} does not export load()`);
    }
    return load({ publicKey: options.publicKey, apiEndpoint: endpoint });
  }

  function agent(): Promise<CollectorAgent> {
    agentPromise ??= loadAgent();
    return agentPromise;
  }

  async function identify(opts?: { skipCache?: boolean }): Promise<Identity> {
    const result = await withTimeout(
      (async () => (await agent()).get(opts))(),
      timeoutMs,
      `traitx collection timed out after ${timeoutMs}ms`,
    );

    // Field names have moved between collector builds; read both spellings.
    const fp = (result?.fingerprint ?? {}) as Record<string, any>;
    const requestId = result?.requestId ?? fp.requestId ?? '';
    if (!requestId) {
      throw new Error('collector returned no requestId; check the publicKey and apiEndpoint');
    }

    const identity: Identity = {
      requestId,
      visitorId: result?.visitorId ?? fp.traitxId ?? fp.deviceId,
      sessionId: result?.sessionId ?? fp.sessionId,
      confidence: result?.confidence,
    };

    if (options.debug) {
      // eslint-disable-next-line no-console
      console.info('[traitx] identity', identity);
    }
    return identity;
  }

  return { identify, agent };
}

/**
 * Collect without ever blocking the user's action. Returns `undefined` on any
 * failure — a fingerprint you could not collect is a reason to evaluate with
 * less context, not a reason to fail a login.
 */
export async function identifySafely(collector: Collector): Promise<Identity | undefined> {
  try {
    return await collector.identify();
  } catch {
    return undefined;
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}
