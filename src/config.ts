import { Action } from './types';
import { ConfigurationError } from './errors';

export interface Thresholds {
  /** Score at or above which an un-policed event becomes a challenge. */
  challenge: number;
  /** Score at or above which an un-policed event becomes a deny. */
  deny: number;
}

export interface BreakerOptions {
  failureThreshold: number;
  resetAfterMs: number;
}

export interface TraitXOptions {
  /** Tenant deployment base URL, e.g. `https://traitx.allytech.sa`. */
  baseUrl: string;
  /** Private key, `trx_pvk_…`. Server-side only. */
  apiKey: string;
  /** Application UUID; sent as `X-Application-ID`. Required for management calls. */
  applicationId?: string;

  /** Per-attempt timeout in ms. Default 2500. */
  timeoutMs?: number;
  /** Extra attempts after the first. Default 2. */
  maxRetries?: number;
  /** Base for exponential backoff with full jitter, ms. Default 100. */
  retryBackoffMs?: number;

  /** Action to return when TraitX is unreachable. Default `allow`. */
  failureMode?: Action;
  /** Action to return when TraitX rejects the request (401/400/…). Default `allow`. */
  clientErrorMode?: Action;

  thresholds?: Partial<Thresholds>;
  /** Signals that escalate to deny when the policy chain gave no action. */
  denyOnSignals?: string[];
  /** Signals that escalate to challenge when the policy chain gave no action. */
  challengeOnSignals?: string[];

  /** Enforce actions from shadow-mode (`pass_through`) policies. Default false. */
  enforceShadowDecisions?: boolean;

  breaker?: Partial<BreakerOptions>;

  userAgent?: string;
  /** Log requests and responses with the API key redacted. */
  debug?: boolean;
  logger?: (message: string, detail?: unknown) => void;

  /** Post-process every decision. Return a replacement or nothing. */
  onDecision?: (decision: import('./decision').Decision) => import('./decision').Decision | void;

  /** Injectable fetch, for tests and for runtimes with a custom agent. */
  fetchImpl?: typeof fetch;
}

export interface ResolvedConfig extends Required<Omit<TraitXOptions,
  'applicationId' | 'thresholds' | 'breaker' | 'onDecision' | 'fetchImpl' | 'logger'>> {
  applicationId?: string;
  thresholds: Thresholds;
  breaker: BreakerOptions;
  onDecision?: TraitXOptions['onDecision'];
  fetchImpl: typeof fetch;
  logger: (message: string, detail?: unknown) => void;
}

export const SDK_VERSION = '1.0.1';

const DEFAULTS = {
  timeoutMs: 2500,
  maxRetries: 2,
  retryBackoffMs: 100,
  failureMode: Action.Allow,
  clientErrorMode: Action.Allow,
  thresholds: { challenge: 40, deny: 70 } as Thresholds,
  denyOnSignals: [] as string[],
  challengeOnSignals: [] as string[],
  enforceShadowDecisions: false,
  breaker: { failureThreshold: 5, resetAfterMs: 30_000 } as BreakerOptions,
  debug: false,
};

/** Render a key for logs: `trx_pvk_…a9f3`. Never log the full value. */
export function redactKey(key: string): string {
  if (!key) return '<empty>';
  const tail = key.length > 4 ? key.slice(-4) : '';
  return `${key.slice(0, 8)}…${tail}`;
}

export function resolveConfig(options: TraitXOptions): ResolvedConfig {
  if (!options || typeof options !== 'object') {
    throw new ConfigurationError('options object is required');
  }

  const baseUrl = String(options.baseUrl ?? '').trim().replace(/\/+$/, '');
  if (!baseUrl) throw new ConfigurationError('baseUrl is required');
  if (!/^https?:\/\/./.test(baseUrl)) {
    throw new ConfigurationError(`baseUrl must be an absolute http(s) URL, got "${options.baseUrl}"`);
  }

  const apiKey = String(options.apiKey ?? '').trim();
  if (!apiKey) throw new ConfigurationError('apiKey is required');
  if (apiKey.startsWith('trx_') && !apiKey.startsWith('trx_pvk_')) {
    throw new ConfigurationError(
      'apiKey looks like a PUBLIC collector key (trx_…). The decision SDK needs the ' +
        'PRIVATE key (trx_pvk_…) and must only ever run server-side.',
    );
  }

  const thresholds: Thresholds = {
    challenge: options.thresholds?.challenge ?? DEFAULTS.thresholds.challenge,
    deny: options.thresholds?.deny ?? DEFAULTS.thresholds.deny,
  };
  if (thresholds.challenge > thresholds.deny) {
    throw new ConfigurationError(
      `thresholds.challenge (${thresholds.challenge}) must not exceed thresholds.deny (${thresholds.deny})`,
    );
  }

  const timeoutMs = options.timeoutMs ?? DEFAULTS.timeoutMs;
  if (!(timeoutMs > 0)) throw new ConfigurationError('timeoutMs must be greater than 0');

  const maxRetries = options.maxRetries ?? DEFAULTS.maxRetries;
  if (maxRetries < 0) throw new ConfigurationError('maxRetries must not be negative');

  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as typeof fetch | undefined);
  if (typeof fetchImpl !== 'function') {
    throw new ConfigurationError(
      'no global fetch available; pass fetchImpl (Node 18+ has fetch built in)',
    );
  }

  return {
    baseUrl,
    apiKey,
    applicationId: options.applicationId,
    timeoutMs,
    maxRetries,
    retryBackoffMs: options.retryBackoffMs ?? DEFAULTS.retryBackoffMs,
    failureMode: options.failureMode ?? DEFAULTS.failureMode,
    clientErrorMode: options.clientErrorMode ?? DEFAULTS.clientErrorMode,
    thresholds,
    denyOnSignals: options.denyOnSignals ?? DEFAULTS.denyOnSignals,
    challengeOnSignals: options.challengeOnSignals ?? DEFAULTS.challengeOnSignals,
    enforceShadowDecisions: options.enforceShadowDecisions ?? DEFAULTS.enforceShadowDecisions,
    breaker: {
      failureThreshold: options.breaker?.failureThreshold ?? DEFAULTS.breaker.failureThreshold,
      resetAfterMs: options.breaker?.resetAfterMs ?? DEFAULTS.breaker.resetAfterMs,
    },
    userAgent: options.userAgent ?? `traitx-sdk-node/${SDK_VERSION}`,
    debug: options.debug ?? DEFAULTS.debug,
    logger: options.logger ?? ((message, detail) => console.error(`[traitx] ${message}`, detail ?? '')),
    onDecision: options.onDecision,
    fetchImpl,
  };
}
