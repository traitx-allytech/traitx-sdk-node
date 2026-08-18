/**
 * HTTP transport: timeouts, retry with full jitter, Retry-After, breaker
 * integration. SPEC.md §9 and §10.
 */

import { CircuitBreaker } from './breaker';
import { redactKey, ResolvedConfig } from './config';
import { HttpOutcome } from './decision';

const RETRYABLE_STATUSES = new Set([408, 429, 500, 502, 503, 504]);
const RETRY_AFTER_CAP_MS = 5_000;

export interface RequestSpec {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  query?: Record<string, string | undefined>;
  body?: unknown;
  /** Overrides the private-key header, e.g. a bearer token for management calls. */
  headers?: Record<string, string>;
  /** Skip the `X-API-Key` header (management calls authenticate differently). */
  omitApiKey?: boolean;
}

export class Transport {
  constructor(
    private readonly config: ResolvedConfig,
    readonly breaker: CircuitBreaker = new CircuitBreaker(config.breaker),
  ) {}

  /**
   * Perform a request, never throwing for transport or HTTP problems: the
   * outcome is data so the caller can turn it into a Decision.
   */
  async send(spec: RequestSpec): Promise<HttpOutcome> {
    const started = Date.now();

    if (!this.breaker.allowRequest()) {
      return { statusCode: 0, latencyMs: 0, transportError: 'circuit breaker open' };
    }

    const url = this.buildUrl(spec);
    const headers = this.buildHeaders(spec);
    const payload = spec.body === undefined ? undefined : JSON.stringify(spec.body);

    let lastError = 'request failed';
    let lastStatus = 0;
    let lastBody: Record<string, unknown> | undefined;
    let lastRetryAfterMs: number | undefined;

    for (let attempt = 0; attempt <= this.config.maxRetries; attempt += 1) {
      if (attempt > 0) {
        await sleep(lastRetryAfterMs ?? this.backoffMs(attempt));
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);

      try {
        this.debug(`→ ${spec.method} ${url}`, payload);
        const response = await this.config.fetchImpl(url, {
          method: spec.method,
          headers,
          body: payload,
          signal: controller.signal,
        });

        lastStatus = response.status;
        lastRetryAfterMs = parseRetryAfter(response.headers.get('retry-after'));

        const text = await response.text();
        lastBody = safeJsonParse(text);
        this.debug(`← ${response.status} ${spec.method} ${url}`, text.slice(0, 2000));

        if (RETRYABLE_STATUSES.has(response.status) && attempt < this.config.maxRetries) {
          lastError = `risk api returned HTTP ${response.status}`;
          continue;
        }

        // Any settled response — success or a non-retryable error — ends the loop.
        if (response.status >= 500 || response.status === 429 || response.status === 408) {
          this.breaker.recordFailure();
        } else {
          this.breaker.recordSuccess();
        }

        return {
          statusCode: response.status,
          body: lastBody,
          latencyMs: Date.now() - started,
        };
      } catch (error) {
        lastRetryAfterMs = undefined;
        lastError = describeTransportError(error, this.config.timeoutMs);
        this.debug(`✗ ${spec.method} ${url}`, lastError);
        if (attempt >= this.config.maxRetries) break;
      } finally {
        clearTimeout(timer);
      }
    }

    this.breaker.recordFailure();
    return {
      statusCode: lastStatus >= 500 || lastStatus === 429 ? lastStatus : 0,
      body: lastBody,
      latencyMs: Date.now() - started,
      transportError: lastError,
    };
  }

  private buildUrl(spec: RequestSpec): string {
    const url = new URL(this.config.baseUrl + spec.path);
    for (const [key, value] of Object.entries(spec.query ?? {})) {
      if (value !== undefined) url.searchParams.set(key, value);
    }
    return url.toString();
  }

  private buildHeaders(spec: RequestSpec): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'User-Agent': this.config.userAgent,
      ...(spec.body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...(spec.omitApiKey ? {} : { 'X-API-Key': this.config.apiKey }),
      ...(this.config.applicationId ? { 'X-Application-ID': this.config.applicationId } : {}),
      ...spec.headers,
    };
    return headers;
  }

  /** Full jitter: `random(0, base * 2^(n-1))`. SPEC.md §9. */
  private backoffMs(attempt: number): number {
    const ceiling = this.config.retryBackoffMs * 2 ** (attempt - 1);
    return Math.floor(Math.random() * ceiling);
  }

  private debug(message: string, detail?: unknown): void {
    if (!this.config.debug) return;
    this.config.logger(`${message} [key ${redactKey(this.config.apiKey)}]`, detail);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}

function safeJsonParse(text: string): Record<string, unknown> | undefined {
  if (!text) return undefined;
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function parseRetryAfter(value: string | null): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(seconds * 1000, RETRY_AFTER_CAP_MS);
  }
  const date = Date.parse(value);
  if (!Number.isNaN(date)) {
    return Math.min(Math.max(0, date - Date.now()), RETRY_AFTER_CAP_MS);
  }
  return undefined;
}

function describeTransportError(error: unknown, timeoutMs: number): string {
  if (error instanceof Error) {
    if (error.name === 'AbortError' || error.name === 'TimeoutError') {
      return `risk api timed out after ${timeoutMs}ms`;
    }
    const cause = (error as { cause?: { code?: string } }).cause;
    return cause?.code ? `${error.message} (${cause.code})` : error.message;
  }
  return String(error);
}
