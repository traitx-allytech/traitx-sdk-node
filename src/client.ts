/**
 * TraitXClient — the object your application holds.
 *
 * Construct one per process and reuse it: the circuit breaker state lives on the
 * instance, and a fresh client per request would never open.
 */

import { CircuitBreaker } from './breaker';
import { redactKey, ResolvedConfig, resolveConfig, SDK_VERSION, TraitXOptions } from './config';
import { Decision, resolveDecision } from './decision';
import { ApiError, ValidationError } from './errors';
import { ManagementClient } from './management';
import { contextFromRequest, serializeEvent } from './serialize';
import { Action, EventStatus, EventType, RiskEvent } from './types';
import { Transport } from './http';

/** Convenience shape for the common `evaluateX` helpers. */
export type PartialEvent = Omit<RiskEvent, 'type'> & { type?: never };

export class TraitXClient {
  readonly config: ResolvedConfig;
  readonly management: ManagementClient;
  private readonly transport: Transport;
  private readonly breaker: CircuitBreaker;

  constructor(options: TraitXOptions) {
    this.config = resolveConfig(options);
    this.breaker = new CircuitBreaker(this.config.breaker);
    this.transport = new Transport(this.config, this.breaker);
    this.management = new ManagementClient(this.config, this.transport);
  }

  static readonly version = SDK_VERSION;

  /**
   * Evaluate an event and return the decision to act on.
   *
   * Never throws for network or API problems — those degrade to
   * `config.failureMode` / `config.clientErrorMode` with `degraded = true`, so a
   * TraitX outage cannot take your login or checkout path down. It *does* throw
   * `ValidationError` for an event the SDK will not send, because that is a bug
   * in the calling code and it should surface in tests, not in production.
   */
  async evaluate(event: RiskEvent): Promise<Decision> {
    const payload = serializeEvent(event);

    const outcome = await this.transport.send({
      method: 'POST',
      path: '/api/v1/risk',
      body: payload,
    });

    let decision = resolveDecision(outcome, this.config, String(event.requestId));

    if (this.config.onDecision) {
      const replacement = this.config.onDecision(decision);
      if (replacement) decision = replacement;
    }

    if (this.config.debug) {
      this.config.logger(`decision ${decision.toString()}`);
    }

    return decision;
  }

  /** `$login` shorthand. */
  evaluateLogin(event: PartialEvent): Promise<Decision> {
    return this.evaluate({ ...event, type: EventType.Login });
  }

  /** `$registration` shorthand. */
  evaluateRegistration(event: PartialEvent): Promise<Decision> {
    return this.evaluate({ ...event, type: EventType.Registration });
  }

  /**
   * `$transaction` shorthand. `amount` and `currency` are sent as root-level
   * attributes, which is where transaction policy triggers look for them.
   */
  evaluateTransaction(
    event: PartialEvent & { amount?: number; currency?: string; payeeId?: string },
  ): Promise<Decision> {
    const { amount, currency, payeeId, attributes, ...rest } = event;
    return this.evaluate({
      ...rest,
      type: EventType.Transaction,
      attributes: {
        ...(amount === undefined ? {} : { amount }),
        ...(currency === undefined ? {} : { currency }),
        ...(payeeId === undefined ? {} : { payee_id: payeeId }),
        ...attributes,
      },
    });
  }

  /** `$password_reset_request` shorthand. */
  evaluatePasswordReset(event: PartialEvent): Promise<Decision> {
    return this.evaluate({ ...event, type: EventType.PasswordResetRequest });
  }

  /** `$profile_update` shorthand. */
  evaluateProfileUpdate(event: PartialEvent): Promise<Decision> {
    return this.evaluate({ ...event, type: EventType.ProfileUpdate });
  }

  /**
   * Report the outcome of a step-up you issued, so the chain learns whether the
   * challenge succeeded. Fire-and-forget is fine — the returned decision is
   * usually ignored.
   */
  reportChallengeOutcome(event: PartialEvent & { passed: boolean }): Promise<Decision> {
    const { passed, ...rest } = event;
    return this.evaluate({
      ...rest,
      type: EventType.Challenge,
      status: passed ? EventStatus.Succeeded : EventStatus.Failed,
    });
  }

  /**
   * Full device fingerprint for a collector `requestId`. Useful for case review
   * and for enriching your own fraud store; not needed for a decision.
   */
  async getFingerprint(requestId: string): Promise<Record<string, unknown>> {
    if (!String(requestId ?? '').trim()) {
      throw new ValidationError('requestId is required');
    }
    const outcome = await this.transport.send({
      method: 'GET',
      path: `/api/v1/fingerprint/${encodeURIComponent(requestId)}`,
    });
    if (outcome.transportError) {
      throw new ApiError(outcome.transportError, outcome.statusCode, outcome.body);
    }
    if (outcome.statusCode >= 400) {
      throw new ApiError(
        `fingerprint lookup failed with HTTP ${outcome.statusCode}`,
        outcome.statusCode,
        outcome.body,
      );
    }
    return outcome.body ?? {};
  }

  /** Liveness probe against `GET /health`. */
  async health(): Promise<boolean> {
    const outcome = await this.transport.send({ method: 'GET', path: '/health' });
    return !outcome.transportError && outcome.statusCode >= 200 && outcome.statusCode < 300;
  }

  /**
   * Connectivity and configuration self-check. Returns human-readable findings
   * rather than throwing, so it can run at boot behind a feature flag or from a
   * CLI. See SPEC.md §13.
   */
  async doctor(probeRequestId?: string): Promise<DoctorReport> {
    const findings: DoctorFinding[] = [];

    findings.push({
      check: 'api key class',
      ok: this.config.apiKey.startsWith('trx_pvk_'),
      detail: this.config.apiKey.startsWith('trx_pvk_')
        ? `private key ${redactKey(this.config.apiKey)}`
        : `key ${redactKey(this.config.apiKey)} is not a trx_pvk_ private key`,
    });

    const healthy = await this.health();
    findings.push({
      check: 'deployment reachable',
      ok: healthy,
      detail: healthy ? `${this.config.baseUrl}/health responded` : `${this.config.baseUrl}/health did not respond`,
    });

    findings.push({
      check: 'application scoping',
      ok: Boolean(this.config.applicationId),
      detail: this.config.applicationId
        ? `X-Application-ID ${this.config.applicationId}`
        : 'no applicationId set — management calls will fall back to the tenant\'s oldest ' +
          'active application, which is rarely the one holding your policies',
    });

    if (probeRequestId) {
      const decision = await this.evaluate({
        requestId: probeRequestId,
        type: EventType.Login,
        status: EventStatus.Succeeded,
      });
      findings.push({
        check: 'risk api accepts the key',
        ok: decision.reason !== 'client_error',
        detail: decision.error ?? `HTTP ${decision.statusCode}, reason ${decision.reason}`,
      });
      findings.push({
        check: 'device enrichment present',
        ok: decision.hasDeviceContext(),
        detail: decision.hasDeviceContext()
          ? 'IP enrichment attached; ip_enrichment.* policies can match'
          : 'no enrichment for this request_id — ip_enrichment.* triggers cannot match',
      });
      findings.push({
        check: 'policy chain returns an action',
        ok: decision.observedAction !== null,
        detail:
          decision.observedAction !== null
            ? `chain action ${decision.observedAction}, ${decision.matchedPolicies.length} matched`
            : 'no chain action in the response; decisions will fall back to score thresholds',
      });
    }

    return { ok: findings.every((f) => f.ok), findings };
  }

  /** Current breaker state, for your own health endpoint. */
  get breakerState(): string {
    return this.breaker.state;
  }

  /** Re-export so callers do not need a second import. */
  static contextFromRequest = contextFromRequest;
  static Action = Action;
  static EventType = EventType;
}

export interface DoctorFinding {
  check: string;
  ok: boolean;
  detail: string;
}

export interface DoctorReport {
  ok: boolean;
  findings: DoctorFinding[];
}
