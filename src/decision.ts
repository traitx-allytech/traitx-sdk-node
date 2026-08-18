/**
 * The decision engine — SPEC.md §5 and §6.
 *
 * This file contains no I/O. Everything here is a pure function of the HTTP
 * outcome plus configuration, which is what makes the conformance vectors in
 * sdk/conformance/vectors.json runnable against it.
 */

import { ResolvedConfig } from './config';
import { Action, MatchedPolicy, Reason, RiskLevel, riskLevelFor, severity } from './types';

export interface DecisionInit {
  action: Action;
  observedAction: Action | null;
  enforced: boolean;
  reason: Reason;
  score: number;
  riskLevel: RiskLevel;
  signals: string[];
  matchedPolicies: MatchedPolicy[];
  degraded: boolean;
  error?: string;
  statusCode: number;
  requestId: string;
  latencyMs: number;
  raw: Record<string, unknown>;
}

/** The result of `evaluate()`. See SPEC.md §7. */
export class Decision implements DecisionInit {
  readonly action: Action;
  readonly observedAction: Action | null;
  readonly enforced: boolean;
  readonly reason: Reason;
  readonly score: number;
  readonly riskLevel: RiskLevel;
  readonly signals: string[];
  readonly matchedPolicies: MatchedPolicy[];
  readonly degraded: boolean;
  readonly error?: string;
  readonly statusCode: number;
  readonly requestId: string;
  readonly latencyMs: number;
  readonly raw: Record<string, unknown>;

  constructor(init: DecisionInit) {
    this.action = init.action;
    this.observedAction = init.observedAction;
    this.enforced = init.enforced;
    this.reason = init.reason;
    this.score = init.score;
    this.riskLevel = init.riskLevel;
    this.signals = init.signals;
    this.matchedPolicies = init.matchedPolicies;
    this.degraded = init.degraded;
    this.error = init.error;
    this.statusCode = init.statusCode;
    this.requestId = init.requestId;
    this.latencyMs = init.latencyMs;
    this.raw = init.raw;
  }

  /** True only for `allow`. Never branch on `!isDenied()` — that lets challenges through. */
  isAllowed(): boolean {
    return this.action === Action.Allow;
  }

  requiresChallenge(): boolean {
    return this.action === Action.Challenge;
  }

  isDenied(): boolean {
    return this.action === Action.Deny;
  }

  /**
   * False when the Risk API had no device enrichment for this `request_id`, which
   * means every `ip_enrichment.*` and `threats.*` trigger was unreachable and
   * those policies could not have matched. See SPEC.md §13.
   */
  hasDeviceContext(): boolean {
    const debug = this.raw?.debug as Record<string, unknown> | undefined;
    if (!debug || typeof debug !== 'object') return true;
    for (const value of Object.values(debug)) {
      if (value && typeof value === 'object') {
        const reason = (value as Record<string, unknown>).reason;
        if (reason === 'no_enrichment_data') return false;
      }
    }
    return true;
  }

  /** True when a policy matched but was deployed pass-through. */
  isShadow(): boolean {
    return this.reason === Reason.Shadow;
  }

  toJSON(): Record<string, unknown> {
    return {
      action: this.action,
      observedAction: this.observedAction,
      enforced: this.enforced,
      reason: this.reason,
      score: this.score,
      riskLevel: this.riskLevel,
      signals: this.signals,
      matchedPolicies: this.matchedPolicies,
      degraded: this.degraded,
      error: this.error,
      statusCode: this.statusCode,
      requestId: this.requestId,
      latencyMs: this.latencyMs,
    };
  }

  toString(): string {
    const bits = [`action=${this.action}`, `reason=${this.reason}`, `score=${this.score}`];
    if (!this.enforced && this.observedAction) bits.push(`observed=${this.observedAction}`);
    if (this.degraded) bits.push('degraded');
    return `TraitXDecision(${bits.join(' ')})`;
  }
}

// ---------------------------------------------------------------------------
// Tolerant parsing — SPEC.md §5.1
// ---------------------------------------------------------------------------

const ACTION_ALIASES: Record<string, Action> = {
  allow: Action.Allow,
  pass: Action.Allow,
  accept: Action.Allow,
  approve: Action.Allow,
  challenge: Action.Challenge,
  stepup: Action.Challenge,
  step_up: Action.Challenge,
  review: Action.Challenge,
  deny: Action.Deny,
  block: Action.Deny,
  reject: Action.Deny,
  decline: Action.Deny,
};

/**
 * Parse an action from the wire. Case-insensitive, tolerates a leading `$`.
 * Anything unrecognised yields `null` — treated as *absent*, never as allow,
 * so a future action name can never silently open the gate.
 */
export function parseAction(value: unknown): Action | null {
  if (typeof value !== 'string') return null;
  const key = value.trim().toLowerCase().replace(/^\$/, '');
  return ACTION_ALIASES[key] ?? null;
}

function firstDefined(source: Record<string, unknown> | undefined, keys: string[]): unknown {
  if (!source) return undefined;
  for (const key of keys) {
    const value = source[key];
    if (value !== undefined && value !== null) return value;
  }
  return undefined;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function asBool(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return ['true', '1', 'yes'].includes(value.toLowerCase());
  if (typeof value === 'number') return value !== 0;
  return false;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

/** Read the chain action from any of the shapes the deployment may return. */
export function extractChainAction(body: Record<string, unknown>): Action | null {
  const policy = asRecord(body.policy);
  const decision = asRecord(body.decision);
  const candidates: unknown[] = [
    firstDefined(policy, ['action', 'decision', 'inline_action', 'inlineAction']),
    firstDefined(decision, ['action', 'decision']),
    body.decision,
    body.action,
  ];
  for (const candidate of candidates) {
    const parsed = parseAction(candidate);
    if (parsed) return parsed;
  }
  return null;
}

/** Read the matched-policy list from any of the shapes the deployment may return. */
export function extractMatchedPolicies(body: Record<string, unknown>): MatchedPolicy[] {
  const policy = asRecord(body.policy);
  const raw =
    firstDefined(policy, ['matched', 'matched_policies', 'matchedPolicies', 'hits']) ??
    firstDefined(body, ['matched_policies', 'matchedPolicies', 'matched']);

  if (!Array.isArray(raw)) return [];

  return raw.flatMap((entry): MatchedPolicy[] => {
    const record = asRecord(entry);
    if (!record) {
      // Some deployments return a bare list of policy ids.
      return typeof entry === 'string'
        ? [{ id: entry, name: entry, action: null, eventGroup: null, passThrough: false }]
        : [];
    }
    return [
      {
        id: String(firstDefined(record, ['id', 'policy_id', 'policyId']) ?? ''),
        name: String(firstDefined(record, ['name', 'policy_name', 'policyName']) ?? ''),
        action: parseAction(firstDefined(record, ['action', 'inline_action', 'inlineAction'])),
        eventGroup:
          (firstDefined(record, ['event_group', 'eventGroup']) as string | undefined) ?? null,
        passThrough: asBool(
          firstDefined(record, ['pass_through', 'passThrough', 'shadow', 'pass_through_mode']),
        ),
      },
    ];
  });
}

export function extractScore(body: Record<string, unknown>): number {
  const data = asRecord(body.data);
  const candidate =
    firstDefined(body, ['score', 'risk_score', 'riskScore']) ??
    firstDefined(data, ['score', 'risk_score', 'riskScore']);
  return asNumber(candidate) ?? 0;
}

export function extractSignals(body: Record<string, unknown>): string[] {
  const data = asRecord(body.data);
  const candidate =
    firstDefined(body, ['signals', 'risk_signals', 'riskSignals']) ??
    firstDefined(data, ['signals', 'risk_signals', 'riskSignals']);
  if (!Array.isArray(candidate)) return [];
  return candidate.filter((s): s is string => typeof s === 'string');
}

/**
 * Is the chain's action suppressed because the deciding policies are shadow-mode?
 *
 * True only when at least one matched policy carries the chain's action AND
 * every such policy is flagged pass-through. If no matched policy exposes a
 * pass-through flag we assume the server is the authority and return false.
 * See SPEC.md §6.1.
 */
export function isShadowed(matched: MatchedPolicy[], chainAction: Action): boolean {
  const deciding = matched.filter((p) => p.action === chainAction);
  const relevant = deciding.length > 0 ? deciding : matched;
  if (relevant.length === 0) return false;
  return relevant.every((p) => p.passThrough);
}

// ---------------------------------------------------------------------------
// Resolution — SPEC.md §6
// ---------------------------------------------------------------------------

export interface HttpOutcome {
  /** HTTP status, or 0 when the request never completed. */
  statusCode: number;
  /** Decoded JSON body, or undefined when there was none / it was not JSON. */
  body?: Record<string, unknown>;
  /** Transport-level failure message, if any. */
  transportError?: string;
  latencyMs: number;
}

const CLIENT_ERROR_STATUSES = new Set([400, 401, 403, 404, 405, 409, 422]);

/**
 * Turn an HTTP outcome into a Decision. Pure; safe to unit-test directly.
 */
export function resolveDecision(
  outcome: HttpOutcome,
  config: ResolvedConfig,
  requestId: string,
): Decision {
  const body = outcome.body ?? {};
  const score = extractScore(body);
  const signals = extractSignals(body);
  const matchedPolicies = extractMatchedPolicies(body);

  const base = {
    score,
    riskLevel: riskLevelFor(score),
    signals,
    matchedPolicies,
    statusCode: outcome.statusCode,
    requestId,
    latencyMs: outcome.latencyMs,
    raw: body,
  };

  // Step 1 — transport failure.
  if (outcome.transportError || outcome.statusCode >= 500 || outcome.statusCode === 429 ||
      outcome.statusCode === 408 || outcome.statusCode === 0) {
    return new Decision({
      ...base,
      action: config.failureMode,
      observedAction: null,
      enforced: false,
      reason: Reason.Degraded,
      degraded: true,
      error: outcome.transportError ?? `risk api returned HTTP ${outcome.statusCode}`,
    });
  }

  // Step 2 — client error. A rotated key is an engineering fault, not a verdict.
  if (CLIENT_ERROR_STATUSES.has(outcome.statusCode) || outcome.statusCode >= 400) {
    return new Decision({
      ...base,
      action: config.clientErrorMode,
      observedAction: null,
      enforced: false,
      reason: Reason.ClientError,
      degraded: true,
      error: describeApiError(outcome.statusCode, body),
    });
  }

  // A 2xx we could not decode is a transport failure, not an allow.
  if (!outcome.body) {
    return new Decision({
      ...base,
      action: config.failureMode,
      observedAction: null,
      enforced: false,
      reason: Reason.Degraded,
      degraded: true,
      error: `risk api returned HTTP ${outcome.statusCode} with a body that is not JSON`,
    });
  }

  // Step 3 — the policy chain decided.
  const chainAction = extractChainAction(body);
  if (chainAction) {
    const shadowed = isShadowed(matchedPolicies, chainAction);
    const enforce = !shadowed || config.enforceShadowDecisions;
    return new Decision({
      ...base,
      action: enforce ? chainAction : Action.Allow,
      observedAction: chainAction,
      enforced: !shadowed,
      reason: shadowed && !config.enforceShadowDecisions ? Reason.Shadow : Reason.PolicyMatch,
      degraded: false,
    });
  }

  // Step 4 — derive from score, then let configured signals escalate.
  let action = Action.Allow;
  let reason = Reason.NoMatch;

  if (score >= config.thresholds.deny) {
    action = Action.Deny;
    reason = Reason.ScoreThreshold;
  } else if (score >= config.thresholds.challenge) {
    action = Action.Challenge;
    reason = Reason.ScoreThreshold;
  }

  const signalSet = new Set(signals);
  let signalAction = Action.Allow;
  if (config.denyOnSignals.some((s) => signalSet.has(s))) {
    signalAction = Action.Deny;
  } else if (config.challengeOnSignals.some((s) => signalSet.has(s))) {
    signalAction = Action.Challenge;
  }

  if (severity(signalAction) > severity(action)) {
    action = signalAction;
    reason = Reason.SignalOverride;
  }

  return new Decision({
    ...base,
    action,
    observedAction: null,
    enforced: true,
    reason,
    degraded: false,
  });
}

function describeApiError(status: number, body: Record<string, unknown>): string {
  const error = typeof body.error === 'string' ? body.error : undefined;
  const message = typeof body.message === 'string' ? body.message : undefined;
  const detail = [error, message].filter(Boolean).join(': ');
  return detail ? `risk api rejected the request (HTTP ${status}): ${detail}`
                : `risk api rejected the request (HTTP ${status})`;
}
