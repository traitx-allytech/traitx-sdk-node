/**
 * TraitX Decision SDK — shared types.
 *
 * Mirrors sdk/SPEC.md. Wire values are the strings the Risk API and the policy
 * engine (models/policy.go) actually use — do not "tidy" them.
 */

/** The three answers the SDK can give. See SPEC.md §1. */
export enum Action {
  Allow = 'allow',
  Challenge = 'challenge',
  Deny = 'deny',
}

/** How the decision was reached. See SPEC.md §6. */
export enum Reason {
  /** A policy in the chain matched and its action is being enforced. */
  PolicyMatch = 'policy_match',
  /** A policy matched but is deployed pass-through, so nothing is enforced. */
  Shadow = 'shadow',
  /** No policy action; the score crossed a configured threshold. */
  ScoreThreshold = 'score_threshold',
  /** No policy action; a configured signal escalated the decision. */
  SignalOverride = 'signal_override',
  /** Nothing matched and the score is below every threshold. */
  NoMatch = 'no_match',
  /** The Risk API could not be reached or failed; `failureMode` applied. */
  Degraded = 'degraded',
  /** The Risk API rejected the request (bad key, bad payload); `clientErrorMode` applied. */
  ClientError = 'client_error',
}

/** Informational risk banding derived from the score. See SPEC.md §6.2. */
export enum RiskLevel {
  Low = 'low',
  Medium = 'medium',
  High = 'high',
  Critical = 'critical',
}

/**
 * Policy event groups, mirroring `PolicyEventGroup` in models/policy.go.
 *
 * `$before_all` and `$after_all` are intentionally absent: they are chain hooks
 * that run on every event, not event types you can send. See SPEC.md §4.
 */
export enum EventType {
  Login = '$login',
  Registration = '$registration',
  Logout = '$logout',
  Transaction = '$transaction',
  Challenge = '$challenge',
  Profile = '$profile',
  ProfileUpdate = '$profile_update',
  ProfileReset = '$profile_reset',
  PasswordResetRequest = '$password_reset_request',
  Custom = '$custom',
  Generic = '$generic',
}

/** Outcome of the business event being reported. */
export enum EventStatus {
  Succeeded = '$succeeded',
  Failed = '$failed',
}

export interface UserAddress {
  line1?: string;
  line2?: string;
  city?: string;
  regionCode?: string;
  postalCode?: string;
  countryCode?: string;
  latitude?: number;
  longitude?: number;
}

export interface EventUser {
  id?: string;
  email?: string;
  name?: string;
  firstName?: string;
  lastName?: string;
  username?: string;
  phone?: string;
  nationalId?: string;
  createdAt?: Date | string;
  registeredAt?: Date | string;
  updatedAt?: Date | string;
  address?: UserAddress;
}

export interface EventSession {
  id?: string;
  createdAt?: Date | string;
}

/**
 * Request-scoped context describing the **end user**, not your server.
 *
 * `headers` is a list of `[name, value]` pairs because headers can repeat and
 * the policy engine matches on ordered pairs. See SPEC.md §3.1.
 */
export interface EventContext {
  ip?: string;
  headers?: Array<[string, string]>;
}

/** One input to `evaluate()`. */
export interface RiskEvent {
  /** `requestId` produced by the browser collector's `get()`. */
  requestId: string;
  type: EventType | string;
  status?: EventStatus | string;
  createdAt?: Date | string;
  session?: EventSession;
  context?: EventContext;
  user?: EventUser;
  /**
   * Business attributes merged into the event root, e.g. `amount`, `currency`,
   * `'merchant.mcc'`. A dotted key is a literal key name, never a nested
   * object. See SPEC.md §3.2.
   */
  attributes?: Record<string, unknown>;
}

/** A policy the chain reported as matched. */
export interface MatchedPolicy {
  id: string;
  name: string;
  action: Action | null;
  eventGroup: string | null;
  /** True when the policy is deployed in shadow mode and must not enforce. */
  passThrough: boolean;
}

/** Score → risk level. See SPEC.md §6.2. */
export function riskLevelFor(score: number): RiskLevel {
  if (score >= 80) return RiskLevel.Critical;
  if (score >= 60) return RiskLevel.High;
  if (score >= 30) return RiskLevel.Medium;
  return RiskLevel.Low;
}

/** Ordering used when escalating between actions. See SPEC.md §6. */
export function severity(action: Action): number {
  switch (action) {
    case Action.Deny:
      return 2;
    case Action.Challenge:
      return 1;
    default:
      return 0;
  }
}
