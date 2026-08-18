/**
 * TraitX Decision SDK for Node.js.
 *
 *   import { TraitXClient, Action, EventType } from '@traitx/sdk';
 *
 *   const traitx = new TraitXClient({
 *     baseUrl: process.env.TRAITX_BASE_URL!,
 *     apiKey: process.env.TRAITX_PRIVATE_KEY!,
 *     applicationId: process.env.TRAITX_APPLICATION_ID,
 *   });
 *
 *   const decision = await traitx.evaluateLogin({
 *     requestId: body.traitxRequestId,
 *     user: { id: user.id, email: user.email },
 *     context: TraitXClient.contextFromRequest(req),
 *   });
 *
 *   if (decision.isDenied()) return res.status(403).end();
 *   if (decision.requiresChallenge()) return sendOtp(user);
 */

export { TraitXClient } from './client';
export type { DoctorFinding, DoctorReport, PartialEvent } from './client';

export { Decision, resolveDecision, parseAction } from './decision';
export type { HttpOutcome } from './decision';

export {
  Action,
  EventStatus,
  EventType,
  Reason,
  RiskLevel,
  riskLevelFor,
  severity,
} from './types';
export type {
  EventContext,
  EventSession,
  EventUser,
  MatchedPolicy,
  RiskEvent,
  UserAddress,
} from './types';

export { resolveConfig, redactKey, SDK_VERSION } from './config';
export type { BreakerOptions, ResolvedConfig, Thresholds, TraitXOptions } from './config';

export { ApiError, ConfigurationError, TraitXError, ValidationError } from './errors';

export { CircuitBreaker, BreakerState } from './breaker';

export { ManagementClient } from './management';
export type { List, ListEntry, NewListEntry, Policy, PolicyTrigger } from './management';

export { contextFromRequest, serializeEvent, validateEvent } from './serialize';

export { traitxMiddleware } from './express';
export type { TraitXMiddlewareOptions } from './express';
