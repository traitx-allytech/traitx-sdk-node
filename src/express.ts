/**
 * Optional Express/Connect middleware.
 *
 * It attaches an `evaluate` helper to the request with the end user's IP and
 * headers already filled in. It deliberately does **not** block anything by
 * itself: enforcement belongs in the route that knows what the user was trying
 * to do, and a middleware that silently 403s is very hard to debug.
 */

import { TraitXClient } from './client';
import { Decision } from './decision';
import { contextFromRequest } from './serialize';
import { EventType, RiskEvent } from './types';

export interface TraitXMiddlewareOptions {
  client: TraitXClient;
  /**
   * Where to find the collector `requestId` on the request. Default: the
   * `x-traitx-request-id` header, then `body.traitxRequestId`, then
   * `query.traitx_request_id`.
   */
  requestIdFrom?: (req: any) => string | undefined;
}

export interface TraitXRequestHelper {
  /** Evaluate with IP/headers pre-filled from this request. */
  evaluate(event: Omit<RiskEvent, 'requestId' | 'context'> & {
    requestId?: string;
    context?: RiskEvent['context'];
  }): Promise<Decision>;
  /** The collector requestId the middleware found, if any. */
  requestId?: string;
}

function defaultRequestIdFrom(req: any): string | undefined {
  const header = req?.headers?.['x-traitx-request-id'];
  const fromHeader = Array.isArray(header) ? header[0] : header;
  return (
    (typeof fromHeader === 'string' && fromHeader) ||
    req?.body?.traitxRequestId ||
    req?.body?.traitx_request_id ||
    req?.query?.traitx_request_id ||
    undefined
  );
}

export function traitxMiddleware(options: TraitXMiddlewareOptions) {
  const { client } = options;
  const findRequestId = options.requestIdFrom ?? defaultRequestIdFrom;

  return function traitx(req: any, _res: any, next: (err?: unknown) => void): void {
    const requestId = findRequestId(req);
    const context = contextFromRequest(req);

    const helper: TraitXRequestHelper = {
      requestId,
      evaluate(event) {
        return client.evaluate({
          ...event,
          type: event.type ?? EventType.Generic,
          requestId: event.requestId ?? requestId ?? '',
          context: event.context ?? context,
        } as RiskEvent);
      },
    };

    req.traitx = helper;
    next();
  };
}
