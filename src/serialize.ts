/**
 * Event → wire payload. SPEC.md §3.
 *
 * The Risk API is snake_case and expects `context.headers` as a list of
 * `[name, value]` pairs; custom attributes live at the event root.
 */

import { ValidationError } from './errors';
import { EventStatus, EventType, RiskEvent } from './types';

const CHAIN_HOOKS = new Set(['$before_all', '$after_all']);

const KNOWN_EVENT_TYPES = new Set<string>(Object.values(EventType));

/** Fields the SDK owns; a custom attribute may not shadow them. */
const RESERVED_ROOT_KEYS = new Set([
  'request_id',
  'type',
  'status',
  'created_at',
  'session',
  'context',
  'user',
]);

function toIso(value: Date | string | undefined, fallback?: Date): string | undefined {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'string' && value.trim() !== '') return value;
  return fallback ? fallback.toISOString() : undefined;
}

function compact<T extends Record<string, unknown>>(source: T): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(source)) {
    if (value === undefined || value === null) continue;
    if (typeof value === 'object' && !Array.isArray(value) && !(value instanceof Date)) {
      const nested = compact(value as Record<string, unknown>);
      if (Object.keys(nested).length > 0) out[key] = nested;
      continue;
    }
    out[key] = value;
  }
  return out;
}

export function validateEvent(event: RiskEvent): void {
  if (!event || typeof event !== 'object') {
    throw new ValidationError('a risk event object is required');
  }

  const type = String(event.type ?? '').trim();
  if (!type) {
    throw new ValidationError('event.type is required, e.g. EventType.Login');
  }
  if (CHAIN_HOOKS.has(type)) {
    throw new ValidationError(
      `"${type}" is a policy chain hook, not an event type — it runs automatically on every ` +
        'event. Send the concrete group instead (EventType.Login, EventType.Transaction, …).',
    );
  }
  if (!type.startsWith('$')) {
    throw new ValidationError(
      `event.type must be a policy event group starting with "$", got "${type}". ` +
        `Known groups: ${[...KNOWN_EVENT_TYPES].join(', ')}.`,
    );
  }

  if (!String(event.requestId ?? '').trim()) {
    throw new ValidationError(
      'event.requestId is required — it is the requestId returned by the browser collector ' +
        "(await (await traitx.load({publicKey})).get()).requestId. Without it the event carries " +
        'no device context and device/IP policies cannot match.',
    );
  }

  for (const key of Object.keys(event.attributes ?? {})) {
    if (RESERVED_ROOT_KEYS.has(key)) {
      throw new ValidationError(
        `attribute "${key}" collides with a reserved root field; use a different name`,
      );
    }
  }
}

export function serializeEvent(event: RiskEvent, now: Date = new Date()): Record<string, unknown> {
  validateEvent(event);

  const user = event.user
    ? compact({
        id: event.user.id,
        email: event.user.email,
        name: event.user.name,
        first_name: event.user.firstName,
        last_name: event.user.lastName,
        username: event.user.username,
        phone: event.user.phone,
        national_id: event.user.nationalId,
        created_at: toIso(event.user.createdAt),
        registered_at: toIso(event.user.registeredAt),
        updated_at: toIso(event.user.updatedAt),
        address: event.user.address
          ? compact({
              line1: event.user.address.line1,
              line2: event.user.address.line2,
              city: event.user.address.city,
              region_code: event.user.address.regionCode,
              postal_code: event.user.address.postalCode,
              country_code: event.user.address.countryCode,
              latitude: event.user.address.latitude,
              longitude: event.user.address.longitude,
            })
          : undefined,
      })
    : undefined;

  const payload: Record<string, unknown> = {
    request_id: String(event.requestId).trim(),
    type: String(event.type),
    status: String(event.status ?? EventStatus.Succeeded),
    created_at: toIso(event.createdAt, now)!,
  };

  if (event.session) {
    const session = compact({
      id: event.session.id,
      created_at: toIso(event.session.createdAt),
    });
    if (Object.keys(session).length > 0) payload.session = session;
  }

  if (event.context) {
    const context: Record<string, unknown> = {};
    if (event.context.ip) context.ip = event.context.ip;
    if (event.context.headers?.length) {
      // Pairs, not an object — see SPEC.md §3.1.
      context.headers = event.context.headers.map(([name, value]) => [String(name), String(value)]);
    }
    if (Object.keys(context).length > 0) payload.context = context;
  }

  if (user && Object.keys(user).length > 0) payload.user = user;

  for (const [key, value] of Object.entries(event.attributes ?? {})) {
    if (value !== undefined) payload[key] = value;
  }

  return payload;
}

/**
 * Extract the end user's request context from a Node-style incoming request.
 * Handles `X-Forwarded-For` so you send the client IP rather than your proxy's.
 */
export function contextFromRequest(req: {
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
  ip?: string;
}): { ip?: string; headers: Array<[string, string]> } {
  const headers: Array<[string, string]> = [];
  const interesting = ['user-agent', 'accept-language', 'accept', 'referer', 'x-forwarded-for'];

  for (const name of interesting) {
    const value = req.headers?.[name];
    if (value === undefined) continue;
    for (const single of Array.isArray(value) ? value : [value]) {
      headers.push([canonicalHeaderName(name), single]);
    }
  }

  const forwarded = req.headers?.['x-forwarded-for'];
  const forwardedFirst = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  const ip =
    forwardedFirst?.split(',')[0]?.trim() || req.ip || req.socket?.remoteAddress || undefined;

  return { ip, headers };
}

function canonicalHeaderName(lower: string): string {
  return lower
    .split('-')
    .map((part) => (part === 'ip' ? 'IP' : part.charAt(0).toUpperCase() + part.slice(1)))
    .join('-');
}
