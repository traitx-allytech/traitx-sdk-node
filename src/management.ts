/**
 * Management client — policies and lists.
 *
 * These are the **portal** APIs (SPEC.md §2). They authenticate with a bearer
 * JWT obtained by a human operator logging in, not with the private key, and
 * they are application-scoped. Unlike `evaluate()`, they throw on failure:
 * an admin script should fail loudly, not silently no-op.
 *
 * Typical uses: assert at boot that the policies you expect are enabled, and
 * push a confirmed-fraud device or IP onto a blocklist after a chargeback.
 */

import { ResolvedConfig } from './config';
import { ApiError, ConfigurationError, ValidationError } from './errors';
import { Transport } from './http';

export interface PolicyTrigger {
  field: string;
  operator: string;
  value?: unknown;
  list_id?: string;
}

export interface Policy {
  id: string;
  tenant_id: string;
  application_id: string;
  name: string;
  description: string;
  event_group: string;
  order: number;
  enabled: boolean;
  pass_through: boolean;
  inline_action?: string;
  triggers: PolicyTrigger[];
  actions?: unknown[];
  deleted: boolean;
  created_at: string;
  updated_at: string;
}

export interface List {
  id: string;
  tenant_id: string;
  application_id: string;
  name: string;
  description: string;
  list_type: string;
  color: string;
  entry_count: number;
  created_at: string;
  updated_at: string;
}

export interface ListEntry {
  id: string;
  list_id: string;
  value: string;
  comment: string;
  expires_at?: string;
  archived: boolean;
  created_at: string;
  updated_at: string;
}

export interface NewListEntry {
  value: string;
  comment?: string;
  expiresAt?: Date | string;
}

export class ManagementClient {
  private bearerToken?: string;

  constructor(
    private readonly config: ResolvedConfig,
    private readonly transport: Transport,
  ) {}

  /**
   * Supply the portal JWT. Obtain it however your operations tooling prefers —
   * `POST /api/v1/user/login` (plus OTP verification) returns one. The SDK does
   * not perform the login flow because it involves a second factor.
   */
  withToken(jwt: string): this {
    if (!String(jwt ?? '').trim()) throw new ConfigurationError('a non-empty JWT is required');
    this.bearerToken = jwt.startsWith('Bearer ') ? jwt.slice(7) : jwt;
    return this;
  }

  // -- policies ------------------------------------------------------------

  async listPolicies(applicationId?: string): Promise<Policy[]> {
    const body = await this.call<{ policies?: Policy[] }>('GET', '/api/v1/policies', {
      query: { application_id: this.appId(applicationId) },
    });
    return body.policies ?? [];
  }

  async getPolicy(id: string): Promise<Policy> {
    return this.call<Policy>('GET', `/api/v1/policies/${encodeURIComponent(id)}`);
  }

  async enablePolicy(id: string): Promise<void> {
    await this.call('PATCH', `/api/v1/policies/${encodeURIComponent(id)}/enable`);
  }

  async disablePolicy(id: string): Promise<void> {
    await this.call('PATCH', `/api/v1/policies/${encodeURIComponent(id)}/disable`);
  }

  /** Put a policy into shadow mode: it evaluates and logs but does not enforce. */
  async enableShadowMode(id: string): Promise<void> {
    await this.call('PATCH', `/api/v1/policies/${encodeURIComponent(id)}/pass-through/enable`);
  }

  /** Promote a policy out of shadow mode so its action is enforced. */
  async disableShadowMode(id: string): Promise<void> {
    await this.call('PATCH', `/api/v1/policies/${encodeURIComponent(id)}/pass-through/disable`);
  }

  /**
   * Assert that the policies you depend on are live. Returns the names of
   * policies that are disabled or still in shadow mode — run it at boot and log
   * the result rather than assuming the control plane matches your code.
   */
  async auditPolicies(applicationId?: string): Promise<{
    total: number;
    disabled: string[];
    shadow: string[];
    live: string[];
  }> {
    const policies = await this.listPolicies(applicationId);
    return {
      total: policies.length,
      disabled: policies.filter((p) => !p.enabled).map((p) => p.name),
      shadow: policies.filter((p) => p.enabled && p.pass_through).map((p) => p.name),
      live: policies.filter((p) => p.enabled && !p.pass_through).map((p) => p.name),
    };
  }

  // -- lists ---------------------------------------------------------------

  async listLists(applicationId?: string): Promise<List[]> {
    const body = await this.call<{ lists?: List[] }>('GET', '/api/v1/lists', {
      query: { application_id: this.appId(applicationId) },
    });
    return body.lists ?? [];
  }

  async getListEntries(listId: string, limit = 100, offset = 0): Promise<ListEntry[]> {
    const body = await this.call<{ entries?: ListEntry[] }>(
      'GET',
      `/api/v1/lists/${encodeURIComponent(listId)}/entries`,
      { query: { limit: String(limit), offset: String(offset) } },
    );
    return body.entries ?? [];
  }

  /** Add one value — a device id, IP, email domain, BIN — to a list. */
  async addListEntry(listId: string, entry: NewListEntry): Promise<ListEntry> {
    if (!String(entry?.value ?? '').trim()) throw new ValidationError('entry.value is required');
    return this.call<ListEntry>('POST', `/api/v1/lists/${encodeURIComponent(listId)}/entries`, {
      body: {
        value: entry.value,
        ...(entry.comment ? { comment: entry.comment } : {}),
        ...(entry.expiresAt
          ? { expires_at: entry.expiresAt instanceof Date ? entry.expiresAt.toISOString() : entry.expiresAt }
          : {}),
      },
    });
  }

  /** Bulk add, capped at 1000 entries per call by the API. */
  async addListEntries(listId: string, entries: NewListEntry[]): Promise<unknown> {
    if (!entries?.length) throw new ValidationError('at least one entry is required');
    if (entries.length > 1000) {
      throw new ValidationError(`the API accepts at most 1000 entries per call, got ${entries.length}`);
    }
    return this.call('POST', `/api/v1/lists/${encodeURIComponent(listId)}/entries/bulk`, {
      body: {
        entries: entries.map((e) => ({
          value: e.value,
          ...(e.comment ? { comment: e.comment } : {}),
          ...(e.expiresAt
            ? { expires_at: e.expiresAt instanceof Date ? e.expiresAt.toISOString() : e.expiresAt }
            : {}),
        })),
      },
    });
  }

  async archiveListEntry(listId: string, entryId: string): Promise<void> {
    await this.call(
      'PATCH',
      `/api/v1/lists/${encodeURIComponent(listId)}/entries/${encodeURIComponent(entryId)}/archive`,
    );
  }

  async deleteListEntry(listId: string, entryId: string): Promise<void> {
    await this.call(
      'DELETE',
      `/api/v1/lists/${encodeURIComponent(listId)}/entries/${encodeURIComponent(entryId)}`,
    );
  }

  // -- internals -----------------------------------------------------------

  private appId(override?: string): string | undefined {
    return override ?? this.config.applicationId;
  }

  private async call<T>(
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
    path: string,
    options: { query?: Record<string, string | undefined>; body?: unknown } = {},
  ): Promise<T> {
    if (!this.bearerToken) {
      throw new ConfigurationError(
        'management calls need a portal JWT: client.management.withToken(jwt). ' +
          'The private API key does not authorise the policy and list endpoints.',
      );
    }

    const outcome = await this.transport.send({
      method,
      path,
      query: options.query,
      body: options.body,
      omitApiKey: true,
      headers: { Authorization: `Bearer ${this.bearerToken}` },
    });

    if (outcome.transportError) {
      throw new ApiError(outcome.transportError, outcome.statusCode, outcome.body);
    }
    if (outcome.statusCode >= 400) {
      const detail =
        (outcome.body?.error as string | undefined) ??
        (outcome.body?.message as string | undefined) ??
        'no detail';
      throw new ApiError(`${method} ${path} failed: HTTP ${outcome.statusCode} — ${detail}`,
        outcome.statusCode, outcome.body);
    }
    return (outcome.body ?? {}) as T;
  }
}
