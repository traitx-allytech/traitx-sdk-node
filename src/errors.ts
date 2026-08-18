/** Base class for every error this SDK raises. */
export class TraitXError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Thrown at construction time for an unusable configuration. */
export class ConfigurationError extends TraitXError {}

/** Thrown by `evaluate()` for an event the SDK refuses to send. */
export class ValidationError extends TraitXError {}

/**
 * Raised by the management client (policies, lists) — those calls are
 * administrative, so they throw instead of degrading to an Action.
 */
export class ApiError extends TraitXError {
  readonly statusCode: number;
  readonly body: unknown;

  constructor(message: string, statusCode: number, body: unknown) {
    super(message);
    this.statusCode = statusCode;
    this.body = body;
  }
}
