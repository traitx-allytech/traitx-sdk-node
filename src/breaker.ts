/**
 * Circuit breaker — SPEC.md §10.
 *
 * Counts transport failures only. Its whole purpose is that one unreachable
 * dependency costs you one timeout, not a timeout on every login.
 */

import { BreakerOptions } from './config';

export enum BreakerState {
  Closed = 'closed',
  Open = 'open',
  HalfOpen = 'half_open',
}

export class CircuitBreaker {
  private failures = 0;
  private openedAt = 0;
  private probeInFlight = false;

  constructor(
    private readonly options: BreakerOptions,
    private readonly now: () => number = () => Date.now(),
  ) {}

  get state(): BreakerState {
    if (this.failures < this.options.failureThreshold) return BreakerState.Closed;
    if (this.now() - this.openedAt >= this.options.resetAfterMs) return BreakerState.HalfOpen;
    return BreakerState.Open;
  }

  /**
   * True when the call may touch the network. In half-open exactly one probe is
   * admitted; concurrent callers are short-circuited until it settles.
   */
  allowRequest(): boolean {
    const state = this.state;
    if (state === BreakerState.Closed) return true;
    if (state === BreakerState.Open) return false;
    if (this.probeInFlight) return false;
    this.probeInFlight = true;
    return true;
  }

  recordSuccess(): void {
    this.failures = 0;
    this.openedAt = 0;
    this.probeInFlight = false;
  }

  recordFailure(): void {
    this.probeInFlight = false;
    this.failures += 1;
    if (this.failures >= this.options.failureThreshold) {
      this.openedAt = this.now();
    }
  }

  /** Test/ops helper. */
  reset(): void {
    this.recordSuccess();
  }
}
