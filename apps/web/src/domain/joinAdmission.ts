/**
 * Picks which public-room join request an owner client admits next.
 * Admissions run one at a time, and a request that keeps failing is left for a manual owner decision.
 */
export class JoinAdmissionQueue {
  readonly #maxAttempts: number;
  readonly #attempts = new Map<string, number>();
  #inFlight: string | null = null;

  constructor(maxAttempts = 3) {
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1) throw new Error("Invalid attempt limit");
    this.#maxAttempts = maxAttempts;
  }

  /** Claims the next candidate, or null while one admission is running or none may be retried. */
  next(candidates: readonly string[]): string | null {
    if (this.#inFlight !== null) return null;
    const requestId = candidates.find((candidate) => (this.#attempts.get(candidate) ?? 0) < this.#maxAttempts);
    if (requestId === undefined) return null;
    this.#attempts.set(requestId, (this.#attempts.get(requestId) ?? 0) + 1);
    this.#inFlight = requestId;
    return requestId;
  }

  /** Releases the claim. Returns true when a failed request may still be retried. */
  settle(requestId: string, admitted: boolean): boolean {
    if (this.#inFlight !== requestId) return false;
    this.#inFlight = null;
    if (admitted) {
      this.#attempts.delete(requestId);
      return false;
    }
    return (this.#attempts.get(requestId) ?? 0) < this.#maxAttempts;
  }
}
