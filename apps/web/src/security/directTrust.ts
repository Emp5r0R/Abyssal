export interface DirectTrustContext {
  chatId: string;
  peerUsername: string;
  safetyNumber: string;
  verificationToken: string;
  sessionGeneration: number;
  connectionGeneration: number;
  localIdentity: Uint8Array;
  peerIdentity: Uint8Array;
}

export interface DirectTrustStatus {
  active: boolean;
  peerUsername: string | null;
  safetyNumber: string | null;
  verificationToken: string | null;
  verified: boolean;
}

export const STABLE_IDENTITY_BYTES = 64;

const EMPTY_STATUS: DirectTrustStatus = {
  active: false,
  peerUsername: null,
  safetyNumber: null,
  verificationToken: null,
  verified: false,
};

interface VerifiedDirect {
  chatId: string;
  peerUsername: string;
  safetyNumber: string;
  verificationToken: string;
  sessionGeneration: number;
  connectionGeneration: number;
  localIdentity: Uint8Array;
  peerIdentity: Uint8Array;
}

/**
 * Process-memory-only direct-chat trust. A displayed safety number is only the
 * user's confirmation input; authorization is bound to both stable long-term
 * identity fingerprints and the active connection generation.
 */
export class DirectTrustStore {
  static readonly MAX_PEERS = 128;
  #verified = new Map<string, VerifiedDirect>();

  markVerified(context: DirectTrustContext, presentedToken: string): boolean {
    if (!context.chatId || !context.peerUsername || !context.safetyNumber ||
      !context.verificationToken || presentedToken !== context.verificationToken ||
      context.sessionGeneration < 0 ||
      context.connectionGeneration < 0 ||
      context.localIdentity.byteLength < STABLE_IDENTITY_BYTES ||
      context.peerIdentity.byteLength < STABLE_IDENTITY_BYTES) {
      return false;
    }
    const key = trustKey(context);
    const previous = this.#verified.get(key);
    if (previous) wipeVerified(previous);
    this.#verified.delete(key);
    while (this.#verified.size >= DirectTrustStore.MAX_PEERS) {
      const oldest = this.#verified.keys().next().value;
      if (oldest === undefined) break;
      const evicted = this.#verified.get(oldest);
      if (evicted) wipeVerified(evicted);
      this.#verified.delete(oldest);
    }
    this.#verified.set(key, {
      chatId: context.chatId,
      peerUsername: context.peerUsername,
      safetyNumber: context.safetyNumber,
      verificationToken: context.verificationToken,
      sessionGeneration: context.sessionGeneration,
      connectionGeneration: context.connectionGeneration,
      localIdentity: context.localIdentity.slice(0, STABLE_IDENTITY_BYTES),
      peerIdentity: context.peerIdentity.slice(0, STABLE_IDENTITY_BYTES),
    });
    return true;
  }

  isVerified(context: DirectTrustContext | null): boolean {
    const verified = context ? this.#verified.get(trustKey(context)) : undefined;
    return verified !== undefined && context !== null &&
      verified.chatId === context.chatId &&
      verified.peerUsername === context.peerUsername &&
      verified.safetyNumber === context.safetyNumber &&
      verified.verificationToken === context.verificationToken &&
      verified.sessionGeneration === context.sessionGeneration &&
      verified.connectionGeneration === context.connectionGeneration &&
      context.localIdentity.byteLength >= STABLE_IDENTITY_BYTES &&
      context.peerIdentity.byteLength >= STABLE_IDENTITY_BYTES &&
      equalBytes(verified.localIdentity, context.localIdentity.subarray(0, STABLE_IDENTITY_BYTES)) &&
      equalBytes(verified.peerIdentity, context.peerIdentity.subarray(0, STABLE_IDENTITY_BYTES));
  }

  invalidateIfIdentityChanged(context: DirectTrustContext | null): void {
    if (!context) return;
    const key = trustKey(context);
    const verified = this.#verified.get(key);
    if (!verified || context.localIdentity.byteLength < STABLE_IDENTITY_BYTES ||
      context.peerIdentity.byteLength < STABLE_IDENTITY_BYTES) return;
    if (!equalBytes(verified.localIdentity, context.localIdentity.subarray(0, STABLE_IDENTITY_BYTES)) ||
      !equalBytes(verified.peerIdentity, context.peerIdentity.subarray(0, STABLE_IDENTITY_BYTES))) {
      this.#verified.delete(key);
      wipeVerified(verified);
    }
  }

  status(context: DirectTrustContext | null): DirectTrustStatus {
    if (!context) return { ...EMPTY_STATUS };
    return {
      active: true,
      peerUsername: context.peerUsername,
      safetyNumber: context.safetyNumber,
      verificationToken: context.verificationToken,
      verified: this.isVerified(context),
    };
  }

  clear(): void {
    this.#verified.forEach(wipeVerified);
    this.#verified.clear();
  }
}

function trustKey(context: DirectTrustContext): string {
  return `${context.chatId}\u0000${context.peerUsername.toLowerCase()}`;
}

function wipeVerified(verified: VerifiedDirect): void {
  verified.localIdentity.fill(0);
  verified.peerIdentity.fill(0);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}
