const PIN_PATTERN = /^\d{6,12}$/u;
const DEFAULT_ITERATIONS = 210_000;
const DEFAULT_BACKOFF_MS = 500;
const MAX_BACKOFF_MS = 30_000;
const SALT_BYTES = 16;
const DIGEST_BYTES = 32;

export interface PinVerifier {
  salt: Uint8Array<ArrayBuffer>;
  digest: Uint8Array<ArrayBuffer>;
  iterations: number;
}

export type PinVerificationResult = "unlock" | "duress" | "invalid" | "blocked";

interface PrivacyPinGateOptions {
  iterations?: number;
  backoffMs?: number;
  maxBackoffMs?: number;
  now?: () => number;
}

export async function createPinVerifier(
  pin: string,
  iterations = DEFAULT_ITERATIONS,
): Promise<PinVerifier> {
  if (!PIN_PATTERN.test(pin) || !Number.isInteger(iterations) || iterations < 1_000) {
    throw new Error("Invalid PIN");
  }
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const pinBytes = new TextEncoder().encode(pin);
  try {
    return {
      salt,
      digest: await derivePinDigest(pinBytes, salt, iterations),
      iterations,
    };
  } catch (error) {
    salt.fill(0);
    throw error;
  } finally {
    pinBytes.fill(0);
  }
}

export async function verifyPin(verifier: PinVerifier, candidate: string): Promise<boolean> {
  if (!PIN_PATTERN.test(candidate)) return false;
  const candidateBytes = new TextEncoder().encode(candidate);
  let actual: Uint8Array<ArrayBuffer> = new Uint8Array(0);
  try {
    actual = await derivePinDigest(candidateBytes, verifier.salt, verifier.iterations);
    return constantTimeEqual(actual, verifier.digest);
  } finally {
    candidateBytes.fill(0);
    actual.fill(0);
  }
}

export function wipePinVerifier(verifier: PinVerifier): void {
  verifier.salt.fill(0);
  verifier.digest.fill(0);
  verifier.iterations = 0;
}

export function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  const length = Math.max(left.byteLength, right.byteLength);
  let difference = left.byteLength ^ right.byteLength;
  for (let index = 0; index < length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

export class PrivacyPinGate {
  readonly #cover: PinVerifier;
  readonly #duress: PinVerifier;
  readonly #backoffMs: number;
  readonly #maxBackoffMs: number;
  readonly #now: () => number;
  #queue: Promise<void> = Promise.resolve();
  #failures = 0;
  #blockedUntil = 0;
  #destroyed = false;

  get destroyed(): boolean {
    return this.#destroyed;
  }

  private constructor(
    cover: PinVerifier,
    duress: PinVerifier,
    options: PrivacyPinGateOptions,
  ) {
    this.#cover = cover;
    this.#duress = duress;
    this.#backoffMs = boundedPositiveInteger(options.backoffMs, DEFAULT_BACKOFF_MS);
    this.#maxBackoffMs = Math.max(
      this.#backoffMs,
      boundedPositiveInteger(options.maxBackoffMs, MAX_BACKOFF_MS),
    );
    this.#now = options.now ?? Date.now;
  }

  static async create(
    coverPin: string,
    duressPin = "",
    options: PrivacyPinGateOptions = {},
  ): Promise<PrivacyPinGate> {
    if (!PIN_PATTERN.test(coverPin) || (duressPin && (!PIN_PATTERN.test(duressPin) || duressPin === coverPin))) {
      throw new Error("Invalid PIN");
    }
    const iterations = options.iterations ?? DEFAULT_ITERATIONS;
    const cover = await createPinVerifier(coverPin, iterations);
    try {
      const duress = duressPin
        ? await createPinVerifier(duressPin, iterations)
        : createUnmatchableVerifier(iterations);
      return new PrivacyPinGate(cover, duress, options);
    } catch (error) {
      wipePinVerifier(cover);
      throw error;
    }
  }

  verify(candidate: string): Promise<PinVerificationResult> {
    let candidateBytes = new TextEncoder().encode(candidate);
    const task = this.#queue.then(async () => {
      try {
        return await this.#verifyBytes(candidateBytes);
      } finally {
        candidateBytes.fill(0);
        candidateBytes = new Uint8Array(0);
      }
    });
    this.#queue = task.then(() => undefined, () => undefined);
    return task;
  }

  destroy(): void {
    this.#destroyed = true;
    this.#blockedUntil = Number.POSITIVE_INFINITY;
    this.#failures = Number.MAX_SAFE_INTEGER;
    wipePinVerifier(this.#cover);
    wipePinVerifier(this.#duress);
  }

  async #verifyBytes(candidateBytes: Uint8Array): Promise<PinVerificationResult> {
    if (this.#destroyed || !validPinBytes(candidateBytes)) return "invalid";
    const now = this.#now();
    if (now < this.#blockedUntil) return "blocked";

    let coverDigest: Uint8Array<ArrayBuffer> = new Uint8Array(0);
    let duressDigest: Uint8Array<ArrayBuffer> = new Uint8Array(0);
    try {
      [coverDigest, duressDigest] = await Promise.all([
        derivePinDigest(candidateBytes, this.#cover.salt, this.#cover.iterations),
        derivePinDigest(candidateBytes, this.#duress.salt, this.#duress.iterations),
      ]);
      if (this.#destroyed) return "invalid";
      const coverMatches = constantTimeEqual(coverDigest, this.#cover.digest);
      const duressMatches = constantTimeEqual(duressDigest, this.#duress.digest);
      if (coverMatches || duressMatches) {
        this.#failures = 0;
        this.#blockedUntil = 0;
        return duressMatches ? "duress" : "unlock";
      }
      this.#failures = Math.min(this.#failures + 1, 31);
      const delay = Math.min(this.#maxBackoffMs, this.#backoffMs * (2 ** (this.#failures - 1)));
      this.#blockedUntil = now + delay;
      return "invalid";
    } finally {
      coverDigest.fill(0);
      duressDigest.fill(0);
    }
  }
}

async function derivePinDigest(
  pinBytes: Uint8Array,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const pinCopy = new Uint8Array(pinBytes);
  const saltCopy = new Uint8Array(salt);
  try {
    const key = await crypto.subtle.importKey("raw", pinCopy, "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: saltCopy, iterations },
      key,
      DIGEST_BYTES * 8,
    );
    return new Uint8Array(bits);
  } finally {
    pinCopy.fill(0);
    saltCopy.fill(0);
  }
}

function createUnmatchableVerifier(iterations: number): PinVerifier {
  return {
    salt: crypto.getRandomValues(new Uint8Array(SALT_BYTES)),
    digest: crypto.getRandomValues(new Uint8Array(DIGEST_BYTES)),
    iterations,
  };
}

function validPinBytes(value: Uint8Array): boolean {
  if (value.byteLength < 6 || value.byteLength > 12) return false;
  let valid = 1;
  for (const byte of value) valid &= Number(byte >= 48 && byte <= 57);
  return valid === 1;
}

function boundedPositiveInteger(value: number | undefined, fallback: number): number {
  return Number.isInteger(value) && (value ?? 0) > 0 ? value as number : fallback;
}
