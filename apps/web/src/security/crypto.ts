const NONCE_BYTES = 12;
const ENCODER = new TextEncoder();
const DECODER = new TextDecoder("utf-8", { fatal: true });

export class InMemoryPayloadCipher {
  #key: CryptoKey | null = null;

  async initialize(nodeId: string): Promise<void> {
    const normalized = nodeId.trim().toUpperCase();
    const material = ENCODER.encode(`ABYSSAL_NODE_PAYLOAD_V1:${normalized}`);
    const digest = await crypto.subtle.digest("SHA-256", material);
    this.#key = await crypto.subtle.importKey(
      "raw",
      digest,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  async encryptText(value: string): Promise<Uint8Array> {
    return this.encryptBytes(ENCODER.encode(value));
  }

  async decryptText(payload: Uint8Array): Promise<string> {
    return DECODER.decode(await this.decryptBytes(payload));
  }

  async encryptBytes(value: BufferSource): Promise<Uint8Array> {
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      this.requireKey(),
      value,
    );
    const result = new Uint8Array(nonce.byteLength + encrypted.byteLength);
    result.set(nonce, 0);
    result.set(new Uint8Array(encrypted), nonce.byteLength);
    return result;
  }

  async decryptBytes(payload: Uint8Array): Promise<Uint8Array> {
    if (payload.byteLength <= NONCE_BYTES) throw new Error("Encrypted payload too short");
    const nonce = payload.slice(0, NONCE_BYTES);
    const ciphertext = payload.slice(NONCE_BYTES);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      this.requireKey(),
      ciphertext,
    );
    return new Uint8Array(decrypted);
  }

  clear(): void {
    this.#key = null;
  }

  private requireKey(): CryptoKey {
    if (!this.#key) throw new Error("Payload cipher unavailable");
    return this.#key;
  }
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function wipeBytes(bytes: Uint8Array): void {
  bytes.fill(0);
}

