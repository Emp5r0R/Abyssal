const NONCE_BYTES = 12;
const PAYLOAD_VERSION = 2;
const ENCODER = new TextEncoder();
const DECODER = new TextDecoder("utf-8", { fatal: true });
const CHAT_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_NODE_ID_BYTES = 128;

export class InMemoryPayloadCipher {
  #nodeSecret: Uint8Array | null = null;

  async initialize(nodeId: string): Promise<void> {
    const normalized = nodeId.trim().toUpperCase();
    if (!normalized || ENCODER.encode(normalized).byteLength > MAX_NODE_ID_BYTES) {
      throw new Error("Node identity unavailable");
    }
    const material = ENCODER.encode(`ABYSSAL_NODE_SECRET_V2:${normalized}`);
    this.clear();
    try {
      this.#nodeSecret = new Uint8Array(await crypto.subtle.digest("SHA-256", material));
    } finally {
      material.fill(0);
    }
  }

  async encryptText(chatId: string, value: string): Promise<Uint8Array> {
    const plain = ENCODER.encode(value);
    try {
      return await this.encryptBytes(chatId, plain);
    } finally {
      plain.fill(0);
    }
  }

  async decryptText(chatId: string, payload: Uint8Array): Promise<string> {
    const plain = await this.decryptBytes(chatId, payload);
    try {
      return DECODER.decode(plain);
    } finally {
      plain.fill(0);
    }
  }

  async encryptBytes(chatId: string, value: BufferSource): Promise<Uint8Array> {
    const normalizedChatId = normalizeChatId(chatId);
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const key = await this.conversationKey(normalizedChatId);
    const additionalData = ENCODER.encode(`ABYSSAL_CONVERSATION_PAYLOAD_V2:${normalizedChatId}`);
    let encrypted: ArrayBuffer;
    try {
      encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
        key,
        value,
      );
    } finally {
      additionalData.fill(0);
    }
    const result = new Uint8Array(1 + nonce.byteLength + encrypted.byteLength);
    result[0] = PAYLOAD_VERSION;
    result.set(nonce, 1);
    result.set(new Uint8Array(encrypted), 1 + nonce.byteLength);
    return result;
  }

  async decryptBytes(chatId: string, payload: Uint8Array): Promise<Uint8Array> {
    const normalizedChatId = normalizeChatId(chatId);
    if (payload.byteLength <= 1 + NONCE_BYTES || payload[0] !== PAYLOAD_VERSION) {
      throw new Error("Encrypted payload unavailable");
    }
    const nonce = payload.slice(1, 1 + NONCE_BYTES);
    const ciphertext = payload.slice(1 + NONCE_BYTES);
    const key = await this.conversationKey(normalizedChatId);
    const additionalData = ENCODER.encode(`ABYSSAL_CONVERSATION_PAYLOAD_V2:${normalizedChatId}`);
    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
        key,
        ciphertext,
      );
      return new Uint8Array(decrypted);
    } finally {
      additionalData.fill(0);
      nonce.fill(0);
      ciphertext.fill(0);
    }
  }

  clear(): void {
    this.#nodeSecret?.fill(0);
    this.#nodeSecret = null;
  }

  private async conversationKey(chatId: string): Promise<CryptoKey> {
    if (!this.#nodeSecret) throw new Error("Payload cipher unavailable");
    const prefix = ENCODER.encode("ABYSSAL_CONVERSATION_KEY_V2:");
    const suffix = ENCODER.encode(`:${chatId}`);
    const material = new Uint8Array(prefix.length + this.#nodeSecret.length + suffix.length);
    material.set(prefix);
    material.set(this.#nodeSecret, prefix.length);
    material.set(suffix, prefix.length + this.#nodeSecret.length);
    try {
      const digest = await crypto.subtle.digest("SHA-256", material);
      return crypto.subtle.importKey("raw", digest, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    } finally {
      material.fill(0);
    }
  }
}

function normalizeChatId(chatId: string): string {
  const normalized = chatId.trim();
  if (!CHAT_ID_PATTERN.test(normalized)) throw new Error("Conversation unavailable");
  return normalized;
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
