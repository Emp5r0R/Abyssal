import { describe, expect, it } from "vitest";
import { base64ToBytes, bytesToBase64, InMemoryPayloadCipher, wipeBytes } from "./crypto";

const CHAT_ID = "forum_security";

describe("InMemoryPayloadCipher", () => {
  it("round-trips authenticated text without exporting its key", async () => {
    const cipher = new InMemoryPayloadCipher();
    await cipher.initialize("abyssal-test-node");
    const encrypted = await cipher.encryptText(CHAT_ID, "classified");

    expect(encrypted.byteLength).toBeGreaterThan("classified".length + 12);
    expect(await cipher.decryptText(CHAT_ID, encrypted)).toBe("classified");
  });

  it("rejects ciphertext after key clear", async () => {
    const cipher = new InMemoryPayloadCipher();
    await cipher.initialize("node");
    const encrypted = await cipher.encryptText(CHAT_ID, "message");
    cipher.clear();
    await expect(cipher.decryptText(CHAT_ID, encrypted)).rejects.toThrow("Payload cipher unavailable");
  });

  it("decrypts attachment bytes for another participant on the same node", async () => {
    const sender = new InMemoryPayloadCipher();
    const recipient = new InMemoryPayloadCipher();
    await sender.initialize("node-alpha");
    await recipient.initialize("NODE-ALPHA");
    const attachment = new Uint8Array([0, 255, 1, 2, 3, 128, 64]);

    const uploaded = await sender.encryptBytes(CHAT_ID, attachment);

    expect(uploaded).not.toEqual(attachment);
    await expect(recipient.decryptBytes(CHAT_ID, uploaded)).resolves.toEqual(attachment);
  });

  it("uses a fresh nonce and rejects tampered or cross-node attachment ciphertext", async () => {
    const sender = new InMemoryPayloadCipher();
    const otherNode = new InMemoryPayloadCipher();
    await sender.initialize("node-alpha");
    await otherNode.initialize("node-beta");
    const payload = new Uint8Array([1, 2, 3, 4]);
    const first = await sender.encryptBytes(CHAT_ID, payload);
    const second = await sender.encryptBytes(CHAT_ID, payload);
    const tampered = first.slice();
    tampered[tampered.length - 1] ^= 1;

    expect(first).not.toEqual(second);
    await expect(sender.decryptBytes(CHAT_ID, tampered)).rejects.toThrow();
    await expect(otherNode.decryptBytes(CHAT_ID, first)).rejects.toThrow();
    await expect(sender.decryptBytes("forum_other", first)).rejects.toThrow();
  });

  it("rejects malformed encrypted payloads and invalid base64 frames", async () => {
    const cipher = new InMemoryPayloadCipher();
    await cipher.initialize("node");

    await expect(cipher.decryptBytes(CHAT_ID, new Uint8Array(12))).rejects.toThrow("Encrypted payload unavailable");
    await expect(cipher.decryptBytes("invalid/chat", new Uint8Array(64))).rejects.toThrow("Conversation unavailable");
    expect(() => base64ToBytes("not base64!")).toThrow();
  });

  it("preserves binary payloads through base64 framing", () => {
    const bytes = new Uint8Array([0, 1, 127, 128, 254, 255]);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });

  it("wipeBytes zeros the buffer in place", () => {
    const buffer = new Uint8Array([10, 20, 30, 40, 50]);
    wipeBytes(buffer);
    expect(buffer).toEqual(new Uint8Array(5));
  });

  it("handles empty Uint8Array roundtrip through encrypt/decrypt", async () => {
    const cipher = new InMemoryPayloadCipher();
    await cipher.initialize("empty-test");
    const empty = new Uint8Array(0);
    const encrypted = await cipher.encryptBytes(CHAT_ID, empty);
    const decrypted = await cipher.decryptBytes(CHAT_ID, encrypted);
    expect(decrypted.byteLength).toBe(0);
  });

  it("case-insensitive node ID normalization in initialize", async () => {
    const a = new InMemoryPayloadCipher();
    const b = new InMemoryPayloadCipher();
    await a.initialize("MyNode");
    await b.initialize("mynode");
    const msg = await a.encryptText(CHAT_ID, "hi");
    expect(await b.decryptText(CHAT_ID, msg)).toBe("hi");
  });

  it("rejects empty and oversized node identities", async () => {
    const cipher = new InMemoryPayloadCipher();
    await expect(cipher.initialize("   ")).rejects.toThrow("Node identity unavailable");
    await expect(cipher.initialize("n".repeat(129))).rejects.toThrow("Node identity unavailable");
  });

  it("sustains multiple encrypt/decrypt cycles without state corruption", async () => {
    const cipher = new InMemoryPayloadCipher();
    await cipher.initialize("cycle-test");
    for (let i = 0; i < 10; i++) {
      const text = `message-${i}`;
      const encrypted = await cipher.encryptText(CHAT_ID, text);
      expect(await cipher.decryptText(CHAT_ID, encrypted)).toBe(text);
    }
  });

  it("base64ToBytes returns empty array for empty string", () => {
    expect(base64ToBytes("")).toEqual(new Uint8Array(0));
  });

  it("bytesToBase64 produces valid base64 for empty input", () => {
    expect(bytesToBase64(new Uint8Array(0))).toBe("");
  });

  it("rejects payload shorter than nonce size", async () => {
    const cipher = new InMemoryPayloadCipher();
    await cipher.initialize("short");
    const tiny = new Uint8Array(6);
    await expect(cipher.decryptBytes(CHAT_ID, tiny)).rejects.toThrow("Encrypted payload unavailable");
  });

  it("encryptBytes before initialize throws", async () => {
    const cipher = new InMemoryPayloadCipher();
    await expect(cipher.encryptBytes(CHAT_ID, new Uint8Array([1]))).rejects.toThrow("Payload cipher unavailable");
  });

  it("decryptText rejects invalid UTF-8 payload from different key", async () => {
    const a = new InMemoryPayloadCipher();
    const b = new InMemoryPayloadCipher();
    await a.initialize("node-x");
    await b.initialize("node-y");
    const encrypted = await a.encryptText(CHAT_ID, "secret");
    await expect(b.decryptText(CHAT_ID, encrypted)).rejects.toThrow();
  });
});
