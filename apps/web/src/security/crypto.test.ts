import { describe, expect, it } from "vitest";
import { base64ToBytes, bytesToBase64, InMemoryPayloadCipher } from "./crypto";

describe("InMemoryPayloadCipher", () => {
  it("round-trips authenticated text without exporting its key", async () => {
    const cipher = new InMemoryPayloadCipher();
    await cipher.initialize("abyssal-test-node");
    const encrypted = await cipher.encryptText("classified");

    expect(encrypted.byteLength).toBeGreaterThan("classified".length + 12);
    expect(await cipher.decryptText(encrypted)).toBe("classified");
  });

  it("rejects ciphertext after key clear", async () => {
    const cipher = new InMemoryPayloadCipher();
    await cipher.initialize("node");
    const encrypted = await cipher.encryptText("message");
    cipher.clear();
    await expect(cipher.decryptText(encrypted)).rejects.toThrow("Payload cipher unavailable");
  });

  it("decrypts attachment bytes for another participant on the same node", async () => {
    const sender = new InMemoryPayloadCipher();
    const recipient = new InMemoryPayloadCipher();
    await sender.initialize("node-alpha");
    await recipient.initialize("NODE-ALPHA");
    const attachment = new Uint8Array([0, 255, 1, 2, 3, 128, 64]);

    const uploaded = await sender.encryptBytes(attachment);

    expect(uploaded).not.toEqual(attachment);
    await expect(recipient.decryptBytes(uploaded)).resolves.toEqual(attachment);
  });

  it("uses a fresh nonce and rejects tampered or cross-node attachment ciphertext", async () => {
    const sender = new InMemoryPayloadCipher();
    const otherNode = new InMemoryPayloadCipher();
    await sender.initialize("node-alpha");
    await otherNode.initialize("node-beta");
    const payload = new Uint8Array([1, 2, 3, 4]);
    const first = await sender.encryptBytes(payload);
    const second = await sender.encryptBytes(payload);
    const tampered = first.slice();
    tampered[tampered.length - 1] ^= 1;

    expect(first).not.toEqual(second);
    await expect(sender.decryptBytes(tampered)).rejects.toThrow();
    await expect(otherNode.decryptBytes(first)).rejects.toThrow();
  });

  it("rejects malformed encrypted payloads and invalid base64 frames", async () => {
    const cipher = new InMemoryPayloadCipher();
    await cipher.initialize("node");

    await expect(cipher.decryptBytes(new Uint8Array(12))).rejects.toThrow("Encrypted payload too short");
    expect(() => base64ToBytes("not base64!")).toThrow();
  });

  it("preserves binary payloads through base64 framing", () => {
    const bytes = new Uint8Array([0, 1, 127, 128, 254, 255]);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });
});
