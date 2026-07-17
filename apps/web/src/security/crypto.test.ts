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

  it("preserves binary payloads through base64 framing", () => {
    const bytes = new Uint8Array([0, 1, 127, 128, 254, 255]);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });
});

