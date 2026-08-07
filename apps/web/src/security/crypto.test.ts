import { describe, expect, it } from "vitest";
import {
  base64ToBytes,
  bytesToBase64,
  conversationSafetyNumber,
  finishOpaqueLogin,
  finishOpaqueRegistration,
  identityContext,
  InMemoryPayloadCipher,
  startOpaque,
  wipeBytes,
} from "./crypto";

const CHAT_ID = "forum_security";
const MESSAGE_ID = "message_1";
const CONTEXT = new TextEncoder().encode("ABYSSAL_IDENTITY_V2:test:CODE-1234567");

function identity(fill: number): InMemoryPayloadCipher {
  const cipher = new InMemoryPayloadCipher();
  cipher.createIdentity(new Uint8Array(64).fill(fill), CONTEXT);
  return cipher;
}

describe("OPAQUE client bindings", () => {
  it("creates independent registration and login requests without exposing password bytes", async () => {
    const state = await startOpaque("correct horse battery staple");
    expect(state.registrationRequest.byteLength).toBeGreaterThan(16);
    expect(state.credentialRequest.byteLength).toBeGreaterThan(16);
    expect(state.registrationRequest).not.toEqual(state.credentialRequest);
    expect(new TextDecoder().decode(state.registrationRequest)).not.toContain("correct horse");
    state.registrationState.fill(0);
    state.registrationRequest.fill(0);
    state.loginState.fill(0);
    state.credentialRequest.fill(0);
  });

  it("rejects malformed server responses", async () => {
    const registration = await startOpaque("password-one");
    await expect(
      finishOpaqueRegistration("password-one", registration, new Uint8Array([1, 2, 3])),
    ).rejects.toThrow();

    const login = await startOpaque("password-one");
    await expect(
      finishOpaqueLogin("password-one", login, new Uint8Array([1, 2, 3])),
    ).rejects.toThrow();
  });
});

describe("conversation safety numbers", () => {
  it("is symmetric and changes when either identity changes", () => {
    const alice = identity(1).publicKey();
    const bob = identity(2).publicKey();
    const eve = identity(3).publicKey();

    expect(conversationSafetyNumber(alice, bob)).toBe(conversationSafetyNumber(bob, alice));
    expect(conversationSafetyNumber(alice, bob)).not.toBe(conversationSafetyNumber(alice, eve));
    expect(conversationSafetyNumber(alice, bob)).toMatch(/^[0-9A-F]{4}( [0-9A-F]{4}){4}$/);
  });
});

describe("recipient E2EE", () => {
  it("decrypts only for intended recipient and verifies sender signature", () => {
    const alice = identity(1);
    const bob = identity(2);
    const eve = identity(3);
    const payload = alice.encryptText(CHAT_ID, MESSAGE_ID, "Alice", "classified", [
      { username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() },
    ]);
    const envelope = payload.envelopes[0];

    expect(payload.version).toBe(5);
    expect(payload.stateRevision).toBe(1);
    expect(payload.identityEnvelope.byteLength).toBeGreaterThan(64);
    expect(payload.ciphertext).not.toEqual(new TextEncoder().encode("classified"));
    expect(
      bob.decryptText(
        CHAT_ID,
        MESSAGE_ID,
        "Alice",
        alice.publicKey(),
        payload,
        envelope.wrappedKey,
        envelope.prekeyId,
        envelope.isPrekey,
        "Bob",
      ),
    ).toBe("classified");
    const receiverState = bob.stateSnapshot();
    expect(receiverState?.revision).toBe(1);
    expect(receiverState?.envelope.byteLength).toBeGreaterThan(64);
    const retryState = bob.stateSnapshot();
    expect(retryState?.revision).toBe(1);
    expect(retryState?.envelope).not.toBe(receiverState?.envelope);
    expect(retryState?.envelope).toEqual(receiverState?.envelope);
    expect(() =>
      eve.decryptText(
        CHAT_ID,
        MESSAGE_ID,
        "Alice",
        alice.publicKey(),
        payload,
        envelope.wrappedKey,
        envelope.prekeyId,
        envelope.isPrekey,
        "Bob",
      ),
    ).toThrow();
  });

  it("handles out-of-order messages, rejects replay, and restores ratchet state", () => {
    const alice = identity(11);
    const bobExport = new Uint8Array(64).fill(12);
    const bob = new InMemoryPayloadCipher();
    bob.createIdentity(bobExport, CONTEXT);
    const recipients = [{ username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() }];
    const first = alice.encryptText(CHAT_ID, "message_early", "Alice", "early", recipients);
    const second = alice.encryptText(CHAT_ID, "message_late", "Alice", "late", recipients);

    expect(bob.decryptText(
      CHAT_ID,
      second.messageId,
      "Alice",
      alice.publicKey(),
      second,
      second.envelopes[0].wrappedKey,
      second.envelopes[0].prekeyId,
      second.envelopes[0].isPrekey,
      "Bob",
    )).toBe("late");
    expect(bob.decryptText(
      CHAT_ID,
      first.messageId,
      "Alice",
      alice.publicKey(),
      first,
      first.envelopes[0].wrappedKey,
      first.envelopes[0].prekeyId,
      first.envelopes[0].isPrekey,
      "Bob",
    )).toBe("early");
    const latest = bob.stateSnapshot();
    expect(latest?.revision).toBe(2);
    expect(() => bob.decryptText(
      CHAT_ID,
      first.messageId,
      "Alice",
      alice.publicKey(),
      first,
      first.envelopes[0].wrappedKey,
      first.envelopes[0].prekeyId,
      first.envelopes[0].isPrekey,
      "Bob",
    )).toThrow();

    const restored = new InMemoryPayloadCipher();
    restored.recoverIdentity(bobExport, CONTEXT, latest!.envelope, bob.publicKey());
    const third = alice.encryptText(CHAT_ID, "message_after_restore", "Alice", "restored", recipients);
    expect(restored.decryptText(
      CHAT_ID,
      third.messageId,
      "Alice",
      alice.publicKey(),
      third,
      third.envelopes[0].wrappedKey,
      third.envelopes[0].prekeyId,
      third.envelopes[0].isPrekey,
      "Bob",
    )).toBe("restored");
  });

  it("rejects ciphertext, signature, sender-key, and conversation tampering", () => {
    const alice = identity(4);
    const bob = identity(5);
    const payload = alice.encryptText(CHAT_ID, MESSAGE_ID, "Alice", "secret", [
      { username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() },
    ]);
    const decrypt = () => bob.decryptText(
      CHAT_ID,
      MESSAGE_ID,
      "Alice",
      alice.publicKey(),
      payload,
      payload.envelopes[0].wrappedKey,
      payload.envelopes[0].prekeyId,
      payload.envelopes[0].isPrekey,
      "Bob",
    );
    expect(() => bob.decryptText(
      CHAT_ID,
      MESSAGE_ID,
      "Alice",
      alice.publicKey(),
      payload,
      payload.envelopes[0].wrappedKey,
      "wrong-prekey",
      true,
      "Bob",
    )).toThrow();
    expect(() => bob.decryptText(
      CHAT_ID,
      MESSAGE_ID,
      "Alice",
      alice.publicKey(),
      payload,
      payload.envelopes[0].wrappedKey,
      "",
      false,
      "Bob",
    )).toThrow();
    payload.ciphertext[0] ^= 1;
    expect(decrypt).toThrow();
    payload.ciphertext[0] ^= 1;
    payload.signature[0] ^= 1;
    expect(decrypt).toThrow();
    payload.signature[0] ^= 1;
    expect(() => bob.decryptText(
      "forum_other",
      MESSAGE_ID,
      "Alice",
      alice.publicKey(),
      payload,
      payload.envelopes[0].wrappedKey,
      payload.envelopes[0].prekeyId,
      payload.envelopes[0].isPrekey,
      "Bob",
    )).toThrow();
    expect(() => bob.decryptText(
      CHAT_ID,
      MESSAGE_ID,
      "Alice",
      bob.publicKey(),
      payload,
      payload.envelopes[0].wrappedKey,
      payload.envelopes[0].prekeyId,
      payload.envelopes[0].isPrekey,
      "Bob",
    )).toThrow();
  });

  it("round-trips signed binary attachments and rejects another recipient", () => {
    const alice = identity(6);
    const bob = identity(7);
    const eve = identity(8);
    const plain = new Uint8Array([0, 255, 1, 128, 64]);
    const encrypted = alice.encryptBytes(CHAT_ID, "attachment_1", "Alice", plain, [
      { username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() },
    ]);
    expect(encrypted).not.toEqual(plain);
    expect(bob.decryptBytes(CHAT_ID, "Alice", alice.publicKey(), encrypted, "Bob")).toEqual(plain);
    expect(() => eve.decryptBytes(CHAT_ID, "Alice", alice.publicKey(), encrypted, "Eve")).toThrow();
  });

  it("recovers stable identity only with correct OPAQUE export key and context", () => {
    const exportKey = new Uint8Array(64).fill(9);
    const first = new InMemoryPayloadCipher();
    const created = first.createIdentity(exportKey, CONTEXT);
    const recovered = new InMemoryPayloadCipher();
    recovered.recoverIdentity(exportKey, CONTEXT, created.envelope, created.publicKey);
    expect(recovered.publicKey()).toEqual(created.publicKey);

    const wrong = new InMemoryPayloadCipher();
    expect(() => wrong.recoverIdentity(
      new Uint8Array(64).fill(10),
      CONTEXT,
      created.envelope,
      created.publicKey,
    )).toThrow();
  });
});

describe("wire helpers", () => {
  it("uses URL-safe unpadded base64", () => {
    const value = new Uint8Array([0, 1, 127, 128, 254, 255]);
    const encoded = bytesToBase64(value);
    expect(encoded).not.toMatch(/[+/=]/u);
    expect(base64ToBytes(encoded)).toEqual(value);
    expect(() => base64ToBytes("not base64!")).toThrow();
  });

  it("wipes mutable buffers and validates identity context", () => {
    const value = new Uint8Array([1, 2, 3]);
    wipeBytes(value);
    expect(value).toEqual(new Uint8Array(3));
    expect(identityContext("node", "code-12345678").byteLength).toBeGreaterThan(16);
    expect(() => identityContext("", "code-12345678")).toThrow();
  });
});
