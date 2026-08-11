import { describe, expect, it } from "vitest";
import {
  base64ToBytes,
  base64NoPaddingLength,
  bytesToBase64,
  conversationSafetyNumber,
  finishOpaqueLogin,
  finishOpaqueRegistration,
  identityContext,
  InMemoryPayloadCipher,
  maxSerializedAttachmentBytes,
  payloadToFrame,
  STATE_SIGNATURE_BYTES,
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

describe("stateless attachment bounds", () => {
  it("accounts for the fixed binary XChaCha envelope overhead", () => {
    expect(base64NoPaddingLength(0)).toBe(0);
    expect(base64NoPaddingLength(1)).toBe(2);
    expect(base64NoPaddingLength(2)).toBe(3);
    expect(base64NoPaddingLength(3)).toBe(4);

    const imageLimit = maxSerializedAttachmentBytes("IMAGE");
    const videoLimit = maxSerializedAttachmentBytes("VIDEO");
    const fileLimit = maxSerializedAttachmentBytes("FILE");
    expect(imageLimit).toBeLessThan(videoLimit);
    expect(videoLimit).toBeLessThan(fileLimit);
    expect(fileLimit).toBe(200 * 1024 * 1024 + 41);
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

    expect(payload.version).toBe(7);
    expect(payload.stateRevision).toBe(1);
    expect(payload.identityEnvelope.byteLength).toBeGreaterThan(64);
    expect(payload.stateSignature.byteLength).toBe(STATE_SIGNATURE_BYTES);
    expect(payload.ciphertext).not.toEqual(new TextEncoder().encode("classified"));
    expect(
      bob.decryptText(
        CHAT_ID,
        MESSAGE_ID,
        "Alice",
        alice.publicKey(),
        payload,
        envelope.signature,
        envelope.wrappedKey,
        envelope.prekeyId,
        envelope.isPrekey,
        "Bob",
      ),
    ).toBe("classified");
    const receiverState = bob.stateSnapshot();
    expect(receiverState?.revision).toBe(1);
    expect(receiverState?.envelope.byteLength).toBeGreaterThan(64);
    const ackSignature = bob.signAcknowledgement(CHAT_ID, MESSAGE_ID, "Alice", envelope.prekeyId);
    expect(ackSignature.byteLength).toBe(STATE_SIGNATURE_BYTES);
    const retryState = bob.stateSnapshot();
    expect(retryState?.revision).toBe(1);
    expect(retryState?.envelope).not.toBe(receiverState?.envelope);
    expect(retryState?.envelope).toEqual(receiverState?.envelope);
    expect(retryState?.stateSignature).not.toBe(receiverState?.stateSignature);
    expect(retryState?.stateSignature).toEqual(receiverState?.stateSignature);
    const duplicateAck = bob.signAcknowledgement(CHAT_ID, MESSAGE_ID, "Alice", envelope.prekeyId);
    expect(duplicateAck).toEqual(ackSignature);
    expect(() =>
      eve.decryptText(
        CHAT_ID,
        MESSAGE_ID,
        "Alice",
        alice.publicKey(),
        payload,
        envelope.signature,
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
      second.envelopes[0].signature,
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
      first.envelopes[0].signature,
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
      first.envelopes[0].signature,
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
      third.envelopes[0].signature,
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
      payload.envelopes[0].signature,
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
      payload.envelopes[0].signature,
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
      payload.envelopes[0].signature,
      payload.envelopes[0].wrappedKey,
      "",
      false,
      "Bob",
    )).toThrow();
    payload.ciphertext[0] ^= 1;
    expect(decrypt).toThrow();
    payload.ciphertext[0] ^= 1;
    payload.envelopes[0].signature[0] ^= 1;
    expect(decrypt).toThrow();
    payload.envelopes[0].signature[0] ^= 1;
    const legacy = { ...payload, version: 5 as const };
    expect(() => bob.decryptText(
      CHAT_ID,
      MESSAGE_ID,
      "Alice",
      alice.publicKey(),
      legacy,
      payload.envelopes[0].signature,
      payload.envelopes[0].wrappedKey,
      payload.envelopes[0].prekeyId,
      payload.envelopes[0].isPrekey,
      "Bob",
    )).toThrow();
    const mismatchedIdentity = payload.identityPublicKey.slice();
    mismatchedIdentity[0] ^= 1;
    expect(() => bob.decryptText(
      CHAT_ID,
      MESSAGE_ID,
      "Alice",
      alice.publicKey(),
      { ...payload, identityPublicKey: mismatchedIdentity },
      payload.envelopes[0].signature,
      payload.envelopes[0].wrappedKey,
      payload.envelopes[0].prekeyId,
      payload.envelopes[0].isPrekey,
      "Bob",
    )).toThrow();
    expect(() => bob.decryptText(
      "forum_other",
      MESSAGE_ID,
      "Alice",
      alice.publicKey(),
      payload,
      payload.envelopes[0].signature,
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
      payload.envelopes[0].signature,
      payload.envelopes[0].wrappedKey,
      payload.envelopes[0].prekeyId,
      payload.envelopes[0].isPrekey,
      "Bob",
    )).toThrow();
  });

  it("round-trips stateless attachments and binds blob context", () => {
    const alice = identity(6);
    const bob = identity(7);
    const plain = new Uint8Array([0, 255, 1, 128, 64]);
    const encrypted = alice.encryptAttachment(CHAT_ID, "attachment_1", "Alice", "FILE", plain);
    expect(encrypted.blob).not.toEqual(plain);
    expect(encrypted.key.byteLength).toBe(32);
    expect(encrypted.blob[0]).toBe(1);
    expect(bob.decryptAttachment(
      CHAT_ID,
      "attachment_1",
      "Alice",
      "FILE",
      encrypted.key,
      encrypted.blob,
    )).toEqual(plain);
    const tampered = encrypted.blob.slice();
    tampered[tampered.length - 1] ^= 1;
    expect(() => bob.decryptAttachment(
      CHAT_ID,
      "attachment_1",
      "Alice",
      "FILE",
      encrypted.key,
      tampered,
    )).toThrow();
    expect(() => bob.decryptAttachment(
      "other_chat",
      "attachment_1",
      "Alice",
      "FILE",
      encrypted.key,
      encrypted.blob,
    )).toThrow();
    expect(() => bob.decryptAttachment(
      CHAT_ID,
      "attachment_other",
      "Alice",
      "FILE",
      encrypted.key,
      encrypted.blob,
    )).toThrow();
    expect(() => bob.decryptAttachment(
      CHAT_ID,
      "attachment_1",
      "Alice",
      "IMAGE",
      encrypted.key,
      encrypted.blob,
    )).toThrow();
    const legacy = encrypted.blob.slice();
    legacy[0] = 0;
    expect(() => bob.decryptAttachment(
      CHAT_ID,
      "attachment_1",
      "Alice",
      "FILE",
      encrypted.key,
      legacy,
    )).toThrow();
    wipeBytes(encrypted.key);
    wipeBytes(encrypted.blob);
    const framePayload = alice.encryptText(CHAT_ID, "frame_1", "Alice", "frame", [
      { username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() },
    ]);
    const frame = payloadToFrame(framePayload);
    framePayload.nonce.fill(0);
    framePayload.ciphertext.fill(0);
    framePayload.identityEnvelope.fill(0);
    framePayload.identityPublicKey.fill(0);
    framePayload.stateSignature.fill(0);
    framePayload.envelopes.forEach((envelope) => {
      envelope.wrappedKey.fill(0);
      envelope.signature.fill(0);
    });
    expect(frame.version).toBe(7);
    expect(frame).not.toHaveProperty("signature_b64");
    expect(frame.state_signature_b64).toBeTruthy();
    expect((frame.envelopes as Array<{ signature_b64: string }>)[0].signature_b64).toBeTruthy();
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
