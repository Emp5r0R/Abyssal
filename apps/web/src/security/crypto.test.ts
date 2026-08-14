import { afterEach, describe, expect, it, vi } from "vitest";
import { WasmE2eeSession } from "../generated/abyssal_core/abyssal_core";
import {
  base64ToBytes,
  base64NoPaddingLength,
  bytesToBase64,
  conversationSafetyNumber,
  finishOpaqueLogin,
  finishOpaqueRegistration,
  FatalCipherError,
  IDENTITY_PUBLIC_KEY_BYTES,
  identityContext,
  InMemoryPayloadCipher,
  maxSerializedAttachmentBytes,
  payloadToFrame,
  STATE_SIGNATURE_BYTES,
  startOpaque,
  wipeBytes,
} from "./crypto";

afterEach(() => vi.restoreAllMocks());

const CHAT_ID = "forum_security";
const MESSAGE_ID = "message_1";
const CONTEXT = new TextEncoder().encode("ABYSSAL_IDENTITY_V2:test:CODE-1234567");

function identity(fill: number): InMemoryPayloadCipher {
  const cipher = new InMemoryPayloadCipher();
  cipher.createIdentity(new Uint8Array(64).fill(fill), CONTEXT);
  return cipher;
}

function commit(cipher: InMemoryPayloadCipher, payload: { messageId: string; stateRevision: number }): void {
  cipher.commitOutbound(payload.messageId, payload.stateRevision);
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
  it("frees a native identity and wipes outputs when sealing fails", () => {
    const cipher = new InMemoryPayloadCipher();
    const free = vi.spyOn(WasmE2eeSession.prototype, "free");
    vi.spyOn(WasmE2eeSession.prototype, "sealIdentity").mockImplementationOnce(() => {
      throw new Error("seal failed");
    });

    expect(() => cipher.createIdentity(new Uint8Array(64).fill(31), CONTEXT))
      .toThrow("seal failed");
    expect(free).toHaveBeenCalledOnce();
    expect(() => cipher.publicKey()).toThrow("Identity unavailable");
  });

  it("rolls back malformed staged output exactly and invalidates unparseable native output", () => {
    const alice = identity(17);
    const bob = identity(18);
    const recipients = [{ username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() }];
    const originalEncrypt = WasmE2eeSession.prototype.encrypt;
    vi.spyOn(WasmE2eeSession.prototype, "encrypt").mockImplementationOnce(function (
      this: WasmE2eeSession,
      ...args: Parameters<WasmE2eeSession["encrypt"]>
    ) {
      const result = JSON.parse(originalEncrypt.apply(this, args)) as {
        envelopes: Array<{ prekey_id: string }>;
      };
      result.envelopes[0].prekey_id = "";
      return JSON.stringify(result);
    });

    let stagedError: unknown;
    try {
      alice.encryptText(CHAT_ID, "malformed-staged", "Alice", "first", recipients);
    } catch (error) {
      stagedError = error;
    }
    expect(stagedError).toBeInstanceOf(Error);
    expect(stagedError).not.toBeInstanceOf(FatalCipherError);

    const retry = alice.encryptText(CHAT_ID, "malformed-staged", "Alice", "retry", recipients);
    commit(alice, retry);

    vi.spyOn(WasmE2eeSession.prototype, "encrypt").mockReturnValueOnce("{");
    expect(() => alice.encryptText(CHAT_ID, "unparseable-staged", "Alice", "fatal", recipients))
      .toThrow(FatalCipherError);
    expect(() => alice.publicKey()).toThrow("Identity unavailable");
  });

  it("preserves the session when native encryption throws before returning staged output", () => {
    const alice = identity(15);
    const bob = identity(16);
    const recipients = [{ username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() }];
    vi.spyOn(WasmE2eeSession.prototype, "encrypt").mockImplementationOnce(() => {
      throw new Error("native rejected before returning");
    });

    expect(() => alice.encryptText(CHAT_ID, "native-rejected", "Alice", "first", recipients))
      .toThrow("Payload unavailable");
    expect(alice.publicKey()).toHaveLength(IDENTITY_PUBLIC_KEY_BYTES);
    const retry = alice.encryptText(CHAT_ID, "native-retry", "Alice", "retry", recipients);
    commit(alice, retry);
  });

  it("keeps the identity for native authentication failures but fails closed after native return", () => {
    const alice = identity(25);
    const bob = identity(26);
    const payload = alice.encryptText(CHAT_ID, "decrypt-phase", "Alice", "classified", [
      { username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() },
    ]);
    commit(alice, payload);
    const envelope = payload.envelopes[0];
    const decryptArgs = () => bob.decryptText(
      CHAT_ID,
      payload.messageId,
      "Alice",
      alice.publicKey(),
      payload,
      envelope.signature,
      envelope.wrappedKey,
      envelope.prekeyId,
      envelope.isPrekey,
      "Bob",
    );

    vi.spyOn(WasmE2eeSession.prototype, "decrypt").mockImplementationOnce(() => {
      throw new Error("authentication rejected before native return");
    });
    let nativeError: unknown;
    try {
      decryptArgs();
    } catch (error) {
      nativeError = error;
    }
    expect(nativeError).toBeInstanceOf(Error);
    expect(nativeError).not.toBeInstanceOf(FatalCipherError);
    expect(bob.publicKey()).toHaveLength(IDENTITY_PUBLIC_KEY_BYTES);
    expect(decryptArgs()).toBe("classified");
  });

  it("invalidates the identity when native decrypt returns unparseable output", () => {
    const alice = identity(29);
    const bob = identity(30);
    const payload = alice.encryptText(CHAT_ID, "unparseable-decrypt", "Alice", "classified", [
      { username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() },
    ]);
    commit(alice, payload);
    const envelope = payload.envelopes[0];
    vi.spyOn(WasmE2eeSession.prototype, "decrypt").mockReturnValueOnce("{");

    expect(() => bob.decryptText(
      CHAT_ID,
      payload.messageId,
      "Alice",
      alice.publicKey(),
      payload,
      envelope.signature,
      envelope.wrappedKey,
      envelope.prekeyId,
      envelope.isPrekey,
      "Bob",
    )).toThrow(FatalCipherError);
    expect(() => bob.publicKey()).toThrow("Identity unavailable");
  });

  it("invalidates the identity when native decrypt returns malformed wrapper state", () => {
    const alice = identity(27);
    const bob = identity(28);
    const payload = alice.encryptText(CHAT_ID, "malformed-decrypt", "Alice", "classified", [
      { username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() },
    ]);
    commit(alice, payload);
    const envelope = payload.envelopes[0];
    const originalDecrypt = WasmE2eeSession.prototype.decrypt;
    vi.spyOn(WasmE2eeSession.prototype, "decrypt").mockImplementationOnce(function (
      this: WasmE2eeSession,
      ...args: Parameters<WasmE2eeSession["decrypt"]>
    ) {
      const result = JSON.parse(originalDecrypt.apply(this, args)) as { state_revision: number };
      result.state_revision = 0;
      return JSON.stringify(result);
    });

    expect(() => bob.decryptText(
      CHAT_ID,
      payload.messageId,
      "Alice",
      alice.publicKey(),
      payload,
      envelope.signature,
      envelope.wrappedKey,
      envelope.prekeyId,
      envelope.isPrekey,
      "Bob",
    )).toThrow(FatalCipherError);
    expect(() => bob.publicKey()).toThrow("Identity unavailable");
  });

  it("accepts an empty prekey id when a reply uses the established session", () => {
    const alice = identity(19);
    const bob = identity(20);
    const recipients = [{ username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() }];

    const first = alice.encryptText(CHAT_ID, "prekey-first", "Alice", "first", recipients);
    expect(first.envelopes[0].isPrekey).toBe(true);
    expect(first.envelopes[0].prekeyId).toMatch(/^[A-Za-z0-9_-]{1,32}$/u);
    commit(alice, first);
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
    )).toBe("first");

    const second = bob.encryptText(CHAT_ID, "prekey-established", "Bob", "second", [{
      username: "Alice",
      publicKey: alice.publicKey(),
      prekeyId: alice.prekeyId(),
    }]);
    expect(second.envelopes[0].isPrekey).toBe(false);
    expect(second.envelopes[0].prekeyId).toBe("");
    commit(bob, second);
    expect(alice.decryptText(
      CHAT_ID,
      second.messageId,
      "Bob",
      bob.publicKey(),
      second,
      second.envelopes[0].signature,
      second.envelopes[0].wrappedKey,
      second.envelopes[0].prekeyId,
      second.envelopes[0].isPrekey,
      "Alice",
    )).toBe("second");
  });

  it("requires an exact outbound commit or rollback before another ratchet operation", () => {
    const alice = identity(21);
    const bob = identity(22);
    const recipients = [{ username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() }];
    const first = alice.encryptText(CHAT_ID, "transaction-one", "Alice", "one", recipients);
    expect(alice.stateSnapshot()?.revision).toBe(first.stateRevision);
    expect(() => alice.encryptText(CHAT_ID, "transaction-two", "Alice", "two", recipients)).toThrow();
    expect(() => alice.commitOutbound(first.messageId, first.stateRevision + 1)).toThrow();
    alice.rollbackOutbound(first.messageId, first.stateRevision);
    expect(alice.stateSnapshot()).toBeNull();
    const retry = alice.encryptText(CHAT_ID, "transaction-two", "Alice", "two", recipients);
    alice.commitOutbound(retry.messageId, retry.stateRevision);
    expect(() => alice.rollbackOutbound(retry.messageId, retry.stateRevision)).toThrow();
  });

  it("uses canonical padded ciphertext buckets and rejects malformed wire payloads", () => {
    const alice = identity(23);
    const bob = identity(24);
    const payload = alice.encryptText(CHAT_ID, "padding-one", "Alice", "padded", [
      { username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() },
    ]);
    alice.commitOutbound(payload.messageId, payload.stateRevision);
    expect(payload.ciphertext.byteLength).toBeGreaterThanOrEqual(272);
    expect((payload.ciphertext.byteLength - 16) % 256).toBe(0);
    const malformed = { ...payload, ciphertext: new Uint8Array(17) };
    expect(() => payloadToFrame(malformed)).toThrow();
  });

  it("decrypts only for intended recipient and verifies sender signature", () => {
    const alice = identity(1);
    const bob = identity(2);
    const eve = identity(3);
    const payload = alice.encryptText(CHAT_ID, MESSAGE_ID, "Alice", "classified", [
      { username: "Bob", publicKey: bob.publicKey(), prekeyId: bob.prekeyId() },
    ]);
    commit(alice, payload);
    const envelope = payload.envelopes[0];

    expect(payload.version).toBe(9);
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
    commit(alice, first);
    const second = alice.encryptText(CHAT_ID, "message_late", "Alice", "late", recipients);
    commit(alice, second);

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
    commit(alice, third);
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
    commit(alice, payload);
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
    commit(alice, framePayload);
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
    expect(frame.version).toBe(9);
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
