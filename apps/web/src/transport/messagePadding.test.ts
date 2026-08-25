import { describe, expect, it } from "vitest";
import {
  CONTROL_TRANSPORT_MAX_BYTES,
  LEGACY_RELAY_DOMAIN_MAX_BYTES,
  MLS_RELAY_DOMAIN_MAX_BYTES,
  MESSAGE_TRANSPORT_BUCKETS,
  padOutgoingControlFrame,
  padOutgoingMessageFrame,
  validateAndStripIncomingControlPadding,
  validateAndStripIncomingMessagePadding,
} from "./messagePadding";

function outgoingFrame(ciphertext = "ciphertext", chatId = "dm_Alice_Bob"): Record<string, unknown> {
  return {
    type: "message",
    chat_id: chatId,
    version: 9,
    message_id: "message-1",
    nonce_b64: "nonce",
    ciphertext_b64: ciphertext,
    state_revision: 1,
    identity_envelope_b64: "identity-envelope",
    identity_public_b64: "identity-public",
    prekey_id: "prekey",
    state_signature_b64: "state-signature",
    envelopes: [{
      recipient_username: "Bob",
      wrapped_key_b64: "wrapped",
      prekey_id: "",
      is_prekey: false,
      signature_b64: "signature",
    }],
    directory_node_id: "node-1",
    directory_revision: 1,
    directory_digest: "directory-digest",
  };
}

function incomingFrame(ciphertext = "ciphertext", chatId = "dm_Alice_Bob"): Record<string, unknown> {
  return {
    type: "message",
    chat_id: chatId,
    version: 9,
    message_id: "message-1",
    nonce_b64: "nonce",
    ciphertext_b64: ciphertext,
    signature_b64: "signature",
    wrapped_key_b64: "wrapped",
    prekey_id: "",
    is_prekey: false,
    sender_username: "Alice",
    sender_public_key_b64: "sender-public",
    identity_public_b64: "sender-public",
    directory_node_id: "node-1",
    directory_revision: 1,
    directory_digest: "directory-digest",
  };
}

function paddedIncoming(
  base: Record<string, unknown>,
): { text: string; frame: Record<string, unknown> } | null {
  for (const bucket of MESSAGE_TRANSPORT_BUCKETS) {
    const empty = JSON.stringify({ ...base, padding_bucket: bucket, padding: "" });
    const emptyBytes = new TextEncoder().encode(empty).byteLength;
    if (emptyBytes > bucket) continue;
    const text = JSON.stringify({
      ...base,
      padding_bucket: bucket,
      padding: "A".repeat(bucket - emptyBytes),
    });
    if (new TextEncoder().encode(text).byteLength !== bucket) throw new Error("bad test fixture");
    return { text, frame: JSON.parse(text) as Record<string, unknown> };
  }
  return null;
}

describe("message transport padding", () => {
  it("uses exact smallest buckets and random filler", () => {
    const first = padOutgoingMessageFrame(outgoingFrame());
    const second = padOutgoingMessageFrame(outgoingFrame());
    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    expect(new TextEncoder().encode(first!).byteLength).toBe(4096);
    expect(new TextEncoder().encode(second!).byteLength).toBe(4096);
    expect((JSON.parse(first!).padding as string)).not.toBe(JSON.parse(second!).padding);

    const cases = [
      ["x".repeat(5_000), 16_384],
      ["x".repeat(20_000), 65_536],
      ["x".repeat(70_000), 262_144],
      ["x".repeat(300_000), 1_048_576],
    ] as const;
    for (const [ciphertext, bucket] of cases) {
      const serialized = padOutgoingMessageFrame(outgoingFrame(ciphertext));
      expect(serialized).not.toBeNull();
      expect(new TextEncoder().encode(serialized!).byteLength).toBe(bucket);
      expect(JSON.parse(serialized!).padding_bucket).toBe(bucket);
    }
  });

  it("uses UTF-8 byte length and leaves caller input unchanged", () => {
    const frame = outgoingFrame("ciphertext", "dm_é_測試");
    const before = JSON.stringify(frame);
    const serialized = padOutgoingMessageFrame(frame);
    expect(serialized).not.toBeNull();
    expect(new TextEncoder().encode(serialized!).byteLength).toBe(4096);
    expect(JSON.stringify(frame)).toBe(before);
    expect(frame).not.toHaveProperty("padding");
  });

  it("rejects invalid, extra, cyclic, and impossible outgoing shapes", () => {
    const missing = outgoingFrame();
    delete missing.envelopes;
    expect(padOutgoingMessageFrame(missing)).toBeNull();
    expect(padOutgoingMessageFrame({ ...outgoingFrame(), unexpected: true })).toBeNull();
    expect(padOutgoingMessageFrame(outgoingFrame("x".repeat(1_048_576)))).toBeNull();
    const cyclic = outgoingFrame();
    cyclic.envelopes = [cyclic];
    expect(padOutgoingMessageFrame(cyclic)).toBeNull();
  });

  it("validates and strips canonical incoming transport fields", () => {
    const padded = paddedIncoming(incomingFrame());
    expect(padded).not.toBeNull();
    const expected = { ...padded!.frame };
    delete expected.padding_bucket;
    delete expected.padding;
    expect(validateAndStripIncomingMessagePadding(padded!.text, padded!.frame)).toBe(true);
    expect(padded!.frame).not.toHaveProperty("padding_bucket");
    expect(padded!.frame).not.toHaveProperty("padding");
    expect(padded!.frame.ciphertext_b64).toBe("ciphertext");
    expect(padded!.frame).toEqual(expected);
  });

  it("validates incoming Unicode by UTF-8 bytes", () => {
    const padded = paddedIncoming(incomingFrame("ciphertext", "dm_é_測試"));
    expect(padded).not.toBeNull();
    expect(padded!.text.length).toBeLessThan(4096);
    expect(new TextEncoder().encode(padded!.text).byteLength).toBe(4096);
    expect(validateAndStripIncomingMessagePadding(padded!.text, padded!.frame)).toBe(true);
  });

  it("rejects missing, extra, wrong-bucket, shortened, and invalid filler without stripping", () => {
    const canonical = paddedIncoming(incomingFrame())!;
    const cases: Record<string, unknown>[] = [];

    const missing = { ...canonical.frame };
    delete missing.padding;
    cases.push(missing);
    cases.push({ ...canonical.frame, unexpected: true });
    cases.push({ ...canonical.frame, padding_bucket: 16_384 });
    cases.push({ ...canonical.frame, padding: (canonical.frame.padding as string).slice(1) });
    cases.push({ ...canonical.frame, padding: `!${(canonical.frame.padding as string).slice(1)}` });

    for (const frame of cases) {
      expect(validateAndStripIncomingMessagePadding(canonical.text, frame)).toBe(false);
      if (Object.hasOwn(frame, "padding")) expect(frame).toHaveProperty("padding");
      if (Object.hasOwn(frame, "padding_bucket")) expect(frame).toHaveProperty("padding_bucket");
    }
  });

  it("rejects noncanonical raw length and an incoming frame beyond the maximum bucket", () => {
    const canonical = paddedIncoming(incomingFrame())!;
    expect(validateAndStripIncomingMessagePadding(`${canonical.text} `, canonical.frame)).toBe(false);
    expect(canonical.frame).toHaveProperty("padding");

    const oversized = incomingFrame("x".repeat(1_048_576));
    expect(paddedIncoming(oversized)).toBeNull();
  });
});

describe("control transport padding", () => {
  it("pads every small control into the same exact minimum bucket", () => {
    const first = padOutgoingControlFrame(
      { type: "activity" },
      LEGACY_RELAY_DOMAIN_MAX_BYTES,
    );
    const second = padOutgoingControlFrame(
      { type: "message_ack", message_id: "message-1", accepted: true },
      LEGACY_RELAY_DOMAIN_MAX_BYTES,
    );
    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    expect(new TextEncoder().encode(first!).byteLength).toBe(4096);
    expect(new TextEncoder().encode(second!).byteLength).toBe(4096);

    const frame = JSON.parse(first!) as Record<string, unknown>;
    expect(validateAndStripIncomingControlPadding(
      first!,
      frame,
      LEGACY_RELAY_DOMAIN_MAX_BYTES,
    )).toBe(true);
    expect(frame).toEqual({ type: "activity" });
  });

  it("uses bounded large buckets only for MLS-domain frames", () => {
    const frame = { type: "mls_application", ciphertext_b64: "A".repeat(1_100_000) };
    expect(padOutgoingControlFrame(frame, LEGACY_RELAY_DOMAIN_MAX_BYTES)).toBeNull();
    const padded = padOutgoingControlFrame(frame, MLS_RELAY_DOMAIN_MAX_BYTES);
    expect(padded).not.toBeNull();
    expect(new TextEncoder().encode(padded!).byteLength).toBe(4_194_304);
    expect(new TextEncoder().encode(padded!).byteLength).toBeLessThanOrEqual(
      CONTROL_TRANSPORT_MAX_BYTES,
    );
  });

  it("rejects changed suffixes, wrong buckets, and embedded transport fields", () => {
    const padded = padOutgoingControlFrame(
      { type: "activity" },
      LEGACY_RELAY_DOMAIN_MAX_BYTES,
    )!;
    const changedBucket = padded.replace(
      "\"padding_bucket\":4096",
      "\"padding_bucket\":16384",
    );
    expect(validateAndStripIncomingControlPadding(
      changedBucket,
      JSON.parse(changedBucket) as Record<string, unknown>,
      LEGACY_RELAY_DOMAIN_MAX_BYTES,
    )).toBe(false);
    expect(validateAndStripIncomingControlPadding(
      `${padded} `,
      JSON.parse(padded) as Record<string, unknown>,
      LEGACY_RELAY_DOMAIN_MAX_BYTES,
    )).toBe(false);
    expect(padOutgoingControlFrame(
      { type: "activity", padding: "hidden" },
      LEGACY_RELAY_DOMAIN_MAX_BYTES,
    )).toBeNull();
    expect(padOutgoingControlFrame(
      { type: "message" },
      LEGACY_RELAY_DOMAIN_MAX_BYTES,
    )).toBeNull();
  });
});
