import { describe, expect, it } from "vitest";
import {
  ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
  ATTACHMENT_CHUNK_RECORD_BYTES,
} from "./crypto";
import {
  encryptAttachmentFile,
  type AttachmentChunkCipher,
} from "./attachmentStreaming";

class RecordingCipher implements AttachmentChunkCipher {
  readonly key = new Uint8Array(32).fill(7);
  readonly plaintextViews: Uint8Array[] = [];
  readonly indexes: number[] = [];
  failAtIndex: number | undefined;

  generateAttachmentKey(): Uint8Array {
    return this.key;
  }

  attachmentEncryptedSize(_mediaType: string, plaintextBytes: number): number {
    return Math.ceil(plaintextBytes / ATTACHMENT_CHUNK_PLAINTEXT_BYTES) *
      ATTACHMENT_CHUNK_RECORD_BYTES;
  }

  encryptAttachmentChunk(
    _chatId: string,
    _messageId: string,
    _senderUsername: string,
    _mediaType: string,
    _key: Uint8Array,
    _totalPlaintextBytes: number,
    chunkIndex: number,
    plaintext: Uint8Array,
  ): Uint8Array {
    this.plaintextViews.push(plaintext);
    this.indexes.push(chunkIndex);
    if (chunkIndex === this.failAtIndex) throw new Error("test failure");
    return new Uint8Array(ATTACHMENT_CHUNK_RECORD_BYTES).fill(chunkIndex + 1);
  }
}

const context = {
  chatId: "dm_alice_bob",
  messageId: "attachment-1",
  senderUsername: "Alice",
  mediaType: "FILE",
};

describe("attachment streaming encryption", () => {
  it("encrypts fixed records in order and wipes each plaintext view", async () => {
    const cipher = new RecordingCipher();
    const source = new Uint8Array(ATTACHMENT_CHUNK_PLAINTEXT_BYTES + 3).fill(0x5a);
    const progress: number[] = [];
    const file = new File([source], "payload.bin", { type: "application/octet-stream" });

    const encrypted = await encryptAttachmentFile(file, context, cipher, (value) => progress.push(value));

    expect(cipher.indexes).toEqual([0, 1]);
    expect(progress).toEqual([ATTACHMENT_CHUNK_PLAINTEXT_BYTES, source.byteLength]);
    expect(encrypted.body.size).toBe(2 * ATTACHMENT_CHUNK_RECORD_BYTES);
    expect(encrypted.key).toBe(cipher.key);
    for (const plaintext of cipher.plaintextViews) {
      expect(plaintext.every((value) => value === 0)).toBe(true);
    }
  });

  it("wipes the attachment key and plaintext when a later chunk fails", async () => {
    const cipher = new RecordingCipher();
    cipher.failAtIndex = 1;
    const file = new File([
      new Uint8Array(ATTACHMENT_CHUNK_PLAINTEXT_BYTES + 1).fill(0x33),
    ], "payload.bin");

    await expect(encryptAttachmentFile(file, context, cipher, () => undefined))
      .rejects.toThrow("test failure");

    expect(cipher.key.every((value) => value === 0)).toBe(true);
    for (const plaintext of cipher.plaintextViews) {
      expect(plaintext.every((value) => value === 0)).toBe(true);
    }
  });

  it("rejects an already-aborted operation before allocating a key", async () => {
    const cipher = new RecordingCipher();
    const controller = new AbortController();
    controller.abort();

    await expect(encryptAttachmentFile(
      new File([new Uint8Array([1])], "payload.bin"),
      context,
      cipher,
      () => undefined,
      controller.signal,
    )).rejects.toMatchObject({ name: "AbortError" });
    expect(cipher.key[0]).toBe(7);
    expect(cipher.plaintextViews).toHaveLength(0);
  });
});
