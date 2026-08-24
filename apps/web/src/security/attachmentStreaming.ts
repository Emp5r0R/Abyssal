import {
  ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
  ATTACHMENT_CHUNK_RECORD_BYTES,
  ATTACHMENT_CIPHER_VERSION,
  wipeBytes,
} from "./crypto";

export interface AttachmentChunkCipher {
  generateAttachmentKey(): Uint8Array;
  attachmentEncryptedSize(mediaType: string, plaintextBytes: number): number;
  encryptAttachmentChunk(
    chatId: string,
    messageId: string,
    senderUsername: string,
    mediaType: string,
    key: Uint8Array,
    totalPlaintextBytes: number,
    chunkIndex: number,
    plaintext: Uint8Array,
  ): Uint8Array;
}

export interface EncryptedAttachmentUpload {
  version: number;
  key: Uint8Array;
  body: Blob;
}

export interface AttachmentEncryptionContext {
  chatId: string;
  messageId: string;
  senderUsername: string;
  mediaType: string;
}

export async function encryptAttachmentFile(
  file: File,
  context: AttachmentEncryptionContext,
  cipher: AttachmentChunkCipher,
  onProgress: (processedPlaintextBytes: number) => void,
  signal?: AbortSignal,
): Promise<EncryptedAttachmentUpload> {
  if (!Number.isSafeInteger(file.size) || file.size <= 0) {
    throw new Error("Payload unavailable");
  }
  signal?.throwIfAborted();
  const key = cipher.generateAttachmentKey();
  const encryptedSize = cipher.attachmentEncryptedSize(context.mediaType, file.size);
  const records: Blob[] = [];
  try {
    let chunkIndex = 0;
    for (let offset = 0; offset < file.size; offset += ATTACHMENT_CHUNK_PLAINTEXT_BYTES) {
      signal?.throwIfAborted();
      const end = Math.min(file.size, offset + ATTACHMENT_CHUNK_PLAINTEXT_BYTES);
      const plaintext = new Uint8Array(await file.slice(offset, end).arrayBuffer());
      let record: Uint8Array | undefined;
      try {
        signal?.throwIfAborted();
        record = cipher.encryptAttachmentChunk(
          context.chatId,
          context.messageId,
          context.senderUsername,
          context.mediaType,
          key,
          file.size,
          chunkIndex,
          plaintext,
        );
        if (record.byteLength !== ATTACHMENT_CHUNK_RECORD_BYTES) {
          throw new Error("Payload unavailable");
        }
        const blobBytes = new Uint8Array(record.byteLength);
        try {
          blobBytes.set(record);
          records.push(new Blob([blobBytes.buffer], { type: "application/octet-stream" }));
        } finally {
          wipeBytes(blobBytes);
        }
      } finally {
        wipeBytes(plaintext);
        if (record) wipeBytes(record);
      }
      chunkIndex += 1;
      onProgress(end);
    }
    signal?.throwIfAborted();
    const body = new Blob(records, { type: "application/octet-stream" });
    if (body.size !== encryptedSize) throw new Error("Payload unavailable");
    return { version: ATTACHMENT_CIPHER_VERSION, key, body };
  } catch (error) {
    wipeBytes(key);
    throw error;
  } finally {
    records.length = 0;
  }
}
