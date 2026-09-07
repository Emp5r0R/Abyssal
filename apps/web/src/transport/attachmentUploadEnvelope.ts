export const ATTACHMENT_UPLOAD_PREFIX_BYTES = 1024;
const MAGIC = new TextEncoder().encode("ABYUP001");

export interface AttachmentUploadMetadata {
  chat_id: string;
  message_id: string;
  media_type: string;
  one_time: boolean;
  delete_after_download: boolean;
  ttl_sec: number;
}

export function decodeAttachmentUploadResponse(value: unknown): string {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== 3) throw new Error("Upload rejected");
  const record = value as Record<string, unknown>;
  if (record.accepted !== true || record.storage !== "ram-only" ||
    typeof record.attachment_id !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(record.attachment_id)) {
    throw new Error("Upload rejected");
  }
  return record.attachment_id;
}

export function attachmentUploadEnvelope(metadata: AttachmentUploadMetadata, encrypted: Blob | Uint8Array): Blob {
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(metadata.chat_id) ||
    !/^[A-Za-z0-9_-]{1,128}$/u.test(metadata.message_id) ||
    !["IMAGE", "VIDEO", "FILE"].includes(metadata.media_type) ||
    typeof metadata.one_time !== "boolean" || typeof metadata.delete_after_download !== "boolean" ||
    !Number.isSafeInteger(metadata.ttl_sec) || metadata.ttl_sec < 0) throw new Error("Upload rejected");
  const json = new TextEncoder().encode(JSON.stringify(metadata));
  const prefix = new Uint8Array(ATTACHMENT_UPLOAD_PREFIX_BYTES);
  try {
    if (json.length === 0 || json.length > prefix.length - 10) throw new Error("Upload rejected");
    prefix.set(MAGIC);
    new DataView(prefix.buffer).setUint16(8, json.length, false);
    prefix.set(json, 10);
    return new Blob([prefix, encrypted as BlobPart], { type: "application/octet-stream" });
  } finally { json.fill(0); prefix.fill(0); }
}
