import { WasmAttachmentExchange } from "../generated/abyssal_core/abyssal_core";
import { postSealedRecord, type TransportKeys } from "./v11Account";

/**
 * Attachment transport v3. Every operation goes to one fixed URL as a sealed
 * action record, so the chat, message, attachment ID, sizes and options are
 * not visible outside the relay. The end-to-end encrypted attachment bytes
 * travel in fixed-size sealed frames, padded to a power-of-two bucket.
 */

export const ATTACHMENT_PATH = "/v3/attachment";
export const ATTACHMENT_ACTION_RECORD_BYTES = 4_170;
export const ATTACHMENT_STREAM_PAYLOAD_BYTES = 256 * 1024;
export const ATTACHMENT_STREAM_FRAME_BYTES = 262_184;

export const enum AttachmentResultKind {
  Failure = 0,
  Success = 1,
  UploadAccepted = 2,
  DownloadAccepted = 3,
}

export const enum AttachmentFrameKind {
  Data = 1,
  Padding = 2,
  End = 3,
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

/** The attachment ID used in message metadata (a UUID string) as the 16 bytes the relay uses. */
export function attachmentIdBytes(id: string): Uint8Array {
  if (!UUID.test(id)) throw new Error("Attachment unavailable");
  const hex = id.replaceAll("-", "");
  return Uint8Array.from({ length: 16 }, (_, index) => Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16));
}

export function attachmentIdString(bytes: Uint8Array): string {
  if (bytes.byteLength !== 16) throw new Error("Attachment unavailable");
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function free(exchange: WasmAttachmentExchange): void {
  exchange.destroy();
  exchange.free();
}

/** Runs an action-only exchange (complete, release, delete) and reports whether it succeeded. */
async function runActionOnly(
  apiBaseUrl: string,
  exchange: WasmAttachmentExchange,
  signal?: AbortSignal,
  fetcher: typeof fetch = fetch,
): Promise<boolean> {
  let request: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let sealed: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  try {
    request = exchange.requestBytes();
    sealed = await postSealedRecord(`${apiBaseUrl}${ATTACHMENT_PATH}`, request, signal, fetcher);
    const result = exchange.openResponse(sealed);
    try {
      return result.kind === AttachmentResultKind.Success;
    } finally {
      result.free();
    }
  } finally {
    request.fill(0);
    sealed.fill(0);
    free(exchange);
  }
}

export interface UploadInput {
  chatId: string;
  messageId: string;
  mediaType: string;
  cipherVersion: number;
  ciphertext: Blob;
  oneTime: boolean;
  deleteAfterDownload: boolean;
  ttlSec: number;
}

/**
 * Seals the request body: the action record, the ciphertext in data frames,
 * padding frames up to the bucket, and the end frame. Kept in a Blob so the
 * browser can page it; the plaintext was already encrypted end to end.
 */
export async function sealUploadBody(exchange: WasmAttachmentExchange, ciphertext: Blob): Promise<Blob> {
  const parts: BlobPart[] = [exchange.requestBytes() as BlobPart];
  let dataFrames = 0;
  for (let offset = 0; offset < ciphertext.size; offset += ATTACHMENT_STREAM_PAYLOAD_BYTES) {
    const slice = new Uint8Array(await ciphertext.slice(offset, offset + ATTACHMENT_STREAM_PAYLOAD_BYTES).arrayBuffer());
    try {
      parts.push(exchange.sealDataFrame(slice) as BlobPart);
      dataFrames += 1;
    } finally {
      slice.fill(0);
    }
  }
  if (dataFrames !== exchange.uploadDataFrameCount()) throw new Error("Upload rejected");
  for (let frame = dataFrames; frame < exchange.uploadBucketFrameCount(); frame += 1) {
    parts.push(exchange.sealPaddingFrame() as BlobPart);
  }
  parts.push(exchange.sealEndFrame() as BlobPart);
  return new Blob(parts, { type: "application/octet-stream" });
}

/** Uploads one encrypted attachment and returns its relay attachment ID. */
export async function uploadAttachmentV11(
  apiBaseUrl: string,
  keys: TransportKeys,
  input: UploadInput,
  onProgress: (loaded: number, total: number) => void,
  signal?: AbortSignal,
): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", await input.ciphertext.arrayBuffer()));
  let exchange: WasmAttachmentExchange;
  try {
    exchange = WasmAttachmentExchange.beginUpload(
      keys.nodePublicKey,
      keys.sessionId,
      keys.transportRoot,
      input.chatId,
      input.messageId,
      input.mediaType,
      input.cipherVersion,
      BigInt(input.ciphertext.size),
      digest,
      input.oneTime,
      input.deleteAfterDownload || input.oneTime,
      Math.max(0, Math.floor(input.ttlSec)),
    );
  } finally {
    digest.fill(0);
  }
  try {
    const body = await sealUploadBody(exchange, input.ciphertext);
    const sealed = await postWithProgress(`${apiBaseUrl}${ATTACHMENT_PATH}`, body, onProgress, signal);
    try {
      const result = exchange.openResponse(sealed);
      try {
        if (result.kind !== AttachmentResultKind.UploadAccepted) throw new Error("Upload rejected");
        return attachmentIdString(result.attachmentId);
      } finally {
        result.free();
      }
    } finally {
      sealed.fill(0);
    }
  } finally {
    free(exchange);
  }
}

function postWithProgress(
  url: string,
  body: Blob,
  onProgress: (loaded: number, total: number) => void,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error("Upload aborted"));
      return;
    }
    const request = new XMLHttpRequest();
    let settled = false;
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", abort);
      callback();
    };
    const abort = () => request.abort();
    request.open("POST", url);
    request.responseType = "arraybuffer";
    request.setRequestHeader("Content-Type", "application/octet-stream");
    request.upload.onprogress = (event) => onProgress(Math.min(event.loaded, body.size), body.size);
    request.onerror = () => finish(() => reject(new Error("Upload failed")));
    request.onabort = () => finish(() => reject(new Error("Upload aborted")));
    request.onload = () => finish(() => {
      const response = request.response as ArrayBuffer | null;
      if (request.status < 200 || request.status >= 300 || !response ||
        response.byteLength !== ATTACHMENT_ACTION_RECORD_BYTES) {
        reject(new Error("Upload rejected"));
        return;
      }
      resolve(new Uint8Array(response));
    });
    signal?.addEventListener("abort", abort, { once: true });
    request.send(body);
  });
}

export interface DownloadResult {
  /** Total ciphertext bytes delivered. */
  total: number;
  /** Present for one-time and delete-after-download attachments; complete or release it. */
  claimId: Uint8Array | null;
}

/**
 * Downloads one attachment's ciphertext through sealed frames, handing each
 * opened payload to [onData] in order (the payload buffer is wiped after the
 * callback returns), so the whole ciphertext is never held at once.
 */
export async function downloadAttachmentV11(
  apiBaseUrl: string,
  keys: TransportKeys,
  attachmentId: string,
  maxCiphertextBytes: number,
  onData: (payload: Uint8Array) => void | Promise<void>,
  signal?: AbortSignal,
  fetcher: typeof fetch = fetch,
): Promise<DownloadResult> {
  const id = attachmentIdBytes(attachmentId);
  const exchange = WasmAttachmentExchange.beginDownload(keys.nodePublicKey, keys.sessionId, keys.transportRoot, id);
  id.fill(0);
  let request: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let claim: Uint8Array | null = null;
  try {
    request = exchange.requestBytes();
    const response = await fetcher(`${apiBaseUrl}${ATTACHMENT_PATH}`, {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      headers: { "Content-Type": "application/octet-stream", Accept: "application/octet-stream" },
      body: request as BodyInit,
      signal,
    });
    if (!response.ok || !response.body) {
      await response.body?.cancel().catch(() => undefined);
      throw new Error("Attachment unavailable");
    }
    const reader = new FixedRecordReader(response.body.getReader());
    try {
      const head = await reader.read(ATTACHMENT_ACTION_RECORD_BYTES);
      const result = exchange.openResponse(head);
      head.fill(0);
      let total = 0;
      try {
        if (result.kind !== AttachmentResultKind.DownloadAccepted) throw new Error("Attachment unavailable");
        total = Number(result.ciphertextLen);
        if (!Number.isSafeInteger(total) || total <= 0 || total > maxCiphertextBytes) throw new Error("Attachment unavailable");
        const claimId = result.claimId;
        claim = claimId.byteLength > 0 ? claimId : null;
      } finally {
        result.free();
      }
      let loaded = 0;
      for (;;) {
        signal?.throwIfAborted();
        const frame = await reader.read(ATTACHMENT_STREAM_FRAME_BYTES);
        const opened = exchange.openStreamFrame(frame);
        frame.fill(0);
        try {
          if (opened.kind === AttachmentFrameKind.End) break;
          if (opened.kind !== AttachmentFrameKind.Data) continue;
          const payload = opened.payload;
          try {
            if (loaded + payload.byteLength > total) throw new Error("Attachment unavailable");
            loaded += payload.byteLength;
            await onData(payload);
          } finally {
            payload.fill(0);
          }
        } finally {
          opened.free();
        }
      }
      if (loaded !== total || !exchange.streamComplete()) throw new Error("Attachment unavailable");
      return { total, claimId: claim };
    } finally {
      await reader.cancel();
    }
  } catch (error) {
    claim?.fill(0);
    throw error;
  } finally {
    request.fill(0);
    free(exchange);
  }
}

/** Confirms a claimed download, which lets the relay delete a one-time or delete-after-download attachment. */
export function completeDownloadV11(apiBaseUrl: string, keys: TransportKeys, attachmentId: string, claimId: Uint8Array, signal?: AbortSignal) {
  const id = attachmentIdBytes(attachmentId);
  try {
    return runActionOnly(apiBaseUrl, WasmAttachmentExchange.completeDownload(keys.nodePublicKey, keys.sessionId, keys.transportRoot, id, claimId), signal);
  } finally {
    id.fill(0);
  }
}

/** Gives back a claim after a failed download so it can be retried once. */
export function releaseDownloadV11(apiBaseUrl: string, keys: TransportKeys, attachmentId: string, claimId: Uint8Array, signal?: AbortSignal) {
  const id = attachmentIdBytes(attachmentId);
  try {
    return runActionOnly(apiBaseUrl, WasmAttachmentExchange.releaseDownload(keys.nodePublicKey, keys.sessionId, keys.transportRoot, id, claimId), signal);
  } finally {
    id.fill(0);
  }
}

/** Deletes an attachment this account uploaded. */
export function deleteAttachmentV11(apiBaseUrl: string, keys: TransportKeys, attachmentId: string, signal?: AbortSignal) {
  const id = attachmentIdBytes(attachmentId);
  try {
    return runActionOnly(apiBaseUrl, WasmAttachmentExchange.deleteAttachment(keys.nodePublicKey, keys.sessionId, keys.transportRoot, id), signal);
  } finally {
    id.fill(0);
  }
}

/** Reads exact-size records from a byte stream. */
export class FixedRecordReader {
  #reader: ReadableStreamDefaultReader<Uint8Array>;
  #buffer = new Uint8Array(0);

  constructor(reader: ReadableStreamDefaultReader<Uint8Array>) {
    this.#reader = reader;
  }

  async read(size: number): Promise<Uint8Array> {
    while (this.#buffer.byteLength < size) {
      const { done, value } = await this.#reader.read();
      if (done) throw new Error("Attachment unavailable");
      const next = new Uint8Array(this.#buffer.byteLength + value.byteLength);
      next.set(this.#buffer);
      next.set(value, this.#buffer.byteLength);
      this.#buffer.fill(0);
      value.fill(0);
      this.#buffer = next;
    }
    const record = this.#buffer.slice(0, size);
    const rest = this.#buffer.slice(size);
    this.#buffer.fill(0);
    this.#buffer = rest;
    return record;
  }

  async cancel(): Promise<void> {
    this.#buffer.fill(0);
    this.#buffer = new Uint8Array(0);
    await this.#reader.cancel().catch(() => undefined);
  }
}
