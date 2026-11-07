import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The fake exchange stands in for the WASM record layer. A fake stream frame
 * is [kind, u32 payload length, payload..., zero fill] at the real frame size,
 * so the reader's exact-size framing is exercised end to end.
 */
const wasm = vi.hoisted(() => {
  const FRAME = 262_184;
  const ACTION = 4_170;
  class FakeResult {
    freed = false;
    constructor(
      readonly kind: number,
      readonly attachmentId: Uint8Array = new Uint8Array(0),
      readonly ciphertextLen = 0n,
      readonly claimId: Uint8Array = new Uint8Array(0),
    ) {}
    free(): void {
      this.freed = true;
    }
  }
  class FakeFrame {
    freed = false;
    constructor(readonly kind: number, readonly payload: Uint8Array) {}
    free(): void {
      this.freed = true;
    }
  }
  class FakeExchange {
    static all: FakeExchange[] = [];
    static beginUploadArgs: unknown[] = [];
    static result: FakeResult = new FakeResult(0);
    static dataFrameCount: number | null = null;
    static bucketFrames = 1;
    readonly request = new Uint8Array(ACTION).fill(0xa0);
    sealedData: number[] = [];
    destroyed = false;
    freed = false;
    endSeen = false;
    openedPayloads: Uint8Array[] = [];
    constructor(readonly kind: string, readonly args: unknown[] = []) {
      FakeExchange.all.push(this);
    }
    requestBytes(): Uint8Array {
      return this.request;
    }
    openResponse(sealed: Uint8Array): FakeResult {
      if (sealed.byteLength !== ACTION) throw new Error("bad record size");
      return FakeExchange.result;
    }
    sealDataFrame(payload: Uint8Array): Uint8Array {
      this.sealedData.push(payload.byteLength);
      return Uint8Array.of(0xd0, payload[0] ?? 0);
    }
    sealPaddingFrame(): Uint8Array {
      return Uint8Array.of(0xd1);
    }
    sealEndFrame(): Uint8Array {
      return Uint8Array.of(0xd2);
    }
    uploadDataFrameCount(): number {
      return FakeExchange.dataFrameCount ?? this.sealedData.length;
    }
    uploadBucketFrameCount(): number {
      return FakeExchange.bucketFrames;
    }
    openStreamFrame(frame: Uint8Array): FakeFrame {
      if (frame.byteLength !== FRAME) throw new Error("bad frame size");
      const length = new DataView(frame.buffer, frame.byteOffset).getUint32(1);
      const payload = frame.slice(5, 5 + length);
      if (frame[0] === 3) this.endSeen = true;
      if (frame[0] === 1) this.openedPayloads.push(payload);
      return new FakeFrame(frame[0]!, payload);
    }
    streamComplete(): boolean {
      return this.endSeen;
    }
    destroy(): void {
      this.destroyed = true;
    }
    free(): void {
      this.freed = true;
    }
    static beginUpload(...args: unknown[]): FakeExchange {
      FakeExchange.beginUploadArgs = args;
      return new FakeExchange("upload", args);
    }
    static beginDownload(...args: unknown[]): FakeExchange {
      return new FakeExchange("download", args);
    }
    static completeDownload(...args: unknown[]): FakeExchange {
      return new FakeExchange("complete", args);
    }
    static releaseDownload(...args: unknown[]): FakeExchange {
      return new FakeExchange("release", args);
    }
    static deleteAttachment(...args: unknown[]): FakeExchange {
      return new FakeExchange("delete", args);
    }
  }
  return { FakeExchange, FakeResult, FRAME, ACTION };
});

vi.mock("../generated/abyssal_core/abyssal_core", () => ({ WasmAttachmentExchange: wasm.FakeExchange }));

import {
  ATTACHMENT_ACTION_RECORD_BYTES,
  ATTACHMENT_PATH,
  ATTACHMENT_STREAM_FRAME_BYTES,
  ATTACHMENT_STREAM_PAYLOAD_BYTES,
  attachmentIdBytes,
  attachmentIdString,
  completeDownloadV11,
  deleteAttachmentV11,
  downloadAttachmentV11,
  releaseDownloadV11,
  sealUploadBody,
  uploadAttachmentV11,
} from "./v11Attachment";
import type { WasmAttachmentExchange } from "../generated/abyssal_core/abyssal_core";

const ID = "123e4567-e89b-42d3-a456-426614174000";
const keys = {
  nodePublicKey: new Uint8Array(32).fill(1),
  sessionId: new Uint8Array(32).fill(2),
  transportRoot: new Uint8Array(32).fill(3),
};

function frame(kind: number, payload = new Uint8Array(0)): Uint8Array {
  const bytes = new Uint8Array(wasm.FRAME);
  bytes[0] = kind;
  new DataView(bytes.buffer).setUint32(1, payload.byteLength);
  bytes.set(payload, 5);
  return bytes;
}

/** Joins records and replays them in awkward chunk sizes that straddle record boundaries. */
function streamedResponse(records: Uint8Array[], chunkBytes = 100_003): Response {
  const joined = new Uint8Array(records.reduce((sum, record) => sum + record.byteLength, 0));
  let offset = 0;
  for (const record of records) {
    joined.set(record, offset);
    offset += record.byteLength;
  }
  let position = 0;
  return new Response(new ReadableStream<Uint8Array>({
    pull(controller) {
      if (position >= joined.byteLength) {
        controller.close();
        return;
      }
      controller.enqueue(joined.slice(position, position + chunkBytes));
      position += chunkBytes;
    },
  }), { status: 200 });
}

const head = () => new Uint8Array(wasm.ACTION).fill(0x0f);

beforeEach(() => {
  wasm.FakeExchange.all = [];
  wasm.FakeExchange.result = new wasm.FakeResult(0);
  wasm.FakeExchange.dataFrameCount = null;
  wasm.FakeExchange.bucketFrames = 1;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("attachment transport v3 framing", () => {
  it("converts message-metadata UUIDs to the relay's 16-byte IDs and back", () => {
    const bytes = attachmentIdBytes(ID);
    expect(bytes).toHaveLength(16);
    expect(bytes[0]).toBe(0x12);
    expect(attachmentIdString(bytes)).toBe(ID);
    expect(() => attachmentIdBytes(ID.toUpperCase())).toThrow("Attachment unavailable");
    expect(() => attachmentIdBytes("../../etc/passwd")).toThrow("Attachment unavailable");
    expect(() => attachmentIdString(new Uint8Array(15))).toThrow("Attachment unavailable");
  });

  it("seals data frames, pads to the bucket and ends the upload body", async () => {
    wasm.FakeExchange.bucketFrames = 4;
    const exchange = new wasm.FakeExchange("upload");
    const ciphertext = new Blob([new Uint8Array(ATTACHMENT_STREAM_PAYLOAD_BYTES * 2 + 10).fill(6)]);

    const body = new Uint8Array(await (await sealUploadBody(exchange as unknown as WasmAttachmentExchange, ciphertext)).arrayBuffer());

    expect(exchange.sealedData).toEqual([ATTACHMENT_STREAM_PAYLOAD_BYTES, ATTACHMENT_STREAM_PAYLOAD_BYTES, 10]);
    expect(Array.from(body.slice(ATTACHMENT_ACTION_RECORD_BYTES))).toEqual([0xd0, 6, 0xd0, 6, 0xd0, 6, 0xd1, 0xd2]);
    expect(body.slice(0, ATTACHMENT_ACTION_RECORD_BYTES).every((byte) => byte === 0xa0)).toBe(true);

    wasm.FakeExchange.dataFrameCount = 2;
    await expect(sealUploadBody(new wasm.FakeExchange("upload") as unknown as WasmAttachmentExchange, ciphertext))
      .rejects.toThrow("Upload rejected");
  });

  it("uploads with progress capped at the body size and returns the relay's attachment ID", async () => {
    const sent: { url: string; body: Blob | null; headers: Record<string, string> } = { url: "", body: null, headers: {} };
    class FakeXhr {
      upload: { onprogress: ((event: { loaded: number }) => void) | null } = { onprogress: null };
      status = 0;
      response: ArrayBuffer | null = null;
      responseType = "";
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      onabort: (() => void) | null = null;
      open(_method: string, url: string) {
        sent.url = url;
      }
      setRequestHeader(name: string, value: string) {
        sent.headers[name] = value;
      }
      send(body: Blob) {
        sent.body = body;
        queueMicrotask(() => {
          this.upload.onprogress?.({ loaded: body.size * 2 });
          this.status = 200;
          this.response = new ArrayBuffer(wasm.ACTION);
          this.onload?.();
        });
      }
      abort() {
        this.onabort?.();
      }
    }
    vi.stubGlobal("XMLHttpRequest", FakeXhr);
    wasm.FakeExchange.result = new wasm.FakeResult(2, attachmentIdBytes(ID));
    const progress: Array<[number, number]> = [];

    const id = await uploadAttachmentV11("https://relay.test", keys, {
      chatId: "dm_1",
      messageId: "message_1",
      mediaType: "IMAGE",
      cipherVersion: 2,
      ciphertext: new Blob([new Uint8Array(20)]),
      oneTime: true,
      deleteAfterDownload: false,
      ttlSec: 59.9,
    }, (loaded, total) => progress.push([loaded, total]));

    expect(id).toBe(ID);
    expect(sent.url).toBe(`https://relay.test${ATTACHMENT_PATH}`);
    expect(sent.headers).toEqual({ "Content-Type": "application/octet-stream" });
    const args = wasm.FakeExchange.beginUploadArgs;
    expect(args.slice(3, 8)).toEqual(["dm_1", "message_1", "IMAGE", 2, 20n]);
    expect((args[8] as Uint8Array).every((byte) => byte === 0)).toBe(true);
    // A one-time attachment is always deleted after its download.
    expect(args.slice(9)).toEqual([true, true, 59]);
    expect(progress).toEqual([[sent.body!.size, sent.body!.size]]);
    expect(wasm.FakeExchange.all[0]!.freed).toBe(true);
    expect(wasm.FakeExchange.result.freed).toBe(true);
  });

  it("streams a claimed download frame by frame, skipping padding and wiping each payload", async () => {
    const first = new Uint8Array(ATTACHMENT_STREAM_PAYLOAD_BYTES).fill(1);
    const second = new Uint8Array(100).fill(2);
    const claim = new Uint8Array(16).fill(9);
    wasm.FakeExchange.result = new wasm.FakeResult(3, new Uint8Array(0), BigInt(first.byteLength + second.byteLength), claim);
    const fetcher = vi.fn<typeof fetch>(async () => streamedResponse([head(), frame(1, first), frame(2), frame(1, second), frame(3)]));
    const received: number[][] = [];

    const result = await downloadAttachmentV11("https://relay.test", keys, ID, 1_000_000, (payload) => {
      received.push([payload.byteLength, payload[0]!]);
    }, undefined, fetcher);

    expect(result).toEqual({ total: first.byteLength + second.byteLength, claimId: claim });
    expect(received).toEqual([[first.byteLength, 1], [100, 2]]);
    const exchange = wasm.FakeExchange.all[0]!;
    expect(exchange.args[3]).toEqual(new Uint8Array(16));
    expect(exchange.openedPayloads.every((payload) => payload.every((byte) => byte === 0))).toBe(true);
    expect(exchange.request.every((byte) => byte === 0)).toBe(true);
    expect(exchange.destroyed && exchange.freed).toBe(true);
    expect(fetcher.mock.calls[0]?.[1]).toMatchObject({ method: "POST", credentials: "omit", redirect: "error" });
    expect(ATTACHMENT_STREAM_FRAME_BYTES).toBe(wasm.FRAME);
  });

  it.each([
    ["a refused download", () => new wasm.FakeResult(0), [frame(3)]],
    ["a length over the caller's limit", () => new wasm.FakeResult(3, new Uint8Array(0), 2_000_001n), [frame(3)]],
    ["a stream longer than announced", () => new wasm.FakeResult(3, new Uint8Array(0), 10n), [frame(1, new Uint8Array(11)), frame(3)]],
    ["a stream shorter than announced", () => new wasm.FakeResult(3, new Uint8Array(0), 10n), [frame(1, new Uint8Array(9)), frame(3)]],
    ["a stream cut before its end frame", () => new wasm.FakeResult(3, new Uint8Array(0), 10n), [frame(1, new Uint8Array(10))]],
  ])("fails closed for %s and wipes the claim", async (_label, result, frames) => {
    const claim = new Uint8Array(16).fill(4);
    const announced = result();
    wasm.FakeExchange.result = announced.kind === 3
      ? new wasm.FakeResult(3, new Uint8Array(0), announced.ciphertextLen, claim)
      : announced;
    const fetcher = vi.fn<typeof fetch>(async () => streamedResponse([head(), ...frames]));

    await expect(downloadAttachmentV11("https://relay.test", keys, ID, 2_000_000, () => undefined, undefined, fetcher))
      .rejects.toThrow("Attachment unavailable");
    if (announced.kind === 3 && announced.ciphertextLen <= 2_000_000n) expect(claim.every((byte) => byte === 0)).toBe(true);
    expect(wasm.FakeExchange.all[0]!.freed).toBe(true);
  });

  it("reports action results for complete, release and delete and frees each exchange", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => new Response(new Uint8Array(wasm.ACTION), { status: 200 }));
    vi.stubGlobal("fetch", fetcher);
    const claim = new Uint8Array(16).fill(5);

    wasm.FakeExchange.result = new wasm.FakeResult(1);
    await expect(completeDownloadV11("https://relay.test", keys, ID, claim)).resolves.toBe(true);
    await expect(deleteAttachmentV11("https://relay.test", keys, ID)).resolves.toBe(true);
    wasm.FakeExchange.result = new wasm.FakeResult(0);
    await expect(releaseDownloadV11("https://relay.test", keys, ID, claim)).resolves.toBe(false);

    expect(wasm.FakeExchange.all.map((exchange) => exchange.kind)).toEqual(["complete", "delete", "release"]);
    expect(wasm.FakeExchange.all.every((exchange) => exchange.destroyed && exchange.freed)).toBe(true);
    expect(wasm.FakeExchange.all[0]!.args[4]).toBe(claim);
    expect(fetcher.mock.calls.every(([url]) => url === `https://relay.test${ATTACHMENT_PATH}`)).toBe(true);
    expect(() => completeDownloadV11("https://relay.test", keys, "not-an-id", claim)).toThrow("Attachment unavailable");
  });
});
