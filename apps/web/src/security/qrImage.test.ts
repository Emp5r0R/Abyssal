import { afterEach, describe, expect, it, vi } from "vitest";
import { QR_TEST_INVITE, qrPng } from "../test/qrFixture";
import { MAX_QR_IMAGE_BYTES, readQrImage } from "./qrImage";
import { parseInvite, wipeParsedInvite } from "./invite";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

vi.mock("./runtime", () => ({ initializeSecurityRuntime: vi.fn(async () => undefined) }));
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

function localFile(bytes: Uint8Array, type = "image/png", declaredSize = bytes.length) {
  const chunks = [bytes.slice(0, 40), bytes.slice(40)].filter((chunk) => chunk.length);
  const stream = vi.fn(() => new ReadableStream({ start(controller) {
    for (const chunk of chunks) controller.enqueue(chunk);
    controller.close();
  } }));
  const file = { type, size: declaredSize, stream, get name(): never { throw new Error("Never read a path"); } } as unknown as File;
  return { file, chunks, stream };
}

describe("QR image import security boundary", () => {
  it("decodes dense PNG output from the operator's independent qrencode renderer", async () => {
    const bytes = readFileSync(resolve(process.cwd(), "../../android/app/src/test/resources/qr/invite-qrencode.png"));
    const value = await readQrImage(localFile(bytes).file, new AbortController().signal);
    expect(value).toBe(QR_TEST_INVITE);
  });
  it("decodes and verifies a real image without using its name, metadata, or networking", async () => {
    const f = localFile(qrPng(QR_TEST_INVITE, "file:///etc/passwd https://evil.example <script>alert(1)</script>"));
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    const value = await readQrImage(f.file, new AbortController().signal);
    expect(value).toBe(QR_TEST_INVITE);
    const invite = await parseInvite(value, 2_000_000_000_000);
    expect(invite.endpoint.apiBaseUrl).toBe("https://node.example.com");
    wipeParsedInvite(invite);
    expect(fetcher).not.toHaveBeenCalled();
    expect(f.chunks.every((chunk) => chunk.every((byte) => byte === 0))).toBe(true);
  });

  it("rejects SVG, URLs, MIME spoofing, truncated data, and byte-count mismatch", async () => {
    for (const f of [
      localFile(new TextEncoder().encode("<svg><image href='file:///etc/passwd'/></svg>")),
      localFile(new TextEncoder().encode("https://evil.example/qr.png")),
      localFile(qrPng(), "image/jpeg"), localFile(qrPng(), "image/svg+xml"),
      localFile(qrPng().slice(0, 40)), localFile(qrPng(), "image/png", 50),
    ]) await expect(readQrImage(f.file, new AbortController().signal)).rejects.toBeDefined();
  });

  it("rejects oversized files and canceled selection before reading any bytes", async () => {
    const huge = localFile(new Uint8Array(1), "image/png", MAX_QR_IMAGE_BYTES + 1);
    await expect(readQrImage(huge.file, new AbortController().signal)).rejects.toThrow();
    expect(huge.stream).not.toHaveBeenCalled();
    const canceled = new AbortController();
    canceled.abort();
    const f = localFile(qrPng());
    await expect(readQrImage(f.file, canceled.signal)).rejects.toThrow();
    expect(f.stream).not.toHaveBeenCalled();
  });

  it("cancels stalled reads on timeout and caller cancellation", async () => {
    vi.useFakeTimers();
    for (const abort of [false, true]) {
      const cancel = vi.fn();
      const file = { size: 100, type: "image/png", stream: () => new ReadableStream({ cancel }) } as unknown as File;
      const controller = new AbortController();
      const result = readQrImage(file, controller.signal);
      const assertion = expect(result).rejects.toThrow("QR image rejected");
      await vi.advanceTimersByTimeAsync(1);
      if (abort) controller.abort();
      else await vi.advanceTimersByTimeAsync(10_001);
      await assertion;
      expect(cancel).toHaveBeenCalledOnce();
    }
  });

  it("keeps arbitrary QR text inert and leaves authenticity to the signed parser", async () => {
    const f = localFile(qrPng("file:///etc/passwd"));
    const value = await readQrImage(f.file, new AbortController().signal);
    await expect(parseInvite(value)).rejects.toBeDefined();
  });
});
