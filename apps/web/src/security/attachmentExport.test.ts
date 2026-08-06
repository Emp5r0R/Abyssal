import { describe, expect, it } from "vitest";
import { attachmentDownloadBlob, attachmentDownloadName } from "./attachmentExport";

describe("attachmentDownloadBlob", () => {
  it("exports the exact decrypted bytes with their authenticated media type", async () => {
    const plaintext = new Uint8Array([0x41, 0x42, 0x59, 0x53, 0x53, 0x41, 0x4c]);
    const blob = attachmentDownloadBlob(plaintext, "application/pdf");

    expect(blob.type).toBe("application/pdf");
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(plaintext);
  });

  it("copies bytes so wiping the source after export does not corrupt the download", async () => {
    const plainImage = new Uint8Array([137, 80, 78, 71]);
    const blob = attachmentDownloadBlob(plainImage, "image/png");
    plainImage.fill(0);

    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(new Uint8Array([137, 80, 78, 71]));
  });

  it("handles empty Uint8Array", async () => {
    const blob = attachmentDownloadBlob(new Uint8Array(0), "application/octet-stream");
    expect(blob.type).toBe("application/octet-stream");
    expect((await blob.arrayBuffer()).byteLength).toBe(0);
  });

  it("creates independent copies from the same source buffer", async () => {
    const source = new Uint8Array([42, 43, 44]);
    const blob1 = attachmentDownloadBlob(source, "application/octet-stream");
    const blob2 = attachmentDownloadBlob(source, "application/octet-stream");
    source.fill(0);
    expect(new Uint8Array(await blob1.arrayBuffer())).toEqual(new Uint8Array([42, 43, 44]));
    expect(new Uint8Array(await blob2.arrayBuffer())).toEqual(new Uint8Array([42, 43, 44]));
  });

  it("handles large buffer without corruption", async () => {
    const large = new Uint8Array(64 * 1024);
    large.fill(0xAB);
    const blob = attachmentDownloadBlob(large, "application/octet-stream");
    large.fill(0);
    const exported = new Uint8Array(await blob.arrayBuffer());
    expect(exported.byteLength).toBe(64 * 1024);
    expect(exported[0]).toBe(0xAB);
    expect(exported[exported.byteLength - 1]).toBe(0xAB);
  });

  it("falls back to a non-executable type for malformed media types", () => {
    expect(attachmentDownloadBlob(new Uint8Array(), "text/html; charset=utf-8").type).toBe("application/octet-stream");
  });

  it("keeps the original extension without adding an Abyssal suffix", () => {
    expect(attachmentDownloadName("report.pdf")).toBe("report.pdf");
    expect(attachmentDownloadName("../bad:name")).toBe("_bad_name");
    expect(attachmentDownloadName("clip.mp4")).toBe("clip.mp4");
    expect(attachmentDownloadName("invoice\u202Efdp.exe")).toBe("invoice_fdp.exe");
    expect(attachmentDownloadName("... ")).toBe("attachment");
  });
});
