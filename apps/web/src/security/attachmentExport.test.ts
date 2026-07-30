import { describe, expect, it } from "vitest";
import { encryptedAttachmentBlob, encryptedExportName } from "./attachmentExport";

describe("encryptedAttachmentBlob", () => {
  it("exports the exact ciphertext with a non-executable media type", async () => {
    const ciphertext = new Uint8Array([0x41, 0x42, 0x59, 0x53, 0x53, 0x41, 0x4c]);
    const blob = encryptedAttachmentBlob(ciphertext);

    expect(blob.type).toBe("application/octet-stream");
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(ciphertext);
  });

  it("copies bytes so wiping the source after export does not corrupt the download", async () => {
    const plainImage = new Uint8Array([137, 80, 78, 71]);
    const blob = encryptedAttachmentBlob(plainImage);
    plainImage.fill(0);

    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(new Uint8Array([137, 80, 78, 71]));
  });

  it("handles empty Uint8Array", async () => {
    const blob = encryptedAttachmentBlob(new Uint8Array(0));
    expect(blob.type).toBe("application/octet-stream");
    expect((await blob.arrayBuffer()).byteLength).toBe(0);
  });

  it("creates independent copies from the same source buffer", async () => {
    const source = new Uint8Array([42, 43, 44]);
    const blob1 = encryptedAttachmentBlob(source);
    const blob2 = encryptedAttachmentBlob(source);
    source.fill(0);
    expect(new Uint8Array(await blob1.arrayBuffer())).toEqual(new Uint8Array([42, 43, 44]));
    expect(new Uint8Array(await blob2.arrayBuffer())).toEqual(new Uint8Array([42, 43, 44]));
  });

  it("handles large buffer without corruption", async () => {
    const large = new Uint8Array(64 * 1024);
    large.fill(0xAB);
    const blob = encryptedAttachmentBlob(large);
    large.fill(0);
    const exported = new Uint8Array(await blob.arrayBuffer());
    expect(exported.byteLength).toBe(64 * 1024);
    expect(exported[0]).toBe(0xAB);
    expect(exported[exported.byteLength - 1]).toBe(0xAB);
  });

  it("creates sanitized Abyssal export names", () => {
    expect(encryptedExportName("report.pdf")).toBe("report.pdf.abyssal");
    expect(encryptedExportName("../bad:name")).toBe(".._bad_name.abyssal");
    expect(encryptedExportName("archive.ABYSSAL")).toBe("archive.ABYSSAL");
  });
});
