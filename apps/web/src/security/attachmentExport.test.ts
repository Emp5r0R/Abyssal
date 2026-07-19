import { describe, expect, it } from "vitest";
import { decryptedAttachmentBlob } from "./attachmentExport";

describe("decryptedAttachmentBlob", () => {
  it("exports the exact decrypted bytes with the original media type", async () => {
    const plainPdf = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37]);
    const blob = decryptedAttachmentBlob(plainPdf, "application/pdf");

    expect(blob.type).toBe("application/pdf");
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(plainPdf);
  });

  it("copies bytes so wiping the source after export does not corrupt the download", async () => {
    const plainImage = new Uint8Array([137, 80, 78, 71]);
    const blob = decryptedAttachmentBlob(plainImage, "image/png");
    plainImage.fill(0);

    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(new Uint8Array([137, 80, 78, 71]));
  });
});
