import { describe, expect, it } from "vitest";
import { attachmentUploadEnvelope, decodeAttachmentUploadResponse, ATTACHMENT_UPLOAD_PREFIX_BYTES } from "./attachmentUploadEnvelope";

const metadata = { chat_id: "dm_Alice_Bob", message_id: "message", media_type: "FILE",
  one_time: false, delete_after_download: false, ttl_sec: 60 };

describe("attachment upload envelope", () => {
  it("accepts the exact relay response and rejects partial or false acceptance", () => {
    const valid = { accepted: true, attachment_id: "8782bc98-9ff6-4b63-ae72-b9ce38bab1d7", storage: "ram-only" };
    expect(decodeAttachmentUploadResponse(valid)).toBe(valid.attachment_id);
    for (const invalid of [null, [], {}, { attachment_id: valid.attachment_id },
      { ...valid, accepted: false }, { ...valid, accepted: "true" },
      { ...valid, storage: "disk" }, { ...valid, unexpected: true },
      { ...valid, attachment_id: "../../private" }, { ...valid, attachment_id: "" },
    ]) expect(() => decodeAttachmentUploadResponse(invalid)).toThrow("Upload rejected");
  });
  it("has one fixed prefix and preserves Blob and sliced buffer bytes", async () => {
    const storage = new Uint8Array([99, 3, 9, 8, 7, 99]);
    const view = storage.subarray(1, 5);
    for (const input of [view, new Blob([view])]) {
      const body = attachmentUploadEnvelope(metadata, input);
      expect(body.type).toBe("application/octet-stream");
      expect(body.size).toBe(ATTACHMENT_UPLOAD_PREFIX_BYTES + view.length);
      const bytes = new Uint8Array(await body.arrayBuffer());
      expect(new TextDecoder().decode(bytes.subarray(0, 8))).toBe("ABYUP001");
      const length = new DataView(bytes.buffer).getUint16(8, false);
      expect(JSON.parse(new TextDecoder().decode(bytes.subarray(10, 10 + length)))).toEqual(metadata);
      expect(bytes.subarray(10 + length, 1024).every((value) => value === 0)).toBe(true);
      expect(bytes.subarray(1024)).toEqual(view);
    }
    expect(storage).toEqual(new Uint8Array([99, 3, 9, 8, 7, 99]));
  });

  it("rejects invalid or oversized metadata before encoding", () => {
    for (const invalid of [
      { chat_id: "a".repeat(129) }, { chat_id: "dm/secret" }, { message_id: "" },
      { media_type: "image/jpeg" }, { ttl_sec: -1 }, { ttl_sec: Infinity },
      { ttl_sec: 0.5 }, { ttl_sec: NaN },
    ]) expect(() => attachmentUploadEnvelope({ ...metadata, ...invalid }, new Uint8Array([3]))).toThrow("Upload rejected");
  });
});
