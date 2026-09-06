import { BarcodeFormat, QRCodeWriter } from "@zxing/library";
import { describe, expect, it } from "vitest";
import { decodeQrFrame, decodeQrLuminance } from "./qrDecoder";

describe("offline QR decoder", () => {
  it.each(["abyssal:invite:fixture", "ABY1-TEST", "file:///etc/passwd", "https://evil.example"])("decodes %s only as inert data", (text) => {
    const matrix = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 240, 240, new Map());
    const rgba = new Uint8ClampedArray(240 * 240 * 4).fill(255);
    for (let y = 0; y < 240; y++) for (let x = 0; x < 240; x++) {
      const value = matrix.get(x, y) ? 0 : 255;
      const offset = (y * 240 + x) * 4;
      rgba[offset] = rgba[offset + 1] = rgba[offset + 2] = value;
    }
    expect(decodeQrFrame(rgba, 240, 240)).toBe(text);
  });
  it("rejects malformed and oversized frames before decoding", () => {
    expect(() => decodeQrFrame(new Uint8ClampedArray(4), 100_000, 100_000)).toThrow();
    expect(() => decodeQrLuminance(new Uint8ClampedArray(4), -1, 4)).toThrow();
    expect(decodeQrFrame(new Uint8ClampedArray(240 * 240 * 4).fill(255), 240, 240)).toBeNull();
  });
});
