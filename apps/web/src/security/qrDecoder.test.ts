import { BarcodeFormat, EncodeHintType, QRCodeWriter } from "@zxing/library";
import { describe, expect, it } from "vitest";
import { decodeQrFrame, decodeQrLuminance } from "./qrDecoder";

// Roughly the density of a real invite deep link.
const INVITE = `abyssal:invite:${"Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z".repeat(10)}`;

interface RenderOptions {
  scale?: number;
  margin?: number;
  /** Blank rows at the bottom of every module row, like terminal line spacing. */
  gapRows?: number;
  invert?: boolean;
  /** Pixels cut from every edge after rendering. */
  crop?: number;
  noise?: number;
  contrast?: [number, number];
}

function render(text: string, options: RenderOptions = {}) {
  const { scale = 4, margin = 4, gapRows = 0, invert = false, crop = 0, noise = 0, contrast = [0, 255] } = options;
  const matrix = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, new Map([[EncodeHintType.MARGIN, margin]]));
  const fullWidth = matrix.getWidth() * scale;
  const fullHeight = matrix.getHeight() * scale;
  const width = fullWidth - crop * 2;
  const height = fullHeight - crop * 2;
  const pixels = new Uint8ClampedArray(width * height);
  let seed = 7;
  const random = () => (seed = (seed * 1_103_515_245 + 12_345) % 2 ** 31) / 2 ** 31;
  for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) {
    const sourceX = x + crop;
    const sourceY = y + crop;
    const inGap = gapRows > 0 && sourceY % scale >= scale - gapRows;
    const dark = !inGap && matrix.get(Math.floor(sourceX / scale), Math.floor(sourceY / scale));
    const level = dark !== invert ? contrast[0] : contrast[1];
    pixels[y * width + x] = level + (random() - 0.5) * noise;
  }
  return { pixels, width, height };
}

function decode(raster: { pixels: Uint8ClampedArray; width: number; height: number }) {
  return decodeQrLuminance(raster.pixels, raster.width, raster.height);
}

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
    expect(decode({ pixels: new Uint8ClampedArray(300 * 300).fill(255), width: 300, height: 300 })).toBeNull();
  });

  it("reads a dense code with no quiet zone at all", () => {
    expect(decode(render(INVITE, { margin: 0 }))).toBe(INVITE);
  });

  it("reads a code cropped into its own border", () => {
    expect(decode(render(INVITE, { margin: 1, crop: 3 }))).toBe(INVITE);
  });

  it.each([
    { scale: 6, gapRows: 2 },
    { scale: 8, gapRows: 3 },
    { scale: 10, gapRows: 4 },
  ])("reads a terminal screenshot with blank lines between rows ($gapRows px of $scale)", ({ scale, gapRows }) => {
    const raster = render(INVITE, { scale, gapRows, margin: 2 });
    if (raster.width > 960) return;
    expect(decode(raster)).toBe(INVITE);
  });

  it("reads light-on-dark codes from stills and live frames", () => {
    const raster = render(INVITE, { invert: true });
    expect(decode(raster)).toBe(INVITE);
    const rgba = new Uint8ClampedArray(raster.width * raster.height * 4);
    raster.pixels.forEach((value, index) => rgba.fill(value, index * 4, index * 4 + 3));
    expect(decodeQrFrame(rgba, raster.width, raster.height)).toBe(INVITE);
  });

  it("reads a noisy, low-contrast photo of a code", () => {
    expect(decode(render(INVITE, { noise: 60, contrast: [70, 190], margin: 2 }))).toBe(INVITE);
  });

  it("leaves the caller's buffer intact for the caller to wipe", () => {
    const raster = render(INVITE, { margin: 0 });
    const before = raster.pixels.slice();
    decode(raster);
    expect(raster.pixels).toEqual(before);
  });
});
