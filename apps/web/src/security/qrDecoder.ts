import { BinaryBitmap, ChecksumException, DecodeHintType, FormatException, HybridBinarizer, NotFoundException, QRCodeReader, RGBLuminanceSource } from "@zxing/library";

export const MAX_QR_TEXT = 2048;
export const MAX_QR_SIDE = 960;

/** Pure, offline decoding. The camera adapter owns and wipes the RGBA frame. */
export function decodeQrFrame(rgba: Uint8ClampedArray, width: number, height: number): string | null {
  if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width < 1 || height < 1 ||
      width > MAX_QR_SIDE || height > MAX_QR_SIDE || rgba.length !== width * height * 4) {
    throw new Error("Invalid camera frame");
  }
  const luminance = new Uint8ClampedArray(width * height);
  try {
    for (let i = 0; i < luminance.length; i++) {
      const offset = i * 4;
      luminance[i] = (rgba[offset] + 2 * rgba[offset + 1] + rgba[offset + 2]) / 4;
    }
    return decodeQrLuminance(luminance, width, height);
  } finally {
    luminance.fill(0);
  }
}

export function decodeQrLuminance(luminance: Uint8ClampedArray, width: number, height: number): string | null {
  if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width < 1 || height < 1 ||
      width > MAX_QR_SIDE || height > MAX_QR_SIDE || luminance.length !== width * height) {
    throw new Error("Invalid camera frame");
  }
  const reader = new QRCodeReader();
  try {
    const bitmap = new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(luminance, width, height)));
    let result;
    try { result = reader.decode(bitmap); }
    catch (error) {
      if (!(error instanceof NotFoundException)) throw error;
      // Standard detection can miss dense, perfectly aligned generated codes.
      // One bounded pure-image pass still requires QR error correction and the
      // caller's signed invite/token verification; it is not a trust bypass.
      result = reader.decode(bitmap, new Map([[DecodeHintType.PURE_BARCODE, true]]));
    }
    try {
      const text = result.getText();
      return text.length > 0 && text.length <= MAX_QR_TEXT ? text : null;
    } finally {
      result.getRawBytes()?.fill(0);
    }
  } catch (error) {
    if (error instanceof NotFoundException || error instanceof ChecksumException || error instanceof FormatException) return null;
    throw new Error("QR scan unavailable", { cause: error });
  } finally {
    reader.reset();
  }
}
