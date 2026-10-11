// Keep the decoder consumable by both Vite and the bounded Node qualification
// scripts. Node loads @zxing/library as CommonJS, so a default namespace import
// avoids environment-specific named-export interop failures.
import * as ZXingModule from "@zxing/library";
import { decodeQrLuminance as decodeWithCore } from "../generated/abyssal_core/abyssal_core.js";

const {
  BinaryBitmap,
  ChecksumException,
  DecodeHintType,
  FormatException,
  HybridBinarizer,
  NotFoundException,
  QRCodeReader,
  RGBLuminanceSource,
} = ((ZXingModule as unknown as Record<string, unknown>)["default"] ?? ZXingModule) as typeof ZXingModule;

export const MAX_QR_TEXT = 2048;
export const MAX_QR_SIDE = 960;

/**
 * How hard to try. A live camera frame gets a few cheap passes because the next
 * frame arrives shortly; a still image gets every repair because it is all there is.
 */
export type QrDecodeEffort = "frame" | "image";

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
    return decodeQrLuminance(luminance, width, height, "frame");
  } finally {
    luminance.fill(0);
  }
}

/**
 * The shared Rust decoder runs first: it repairs cropped borders, terminal line
 * gaps, inverted colours and sensor noise identically on web and Android. ZXing
 * remains a fallback for anything it cannot place.
 */
export function decodeQrLuminance(
  luminance: Uint8ClampedArray,
  width: number,
  height: number,
  effort: QrDecodeEffort = "image",
): string | null {
  if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width < 1 || height < 1 ||
      width > MAX_QR_SIDE || height > MAX_QR_SIDE || luminance.length !== width * height) {
    throw new Error("Invalid camera frame");
  }
  return decodeShared(luminance, width, height, effort) ?? decodeWithZxing(luminance, width, height);
}

function decodeShared(luminance: Uint8ClampedArray, width: number, height: number, effort: QrDecodeEffort): string | null {
  // The core receives its own copy, which it zeroizes; ours stays with the caller.
  const copy = new Uint8Array(luminance);
  try {
    const text = decodeWithCore(copy, width, height, effort === "image");
    return text && text.length <= MAX_QR_TEXT ? text : null;
  } catch {
    // The WASM core may still be loading; ZXing then answers on its own.
    return null;
  } finally {
    copy.fill(0);
  }
}

function decodeWithZxing(luminance: Uint8ClampedArray, width: number, height: number): string | null {
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
