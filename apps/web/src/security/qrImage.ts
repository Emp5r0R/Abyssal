import { decodeQrImage } from "../generated/abyssal_core/abyssal_core";
import { initializeSecurityRuntime } from "./runtime";
import { decodeQrLuminance } from "./qrDecoder";

export const MAX_QR_IMAGE_BYTES = 8 * 1024 * 1024;

/** File is only a local Blob: its name/path/metadata never becomes a request. */
export async function readQrImage(file: File, signal: AbortSignal): Promise<string> {
  if (signal.aborted || file.size <= 0 || file.size > MAX_QR_IMAGE_BYTES ||
      !["", "image/png", "image/jpeg"].includes(file.type)) throw new Error("QR image rejected");
  await initializeSecurityRuntime();
  if (signal.aborted) throw new Error("QR image rejected");
  const reader = file.stream().getReader();
  const bytes = new Uint8Array(file.size);
  const cancel = () => { void reader.cancel().catch(() => undefined); };
  signal.addEventListener("abort", cancel, { once: true });
  let timedOut = false;
  const timeout = setTimeout(() => { timedOut = true; cancel(); }, 10_000);
  let offset = 0;
  let luminance: Uint8Array | undefined;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      try {
        if (signal.aborted || timedOut || value.length > bytes.length - offset) throw new Error("QR image rejected");
        bytes.set(value, offset);
        offset += value.length;
      } finally { value.fill(0); }
    }
    if (signal.aborted || timedOut || offset !== bytes.length) throw new Error("QR image rejected");
    const decoded = decodeQrImage(bytes, file.type) as { width: number; height: number; luminance: Uint8Array };
    luminance = decoded.luminance;
    if (!(luminance instanceof Uint8Array)) throw new Error("QR image rejected");
    const value = decodeQrLuminance(new Uint8ClampedArray(luminance.buffer, luminance.byteOffset, luminance.byteLength), decoded.width, decoded.height);
    if (!value || signal.aborted) throw new Error("QR image rejected");
    return value;
  } finally {
    bytes.fill(0);
    luminance?.fill(0);
    clearTimeout(timeout);
    signal.removeEventListener("abort", cancel);
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}
