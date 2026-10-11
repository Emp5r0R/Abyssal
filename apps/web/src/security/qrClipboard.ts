const SCANNABLE_TYPES = new Set(["image/png", "image/jpeg"]);

export type PastedQrImage =
  | { kind: "none" }
  | { kind: "unsupported" }
  | { kind: "image"; file: File };

/**
 * Decides whether a paste carries a QR screenshot for us. Text pasted into a text
 * field is left alone even when an image rides along, so typing a code still works.
 */
export function pastedQrImage(event: Pick<ClipboardEvent, "clipboardData" | "target">): PastedQrImage {
  const data = event.clipboardData;
  if (!data) return { kind: "none" };
  const images = Array.from(data.files).filter((file) => file.type.startsWith("image/"));
  if (images.length === 0) return { kind: "none" };
  if (isTextField(event.target) && data.getData("text/plain").trim() !== "") return { kind: "none" };
  const scannable = images.find((file) => SCANNABLE_TYPES.has(file.type));
  return scannable ? { kind: "image", file: scannable } : { kind: "unsupported" };
}

function isTextField(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || target instanceof HTMLTextAreaElement ||
    (target instanceof HTMLInputElement && !["button", "checkbox", "radio", "file", "submit"].includes(target.type));
}
