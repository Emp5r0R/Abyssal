export function encryptedAttachmentBlob(bytes: Uint8Array): Blob {
  return new Blob([bytes.slice().buffer], { type: "application/octet-stream" });
}

export function encryptedExportName(name: string): string {
  const safe = [...name.trim()]
    .map((character) => character.charCodeAt(0) < 32 || "\\/:*?\"<>|".includes(character) ? "_" : character)
    .join("") || "attachment";
  return safe.toLowerCase().endsWith(".abyssal") ? safe : `${safe}.abyssal`;
}
