const MIME_TYPE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}$/u;
const BIDI_CONTROL_PATTERN = /[\u202A-\u202E\u2066-\u2069]/u;

export function attachmentDownloadBlob(bytes: Uint8Array, mimeType: string): Blob {
  if (bytes.byteLength === 0) throw new Error("Attachment unavailable");
  const safeMimeType = MIME_TYPE_PATTERN.test(mimeType) ? mimeType : "application/octet-stream";
  return new Blob([bytes.slice().buffer], { type: safeMimeType });
}

export function attachmentDownloadName(name: string): string {
  const safe = [...name.trim().slice(0, 160)]
    .map((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint < 32 || codePoint === 127 || BIDI_CONTROL_PATTERN.test(character) || "\\/:*?\"<>|".includes(character)
        ? "_"
        : character;
    })
    .join("")
    .replace(/^[. ]+|[. ]+$/gu, "");
  return safe || "attachment";
}
