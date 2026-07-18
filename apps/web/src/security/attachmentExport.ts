/**
 * Builds an explicit user export from already decrypted attachment bytes.
 * The caller retains ownership of the source buffer and must wipe it after
 * creating the Blob.
 */
export function decryptedAttachmentBlob(bytes: Uint8Array, mimeType: string): Blob {
  return new Blob([bytes.slice().buffer], { type: mimeType });
}
