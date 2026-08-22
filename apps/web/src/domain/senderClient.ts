/**
 * Sender-client origin disclosure for encrypted message payloads.
 *
 * The tag travels only inside the authenticated, encrypted inner payload, so
 * the relay never observes it and cannot forge or strip it. It is a claim
 * made by the sending client build, not an attestation: receivers surface it
 * as advisory context and fail closed when it is missing or unknown.
 */
export type SenderClient = "android" | "web";

/** The platform of this client build. Every outbound payload is tagged with it. */
export const LOCAL_SENDER_CLIENT: SenderClient = "web";

const WIRE_FIELD = "sender_client";

export function senderClientWireField(): string {
  return WIRE_FIELD;
}

/** Strict allowlist parse. Returns null for missing, mistyped, or unknown values. */
export function parseSenderClient(value: unknown): SenderClient | null {
  return value === "android" || value === "web" ? value : null;
}

export function isWebSender(client: SenderClient | undefined | null): boolean {
  return client === "web";
}

/**
 * Advisory text rendered next to a received message. Own messages never need
 * one; callers must not invoke this for locally composed messages.
 */
export function senderOriginNotice(client: SenderClient): string {
  return client === "web"
    ? "Sent from the web client: that device may lack screenshot protection, and its browser cannot guarantee memory wiping."
    : "Sent from the Android app: the sending device enforces screen-capture and memory protections.";
}
