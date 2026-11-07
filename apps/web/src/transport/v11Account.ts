import {
  WasmAccountBootstrapExchange,
  type WasmAccountBootstrapResponse,
} from "../generated/abyssal_core/abyssal_core";

/**
 * Protocol-v11 account entry. Every request and response is one fixed-size
 * record sealed to the relay's bootstrap key (HPKE), so the capability, the
 * OPAQUE messages and the identity material never appear as readable fields
 * to anything between the browser and the relay, including a TLS-terminating
 * proxy or CDN.
 */

export const BOOTSTRAP_PATH = "/v1/bootstrap";
/** Upper bound for a sealed response read into memory. */
export const MAX_SEALED_RESPONSE_BYTES = 256 * 1024;

/** Keys that authenticate every later control, WebSocket and attachment record. */
export interface TransportKeys {
  nodePublicKey: Uint8Array;
  sessionId: Uint8Array;
  transportRoot: Uint8Array;
}

export const enum BootstrapKind {
  Failure = 0,
  LoginStart = 1,
  RegistrationStart = 2,
  RegistrationContinuation = 3,
  Session = 4,
}

export function wipeTransportKeys(keys: TransportKeys | null | undefined): void {
  keys?.nodePublicKey.fill(0);
  keys?.sessionId.fill(0);
  keys?.transportRoot.fill(0);
}

/** POSTs one sealed record and returns the sealed response bytes. */
export async function postSealedRecord(
  url: string,
  body: Uint8Array,
  signal?: AbortSignal,
  fetcher: typeof fetch = fetch,
): Promise<Uint8Array> {
  const response = await fetcher(url, {
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    referrerPolicy: "no-referrer",
    headers: { "Content-Type": "application/octet-stream", Accept: "application/octet-stream" },
    body: body as BodyInit,
    signal,
  });
  if (!response.ok || !response.body) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error("Wrong information");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_SEALED_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        chunks.forEach((chunk) => chunk.fill(0));
        throw new Error("Wrong information");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
    chunk.fill(0);
  }
  return output;
}

/**
 * Sends one bootstrap exchange and opens its response. The exchange keeps
 * its exact sealed request for a retry until a response authenticates.
 */
export async function runBootstrapExchange(
  apiBaseUrl: string,
  exchange: WasmAccountBootstrapExchange,
  signal?: AbortSignal,
  fetcher: typeof fetch = fetch,
): Promise<WasmAccountBootstrapResponse> {
  let request: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let sealed: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  try {
    request = exchange.requestBytes();
    sealed = await postSealedRecord(`${apiBaseUrl}${BOOTSTRAP_PATH}`, request, signal, fetcher);
    return exchange.openResponse(sealed);
  } finally {
    request.fill(0);
    sealed.fill(0);
  }
}

/** What a successful v11 sign-in yields, besides the transport keys. */
export interface BootstrapSession {
  created: boolean;
  username: string;
  maxRoomsPerUser: number;
  sessionInactivitySec: number;
  identityPublic: Uint8Array;
  identityPrekeyId: string;
  identityEnvelope: Uint8Array;
  /** Present when the relay allows device storage (not used by the web client). */
  deviceStorageShare: Uint8Array;
  sessionId: Uint8Array;
}

/** Copies a Session response out of WASM memory; throws for any other kind. */
export function readBootstrapSession(response: WasmAccountBootstrapResponse): BootstrapSession {
  if (response.kind !== BootstrapKind.Session) throw new Error("Wrong information");
  return {
    created: response.created,
    username: response.username,
    maxRoomsPerUser: response.maxRoomsPerUser,
    sessionInactivitySec: response.sessionInactivitySec,
    identityPublic: response.identityPublic,
    identityPrekeyId: response.identityPrekeyId,
    identityEnvelope: response.identityEnvelope,
    deviceStorageShare: response.deviceStorageShare,
    sessionId: response.sessionId,
  };
}

export function wipeBootstrapSession(session: BootstrapSession | null | undefined): void {
  session?.identityPublic.fill(0);
  session?.identityEnvelope.fill(0);
  session?.deviceStorageShare.fill(0);
  session?.sessionId.fill(0);
}
