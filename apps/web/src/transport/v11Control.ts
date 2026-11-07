import { WasmControlExchange } from "../generated/abyssal_core/abyssal_core";
import { postSealedRecord, type TransportKeys } from "./v11Account";

/**
 * Protocol-v11 control requests: WebSocket tickets (with the signed build
 * attestation) and logout, each one fixed-size AEAD record to `/v1/control`
 * bound to the session's transport root. No bearer token is ever sent.
 */

export const CONTROL_PATH = "/v1/control";

export const enum ControlKind {
  Failure = 0,
  WsTicket = 1,
  LoggedOut = 2,
  BuildRejected = 3,
  PlatformConflict = 4,
}

/** Why a ticket request ended for good; anything else is retried. */
export type ControlRejection = "build" | "session-expired" | "platform-conflict";

export interface BuildAttestation {
  platform: string;
  version: string;
  buildSignatureB64: string;
}

export interface WsTicket {
  ticket: string;
  expiresInSec: number;
}

/** Thrown for a terminal refusal; [rejection] says which. */
export class ControlRejected extends Error {
  constructor(readonly rejection: ControlRejection | null = null) {
    super("Session unavailable");
  }
}

/**
 * A response that does not open under the session keys means the relay no
 * longer knows this session (it restarted, or a newer sign-in replaced it).
 */
function openOrExpired<T>(open: () => T): T {
  try {
    return open();
  } catch {
    throw new ControlRejected("session-expired");
  }
}

async function runControl(
  apiBaseUrl: string,
  exchange: WasmControlExchange,
  signal?: AbortSignal,
  fetcher: typeof fetch = fetch,
) {
  let request: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let sealed: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  try {
    request = exchange.requestBytes();
    sealed = await postSealedRecord(`${apiBaseUrl}${CONTROL_PATH}`, request, signal, fetcher);
    return openOrExpired(() => exchange.openResponse(sealed));
  } finally {
    request.fill(0);
    sealed.fill(0);
  }
}

/** Requests a one-time WebSocket ticket; the relay checks the build attestation here. */
export async function issueWsTicketV11(
  apiBaseUrl: string,
  keys: TransportKeys,
  attestation: BuildAttestation,
  signal?: AbortSignal,
  fetcher: typeof fetch = fetch,
): Promise<WsTicket> {
  const exchange = WasmControlExchange.issueWsTicket(
    keys.nodePublicKey,
    keys.sessionId,
    keys.transportRoot,
    attestation.platform,
    attestation.version,
    attestation.buildSignatureB64,
  );
  try {
    const response = await runControl(apiBaseUrl, exchange, signal, fetcher);
    try {
      if (response.kind === ControlKind.BuildRejected) throw new ControlRejected("build");
      if (response.kind === ControlKind.PlatformConflict) throw new ControlRejected("platform-conflict");
      if (response.kind !== ControlKind.WsTicket) throw new ControlRejected();
      const ticket = response.ticket;
      const expiresInSec = response.expiresInSec;
      if (!/^[A-Za-z0-9_-]{43}$/u.test(ticket) || expiresInSec < 1 || expiresInSec > 30) {
        throw new ControlRejected();
      }
      return { ticket, expiresInSec };
    } finally {
      response.free();
    }
  } finally {
    exchange.destroy();
    exchange.free();
  }
}

/** Revokes the session on the relay. Best effort: local state is cleared regardless. */
export async function logoutV11(
  apiBaseUrl: string,
  keys: TransportKeys,
  signal?: AbortSignal,
  fetcher: typeof fetch = fetch,
): Promise<boolean> {
  const exchange = WasmControlExchange.logout(keys.nodePublicKey, keys.sessionId, keys.transportRoot);
  try {
    const response = await runControl(apiBaseUrl, exchange, signal, fetcher);
    try {
      return response.kind === ControlKind.LoggedOut;
    } finally {
      response.free();
    }
  } finally {
    exchange.destroy();
    exchange.free();
  }
}
