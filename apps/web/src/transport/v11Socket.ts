import { WasmWsClientConnection } from "../generated/abyssal_core/abyssal_core";
import type { TransportKeys } from "./v11Account";
import type { SocketChannel } from "./nodeClient";

/** The only WebSocket subprotocol a v11 relay accepts. */
export const WS_PROTOCOL_V11 = "abyssal-v11";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * One v11 WebSocket's record layer. The one-time ticket travels inside the
 * encrypted ClientHello, not in a header; after the relay's ServerHello every
 * frame in either direction is an AEAD record with a monotonic counter, so
 * replayed, reordered or altered frames fail closed.
 */
export class V11SocketChannel implements SocketChannel {
  #connection: WasmWsClientConnection | null;
  #ready = false;

  constructor(keys: TransportKeys, ticket: string) {
    const ticketBytes = encoder.encode(ticket);
    try {
      this.#connection = new WasmWsClientConnection(keys.nodePublicKey, keys.sessionId, keys.transportRoot, ticketBytes);
    } finally {
      ticketBytes.fill(0);
    }
  }

  get ready(): boolean {
    return this.#ready;
  }

  /** The first binary message to send once the socket opens. */
  clientHello(): Uint8Array {
    if (!this.#connection) throw new Error("Transport unavailable");
    return this.#connection.clientHelloBytes();
  }

  /**
   * Handles one binary message from the relay. Returns the opened text frame,
   * or null for the ServerHello (after which the channel is ready). Throws on
   * anything that does not authenticate.
   */
  receive(data: unknown): string | null {
    const connection = this.#connection;
    // Only binary records exist on a v11 socket; plaintext text frames fail closed.
    if (!connection || !(data instanceof ArrayBuffer)) throw new Error("Transport unavailable");
    const record = new Uint8Array(data);
    if (!this.#ready) {
      connection.openServerHello(record);
      if (!connection.ready()) throw new Error("Transport unavailable");
      this.#ready = true;
      return null;
    }
    const plaintext = connection.openFrame(record);
    try {
      return decoder.decode(plaintext);
    } finally {
      plaintext.fill(0);
    }
  }

  /** Seals one text frame for sending; only after the handshake completed. */
  seal(text: string): Uint8Array {
    const connection = this.#connection;
    if (!connection || !this.#ready) throw new Error("Transport unavailable");
    const plaintext = encoder.encode(text);
    try {
      return connection.sealFrame(plaintext);
    } finally {
      plaintext.fill(0);
    }
  }

  destroy(): void {
    const connection = this.#connection;
    this.#connection = null;
    this.#ready = false;
    if (connection) {
      connection.destroy();
      connection.free();
    }
  }
}
