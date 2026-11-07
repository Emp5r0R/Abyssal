import { describe, expect, it, vi } from "vitest";

vi.mock("../generated/abyssal_core/abyssal_core", () => ({ WasmAccountBootstrapExchange: class {} }));

import {
  BOOTSTRAP_PATH,
  MAX_SEALED_RESPONSE_BYTES,
  postSealedRecord,
  readBootstrapSession,
  runBootstrapExchange,
  wipeBootstrapSession,
  wipeTransportKeys,
} from "./v11Account";
import type { WasmAccountBootstrapExchange, WasmAccountBootstrapResponse } from "../generated/abyssal_core/abyssal_core";

function chunkedResponse(chunks: Uint8Array[], status = 200): Response {
  return new Response(new ReadableStream<Uint8Array>({
    pull(controller) {
      const next = chunks.shift();
      if (next) controller.enqueue(next);
      else controller.close();
    },
  }), { status });
}

describe("protocol-v11 sealed record transport", () => {
  it("posts opaque bytes without credentials and joins a chunked reply, wiping the chunks", async () => {
    const first = new Uint8Array([1, 2]);
    const second = new Uint8Array([3]);
    const fetcher = vi.fn<typeof fetch>(async () => chunkedResponse([first, second]));
    const body = new Uint8Array([9, 9]);

    await expect(postSealedRecord("https://relay.test/v1/bootstrap", body, undefined, fetcher))
      .resolves.toEqual(new Uint8Array([1, 2, 3]));

    expect(fetcher).toHaveBeenCalledWith("https://relay.test/v1/bootstrap", expect.objectContaining({
      method: "POST",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      cache: "no-store",
      headers: { "Content-Type": "application/octet-stream", Accept: "application/octet-stream" },
      body,
    }));
    expect([...first, ...second].every((byte) => byte === 0)).toBe(true);
  });

  it("rejects an error status and an oversized reply without keeping its bytes", async () => {
    await expect(postSealedRecord("https://relay.test", new Uint8Array(1), undefined,
      vi.fn<typeof fetch>(async () => chunkedResponse([new Uint8Array(1)], 403)))).rejects.toThrow("Wrong information");

    const big = new Uint8Array(MAX_SEALED_RESPONSE_BYTES).fill(5);
    const tail = new Uint8Array(1).fill(5);
    await expect(postSealedRecord("https://relay.test", new Uint8Array(1), undefined,
      vi.fn<typeof fetch>(async () => chunkedResponse([big, tail])))).rejects.toThrow("Wrong information");
    expect(big.every((byte) => byte === 0)).toBe(true);
  });

  it("runs one bootstrap exchange against the fixed path and wipes request and reply", async () => {
    const request = new Uint8Array([4, 4, 4]);
    let sealedSeen: Uint8Array | null = null;
    const opened = { kind: 4 };
    const exchange = {
      requestBytes: () => request,
      openResponse: (sealed: Uint8Array) => {
        sealedSeen = sealed;
        return opened;
      },
    } as unknown as WasmAccountBootstrapExchange;
    const fetcher = vi.fn<typeof fetch>(async () => chunkedResponse([new Uint8Array([7, 7])]));

    await expect(runBootstrapExchange("https://relay.test", exchange, undefined, fetcher)).resolves.toBe(opened);
    expect(fetcher.mock.calls[0]?.[0]).toBe(`https://relay.test${BOOTSTRAP_PATH}`);
    expect(request.every((byte) => byte === 0)).toBe(true);
    expect(sealedSeen!.every((byte) => byte === 0)).toBe(true);
  });

  it("reads only Session replies and wipes the secret parts of a session and its keys", () => {
    const response = {
      kind: 4,
      created: true,
      username: "Alice",
      maxRoomsPerUser: 3,
      sessionInactivitySec: 900,
      identityPublic: new Uint8Array(32).fill(1),
      identityPrekeyId: "prekey",
      identityEnvelope: new Uint8Array(8).fill(2),
      deviceStorageShare: new Uint8Array(32).fill(3),
      sessionId: new Uint8Array(32).fill(4),
    } as unknown as WasmAccountBootstrapResponse;
    const session = readBootstrapSession(response);
    expect(session).toMatchObject({ created: true, username: "Alice", maxRoomsPerUser: 3, identityPrekeyId: "prekey" });
    expect(() => readBootstrapSession({ kind: 1 } as unknown as WasmAccountBootstrapResponse)).toThrow("Wrong information");

    wipeBootstrapSession(session);
    for (const bytes of [session.identityPublic, session.identityEnvelope, session.deviceStorageShare, session.sessionId]) {
      expect(bytes.every((byte) => byte === 0)).toBe(true);
    }
    const keys = {
      nodePublicKey: new Uint8Array(32).fill(1),
      sessionId: new Uint8Array(32).fill(2),
      transportRoot: new Uint8Array(32).fill(3),
    };
    wipeTransportKeys(keys);
    wipeTransportKeys(null);
    expect([...keys.nodePublicKey, ...keys.sessionId, ...keys.transportRoot].every((byte) => byte === 0)).toBe(true);
  });
});
