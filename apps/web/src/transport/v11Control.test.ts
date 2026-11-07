import { beforeEach, describe, expect, it, vi } from "vitest";

const wasm = vi.hoisted(() => {
  class FakeResponse {
    freed = false;
    constructor(readonly kind: number, readonly ticket = "", readonly expiresInSec = 0) {}
    free(): void {
      this.freed = true;
    }
  }
  class FakeExchange {
    static last: FakeExchange | null = null;
    static issueArgs: unknown[] = [];
    static respond: (sealed: Uint8Array) => FakeResponse = () => new FakeResponse(0);
    readonly request = new Uint8Array(4_170).fill(7);
    destroyed = false;
    freed = false;
    requestBytes(): Uint8Array {
      return this.request;
    }
    openResponse(sealed: Uint8Array): FakeResponse {
      return FakeExchange.respond(sealed);
    }
    destroy(): void {
      this.destroyed = true;
    }
    free(): void {
      this.freed = true;
    }
    static issueWsTicket(...args: unknown[]): FakeExchange {
      FakeExchange.issueArgs = args;
      FakeExchange.last = new FakeExchange();
      return FakeExchange.last;
    }
    static logout(): FakeExchange {
      FakeExchange.last = new FakeExchange();
      return FakeExchange.last;
    }
  }
  return { FakeExchange, FakeResponse };
});

vi.mock("../generated/abyssal_core/abyssal_core", () => ({ WasmControlExchange: wasm.FakeExchange }));

import { CONTROL_PATH, ControlRejected, issueWsTicketV11, logoutV11 } from "./v11Control";

const keys = {
  nodePublicKey: new Uint8Array(32).fill(1),
  sessionId: new Uint8Array(32).fill(2),
  transportRoot: new Uint8Array(32).fill(3),
};
const attestation = { platform: "web", version: "4.0.0", buildSignatureB64: "sig" };
const TICKET = "A".repeat(43);

function sealedFetcher() {
  return vi.fn<typeof fetch>(async () => new Response(new Uint8Array(4_170).fill(9), { status: 200 }));
}

async function rejectionOf(promise: Promise<unknown>): Promise<ControlRejected> {
  const error = await promise.then(() => null, (caught: unknown) => caught);
  expect(error).toBeInstanceOf(ControlRejected);
  return error as ControlRejected;
}

beforeEach(() => {
  wasm.FakeExchange.last = null;
  wasm.FakeExchange.respond = () => new wasm.FakeResponse(0);
});

describe("protocol-v11 control client", () => {
  it("posts one sealed record for a ticket and wipes and frees everything it used", async () => {
    let response: InstanceType<typeof wasm.FakeResponse> | null = null;
    let opened: Uint8Array | null = null;
    wasm.FakeExchange.respond = (sealed) => {
      opened = sealed;
      response = new wasm.FakeResponse(1, TICKET, 30);
      return response;
    };
    const fetcher = sealedFetcher();

    await expect(issueWsTicketV11("https://relay.test", keys, attestation, undefined, fetcher))
      .resolves.toEqual({ ticket: TICKET, expiresInSec: 30 });

    expect(wasm.FakeExchange.issueArgs).toEqual([
      keys.nodePublicKey, keys.sessionId, keys.transportRoot, "web", "4.0.0", "sig",
    ]);
    const [url, init] = fetcher.mock.calls[0]!;
    expect(url).toBe(`https://relay.test${CONTROL_PATH}`);
    expect(init).toMatchObject({ method: "POST", credentials: "omit", redirect: "error", cache: "no-store" });
    expect((init?.headers as Record<string, string>).Authorization).toBeUndefined();
    const exchange = wasm.FakeExchange.last!;
    expect(exchange.request.every((byte) => byte === 0)).toBe(true);
    expect(opened!.every((byte) => byte === 0)).toBe(true);
    expect(exchange.destroyed && exchange.freed).toBe(true);
    expect(response!.freed).toBe(true);
  });

  it.each([
    [3, "build"],
    [4, "platform-conflict"],
    [0, null],
    [2, null],
  ])("maps response kind %i to a terminal rejection of %s", async (kind, rejection) => {
    wasm.FakeExchange.respond = () => new wasm.FakeResponse(kind);
    const error = await rejectionOf(issueWsTicketV11("https://relay.test", keys, attestation, undefined, sealedFetcher()));
    expect(error.rejection).toBe(rejection);
    expect(wasm.FakeExchange.last!.freed).toBe(true);
  });

  it.each([
    ["a short ticket", "A".repeat(42), 30],
    ["a ticket with a forbidden character", `${"A".repeat(42)}=`, 30],
    ["a zero lifetime", TICKET, 0],
    ["an over-long lifetime", TICKET, 31],
  ])("refuses %s as a transient failure", async (_label, ticket, expiresInSec) => {
    wasm.FakeExchange.respond = () => new wasm.FakeResponse(1, ticket, expiresInSec);
    const error = await rejectionOf(issueWsTicketV11("https://relay.test", keys, attestation, undefined, sealedFetcher()));
    expect(error.rejection).toBeNull();
  });

  it("treats a reply that does not open under the session keys as an expired session", async () => {
    wasm.FakeExchange.respond = () => {
      throw new Error("aead");
    };
    const error = await rejectionOf(issueWsTicketV11("https://relay.test", keys, attestation, undefined, sealedFetcher()));
    expect(error.rejection).toBe("session-expired");
    expect(wasm.FakeExchange.last!.destroyed).toBe(true);
  });

  it("keeps network failures transient and distinct from rejections", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => new Response(null, { status: 503 }));
    const error = await issueWsTicketV11("https://relay.test", keys, attestation, undefined, fetcher)
      .then(() => null, (caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(ControlRejected);
    expect(wasm.FakeExchange.last!.freed).toBe(true);
  });

  it("reports logout success only for a LoggedOut reply", async () => {
    wasm.FakeExchange.respond = () => new wasm.FakeResponse(2);
    await expect(logoutV11("https://relay.test", keys, undefined, sealedFetcher())).resolves.toBe(true);
    wasm.FakeExchange.respond = () => new wasm.FakeResponse(0);
    await expect(logoutV11("https://relay.test", keys, undefined, sealedFetcher())).resolves.toBe(false);
    expect(wasm.FakeExchange.last!.destroyed && wasm.FakeExchange.last!.freed).toBe(true);
  });
});
