import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("./runtime", () => ({
  initializeSecurityRuntime: vi.fn(async () => undefined),
}));

import {
  parseInvite,
  verifyConnectedInviteNode,
  wipeParsedInvite,
} from "./invite";

const DEEP_LINK = "abyssal:invite:glh3igFwb3JnLmFieXNzYWwuY2hhdAFYINBKsjJ0K7SrOhNovUYV5ObQIkq3GgFrr4UgozLJd4c3gYMBcG5vZGUuZXhhbXBsZS5jb20ZAbtYICIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiCQoAGn0rdQBYQDgZJxVYJlrtgAJBj4VbdykqYpymbDWTNY0Uz-18fOOxGzi6fwKTPzEnVkJ6QldbfyY0pl1JJchNJv3TknkT-Qs";
const MANUAL = "ABY1-G9C7F-2G1E1-QQ4SS-EC5H7-JWVKC-5P2WR-V8C5T-02P10-T15B4-CKM5E-TAPEG-KD2YM-C5F4W-V824J-NQ380-PQBW5-42HK5-JBQGW-VR30R-1E1Q6-YS355-SJQGR-BDE1P-6ABK3-DXPHJ-0DVB0-G248H-248H2-48H24-8H248-H248H-248H2-48H24-8H248-H248H-248H2-48G91-801MZ-9BEM0-5GG1R-34KHA-P16BB-PR00J-1HY2N-PXS95-9H9S9-KC6P9-KB38M-SZPQR-Z73P4-DKHEK-Z0A9K-YC97A-S17MG-JQBDZ-JCD56-BN4JB-J2D4V-YX74K-S2FWG-PB8D2-V6G";
const DESCRIPTOR_HEX = "8258508801706f72672e6162797373616c2e636861745820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737818301706e6f64652e6578616d706c652e636f6d1901bb01090a00584011d674f2075930853f2ae2ea008d7787de469c3d1e954ea8aea6ae5a19e31a2c7d790ce0c473036e3bb016c3bc50c96e85b214659d994da7a8a43dfcff383401";
const VECTOR_LOCATION = {
  protocol: "https:",
  hostname: "node.example.com",
  origin: "https://node.example.com",
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("Invite Capsule bootstrap", () => {
  it("parses the shared deep-link and manual vectors identically", async () => {
    const deep = await parseInvite(DEEP_LINK, 2_000_000_000_000);
    const manual = await parseInvite(MANUAL.toLowerCase(), 2_000_000_000_000);

    expect(deep.nodeId).toBe("abyssal-node-v1:zlLjZjAl8CVJZ5l9jVgQUhve1mxyTiVNmey5lQsROLU");
    expect(deep.endpoint.apiBaseUrl).toBe("https://node.example.com");
    expect(Array.from(deep.capability)).toEqual(Array(32).fill(0x22));
    expect(bytesToHex(deep.accountContext)).toBe("f5145cdbee41235643f64efca7a605d19ebce805cdb66295ff479414856f2734");
    expect(manual).toEqual(deep);

    wipeParsedInvite(deep);
    wipeParsedInvite(manual);
    expect(deep.capability.every((byte) => byte === 0)).toBe(true);
    expect(manual.nodePublicKey.every((byte) => byte === 0)).toBe(true);
  });

  it("rejects tampered and expired invite text before networking", async () => {
    const tampered = `${DEEP_LINK.slice(0, -1)}A`;
    await expect(parseInvite(tampered, 2_000_000_000_000)).rejects.toThrow();
    await expect(parseInvite(DEEP_LINK, 2_100_000_001_000)).rejects.toThrow("Invite expired");
  });

  it("accepts only the bounded signed descriptor for the invited node", async () => {
    const invite = await parseInvite(DEEP_LINK, 2_000_000_000_000);
    const descriptor = hexToBytes(DESCRIPTOR_HEX);
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(ownedBuffer(descriptor), {
      status: 200,
      headers: { "content-type": "application/cbor", "content-length": String(descriptor.length) },
    }));
    vi.stubGlobal("fetch", fetcher);

    await expect(verifyConnectedInviteNode(
      invite,
      new AbortController().signal,
      VECTOR_LOCATION,
    )).resolves.toBeUndefined();
    expect(fetcher).toHaveBeenCalledWith("https://node.example.com/v1/node", expect.objectContaining({
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      headers: { Accept: "application/cbor" },
    }));
    wipeParsedInvite(invite);
  });

  it("fails closed for an oversized or mismatched descriptor", async () => {
    const invite = await parseInvite(DEEP_LINK, 2_000_000_000_000);
    vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockResolvedValue(new Response(new Uint8Array(1), {
      status: 200,
      headers: { "content-type": "application/cbor", "content-length": "1025" },
    })));
    await expect(verifyConnectedInviteNode(
      invite,
      new AbortController().signal,
      VECTOR_LOCATION,
    )).rejects.toThrow("Node descriptor rejected");

    const descriptor = hexToBytes(DESCRIPTOR_HEX);
    descriptor[descriptor.length - 1] ^= 1;
    vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockResolvedValue(new Response(ownedBuffer(descriptor), {
      status: 200,
      headers: { "content-type": "application/cbor" },
    })));
    await expect(verifyConnectedInviteNode(
      invite,
      new AbortController().signal,
      VECTOR_LOCATION,
    )).rejects.toThrow();
    wipeParsedInvite(invite);
  });

  it("rejects cross-origin production and remote development locators before fetch", async () => {
    const invite = await parseInvite(DEEP_LINK, 2_000_000_000_000);
    const fetcher = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetcher);

    await expect(verifyConnectedInviteNode(invite, new AbortController().signal, {
      protocol: "https:",
      hostname: "other.example.com",
      origin: "https://other.example.com",
    })).rejects.toThrow("Node identity mismatch");
    await expect(verifyConnectedInviteNode(invite, new AbortController().signal, {
      protocol: "http:",
      hostname: "localhost",
      origin: "http://localhost:4173",
    })).rejects.toThrow("Unsupported transport");
    expect(fetcher).not.toHaveBeenCalled();
    wipeParsedInvite(invite);
  });

  it("recognizes bracketed IPv6 as an explicit development origin", async () => {
    const invite = await parseInvite(DEEP_LINK, 2_000_000_000_000);
    invite.endpoint = {
      apiBaseUrl: "http://[::1]:4020",
      wsBaseUrl: "ws://[::1]:4020",
      displayHost: "[::1]:4020",
    };
    const fetcher = vi.fn<typeof fetch>().mockRejectedValue(new TypeError("unavailable"));
    vi.stubGlobal("fetch", fetcher);

    await expect(verifyConnectedInviteNode(invite, new AbortController().signal, {
      protocol: "http:",
      hostname: "[::1]",
      origin: "http://[::1]:4173",
    })).rejects.toThrow("Unable to reach node");
    expect(fetcher).toHaveBeenCalledWith("http://[::1]:4020/v1/node", expect.any(Object));
    wipeParsedInvite(invite);
  });

  it("maps a descriptor transport failure without exposing implementation detail", async () => {
    const invite = await parseInvite(DEEP_LINK, 2_000_000_000_000);
    vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockRejectedValue(new TypeError("DNS details")));

    await expect(verifyConnectedInviteNode(
      invite,
      new AbortController().signal,
      VECTOR_LOCATION,
    )).rejects.toThrow("Unable to reach node");
    wipeParsedInvite(invite);
  });
});

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/.{2}/gu) ?? [], (pair) => Number.parseInt(pair, 16));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function ownedBuffer(bytes: Uint8Array): ArrayBuffer {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  return owned.buffer;
}
