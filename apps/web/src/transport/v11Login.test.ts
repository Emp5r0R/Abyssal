import { beforeEach, describe, expect, it, vi } from "vitest";

const fakes = vi.hoisted(() => {
  class FakeExchange {
    static all: FakeExchange[] = [];
    destroyed = false;
    freed = false;
    constructor(readonly step: string, readonly args: unknown[]) {
      FakeExchange.all.push(this);
    }
    destroy(): void {
      this.destroyed = true;
    }
    free(): void {
      this.freed = true;
    }
    static start(...args: unknown[]) {
      return new FakeExchange("start", args);
    }
    static finishRegistration(...args: unknown[]) {
      return new FakeExchange("finishRegistration", args);
    }
    static finishLogin(...args: unknown[]) {
      return new FakeExchange("finishLogin", args);
    }
  }
  const replies: Record<string, () => Record<string, unknown>> = {};
  const runBootstrapExchange = vi.fn(async (_url: string, exchange: FakeExchange) => {
    const reply = replies[exchange.step]?.();
    if (!reply) throw new Error("Wrong information");
    return { ...reply, free: vi.fn() };
  });
  const opaque = {
    startOpaque: vi.fn(),
    finishOpaqueRegistration: vi.fn(),
    finishOpaqueLogin: vi.fn(),
    wipeOpaqueStart: vi.fn((state: Record<string, Uint8Array>) => Object.values(state).forEach((bytes) => bytes.fill(0))),
  };
  return { FakeExchange, replies, runBootstrapExchange, opaque };
});

vi.mock("../generated/abyssal_core/abyssal_core", () => ({ WasmAccountBootstrapExchange: fakes.FakeExchange }));
vi.mock("../security/crypto", () => fakes.opaque);
vi.mock("./v11Account", async (importOriginal) => ({
  ...await importOriginal<typeof import("./v11Account")>(),
  runBootstrapExchange: fakes.runBootstrapExchange,
}));

import { signInV11, type IdentityOperations, type V11SignInInput } from "./v11Login";

const HANDSHAKE = Uint8Array.from({ length: 16 }, (_, index) => index);
const HANDSHAKE_ID = "00010203-0405-0607-0809-0a0b0c0d0e0f";

function sessionReply(created: boolean) {
  return {
    kind: 4,
    created,
    username: "Alice",
    maxRoomsPerUser: 2,
    sessionInactivitySec: 900,
    identityPublic: new Uint8Array(32).fill(0x1d),
    identityPrekeyId: "prekey",
    identityEnvelope: new Uint8Array(8).fill(0xe0),
    deviceStorageShare: new Uint8Array(0),
    sessionId: new Uint8Array(32).fill(0x51),
  };
}

function identity() {
  return {
    createIdentity: vi.fn<IdentityOperations["createIdentity"]>(() => ({
      publicKey: new Uint8Array(32).fill(0x1d),
      prekeyId: "prekey",
      envelope: new Uint8Array(8).fill(0xe0),
    })),
    recoverIdentity: vi.fn<IdentityOperations["recoverIdentity"]>(),
    signRegistrationIdentityProof: vi.fn<IdentityOperations["signRegistrationIdentityProof"]>(() => new Uint8Array(64).fill(0x9f)),
  };
}

function input(overrides: Partial<V11SignInInput> = {}): V11SignInInput {
  return {
    apiBaseUrl: "https://relay.test",
    nodeId: "node-one",
    nodePublicKey: new Uint8Array(32).fill(0x0a),
    bootstrapPublicKey: new Uint8Array(32).fill(0x0b),
    capability: new Uint8Array(32).fill(0x0c),
    accountContext: new Uint8Array(32).fill(0x0d),
    password: new TextEncoder().encode("password"),
    identity: identity(),
    ensureActive: () => undefined,
    ...overrides,
  };
}

const zero = (bytes: Uint8Array) => bytes.every((byte) => byte === 0);

beforeEach(() => {
  vi.clearAllMocks();
  fakes.FakeExchange.all = [];
  for (const key of Object.keys(fakes.replies)) delete fakes.replies[key];
  fakes.runBootstrapExchange.mockClear();
  fakes.opaque.startOpaque.mockImplementation(async () => ({
    registrationState: new Uint8Array([1]),
    registrationRequest: new Uint8Array([2]),
    loginState: new Uint8Array([3, 3]),
    credentialRequest: new Uint8Array([4]),
  }));
  fakes.opaque.finishOpaqueRegistration.mockImplementation(async (_password: Uint8Array, state: Record<string, Uint8Array>) => {
    // The real registration wipes the whole start state, including the login half.
    Object.values(state).forEach((bytes) => bytes.fill(0));
    return { registrationUpload: new Uint8Array([5]), exportKey: new Uint8Array([6]) };
  });
  fakes.opaque.finishOpaqueLogin.mockImplementation(async () => ({
    credentialFinalization: new Uint8Array([7]),
    exportKey: new Uint8Array([8]),
    transportRoot: new Uint8Array(32).fill(0x77),
  }));
});

describe("protocol-v11 sign-in", () => {
  it("signs in a returning account, recovers its identity and hands over the transport keys", async () => {
    const recovered = { public: new Uint8Array(32).fill(0x1d), envelope: new Uint8Array(8).fill(0xe0) };
    fakes.replies.start = () => ({
      kind: 1,
      handshakeId: HANDSHAKE.slice(),
      opaqueResponse: new Uint8Array([0x0e]),
      identityPublic: recovered.public,
      identityEnvelope: recovered.envelope,
    });
    fakes.replies.finishLogin = () => sessionReply(false);
    const operations = identity();
    const login = input({ identity: operations });

    const result = await signInV11(login);

    expect(result.mode).toBe("login");
    expect(result.session.username).toBe("Alice");
    expect(result.keys.transportRoot).toEqual(new Uint8Array(32).fill(0x77));
    expect(result.keys.sessionId).toEqual(result.session.sessionId);
    expect(result.keys.sessionId).not.toBe(result.session.sessionId);
    expect(result.keys.nodePublicKey).not.toBe(login.nodePublicKey);
    expect(fakes.FakeExchange.all.map((exchange) => exchange.step)).toEqual(["start", "finishLogin"]);
    const [startArgs, finishArgs] = fakes.FakeExchange.all.map((exchange) => exchange.args);
    expect(startArgs?.slice(0, 3)).toEqual([login.nodePublicKey, login.bootstrapPublicKey, login.capability]);
    // The OPAQUE requests are wiped with the start state once sign-in ends.
    expect(zero(startArgs![3] as Uint8Array) && zero(startArgs![4] as Uint8Array)).toBe(true);
    expect(finishArgs?.slice(0, 2)).toEqual([login.nodePublicKey, login.bootstrapPublicKey]);
    // The handshake and finalization buffers are wiped once the request is sealed.
    expect(zero(finishArgs![2] as Uint8Array) && zero(finishArgs![3] as Uint8Array)).toBe(true);
    const [exportKey, context, envelope, publicKey] = operations.recoverIdentity.mock.calls[0]!;
    expect(context).toBe(login.accountContext);
    expect(zero(exportKey) && zero(envelope) && zero(publicKey)).toBe(true);
    expect(fakes.FakeExchange.all.every((exchange) => exchange.destroyed && exchange.freed)).toBe(true);
    expect(fakes.opaque.wipeOpaqueStart).toHaveBeenCalledOnce();
  });

  it("registers on first use, then logs in with the kept login state", async () => {
    fakes.replies.start = () => ({
      kind: 2,
      handshakeId: HANDSHAKE.slice(),
      challenge: new Uint8Array(32).fill(0xc4),
      opaqueResponse: new Uint8Array([0x0e]),
    });
    fakes.replies.finishRegistration = () => ({ kind: 3, handshakeId: HANDSHAKE.slice(), opaqueResponse: new Uint8Array([0x0f]) });
    fakes.replies.finishLogin = () => sessionReply(true);
    const operations = identity();
    const registration = input({ identity: operations });

    const result = await signInV11(registration);

    expect(result.mode).toBe("registration");
    expect(fakes.FakeExchange.all.map((exchange) => exchange.step)).toEqual(["start", "finishRegistration", "finishLogin"]);
    expect(operations.createIdentity).toHaveBeenCalledWith(expect.any(Uint8Array), registration.accountContext);
    const proofArgs = operations.signRegistrationIdentityProof.mock.calls[0]!;
    expect(proofArgs[0]).toBe("node-one");
    expect(proofArgs[1]).toBe(HANDSHAKE_ID);
    // finishOpaqueRegistration wiped the start state, yet the login still sees the original login state.
    const loginState = fakes.opaque.finishOpaqueLogin.mock.calls[0]![1] as { loginState: Uint8Array };
    expect(loginState.loginState).toBeInstanceOf(Uint8Array);
    expect(fakes.opaque.finishOpaqueLogin.mock.calls[0]![2]).toEqual(new Uint8Array([0]));
    const registrationArgs = fakes.FakeExchange.all[1]!.args;
    expect(registrationArgs.slice(4, 6)).toEqual([new Uint8Array(32).fill(0), "prekey"]);
    expect(zero(registrationArgs[7] as Uint8Array)).toBe(true);
    expect(fakes.FakeExchange.all.every((exchange) => exchange.destroyed && exchange.freed)).toBe(true);
  });

  it("checks the kept login state is the one OPAQUE started with", async () => {
    let seen: number[] = [];
    fakes.opaque.finishOpaqueLogin.mockImplementationOnce(async (_password: Uint8Array, state: { loginState: Uint8Array }) => {
      seen = Array.from(state.loginState);
      return { credentialFinalization: new Uint8Array([7]), exportKey: new Uint8Array([8]), transportRoot: new Uint8Array(32).fill(0x77) };
    });
    fakes.replies.start = () => ({ kind: 2, handshakeId: HANDSHAKE.slice(), challenge: new Uint8Array(32), opaqueResponse: new Uint8Array([1]) });
    fakes.replies.finishRegistration = () => ({ kind: 3, handshakeId: HANDSHAKE.slice(), opaqueResponse: new Uint8Array([2]) });
    fakes.replies.finishLogin = () => sessionReply(true);

    await signInV11(input());
    expect(seen).toEqual([3, 3]);
  });

  it.each([
    ["a failure at the start", false, { start: () => ({ kind: 0 }) }],
    ["a session where a continuation belongs", false, {
      start: () => ({ kind: 2, handshakeId: HANDSHAKE.slice(), challenge: new Uint8Array(32), opaqueResponse: new Uint8Array([1]) }),
      finishRegistration: () => sessionReply(true),
    }],
    ["a failure in place of the session", true, {
      start: () => ({ kind: 1, handshakeId: HANDSHAKE.slice(), opaqueResponse: new Uint8Array([1]), identityPublic: new Uint8Array(32), identityEnvelope: new Uint8Array(8) }),
      finishLogin: () => ({ kind: 0 }),
    }],
  ])("rejects %s, wiping any transport root and freeing every exchange", async (_label, reachesLogin, replies) => {
    Object.assign(fakes.replies, replies);
    const root = new Uint8Array(32).fill(0x77);
    fakes.opaque.finishOpaqueLogin.mockImplementation(async () => ({
      credentialFinalization: new Uint8Array([7]),
      exportKey: new Uint8Array([8]),
      transportRoot: root,
    }));

    await expect(signInV11(input())).rejects.toThrow("Wrong information");
    expect(fakes.FakeExchange.all.every((exchange) => exchange.destroyed && exchange.freed)).toBe(true);
    // Only a completed OPAQUE login yields a transport root; when it does, it must not outlive the failure.
    expect(fakes.opaque.finishOpaqueLogin.mock.calls.length > 0).toBe(reachesLogin);
    expect(zero(root)).toBe(reachesLogin);
    expect(fakes.opaque.wipeOpaqueStart).toHaveBeenCalledOnce();
  });

  it("stops between steps once the caller is no longer active", async () => {
    fakes.replies.start = () => ({ kind: 1, handshakeId: HANDSHAKE.slice(), opaqueResponse: new Uint8Array([1]), identityPublic: new Uint8Array(32), identityEnvelope: new Uint8Array(8) });
    fakes.replies.finishLogin = () => sessionReply(false);
    let active = true;
    const operations = identity();
    operations.recoverIdentity.mockImplementation(() => {
      active = false;
    });

    await expect(signInV11(input({
      identity: operations,
      ensureActive: () => {
        if (!active) throw new Error("Action unavailable");
      },
    }))).rejects.toThrow("Action unavailable");
    expect(fakes.FakeExchange.all.map((exchange) => exchange.step)).toEqual(["start"]);
  });
});
