import { WasmAccountBootstrapExchange, type WasmAccountBootstrapResponse } from "../generated/abyssal_core/abyssal_core";
import {
  finishOpaqueLogin,
  finishOpaqueRegistration,
  startOpaque,
  wipeOpaqueStart,
  type OpaqueStartState,
} from "../security/crypto";
import { attachmentIdString } from "./v11Attachment";
import {
  BootstrapKind,
  readBootstrapSession,
  runBootstrapExchange,
  type BootstrapSession,
  type TransportKeys,
} from "./v11Account";

/** The identity operations sign-in needs from the in-memory cipher. */
export interface IdentityOperations {
  createIdentity(exportKey: Uint8Array, context: Uint8Array): { publicKey: Uint8Array; prekeyId: string; envelope: Uint8Array };
  recoverIdentity(exportKey: Uint8Array, context: Uint8Array, envelope: Uint8Array, publicKey: Uint8Array): void;
  signRegistrationIdentityProof(
    nodeId: string,
    handshakeId: string,
    challenge: Uint8Array,
    registrationUpload: Uint8Array,
    identityPublic: Uint8Array,
    identityPrekeyId: string,
    identityEnvelope: Uint8Array,
  ): Uint8Array;
}

export interface V11SignInInput {
  apiBaseUrl: string;
  nodeId: string;
  nodePublicKey: Uint8Array;
  bootstrapPublicKey: Uint8Array;
  capability: Uint8Array;
  accountContext: Uint8Array;
  password: Uint8Array;
  identity: IdentityOperations;
  ensureActive: () => void;
  signal?: AbortSignal;
  fetcher?: typeof fetch;
}

export interface V11SignInResult {
  /** Which path the relay took: a first use of the invite, or a returning sign-in. */
  mode: "registration" | "login";
  session: BootstrapSession;
  keys: TransportKeys;
}

function take(response: WasmAccountBootstrapResponse, kind: BootstrapKind): WasmAccountBootstrapResponse {
  if (response.kind !== kind) {
    response.free();
    throw new Error("Wrong information");
  }
  return response;
}

/**
 * Signs in (or creates the account on first use of an invite) over the
 * protocol-v11 encrypted bootstrap. On success the caller owns the returned
 * transport keys and session bytes and must wipe them.
 */
export async function signInV11(input: V11SignInInput): Promise<V11SignInResult> {
  const { apiBaseUrl, nodePublicKey, bootstrapPublicKey, signal, fetcher } = input;
  const opaque = await startOpaque(input.password);
  // Registration wipes the whole OPAQUE state, but v11 registration continues with a login.
  const loginState = opaque.loginState.slice();
  const loginOnly = (): OpaqueStartState => ({
    registrationState: new Uint8Array(0),
    registrationRequest: new Uint8Array(0),
    loginState,
    credentialRequest: new Uint8Array(0),
  });
  const exchanges: WasmAccountBootstrapExchange[] = [];
  const track = (exchange: WasmAccountBootstrapExchange) => {
    exchanges.push(exchange);
    return exchange;
  };
  let transportRoot: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  try {
    input.ensureActive();
    const start = await runBootstrapExchange(apiBaseUrl, track(WasmAccountBootstrapExchange.start(
      nodePublicKey,
      bootstrapPublicKey,
      input.capability,
      opaque.registrationRequest,
      opaque.credentialRequest,
    )), signal, fetcher);
    input.ensureActive();
    let loginHandshake: Uint8Array;
    let credentialResponse: Uint8Array;
    try {
      if (start.kind === BootstrapKind.RegistrationStart) {
        const handshake = start.handshakeId;
        const challenge = start.challenge;
        const registrationResponse = start.opaqueResponse;
        const registration = await finishOpaqueRegistration(input.password, opaque, registrationResponse);
        registrationResponse.fill(0);
        const identity = input.identity.createIdentity(registration.exportKey, input.accountContext);
        let proof: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
        try {
          proof = input.identity.signRegistrationIdentityProof(
            input.nodeId,
            attachmentIdString(handshake),
            challenge,
            registration.registrationUpload,
            identity.publicKey,
            identity.prekeyId,
            identity.envelope,
          );
          input.ensureActive();
          const continuation = take(await runBootstrapExchange(apiBaseUrl, track(WasmAccountBootstrapExchange.finishRegistration(
            nodePublicKey,
            bootstrapPublicKey,
            handshake,
            registration.registrationUpload,
            identity.publicKey,
            identity.prekeyId,
            identity.envelope,
            proof,
          )), signal, fetcher), BootstrapKind.RegistrationContinuation);
          try {
            loginHandshake = continuation.handshakeId;
            credentialResponse = continuation.opaqueResponse;
          } finally {
            continuation.free();
          }
        } finally {
          proof.fill(0);
          identity.publicKey.fill(0);
          identity.envelope.fill(0);
          registration.registrationUpload.fill(0);
          registration.exportKey.fill(0);
          handshake.fill(0);
          challenge.fill(0);
        }
        input.ensureActive();
        const login = await finishOpaqueLogin(input.password, loginOnly(), credentialResponse);
        login.exportKey.fill(0);
        transportRoot = login.transportRoot;
        credentialResponse.fill(0);
        const session = await finishLogin(input, loginHandshake, login.credentialFinalization, track);
        return {
          mode: "registration",
          session,
          keys: { nodePublicKey: nodePublicKey.slice(), sessionId: session.sessionId.slice(), transportRoot },
        };
      }
      if (start.kind !== BootstrapKind.LoginStart) throw new Error("Wrong information");
      loginHandshake = start.handshakeId;
      credentialResponse = start.opaqueResponse;
      const identityPublic = start.identityPublic;
      const identityEnvelope = start.identityEnvelope;
      const login = await finishOpaqueLogin(input.password, opaque, credentialResponse);
      credentialResponse.fill(0);
      transportRoot = login.transportRoot;
      try {
        input.identity.recoverIdentity(login.exportKey, input.accountContext, identityEnvelope, identityPublic);
      } finally {
        login.exportKey.fill(0);
        identityPublic.fill(0);
        identityEnvelope.fill(0);
      }
      input.ensureActive();
      const session = await finishLogin(input, loginHandshake, login.credentialFinalization, track);
      return {
        mode: "login",
        session,
        keys: { nodePublicKey: nodePublicKey.slice(), sessionId: session.sessionId.slice(), transportRoot },
      };
    } finally {
      start.free();
    }
  } catch (error) {
    transportRoot.fill(0);
    throw error;
  } finally {
    loginState.fill(0);
    wipeOpaqueStart(opaque);
    for (const exchange of exchanges) {
      exchange.destroy();
      exchange.free();
    }
  }
}

async function finishLogin(
  input: V11SignInInput,
  handshake: Uint8Array,
  finalization: Uint8Array,
  track: (exchange: WasmAccountBootstrapExchange) => WasmAccountBootstrapExchange,
): Promise<BootstrapSession> {
  try {
    const response = take(await runBootstrapExchange(input.apiBaseUrl, track(WasmAccountBootstrapExchange.finishLogin(
      input.nodePublicKey,
      input.bootstrapPublicKey,
      handshake,
      finalization,
    )), input.signal, input.fetcher), BootstrapKind.Session);
    try {
      return readBootstrapSession(response);
    } finally {
      response.free();
    }
  } finally {
    handshake.fill(0);
    finalization.fill(0);
  }
}
