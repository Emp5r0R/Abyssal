// Protocol-v11 client for the live relay integration check. It speaks only
// the sealed routes (/v1/bootstrap, /v1/control, /v1/ws with the abyssal-v11
// subprotocol, /v3/attachment) through the shared WASM core, so the check
// exercises exactly what the web and Android clients send.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export const BootstrapKind = Object.freeze({ Failure: 0, LoginStart: 1, RegistrationStart: 2, Continuation: 3, Session: 4 });
export const ControlKind = Object.freeze({ Failure: 0, WsTicket: 1, LoggedOut: 2, BuildRejected: 3, PlatformConflict: 4 });
export const AttachmentKind = Object.freeze({ Failure: 0, Success: 1, UploadAccepted: 2, DownloadAccepted: 3 });
const FrameKind = Object.freeze({ Data: 1, Padding: 2, End: 3 });

export const CONTROL_RECORD_BYTES = 4_170;
export const ATTACHMENT_ACTION_RECORD_BYTES = 4_170;
export const ATTACHMENT_STREAM_PAYLOAD_BYTES = 256 * 1024;
export const ATTACHMENT_STREAM_FRAME_BYTES = 262_184;
export const ATTACHMENT_CIPHER_VERSION = 2;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

export function uuidBytes(id) {
  assert.match(id, UUID);
  return Uint8Array.from(Buffer.from(id.replaceAll("-", ""), "hex"));
}

export function uuidString(bytes) {
  assert.equal(bytes.byteLength, 16);
  const hex = Buffer.from(bytes).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * @param wasm the initialized WASM module exports
 * @param baseUrl the relay origin
 */
export function v11Client(wasm, baseUrl) {
  /** POSTs one sealed record; the relay answers every v11 request 200 with a sealed body. */
  async function post(path, body) {
    const response = await fetch(`${baseUrl}${path}`, {
      method: "POST",
      cache: "no-store",
      headers: { "content-type": "application/octet-stream", accept: "application/octet-stream" },
      body,
    });
    assert.equal(response.status, 200, `${path} answered ${response.status}`);
    assert.match(response.headers.get("cache-control") ?? "", /no-store/u);
    return new Uint8Array(await response.arrayBuffer());
  }

  /** Runs one bootstrap exchange and returns its opened reply, copied out of WASM. */
  async function bootstrap(exchange) {
    try {
      const reply = exchange.openResponse(await post("/v1/bootstrap", exchange.requestBytes()));
      try {
        const read = (field) => { try { return reply[field]; } catch { return undefined; } };
        return {
          kind: reply.kind,
          handshakeId: read("handshakeId"),
          opaqueResponse: read("opaqueResponse"),
          challenge: read("challenge"),
          identityPublic: read("identityPublic"),
          identityPrekeyId: read("identityPrekeyId"),
          identityEnvelope: read("identityEnvelope"),
          created: read("created"),
          username: read("username"),
          maxRoomsPerUser: read("maxRoomsPerUser"),
          sessionInactivitySec: read("sessionInactivitySec"),
          sessionId: read("sessionId"),
          deviceStorageShare: read("deviceStorageShare"),
        };
      } finally {
        reply.free();
      }
    } finally {
      exchange.destroy();
      exchange.free();
    }
  }

  /** The OPAQUE start for [password], parsed out of the WASM JSON reply. */
  function opaqueStart(password) {
    const parsed = JSON.parse(wasm.opaqueClientStart(password));
    return {
      registrationState: new Uint8Array(parsed.registration_state),
      registrationRequest: new Uint8Array(parsed.registration_request),
      loginState: new Uint8Array(parsed.login_state),
      credentialRequest: new Uint8Array(parsed.credential_request),
    };
  }

  function finishLoginOrJunk(password, loginState, credentialResponse) {
    try {
      const finished = JSON.parse(wasm.opaqueClientFinishLogin(password, loginState, credentialResponse));
      return {
        finalization: new Uint8Array(finished.credential_finalization),
        exportKey: new Uint8Array(finished.export_key),
        transportRoot: new Uint8Array(finished.transport_root),
      };
    } catch {
      // A wrong password fails on the client; finish with junk so the relay must reject it too.
      return { finalization: crypto.getRandomValues(new Uint8Array(64)), exportKey: null, transportRoot: null };
    }
  }

  /** The first bootstrap reply's kind for [password]; the relay cannot check a password at the start. */
  async function startKind(invite, password) {
    const opaque = opaqueStart(password);
    const reply = await bootstrap(wasm.WasmAccountBootstrapExchange.start(
      invite.nodePublicKey, invite.bootstrapPublicKey, invite.capability, opaque.registrationRequest, opaque.credentialRequest,
    ));
    return reply.kind;
  }

  /**
   * Signs in over the sealed bootstrap. A first use registers: the identity is
   * created from the OPAQUE export key, proven to the relay, then the account
   * logs in. Returns the session with its transport keys, or the failing reply kind.
   */
  async function signIn(invite, password, { expectRegistration } = {}) {
    const opaque = opaqueStart(password);
    const start = await bootstrap(wasm.WasmAccountBootstrapExchange.start(
      invite.nodePublicKey, invite.bootstrapPublicKey, invite.capability, opaque.registrationRequest, opaque.credentialRequest,
    ));
    let identity = null;
    let login;
    let handshake;
    if (start.kind === BootstrapKind.RegistrationStart) {
      assert.notEqual(expectRegistration, false, "the relay offered registration for an existing account");
      const finished = JSON.parse(wasm.opaqueClientFinishRegistration(password, opaque.registrationState, start.opaqueResponse));
      const exportKey = new Uint8Array(finished.export_key);
      const upload = new Uint8Array(finished.registration_upload);
      identity = wasm.WasmE2eeSession.create(exportKey);
      const publicKey = identity.publicKey();
      const prekeyId = identity.prekeyId();
      const envelope = identity.sealIdentity(exportKey, invite.accountContext);
      const proof = identity.signRegistrationIdentityProof(
        invite.nodeId, uuidString(start.handshakeId), start.challenge, upload, publicKey, prekeyId, envelope,
      );
      exportKey.fill(0);
      const continuation = await bootstrap(wasm.WasmAccountBootstrapExchange.finishRegistration(
        invite.nodePublicKey, invite.bootstrapPublicKey, start.handshakeId, upload, publicKey, prekeyId, envelope, proof,
      ));
      if (continuation.kind !== BootstrapKind.Continuation) {
        identity.free();
        return { kind: continuation.kind };
      }
      login = finishLoginOrJunk(password, opaque.loginState, continuation.opaqueResponse);
      handshake = continuation.handshakeId;
      login.exportKey?.fill(0);
    } else if (start.kind === BootstrapKind.LoginStart) {
      assert.notEqual(expectRegistration, true, "the relay offered a login for a fresh invite");
      login = finishLoginOrJunk(password, opaque.loginState, start.opaqueResponse);
      handshake = start.handshakeId;
      if (login.exportKey) {
        identity = wasm.WasmE2eeSession.recover(login.exportKey, invite.accountContext, start.identityEnvelope, start.identityPublic);
        login.exportKey.fill(0);
      }
    } else {
      return { kind: start.kind };
    }
    const session = await bootstrap(wasm.WasmAccountBootstrapExchange.finishLogin(
      invite.nodePublicKey, invite.bootstrapPublicKey, handshake, login.finalization,
    ));
    login.finalization.fill(0);
    if (session.kind !== BootstrapKind.Session) {
      identity?.free();
      return { kind: session.kind };
    }
    assert.equal(session.created, start.kind === BootstrapKind.RegistrationStart);
    return {
      kind: session.kind,
      created: session.created,
      username: session.username,
      node_id: invite.nodeId,
      identity,
      identityPublic: session.identityPublic,
      identityPrekeyId: session.identityPrekeyId,
      deviceStorageShare: session.deviceStorageShare,
      keys: { nodePublicKey: invite.nodePublicKey.slice(), sessionId: session.sessionId, transportRoot: login.transportRoot },
    };
  }

  /** One control exchange: its reply kind and fields, or "unopenable" when the relay no longer knows the session. */
  async function control(exchange) {
    try {
      const sealed = await post("/v1/control", exchange.requestBytes());
      assert.equal(sealed.byteLength, CONTROL_RECORD_BYTES);
      let reply;
      try {
        reply = exchange.openResponse(sealed);
      } catch {
        return { kind: "unopenable" };
      }
      try {
        return reply.kind === ControlKind.WsTicket
          ? { kind: reply.kind, ticket: reply.ticket, expiresInSec: reply.expiresInSec }
          : { kind: reply.kind };
      } finally {
        reply.free();
      }
    } finally {
      exchange.destroy();
      exchange.free();
    }
  }

  function issueTicket(account, attestation) {
    const { nodePublicKey, sessionId, transportRoot } = account.keys;
    return control(wasm.WasmControlExchange.issueWsTicket(
      nodePublicKey, sessionId, transportRoot, attestation.platform, attestation.version, attestation.buildSignatureB64,
    ));
  }

  function logout(account) {
    const { nodePublicKey, sessionId, transportRoot } = account.keys;
    return control(wasm.WasmControlExchange.logout(nodePublicKey, sessionId, transportRoot));
  }

  /**
   * A WebSocket-shaped wrapper over one sealed v11 socket: "open" fires only
   * after the relay's ServerHello authenticates, "message" events carry the
   * opened text, and send() seals. Any frame that does not authenticate
   * closes the socket.
   */
  class SealedSocket extends EventTarget {
    static OPEN = 1;
    #socket;
    #connection;
    #ready = false;

    constructor(account, ticket) {
      super();
      const { nodePublicKey, sessionId, transportRoot } = account.keys;
      const ticketBytes = new TextEncoder().encode(ticket);
      this.#connection = new wasm.WasmWsClientConnection(nodePublicKey, sessionId, transportRoot, ticketBytes);
      ticketBytes.fill(0);
      this.#socket = new WebSocket(`${baseUrl.replace(/^http/u, "ws")}/v1/ws`, ["abyssal-v11"]);
      this.#socket.binaryType = "arraybuffer";
      this.#socket.addEventListener("open", () => this.#socket.send(this.#connection.clientHelloBytes()));
      this.#socket.addEventListener("message", (event) => this.#receive(event.data));
      this.#socket.addEventListener("error", (event) => this.dispatchEvent(Object.assign(new Event("error"), { error: event?.error, message: event?.message })));
      this.#socket.addEventListener("close", (event) => {
        if (process.env.ABYSSAL_V11_DEBUG) console.error(`[v11] socket closed code=${event.code} reason=${event.reason} ready=${this.#ready}`);
        this.#destroy();
        this.dispatchEvent(Object.assign(new Event("close"), { code: event.code, reason: event.reason }));
      });
    }

    get readyState() {
      return this.#ready && this.#socket.readyState === WebSocket.OPEN ? WebSocket.OPEN : this.#socket.readyState === WebSocket.OPEN ? WebSocket.CONNECTING : this.#socket.readyState;
    }

    #receive(data) {
      if (!(data instanceof ArrayBuffer) || !this.#connection) {
        this.#socket.close(1008, "plaintext frame");
        return;
      }
      try {
        if (!this.#ready) {
          this.#connection.openServerHello(new Uint8Array(data));
          assert.ok(this.#connection.ready());
          this.#ready = true;
          this.dispatchEvent(new Event("open"));
          return;
        }
        const plaintext = this.#connection.openFrame(new Uint8Array(data));
        const text = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
        plaintext.fill(0);
        this.dispatchEvent(Object.assign(new Event("message"), { data: text }));
      } catch (error) {
        if (process.env.ABYSSAL_V11_DEBUG) console.error(`[v11] unauthenticated frame: ${error?.message ?? error}`);
        this.#socket.close(1008, "unauthenticated frame");
      }
    }

    send(text) {
      if (process.env.ABYSSAL_V11_DEBUG) console.error(`[v11] send ${text.slice(0, 40)} (${text.length})`);
      assert.ok(this.#ready && this.#connection, "sealed socket is not open");
      this.#socket.send(this.#connection.sealFrame(new TextEncoder().encode(text)));
    }

    /** Sends raw bytes without sealing, to check the relay refuses them. */
    sendRaw(data) {
      this.#socket.send(data);
    }

    close(code, reason) {
      this.#socket.close(code, reason);
    }

    #destroy() {
      const connection = this.#connection;
      this.#connection = null;
      this.#ready = false;
      if (connection) {
        connection.destroy();
        connection.free();
      }
    }
  }

  async function attachmentAction(exchange) {
    try {
      const sealed = await post("/v3/attachment", exchange.requestBytes());
      assert.equal(sealed.byteLength, ATTACHMENT_ACTION_RECORD_BYTES);
      const reply = exchange.openResponse(sealed);
      try {
        return {
          kind: reply.kind,
          attachmentId: reply.kind === AttachmentKind.UploadAccepted ? uuidString(reply.attachmentId) : null,
        };
      } finally {
        reply.free();
      }
    } finally {
      exchange.destroy();
      exchange.free();
    }
  }

  /** Uploads [ciphertext] (an attachment blob); returns the reply kind and attachment ID. */
  async function uploadAttachment(account, { chatId, messageId, mediaType = "FILE", oneTime = false, deleteAfterDownload = oneTime, ttlSec = 0 }, ciphertext) {
    const { nodePublicKey, sessionId, transportRoot } = account.keys;
    const digest = new Uint8Array(createHash("sha256").update(ciphertext).digest());
    const exchange = wasm.WasmAttachmentExchange.beginUpload(
      nodePublicKey, sessionId, transportRoot, chatId, messageId, mediaType, ATTACHMENT_CIPHER_VERSION,
      BigInt(ciphertext.byteLength), digest, oneTime, deleteAfterDownload || oneTime, ttlSec,
    );
    try {
      const parts = [exchange.requestBytes()];
      let frames = 0;
      for (let offset = 0; offset < ciphertext.byteLength; offset += ATTACHMENT_STREAM_PAYLOAD_BYTES) {
        parts.push(exchange.sealDataFrame(ciphertext.subarray(offset, offset + ATTACHMENT_STREAM_PAYLOAD_BYTES)));
        frames += 1;
      }
      assert.equal(frames, exchange.uploadDataFrameCount());
      for (let frame = frames; frame < exchange.uploadBucketFrameCount(); frame += 1) parts.push(exchange.sealPaddingFrame());
      parts.push(exchange.sealEndFrame());
      const sealed = await post("/v3/attachment", Buffer.concat(parts));
      assert.equal(sealed.byteLength, ATTACHMENT_ACTION_RECORD_BYTES);
      const reply = exchange.openResponse(sealed);
      try {
        return {
          kind: reply.kind,
          attachmentId: reply.kind === AttachmentKind.UploadAccepted ? uuidString(reply.attachmentId) : null,
        };
      } finally {
        reply.free();
      }
    } finally {
      exchange.destroy();
      exchange.free();
    }
  }

  /**
   * Downloads one attachment. Returns the reply kind; on DownloadAccepted also
   * the ciphertext and any destructive claim. [stopAfterHead] reads only the
   * head record, leaving a claimed download uncompleted (as a dropped connection would).
   */
  async function downloadAttachment(account, attachmentId, { stopAfterHead = false } = {}) {
    const { nodePublicKey, sessionId, transportRoot } = account.keys;
    const exchange = wasm.WasmAttachmentExchange.beginDownload(nodePublicKey, sessionId, transportRoot, uuidBytes(attachmentId));
    try {
      const response = await fetch(`${baseUrl}/v3/attachment`, {
        method: "POST",
        cache: "no-store",
        headers: { "content-type": "application/octet-stream" },
        body: exchange.requestBytes(),
      });
      assert.equal(response.status, 200);
      const body = new Uint8Array(await response.arrayBuffer());
      assert.ok(body.byteLength >= ATTACHMENT_ACTION_RECORD_BYTES);
      const head = exchange.openResponse(body.subarray(0, ATTACHMENT_ACTION_RECORD_BYTES));
      let total;
      let claim;
      try {
        if (head.kind !== AttachmentKind.DownloadAccepted) return { kind: head.kind };
        total = Number(head.ciphertextLen);
        claim = head.claimId.byteLength > 0 ? uuidString(head.claimId) : null;
      } finally {
        head.free();
      }
      if (stopAfterHead) return { kind: AttachmentKind.DownloadAccepted, claim };
      const chunks = [];
      let offset = ATTACHMENT_ACTION_RECORD_BYTES;
      for (;;) {
        assert.ok(offset + ATTACHMENT_STREAM_FRAME_BYTES <= body.byteLength, "download ended before its end frame");
        const frame = exchange.openStreamFrame(body.subarray(offset, offset + ATTACHMENT_STREAM_FRAME_BYTES));
        offset += ATTACHMENT_STREAM_FRAME_BYTES;
        try {
          if (frame.kind === FrameKind.End) break;
          if (frame.kind === FrameKind.Data) chunks.push(frame.payload);
        } finally {
          frame.free();
        }
      }
      assert.equal(offset, body.byteLength);
      assert.ok(exchange.streamComplete());
      const ciphertext = new Uint8Array(Buffer.concat(chunks));
      assert.equal(ciphertext.byteLength, total);
      return { kind: AttachmentKind.DownloadAccepted, ciphertext, claim };
    } finally {
      exchange.destroy();
      exchange.free();
    }
  }

  function completeDownload(account, attachmentId, claim) {
    const { nodePublicKey, sessionId, transportRoot } = account.keys;
    return attachmentAction(wasm.WasmAttachmentExchange.completeDownload(
      nodePublicKey, sessionId, transportRoot, uuidBytes(attachmentId), uuidBytes(claim),
    ));
  }

  function releaseDownload(account, attachmentId, claim) {
    const { nodePublicKey, sessionId, transportRoot } = account.keys;
    return attachmentAction(wasm.WasmAttachmentExchange.releaseDownload(
      nodePublicKey, sessionId, transportRoot, uuidBytes(attachmentId), uuidBytes(claim),
    ));
  }

  function deleteAttachment(account, attachmentId) {
    const { nodePublicKey, sessionId, transportRoot } = account.keys;
    return attachmentAction(wasm.WasmAttachmentExchange.deleteAttachment(
      nodePublicKey, sessionId, transportRoot, uuidBytes(attachmentId),
    ));
  }

  return {
    startKind,
    signIn,
    issueTicket,
    logout,
    SealedSocket,
    uploadAttachment,
    downloadAttachment,
    completeDownload,
    releaseDownload,
    deleteAttachment,
  };
}
