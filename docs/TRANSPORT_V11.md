# Encrypted transport (protocol v11)

From release 4.0 the official web and Android clients talk to the relay only
through protocol v11. It removes readable request metadata from the path
between the client and the relay, including any TLS-terminating proxy or CDN.
End-to-end message encryption (direct protocol v9, MLS protocol v10) is
unchanged and still runs inside these records.

## What each request looks like

| Purpose | Route | On the wire |
| --- | --- | --- |
| Node identity | `GET /v1/node` | The node-signed descriptor (public): node key, locators and the relay's process-lifetime bootstrap HPKE key. |
| Sign-in and registration | `POST /v1/bootstrap` | One fixed-size record sealed to the bootstrap key. It carries the invite capability, the OPAQUE messages and the identity material. |
| WebSocket ticket, logout | `POST /v1/control` | One 4,170-byte AEAD record. It is bound to the session's transport root and carries the signed build attestation. |
| Messaging | `GET /v1/ws`, subprotocol `abyssal-v11` | An encrypted ClientHello that carries the one-time ticket, then directional AEAD records with monotonic counters. |
| Attachments | `POST /v3/attachment` | A 4,170-byte sealed action record, then fixed 262,184-byte sealed frames padded to a power-of-two bucket. |

- No bearer token exists on the client. Each session authenticates with a
  transport root derived from the OPAQUE login. The relay never sees the raw
  session key, and the root never leaves the device's memory.
- Registration finishes with an automatic OPAQUE login. A usable session exists
  only after that login succeeds.
- Every record is versioned and bound to its direction, node, session and
  counter. Replayed, reordered, reflected or altered records fail closed. A
  reply that does not authenticate is treated as an ended session, never as data.
- The WebSocket ticket travels only inside the encrypted ClientHello, never in a
  header or subprotocol. Nothing is published to a socket before the relay's
  ServerHello authenticates.
- An attachment upload declares its ciphertext length and SHA-256 inside the
  sealed action record. The relay rejects any stream that differs. Android
  streams large files from storage without holding the ciphertext: it encrypts
  twice with the same per-upload nonces, which never leave the Rust core. If the
  file changes between the two passes, the upload is refused before anything is
  sealed.

## What it does not hide

- The relay is still the routing and policy authority. After decryption it
  sees what it needs for routing, membership, authorization, quotas, retention
  and expiry, exactly as before.
- IP addresses, timing, packet counts and padded sizes stay visible to the
  network. Hiding them would need an anonymity network and cover traffic, which
  this release does not provide.
- The signed node descriptor and invite locators are public by design.

## Compatibility

- 4.0 clients cannot talk to older relays, and older clients cannot talk to a
  4.0 deployment: the relay admits only the current signed build of each
  platform, so every release already requires updating the Android app.
- During the 4.0 transition the relay still answers the old protocol-v2 routes,
  but official clients never use them. A ticket issued over the encrypted
  control channel can be redeemed only inside an encrypted ClientHello, never
  through the legacy subprotocol. The legacy routes will be removed in a later
  release.
