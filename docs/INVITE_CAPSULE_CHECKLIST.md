# Invite Capsule Acceptance

No tag, APK publication or production deployment until every release check
below has evidence. A passing checkpoint is not permission to publish the older
pre-QR Android package or bypass signed release admission.

## Implemented Boundaries

- Canonical, bounded CBOR capsule and descriptor codecs in `abyssal-invite`,
  with a separate node Ed25519 identity and 256-bit bootstrap capability.
- Shared Rust verification exposed through WASM and UniFFI. Normal account
  entry is invite plus password, followed by node verification and OPAQUE.
- Server capability expiry, atomic registration consumption, session limits
  and keyed lookup; messaging v9/v10 remains separate from bootstrap.
- Web and Android explicit camera entry and local PNG/JPEG image selection.
  Images are not uploaded, opened as URLs, rendered as markup or persisted by
  the QR pipeline. Signed invite validation remains mandatory after decoding.
- Shared raster bounds, MIME/magic checks, inert metadata, stream cancellation,
  camera teardown, and a bounded pure-image decode fallback for dense generated
  codes. Independent `qrencode` output is a regression fixture on both clients.
- One-shot operator QR rendering from stdin in terminal or explicit PNG mode.
  PNG output contains a bearer credential; saving it is an operator decision.
- Signed Onion v3/I2P B32 locator issuance and server ingress profiles. Existing
  clients reject private-only capsules without resolving their hostnames.
- Deterministic signed web archives readable by the unprivileged container,
  without copying local source-directory permission mistakes into the archive.
- Dependency advisory warnings are fatal, including yanked dependencies.

## Automated Verification

Run against the final integrated source, not an earlier checkpoint:

```bash
./scripts/test-all.sh crypto
./scripts/test-all.sh all
node scripts/test-invite-qr-roundtrip.mjs
python3 scripts/test-private-transport-profiles.py --tor /usr/bin/tor --i2pd /usr/bin/i2pd
```

Use Node 26.7.0, the pinned Rust/NDK/UniFFI toolchain, `qrencode`, and actual
installed daemon paths. The native I2P test needs Linux user/network
namespaces; an unavailable namespace or executable is not a successful test.
`all` includes web lint/unit/build, Rust tests/Clippy, Android JVM/lint/Kotlin
checks, disposable signed-invite OPAQUE/direct/MLS integration, deployment
and generated-artifact checks, and live npm/RustSec audits. It never packages
an APK or AAB. Do not bypass a stale artifact or unavailable advisory check.

With a local Vite server and Python Playwright/Chromium, run
`python3 scripts/test-qr-browser.py http://127.0.0.1:4197`. This checks real
PNG/JPEG and simulated camera frames at desktop/mobile sizes, hostile inputs,
track cleanup, layout, and absence of login or external network requests. It
isolates the entrance mount, not the QR parser; it is not a full release-origin
attestation or physical camera test. The native renderer round-trip also uses
the real shared WASM raster/parser and client QR decoder, not a mocked decoder.

## Qualification Evidence

On 2026-09-06, source `0f4e898f4d12b0c2c0dbca2345f96f5c98aa1758`
passed hosted CI (run `34037354761`) and CodeQL (run `34037354781`).
On the paired Android 16 device, the attested debug build reached account
entry; camera denial/regrant and background teardown were checked. Canceling
the system image picker returned to empty account entry. Importing the
independent `invite-qrencode.png` fixture through the local media provider
populated the expected invite, left the password empty and login disabled.
These observations do not replace the remaining physical camera checks.

An isolated Tor 0.4.9.11 service on the operator's ARM64 host forwarded to a
disposable current-source relay through a loopback SSH tunnel. A separate Tor
probe retrieved the signed descriptor and health response. The descriptor
matched the locally verified node identity and advertised Onion locator.
After restarting the service, its Onion identity was unchanged, descriptor
retrieval passed again, and a ticket obtained through test OPAQUE registration
was accepted with WebSocket HTTP status 101 through the Onion service. Initial
requests during network startup timed out; success required established
circuits. This qualifies the supplied Tor forwarding profile with test state,
not a production overlay deployment or a claim of anonymity.

The isolated I2P 2.61.0 instance loaded an owner-only destination key and
populated its router database, but reported unavailable peers when attempting
inbound tunnels. End-to-end I2P ingress remains unverified. All overlay test
identities and account fixtures were separate from production.

## Release Checks Still Required

- The expanded no-plaintext-metadata requirement remains unmet: the relay still
  handles usernames, room IDs/catalog, membership and policy metadata in
  plaintext after TLS termination. Removing diagnostic leaks does not satisfy
  that requirement. Complete and cross-client test the relevant confidentiality
  migration before publication, with an explicit threat boundary for necessary
  public bootstrap information and observable network timing/addresses. Do not
  publish a metadata-free claim or silently treat these limits as accepted.
  Room names now travel in owner-authenticated MLS text/attachment payloads;
  clients learn them on owner-message delivery and keep them only in RAM.
  Attachment upload metadata now travels in a bounded body envelope rather than
  URL queries; this is access-log minimization, not an end-to-end metadata channel.
  Coordinate relay/web/Android updates for the v2 upload endpoint; v1 uploads
  are intentionally rejected without fallback.
- Physical Android camera scan, permission denial/regrant, backgrounding,
  rotation, repeated scans and local document-provider cancellation. Confirm
  secure screenshots and that no QR action submits credentials automatically.
- Live operator-controlled I2P ingress qualification: descriptor
  identity/signature, health, WebSocket upgrade and stable service identity
  after restart. Local native profile checks only prove startup/configuration
  and destination-key behavior, not routability or anonymity.
- Hosted CI and CodeQL for the committed final checkpoint, then coordinated
  signed web/Android artifacts from that exact source. Verify manifest, asset
  sizes/digests, native package signatures and deployment admission together.
- An explicit final release decision after these checks. No production restart
  or release merely to obtain a testable package.

## Not Claimed

Client Tor/Arti/SOCKS/I2P transport, browser/Tor integration, extended I2P B32,
short rendezvous invites, additional capability types and device linking are
not implemented. Long-running coverage-guided fuzz campaigns and independent
penetration testing are not represented by bounded mutation/unit tests.
First-contact replacement, public signed locators, endpoint memory copies and
routing/timing metadata remain trust limits, not completed security fixes.
See `INVITE_CAPSULE_V1.md`, `PRIVATE_TRANSPORTS.md` and `../SECURITY.md`.
