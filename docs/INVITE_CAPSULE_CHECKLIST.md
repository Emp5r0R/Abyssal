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

On 2026-09-09, the native terminal-QR round trip and real browser QR matrix
passed at 1440x1000 and 390x844. The isolated native Tor/I2P profile test also
passed startup and stable destination-key checks; this is not live I2P ingress
evidence. Source checkpoint `8e474ed` passed the full integrated `all` gate,
including 440 web tests and 367 Rust tests, Android JVM/lint/Kotlin checks,
live relay integration, generated-artifact checks, and strict advisory gates.
Hosted CI (`34357801497`) and CodeQL (`34357801504`) also passed that checkpoint.

A qualification-only debug APK and instrumentation APK from `8e474ed` were
installed on the paired A059 Android 16 device. The invite-field Compose
instrumentation test passed on the unlocked device. Account entry loaded;
camera background teardown, repeated open/close, denied-permission fallback
and recovery after granting permission, and image-picker cancellation passed.
Importing the independent PNG fixture through the local document provider
populated a masked invite, left the password empty and kept login disabled.
A screenshot captured into host memory showed a black central app region;
the activity and scanner dialog also carried `FLAG_SECURE`. Rotating during
scanning dismissed the scanner and released the camera; reopening worked
after restoring the original rotation setting. These checks do not establish
a successful physical camera decode or qualify a production-signed release.

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

On 2026-09-10, isolated i2pd 2.61.0 server and probe routers on the operator's
ARM64 host passed live ingress qualification against a disposable `8e474ed`
relay. An SSH reverse forward connected the server destination only to that
local test relay; a separate loopback forward reached the probe router's I2P
client tunnel. Health, the shared-core-verified signed node descriptor, OPAQUE
registration and the authenticated WebSocket upgrade all passed through I2P.
After stopping and restarting both routers, their owner-only destination key
digests were unchanged and all four network checks passed again. Initial
requests during tunnel establishment failed before routing became available.
The checked-in generic TCP server profile was used with only its target port
changed; diagnostics were enabled explicitly for this disposable qualification.
Router keys and logs stayed in tmpfs, and all identities/accounts were separate
from production. This closes the live I2P ingress check, not client overlay
support, anonymity, production deployment, or a guarantee of network uptime.

The full integrated gate also passed locally on 2026-09-10. An independent
server audit using the official digest-verified cargo-audit 0.22.2 ARM64 asset,
the exact same lockfile, and the unchanged strict validator checked 358
dependencies against 1,243 advisories with no findings, warnings or diagnostics.
Earlier local registry timeouts were rejected, not suppressed or counted as
successful audits.

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
  New account identifiers are opaque random values; client display names are
  carried only by encrypted messages. Identifiers and relationship graphs are
  still relay-visible, and legacy account names are not retroactively hidden.
  Attachment upload metadata now travels in a bounded body envelope rather than
  URL queries; this is access-log minimization, not an end-to-end metadata channel.
  Coordinate relay/web/Android updates for the v2 upload endpoint; v1 uploads
  are intentionally rejected without fallback.
- Successful physical Android camera decode of an operator-generated QR,
  including repeated successful scans and confirmation that camera import
  fills only the masked invite without submitting credentials. Camera
  lifecycle, image import, cancellation and screenshot observations above
  cover the qualification debug build, not a later production-signed artifact.
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
