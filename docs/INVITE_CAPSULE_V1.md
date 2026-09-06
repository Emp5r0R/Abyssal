# Abyssal Invite Capsule V1

## Purpose

Invite Capsule V1 replaces separate node-address and access-code input with one
signed bootstrap object. The password remains separate and is authenticated by
OPAQUE. The format contains no networking implementation and can add locator
types later without changing capability or signature semantics.

## Primitive Types

- Integers use deterministic CBOR unsigned-integer encoding with the shortest
  valid representation.
- Arrays have definite lengths. Maps, tags, indefinite values, floats, and
  duplicate fields are not used.
- Text is valid UTF-8. V1 application and remote-host text is ASCII.
- Byte strings have definite lengths.
- Ed25519 keys are 32-byte public keys and signatures are 64 bytes.
- All multi-byte domain-length prefixes described below are unsigned big-endian.

Decoders must re-encode and compare the complete signed object byte-for-byte.
Any alternate or trailing representation fails.

## Signed Invite

The canonical binary invite is a CBOR array of exactly two items:

```text
[
  bstr(canonical_payload),
  bstr64(signature)
]
```

`canonical_payload` is a CBOR array of exactly ten positional fields:

| Index | Type | V1 meaning |
| --- | --- | --- |
| 0 | uint | format version, exactly `1` |
| 1 | tstr | application ID, exactly `org.abyssal.chat` |
| 2 | uint | capability type, `1` = `AccountBootstrap` |
| 3 | bstr32 | node Ed25519 public key |
| 4 | array | one to four unique node locators |
| 5 | bstr32 | 256-bit account-bootstrap capability |
| 6 | uint | minimum compatible messaging protocol |
| 7 | uint | maximum compatible messaging protocol |
| 8 | uint | extension flags, exactly `0` in V1 |
| 9 | uint/null | optional Unix-seconds registration expiry |

The node signs:

```text
"INVITE-CAPSULE-V1"
|| u16be(byte_length(application_id))
|| application_id
|| canonical_payload
```

Every field above is therefore authenticated. A V1 Abyssal client also requires
the protocol interval to include direct protocol 9 and room protocol 10.

## Locators

Each locator is a CBOR array of exactly three items. Selection is separate from
parsing and prefers supported HTTPS before explicit development loopback.

```text
Https = [1, lowercase_ascii_dns_host, port]
LoopbackDevelopment = [2, host_tag, port]
OnionV3 = [3, bstr32(service_identity), port]
I2pB32 = [4, bstr32(destination_hash), port]
```

Development host tags are `1 = localhost`, `2 = 127.0.0.1`, `3 = ::1`, and
`4 = Android emulator host 10.0.2.2`. Ports are 1-65535.

Remote clearnet locators require HTTPS and a canonical lowercase ASCII DNS name. IP
literals, credentials, paths, queries, fragments, trailing dots, non-ASCII
input, `.local`, `.localhost`, `.internal`, `.onion`, `.i2p`, `.home.arpa`, reserved
testing TLDs, invalid DNS labels, and every other URI scheme fail.
Android resolves remote DNS through a public-address policy and rejects any
mixed or private/reserved result. Browser JavaScript cannot safely pin DNS
resolution, so production web bootstrap requires the capsule's HTTPS locator
to equal the page's own origin; explicit loopback development accepts only the
four typed development hosts. Security-sensitive bootstrap requests do not
follow redirects.

Tags 3 and 4 are server-side advertised locators, not permission for a client
to use ordinary HTTP or DNS. Current production and development client
transport policies select neither type. An overlay-only capsule returns
`Unsupported transport` before bootstrap; a mixed capsule may select HTTPS
(or explicit development loopback). Older parsers without these tags reject
the entire capsule, including a mixed one, rather than ignoring unknown data.

For Onion v3, `service_identity` is a valid non-weak Ed25519 public key. The
canonical host is lowercase unpadded RFC 4648 Base32 of
`public_key || checksum || 0x03`, followed by `.onion`. `checksum` is the first
two bytes of `SHA3-256(".onion checksum" || public_key || 0x03)`. Host import
checks the length, alphabet, version, key and checksum. This is the
[Tor v3 address encoding](https://spec.torproject.org/rend-spec/encoding-onion-addresses.html),
not the separate Abyssal node signing identity.

For traditional I2P B32, `destination_hash` is a nonzero 32-byte SHA-256 hash
of the serialized I2P destination. Its canonical host is the 52-character
lowercase unpadded RFC 4648 Base32 representation plus `.b32.i2p`; unused tail
bits must be zero. Address-book aliases, subdomains and extended/encrypted
LeaseSet B32 names are not supported. See the
[I2P naming specification](https://www.i2p.net/en/docs/overview/naming/).

Operator URL import accepts only `http://<canonical-overlay-host>[:port]` for
these types. HTTPS overlay wrappers, credentials, queries, fragments and
non-root paths reject. The `http` label describes the local HTTP service
carried inside an independently configured overlay, never public plaintext
transport. No client Tor, Arti, SOCKS, I2P or proxy implementation is present.

## Node Identity and Descriptor

The stable logical node ID is:

```text
"abyssal-node-v1:"
|| base64url_no_padding(
     SHA-256("ABYSSAL-NODE-ID-V1" || node_public_key)
   )
```

`GET /v1/node` returns `application/cbor` containing another two-item signed
array `[bstr(payload), bstr64(signature)]`. Its payload has exactly eight fields:

```text
[
  1,                       # descriptor version
  "org.abyssal.chat",
  bstr32(node_public_key),
  node_locators,
  1,                       # invite format
  9,                       # direct protocol
  10,                      # room protocol
  0                        # flags
]
```

The descriptor signature input uses the same length-prefixed application
construction with domain `ABYSSAL-NODE-DESCRIPTOR-V1`. Before OPAQUE, a client
requires a valid descriptor signed by the invite key and containing the exact
selected locator. TLS hostname validation alone is insufficient.

The node signing seed is separate from account, release, OPAQUE, direct-chat,
MLS, Onion service and I2P destination keys. It is persistent infrastructure identity while
accounts and conversations remain RAM-only.

Generate it once with `deploy/generate-node-key.sh`, keep the resulting raw
32-byte `.secrets/node-signing.key` owner-only, and back it up through a
separate secure channel. The generator is no-clobber and refuses rotation. The
relay opens the configured file without following symlinks, validates the
opened regular file's exact size and permissions, never prints the private
seed, and reports only the derived public node ID and fingerprint.

## Text Forms

The primary paste/QR form is:

```text
abyssal:invite:<base64url-no-padding canonical binary>
```

Bare canonical Base64URL is also accepted for paste convenience. Padding,
whitespace, non-URL-safe characters, and noncanonical Base64URL fail.

The manual form is Crockford Base32:

```text
ABY1-<groups of five symbols>
```

Its encoded bytes are `canonical_binary || checksum`, where checksum is the
first four bytes of:

```text
SHA-256("ABYSSAL-INVITE-CHECKSUM-V1" || canonical_binary)
```

Manual input is case-insensitive, ignores single separators, and accepts the
Crockford transcription aliases `O -> 0` and `I/L -> 1`. The checksum detects
typing mistakes only. It provides no authenticity; Ed25519 verification is
authoritative.

## Limits and Validation

- Encoded input: at most 2,048 bytes.
- Canonical binary invite: at most 1,024 bytes.
- Signed descriptor: at most 1,024 bytes.
- Application ID: at most 64 bytes and exact-match required.
- Remote hostname: at most 253 bytes.
- Locators: 1-4, unique.
- Capability: exactly 32 nonzero bytes.
- Node public key: exactly 32 nonzero bytes.
- Signature: exactly 64 bytes.
- Unknown versions, capabilities, locator tags, or nonzero flags fail closed.
- Expiry is covered by the signature. Clients reject it early; the relay is
  authoritative and removes an expired unused capability before registration.

## Camera and Local QR Images

Both account-entry clients offer an explicit camera scanner and local image
picker. They decode QR text as data and pass it through the same bounded
Rust invite verifier before filling the input. Successful scanning does not
submit credentials or open any locator. Camera sessions expire after 60
seconds and stop on cancellation, backgrounding or teardown.

Image inputs are PNG/JPEG only, at most 8 MiB, 4,194,304 pixels and 4,096
pixels on either side. A shared Rust raster decoder checks magic bytes against
the declared MIME type (an absent MIME type is permitted), dimensions and
8-bit channel layout, sets a best-effort 32 MiB decoder allocation limit, and
creates an explicitly bounded grayscale buffer with a 960-pixel longest side.
SVG/XML/HTML, URL text masquerading as an image, mismatched MIME and malformed
rasters reject. File names, EXIF/comments and embedded URLs never become paths,
HTML or network requests. QR text remains subject to the 2,048-byte capsule
limit and signature checks regardless of image metadata.

Browser input is a user-selected local Blob. Android input is an ephemeral
`content://` grant read through the content resolver, not a converted filesystem
path; neither client uploads QR images or retains file permission. Reads have
size/deadline/cancellation checks and mutable buffers are wiped where owned.
An Android document provider may itself be cloud-backed. OS/browser/provider
copies, camera internals and native decoder execution are not a physical
zeroization or hard real-time guarantee.

## Capability Consumption

The relay derives its RAM lookup key as:

```text
HMAC-SHA-256(process_random_pepper,
  "ABYSSAL_CAPABILITY_ID_V1" || capability)
```

OPAQUE uses this 32-byte credential identifier:

```text
SHA-256("ABYSSAL-ACCOUNT-CONTEXT-V1" || node_public_key || capability)
```

Registration consumes the capability exactly once under the relay account
transaction lock. Later login presents the same invite plus password and finds
the existing RAM account. Parallel valid registration finishes produce exactly
one account. Relay restart or wipe destroys accounts, the lookup pepper, and
all derived identifiers.

## Migration and Compatibility

Invite Capsule V1 is the only normal account-entry path. Android and web no
longer accept a separate URL or short access code, and there is no production
manual-URL bypass around signature or node-descriptor verification. Development
uses the same signed format with a typed loopback locator.

The relay temporarily accepts legacy `ABYSSAL_CODE_COUNT` only as an operator
configuration alias for `ABYSSAL_INVITE_COUNT`; it does not issue legacy codes
or accept the legacy account request shape. Existing protocol-v9 direct and
protocol-v10 MLS messaging semantics are unchanged after account bootstrap,
but older clients cannot authenticate to a Capsule V1 relay and fail closed.
This deliberate compatibility boundary avoids reducing the binary capability
to the entropy or parsing model of the old human code.

## Trust Boundary

The signature detects modification of an invite obtained through a trusted
channel. It cannot distinguish the intended invite from an attacker's complete,
independently valid replacement invite before first contact. QR, message,
clipboard, or printed delivery inherits the security of that out-of-band
channel. Compare the node fingerprint through another trusted path when that
replacement threat matters.

Possession of an invite reveals its bearer capability and selected node. Do not
place it in URLs, analytics, crash reports, persistent logs, or tickets. Startup
output is intentionally one-shot. Losing it does not create a recovery API;
restarting the RAM-only relay issues fresh capabilities but preserves node
identity only when the node key is retained.

## Conformance Vector

Fixed non-production vectors, including canonical binary, signature, deep link,
manual form, derived node ID/account context, and signed descriptor, live in
`abyssal-invite/tests/capsule.rs`. Rust, WASM/web, and UniFFI/Android tests parse
that same vector.
