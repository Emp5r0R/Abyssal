# Attachment Upload V2

This HTTP framing change removes upload metadata from request URLs. It does not
change attachment cipher-v2 records, direct protocol v9, or MLS protocol v10.
It is not an additional encryption layer: the relay and TLS terminator can
read the upload metadata. Attachment filenames, keys and original content remain
in their existing E2EE channels.

## Wire Format

`POST /v2/attachment`, with no query string, requires:

- `Authorization: Bearer <session token>`
- `Content-Type: application/octet-stream`
- `Content-Length` equal to 1024 plus the serialized ciphertext size

The body contains one fixed-size 1024-byte prefix, followed immediately by the
existing fixed-size encrypted attachment records. All integer offsets below
are zero-based:

| Offset | Size | Value |
| --- | --- | --- |
| 0 | 8 bytes | ASCII `ABYUP001` |
| 8 | 2 bytes | Big-endian unsigned JSON byte length, 1-1014 |
| 10 | JSON length | UTF-8 JSON object |
| After JSON | To byte 1023 inclusive | Zero padding |
| 1024 | Remaining body | Unchanged attachment ciphertext records |

The JSON object accepts only `chat_id` and `message_id` strings plus the existing
`media_type`, `one_time`, `delete_after_download` and `ttl_sec` policy fields.
Official clients send all six fields. The relay retains the existing optional
policy defaults: FILE, false, the one-time value, and node/room retention rules,
respectively. Unknown or duplicate fields, invalid JSON/types, invalid magic,
out-of-bounds lengths, and nonzero padding fail closed. This is not a signed
canonical JSON format; field order has no meaning. Existing conversation access,
message binding and room-policy validation remain authoritative.

A successful response is the exact JSON object with `accepted: true`,
`attachment_id` containing the new canonical UUIDv4, and `storage: "ram-only"`.
Web validates all three fields and rejects missing/extra fields or false
acceptance. Live relay tests use this same web response decoder, preventing
unit-test mocks from silently diverging from the server contract.

## Resource And Lifecycle Rules

The relay authenticates and checks declared total length before polling the
body. Prefix readers use the existing per-account and global upload admission
limits, with a 10-second total deadline, including empty or fragmented chunks.
The parser allocates one fixed prefix buffer and hands the remaining stream to
the existing upload pipeline; it does not buffer a second full ciphertext copy.
The pipeline revalidates authentication, message access, declared ciphertext
length, media limit, memory/record quotas and purge generation before staging.
Only ciphertext counts toward stored attachment bytes. A malformed envelope,
logout, wipe or rejected upload cannot publish attachment bytes.

Android streams the prefix followed by encrypted chunks and clears its owned
prefix buffer after the request completes or fails. Web composes a Blob with
the prefix and encrypted content; Uint8Array inputs may be copied by Blob
construction, and browser-owned Blob copies cannot be zeroized. Web progress
subtracts the prefix bytes; Android progress remains based on plaintext bytes
processed. Download bytes do not include this upload-only prefix.

## Migration

Update the relay and both clients together. `POST /v1/attachment` returns 410;
there is no legacy query fallback. Download, claim completion/release and owner
cleanup continue to use their existing endpoints and authentication. A generic
access log of the new upload URL no longer contains conversation IDs, message
IDs, media type or timers. Body/header logging and the relay's own in-memory
knowledge are not protected by this framing change.
