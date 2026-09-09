# Encrypted Room Profiles V1

Room names are participant content, not relay catalog metadata. Official Android
and web clients include the following optional field inside an MLS v10 encrypted
`text` or `attachment` application payload when the sender is the room owner and
still has the name in its live room handle:

```json
{"room_profile":{"version":1,"name":"Private incident response"}}
```

The profile has exactly two fields: numeric `version` equal to 1 and a `name`
string of 1-36 UTF-16 code units. Leading/trailing ECMAScript whitespace, Unicode
control characters and unpaired UTF-16 surrogates are rejected. Unicode names
and embedded spaces are allowed. Unknown versions, extra fields, explicit null,
wrong types and malformed values fail closed. JSON member order is irrelevant;
the entire original payload is authenticated by MLS, not separately signed JSON.

## Authentication and Publication

The existing MLS application authenticated data is four consecutive fields,
each prefixed by a four-byte big-endian byte length (no field-count prefix):

1. ASCII `ABYSSAL-MLS-V10-APPLICATION`.
2. Room ID UTF-8 bytes.
3. Message ID UTF-8 bytes.
4. Sender username UTF-8 bytes.

The native core rejects wrong context, malformed lengths and suffixes. Outbound
sender must match the local account. On receipt the claimed canonical username
must match the signed credential at the cryptographically authenticated MLS
sender index. A mismatch restores the prior ratchet checkpoint, without
publishing plaintext or consuming the replay ID.

Both clients accept a profile only from the room owner recorded in their bound
room context. It may initialize an unknown name or repeat the known name, but
cannot rename it. Publication waits for the exact accepted inbound snapshot
transaction. Invalid profiles do not publish the message/name; web drops this
authenticated application data without closing the local session. Application
validation can occur after the relay ACK, so it does not promise redelivery of
invalid content. Native authentication and state failures remain fail closed.
An absent field is compatible
with older clients and does not change a known name. Read receipts and direct
messages do not publish profiles.

## Confidentiality and Lifecycle

- The name is absent from creation frames, policy, catalog, application AAD,
  attachment upload envelopes and native sealed snapshots. MLS encrypts it
  alongside message content or attachment metadata, with no new encryption key.
- Every owner text/attachment repeats the profile while the owner knows it.
  A joining or recovered client displays an ID-derived label until it receives
  such a message. There is no separate profile request, persistent name store,
  automatic history replay or rename protocol.
- Learned names remain only in bounded client RAM room handles and UI state.
  Removing the handle, logout, wipe or process teardown forgets them. A recovered
  owner without a name cannot reconstruct it from a native snapshot alone.
- Members can copy a decrypted name, and a compromised client/owner can disclose
  it. JVM/JS strings cannot be guaranteed physically erased. An owner can also
  equivocate about an initial name to clients without a shared comparison anchor.
- IDs, roster usernames, membership, retention policy and network observations
  remain visible to their respective relay/network observers. This change is
  encrypted room-name sharing, not a metadata-free protocol.

No wire-version bump is needed: production clients already emit the same AAD
format, and older clients ignore the optional encrypted JSON field. They do not
gain the new authenticated-sender check until updated. Mixed-version deployment
must not be described as uniformly hardened.
