# Private Sender Profiles V1

## Identity Separation

New relay accounts receive `acct_` followed by the 32 lowercase hexadecimal
digits of a random UUIDv4 (122 random bits). This is a public routing identifier,
not a bearer credential. The legacy wire field remains named `username` so the
directory, DM v9, MLS v10, attachment, mention and verification contracts do not
change. Uniqueness is checked under account/conversation serialization; bounded
generation failure rejects registration before consuming its capability.

Each successful client login independently creates a fresh display name from
eight CSPRNG bytes. The first two bytes select prefix/suffix lists using their
low four bits; the final six bytes become twelve uppercase hex characters.
The generated label has 56 random selection bits, but is not an authentication
secret or a guaranteed unique identity. No key derivation, password or account
identifier is used to generate it. It remains stable during that live session,
including privacy cover and socket reconnect, and changes on a new login.

## Encrypted Wire Field

Android and web add this optional field inside E2EE text and attachment payloads:

```json
{"sender_profile":{"version":1,"display_name":"SilentSignal0203040506FF"}}
```

Both clients require exactly two fields, numeric version 1 and an ASCII name
matching `[A-Za-z][A-Za-z0-9_-]{0,35}`. Unknown versions, wrong types, extra fields,
explicit null, Unicode controls, whitespace and markup fail closed. An absent
field is valid for legacy messages. The generation conformance vector uses
entropy bytes `00 01 02 03 04 05 06 ff` for the example name above.

The complete original JSON payload is authenticated/encrypted by the existing
DM or MLS protocol. There is no separate signature or new profile key. Native
sender authentication remains authoritative: profile text cannot replace the
verified account ID, public key, MLS credential or sender binding.

## Publication and UX

- Incoming names publish only with an accepted authenticated message after the
  existing exact delivery/state acknowledgement. Invalid profiles are not
  displayed, but may already have been acknowledged; rejection does not promise
  redelivery. Existing direct and MLS error handling remains in force.
- Incoming message headers display the name and its original account ID. Clicking
  an author mentions the account ID, never the display name. Safety numbers,
  direct targets, membership approval, ownership and mention matching still use
  account IDs, not labels.
- Discovery, presence, DM lists and verification screens continue to identify
  accounts by routing ID. Profiles do not create an unsolicited directory or
  expose names before encrypted communication. No global peer-name cache is added.
- Received names are message-local and expire with the message. Old messages may
  show a previous login's name for the same account. Logout/wipe removes account
  and message references; web eviction also clears the mutable display-name field.
  JVM/JS string copies still cannot be guaranteed physically erased.

## Limits and Migration

Anyone controlling a sender can choose another person's display name. It is
authenticated only as that account's assertion. Do not make trust decisions by
name. Recipients and a compromised client can disclose names. This change hides
official-client display profiles from the relay, not account IDs, presence,
membership, communication relationships or network timing/volume.

No existing ID is rewritten. Old relay accounts retain their old visible names;
they disappear only with normal ephemeral-state destruction. Existing clients
accept the new identifiers and ignore unknown encrypted profile fields. Updated
clients accept legacy messages without a profile. No release, deployment or
forced relay wipe is required to create a development checkpoint.
