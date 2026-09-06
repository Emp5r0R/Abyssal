# Private Inbound Services

## Boundary

The relay can sign Onion v3 and traditional I2P B32 locators in the same
Invite Capsule and node descriptor as HTTPS locators. The supplied profiles
forward inbound overlay streams to the existing loopback relay on port 4020.
They do not add another account protocol or replace OPAQUE, direct v9, MLS v10,
node identity verification, or release verification.

**Android and web do not yet route Tor or I2P traffic.** They reject
private-only invites before network access. Mixed invites select an enabled
HTTPS/development locator; they do not secretly use a proxy or fall back from
an overlay. Opening the web bundle through an overlay does not bypass its
existing secure-origin and bootstrap policy. Client Tor/Arti/SOCKS/I2P,
browser/Tor integration, extended I2P B32 names, rendezvous invites and new
capability types remain unimplemented.

## Advertise the Real Services

Provision the normal Abyssal node key with `deploy/generate-node-key.sh`.
Overlay service keys are separate infrastructure identities; never reuse the
node, account or release signing key for them. After creating and checking the
actual overlay addresses, configure **one** of these alternatives:

```dotenv
ABYSSAL_PUBLIC_URL=https://chat.example.com
ABYSSAL_PUBLIC_LOCATORS=
```

Or leave `ABYSSAL_PUBLIC_URL` empty and put one to four URLs in the JSON array:

```text
ABYSSAL_PUBLIC_URL=
ABYSSAL_PUBLIC_LOCATORS=["https://chat.example.com","http://<56-character-onion-host>.onion","http://<52-character-destination-hash>.b32.i2p"]
```

The angle-bracket placeholders above are not usable addresses. Replace them
with your daemon's public service addresses. Invalid addresses, duplicate
locators and conflicting nonempty settings abort relay startup. Bind addresses
never become advertised locators automatically. Native clients without the new
locator tags reject such capsules, even when the array also contains HTTPS.

## Common Host Requirements

Use dedicated unprivileged service accounts and dedicated configurations, not
another application's Tor/I2P router. Install daemons and their verification
certificates from an authenticated operating-system package source. Do not
replace or restart an existing service while testing these profiles.

Keep port 4020 bound to loopback. The overlay daemons must share that host
network namespace with the relay's loopback publication. Do not expose a
plaintext relay port publicly, use an HTTP rewriting proxy, or enable access
logs. A generic I2P TCP tunnel preserves HTTP and WebSocket bytes without
adding the `X-I2P-*` identity headers of its HTTP tunnel mode.

Keep runtime router state on a verified tmpfs, normally `/run`, with mode 700
and the dedicated daemon's ownership. Disable swap or use an appropriate
encrypted-swap policy for the threat model; tmpfs alone is not a no-disk
guarantee. Launch with `umask 077` and `ulimit -c 0`. Keep logs out of journald,
log files, container log stores and terminal recording. The profiles disable
ordinary daemon logging, but supervisors can still capture startup failures.
Set resource limits appropriate to the host and monitor liveness without
recording invite material or request metadata.

## Tor Server

Use `deploy/private-transports/torrc.example` as a dedicated config. Prepare
`/run/abyssal-tor` on tmpfs and `/var/lib/tor/abyssal-onion` as a persistent,
owner-only directory belonging to that Tor instance. Only the latter stores
the stable service identity; transient router state goes under `/run`.

Validate and start as the dedicated service user in the foreground:

```bash
umask 077
ulimit -c 0
tor --verify-config -f /etc/abyssal/torrc
tor -f /etc/abyssal/torrc
```

The generated `hostname` inside the service directory is public; private key
files beside it must never be printed. Back up the service directory securely
before distributing its address. For subsequent starts, check that its existing
key files are present and readable before launching: Tor can otherwise create
a replacement service identity. Do not remove keys to repair a routing issue.
The profile disables SOCKS and control listeners and forwards service port 80
to `127.0.0.1:4020`. See the
[Tor operator setup](https://community.torproject.org/onion-services/setup/).

## I2P Server

Use a daemon version that accepts the complete supplied profile. Native profile
checks have passed with i2pd 2.59.0, and isolated Ubuntu ARM64 startup has passed
with 2.61.0. Ubuntu 24.04's 2.49.0 package rejects `reseed.followredirect` and is
not compatible with this profile. Do not remove that restriction to make an
older daemon start. Run the native profile check against the actual executable
before provisioning; successful startup alone does not prove ingress works.

Use both `i2pd.conf.example` and `i2pd-tunnels.conf.example` from
`deploy/private-transports/`. Create an empty, dedicated tunnels directory so
the daemon does not auto-load unrelated `.conf` files. Supply the installed
reseed certificate directory explicitly; signature verification stays enabled.

The tunnel key name is **relative** to `--datadir`:
`identity/abyssal-destination.dat`. Do not replace it with an absolute path;
i2pd 2.59.0 prepends its data directory even to that string. During explicit
first-time provisioning, create `/run/abyssal-i2pd/identity` with owner-only
permissions, start the dedicated daemon with `--loglevel=info` in a private,
unrecorded terminal, note its public B32 destination, and then stop it. Do not
retain that verbose setting for normal starts. Before advertising
the destination, securely preserve the generated key in
`/var/lib/abyssal-i2p/abyssal-destination.dat` without overwriting an existing
identity. This is an infrastructure key, not an account or message database.

For normal starts, read-only bind-mount `/var/lib/abyssal-i2p` at
`/run/abyssal-i2pd/identity`. Verify the mount, owner-only key permissions and
readability **before every launch**. Abort if the preserved key is absent;
do not let the daemon silently regenerate it. Recreate only the tmpfs runtime
directory and bind mount after a machine reboot. Example launch, as the
dedicated service user, after that preparation:

```bash
umask 077
ulimit -c 0
test -s /run/abyssal-i2pd/identity/abyssal-destination.dat || exit 1
i2pd --conf=/etc/abyssal/i2pd.conf \
  --tunconf=/etc/abyssal/i2pd-tunnels.conf \
  --tunnelsdir=/etc/abyssal/empty-tunnels.d \
  --datadir=/run/abyssal-i2pd \
  --certsdir=/usr/share/i2pd/certificates
```

Certificate paths differ by distribution; use the installed package's path.
Obtain the public B32 destination from the daemon's provisioning output or a
trusted offline destination-inspection tool, not by publishing its private key.
Do not leave verbose provisioning logs enabled in normal operation. The
profile disables consoles, HTTP/SOCKS proxies, SAM, BOB, I2CP, I2PControl,
UPnP, address-book subscriptions and built-in NTP. See
[i2pd configuration](https://docs.i2pd.website/en/latest/user-guide/configuration/)
and [tunnel configuration](https://docs.i2pd.website/en/latest/user-guide/tunnels/).

## Verification and Release Gate

```bash
python3 scripts/test-private-transport-profiles.py
python3 scripts/test-private-transport-profiles.py --tor /usr/bin/tor --i2pd /usr/bin/i2pd
./scripts/test-all.sh all
```

Use the installed executable paths. The optional native I2P check requires
Linux `unshare` with user/network namespace support. It has no external
network interfaces, creates only disposable test keys, verifies owner-only
permissions and unchanged identity on restart, and cleans up the process and
temporary state. Native profile checks are **not** live overlay routing tests.

Before deployment, independently test each real service's bounded `/v1/node`
descriptor, node signature/identity, health and WebSocket upgrade through the
overlay, then repeat after a controlled daemon restart. Do not use production
invites as test fixtures. The application release remains held until the full
Invite Capsule checklist, including Android device behavior, is qualified.

## Metadata and Trust

Invite signatures authenticate but do not encrypt the capsule. A holder sees
every locator and can correlate them by the stable node key. The public node
descriptor also lists those aliases. Advertising clearnet and overlay addresses
for one identity deliberately links them; this cannot provide hidden origin
identity. Startup output contains the bearer invite and must remain private.

Neither overlay removes all timing, traffic-size, service-availability or
endpoint observations. The relay still sees account sessions and routing.
TLS termination, web-code delivery, endpoint compromise, first-contact invite
replacement and the limits in `SECURITY.md` remain relevant. Server profiles
alone are not an anonymity or no-metadata guarantee.
