# Design

The iOS and Android store apps of TeamCraft are signed and published by one party (the
**publisher**). Apple and Google tie push delivery to the app's signing identity: only the holder of
the app's APNs key and FCM project can send to its devices. A self-hosted TeamCraft server can't have
those credentials, so without help the store apps would never get a push from any server but the
publisher's own. The gateway is that help: a small service that holds the publisher's credentials and
forwards **sealed wake-ups** from any TeamCraft server to Apple and Google. It sees device tokens and
ciphertext, never users, devices, keys or content.

The HTTP contract is [api.md](api.md); running one is [operations.md](operations.md). The TeamCraft side
(server settings, the end-to-end encryption of the wake-up) is documented in the TeamCraft repository
(`docs/push-gateway.md`, `docs/e2ee.md` §7).

## 1. Principles

- **No special role for the publisher's own server.** It is a customer of the gateway like every other
  server: same API, same limits, same signature check.
- **Direct stays possible.** Whoever builds and signs their own apps has their own APNs key and FCM
  project and configures them on their server; no gateway is involved.
- **Web Push and UnifiedPush never use it.** Those endpoints belong to the user's browser or distributor.
- **Small and boring.** One binary, one SQLite file, no accounts, nothing stored about users.
- **Vendor-neutral protocol.** The API names a provider (`apns`, `fcm`) and a notification kind, nothing
  more; another operator can run the same binary for their own apps.

## 2. Flow

```
device ──token + push key──▶ TeamCraft server ──sealed wake-up + token (signed)──▶ gateway ──▶ APNs / FCM ──▶ device
                              seals the wake-up                                    adds the publisher's
                              with the device's push key                           credentials, enforces limits
```

The device (notification service extension, FCM service) opens the wake-up with the push key and fetches
the message from its own server. The gateway builds the APNs or FCM request with its credentials and tells
the server whether the token is dead.

## 3. Threat model

What a gateway **sees**: the device token (an opaque handle at Apple/Google), the opaque `server_id`, the
time and size of each wake-up and its kind, the connecting address of the server, and, because it
forwards, what Apple or Google see anyway. It does not see user, device or conversation IDs, the
server's name, push keys or any plaintext: the payload is sealed to the device's push key, which only the
device and its server know.

A **malicious or compromised gateway** can:

- **drop or delay** pushes, or refuse a server (availability only: apps catch up when they run or
  reconnect, so no message is lost, just the prompt notification);
- **replay** a sealed wake-up it has seen: the device opens it, fetches the referenced message and at worst
  shows a duplicate notification; wake-ups name a message but carry no instruction;
- **correlate** tokens with servers and traffic patterns over time (metadata).

It **cannot** read a wake-up, forge one (it has no push key; a made-up ciphertext fails authentication in the
app and is discarded), learn who the users are, or influence the content of any message.

A **malicious or compromised TeamCraft server** can use the gateway's capacity: flood it with pushes to its
own devices or to tokens it learned. That is bounded by per-server rate, burst and daily quota, a
per-token limit (a device token receives at most `pushes_per_token_per_minute` wake-ups per minute no
matter how many servers send to it; far fewer for call pushes), a budget per push service that all
servers share, body and field limits, and the **block list**. A server can't send arbitrary text (the
alert text is the gateway's) or choose topics (the gateway's bundle ID).

Tokens are only ever handed to a server by the device itself, and since 1.0 the server never holds a
usable one: the app seals it **bound to that server** (§4), so a leaked server database, a hostile
server, or a server the user left can't push to the device through any other server's identity, and
ends at the latest when the sealed token expires (or at once if the app revokes it).

Many registered servers multiply the per-server limits; the shared per-service budget, low limits
for new keys where needed (`servers limits`), the per-address registration limit, pruning of servers
that never push and the block list bound that.

A **network attacker** needs a server's private key to send, and can't alter or redirect a signed request.
TLS (the reverse proxy) protects tokens in transit.

Registration is open by default because any self-hosted server must be able to join without asking.
Abuse is handled by limits per client address and in total, a cap on the number of servers, and the
block list; operators who prefer an allow list set `registration.mode = "closed"`.

The gateway holds credentials that can push to every installation of the store apps. Treat the host
accordingly: nothing else on it, credentials as files or container secrets, no shell access for chat
operators.

## 4. Bound device tokens

An APNs or FCM token is a bearer secret: whoever holds it and can reach a gateway can wake the device.
Without more, an app that signs in to several servers would hand the same raw token to each, and
any of them (or an attacker with a copy of its database) could push generic alerts and call rings to the
device for as long as the token lives. So the app **seals the token for the gateway**, bound to one server:

1. The gateway publishes a **token key** (X25519; `GET /v1/info`). The app gets it directly from its
   gateway, not through the server it registers with (a hostile server could substitute its own key).
2. The app seals `{provider, server_id, expires_at, token}` to that key (HPKE, RFC 9180) and gives the
   server only the opaque blob. `server_id` is the ID the gateway knows the server by (a hash of the
   server's gateway public key, which the server tells its apps).
3. The server includes the blob in its signed push request instead of a token. The gateway opens it,
   and uses the token only if the authenticated server is the `server_id` in it, it has not expired
   (nor exceeds `tokens.max_lifetime_secs`), is for the right push service, and has not been revoked.
   Each failure is `410` with its own code, which makes the server forget the registration; the app
   registers again (sealing anew) the next time it runs.
4. The app **seals again periodically** (before expiry, and when the gateway rotates its key), and on a
   change of server. When the user **leaves or removes a server**, the app **revokes** the blob at the
   gateway (`POST /v1/tokens/revoke`, which only whoever holds the blob can meaningfully call); the
   gateway keeps its digest until the token would have expired anyway.

What this does not do: a server can still push to the devices of its *own* users through its own identity,
bounded by the limits (§5), and a server that lies to an app about its `server_id` (naming a
colluding server) gets the app's pushes through that other server; neither gives it anything it
doesn't have already, and neither reaches users of other servers. The token itself is never visible
to the server, so it can't register it elsewhere.

**Key management.** Token keys live in `tokens.dir` (files, owner-only). Rotation (`keys rotate`) makes a
new key current; apps pick it up with their next sealing. Older keys keep opening existing blobs until
`keys prune`, so keep them for at least `max_lifetime_secs` after a rotation. Losing the keys makes every
blob unopenable: servers drop the registrations and apps register again; no message is lost, only
pushes until the apps next run. Back the directory up with the database.

**Transition.** `tokens.accept_unbound = true` also accepts raw tokens (`token` instead of
`bound_token`), for servers and apps that don't seal yet. It is off by default; with it off, a raw token
is `410 token_unbound`.

Binding protects tokens that were sealed from the start. The gateway can't tell a blob an app made from
one anybody else made with its public key, so a raw token a server ever held (from the transition, an
older app, an older database, or a leak of the token keys) can be sealed by that server for itself again
and again. The apps therefore never hand out a raw token once they seal (Android also fetches a fresh
FCM token once); iOS tokens only change with a reinstall. Keep the transition short. The token keys'
backup can open every sealed token: store it like the APNs and FCM credentials.

Revocations are kept no longer than the longest lifetime the gateway honours (`tokens.max_lifetime_secs`;
a blob claiming more is refused for revocation as it is for pushes) and are looked up in the database,
not held in memory, so revocation requests can't exhaust it.

## 5. Limits

All values are settings with defaults; a per-server override is possible (`servers limits`).

| Limit                                       | Default        | Scope                                |
|---------------------------------------------|----------------|--------------------------------------|
| `pushes_per_second` / `burst`               | 50 / 200       | per server (token bucket)            |
| `pushes_per_day`                            | 200,000        | per server and UTC day               |
| `pushes_per_token_per_minute`               | 30             | per device token, across all servers |
| `call_pushes_per_token_per_minute`          | 6              | call pushes per device token         |
| `dismiss_pushes_per_token_per_minute`       | 120            | withdrawals per device token         |
| `global_pushes_per_second` / `global_burst` | 2,000 / 10,000 | per push service, all servers        |
| `max_body_bytes`                            | 16 KiB         | per request                          |
| `max_sealed_bytes`                          | 2 KiB          | per wake-up                          |
| `max_ttl_secs`                              | 7 days         | per wake-up                          |
| `timestamp_window_secs`                     | 300            | per request                          |
| `registration.per_address_per_hour`         | 10             | per client address (IPv6 per /48)    |
| `registration.global_per_hour`              | 600            | all addresses                        |
| `registration.max_servers`                  | 100,000        | total                                |
| `database.prune_unused_after_days`          | 7              | servers that never pushed            |

Per device token, messages, calls and withdrawals (`dismiss`) have budgets of their own: a user who
reads many conversations in a row causes one withdrawal per conversation, and those must not use up
the budget that lets the next message through. Withdrawals still count against the sending server's
rate and daily quota.

Per-token windows are kept as a process-keyed 64-bit hash that only lives in memory; tokens themselves
are never stored or logged.

## 6. State store: SQLite

The gateway stores servers (ID, public key, created and last seen, block state and reason, limit
overrides) and **daily counters** per server (accepted, token gone, failed). Everything else (rate-limit
buckets, token windows, replay IDs) is in memory and rebuilt from nothing after a restart. No tokens,
wake-ups, IP addresses or payloads are stored or logged.

**SQLite, not Postgres,** because the data is a few kilobytes per server in two tables, written by one
process on one host, and the gateway should be trivial to run: a binary or container plus a volume.
Postgres would add a second service to operate (and to secure) where the publisher wants the smallest
possible attack surface, for no capability the gateway uses (no cross-process transactions, no
multi-writer scaling). WAL mode lets the operator CLI edit the block list while the gateway runs. Usage
counters are flushed periodically (default 10 s) and on shutdown, so a crash loses at most that interval
of quota accounting. The trade-off is a single instance: running several would need blocks and quotas in
shared storage. One instance handles far more pushes than the expected number of servers send (the
bottleneck is Apple's and Google's API latency); revisit when high availability is needed.

## 7. Decisions

- **Per request, not a long-lived stream.** One signed POST per wake-up keeps the gateway stateless per
  connection and trivially load-balanceable. Batching is a later optimization.
- **Server key pair instead of accounts or API keys.** A server proves itself with a key it generated; no
  registration form, no secret the gateway stores (only the public key), and a leaked database doesn't let
  anyone impersonate a server.
- **Token limits across servers.** A device token is the thing worth protecting: limiting per token caps
  what any set of servers can do to one device.
- **The contract is a separate repository.** Like a push proxy next to a chat server, the gateway is built,
  released and run by the publisher independently of server releases; only [api.md](api.md) and the shared
  JSON fixtures connect the two.
- **Sealing in the app, not in the server.** Only the app can create a blob the server can't read; the
  gateway key reaches the app from the gateway itself. HPKE is the standard construction for sealing to a
  public key and already part of TeamCraft's cryptography.
- **Expiry and revocation instead of a gateway-side device list.** The gateway stores digests of revoked
  blobs until they expire, nothing about devices: no account, no token inventory.
