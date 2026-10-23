# Gateway API (v1)

The contract between a TeamCraft server and a push gateway. JSON over HTTPS, versioned in the path
(`/v1/...`); within `v1` the API only changes compatibly (new optional fields, new error codes, new
enum values: clients treat unknown ones as errors of their HTTP status class, servers ignore unknown
fields). The JSON in [`tests/fixtures/`](../tests/fixtures/) is normative examples: this repository
and TeamCraft's server both parse and produce exactly these documents (the files are copied between
the repositories and must stay identical), including the signature known answer.

| Endpoint                 | Auth      | Purpose                                                                            |
|--------------------------|-----------|------------------------------------------------------------------------------------|
| `POST /v1/servers`       | signature | Register a server's public key. Idempotent. Returns `server_id` and default limits |
| `POST /v1/push`          | signature | Forward one sealed wake-up to one device token                                     |
| `GET /v1/info`           | none      | Version, providers, whether registration is open, default limits, the token key    |
| `POST /v1/tokens/revoke` | none      | End a sealed device token (the app, when it leaves a server)                       |

`/healthz` and `/metrics` are on a separate listener for the operator's network (see
[operations.md](operations.md)); they are not part of the contract.

Byte fields (`request_id`, `sealed`, `public_key`) are standard base64 with padding. Error bodies are
`{ "error_code": "...", "message": "...", "retry_after_secs": n }` (`retry_after_secs` only when waiting
helps; the `Retry-After` header carries the same).

## 1. Server identity

A server owns an **Ed25519 key pair** for the gateway. The gateway knows it by `server_id`: the first
16 bytes of `SHA-256(len(label) || label || public_key)` with the label
`TeamCraft-v1 push gateway server id`, as 32 lower-case hex characters. The ID is an opaque handle: it
says nothing about the server's name, address or users, and the gateway never asks for any of them.

## 2. Signatures

Every request carries:

| Header                  | Content                                                                     |
|-------------------------|-----------------------------------------------------------------------------|
| `x-teamcraft-server`    | `server_id` (not on registration: the key is in the body)                   |
| `x-teamcraft-timestamp` | sender clock, milliseconds since the Unix epoch; accepted within ±5 minutes |
| `x-teamcraft-signature` | base64url (no padding) Ed25519 signature                                    |

The signed message is `len(label) || label || body` with the label
`TeamCraft-v1 push gateway request` (one length byte) and

```
body = METHOD "\n" path "\n" timestamp_ms_decimal "\n" SHA-256(request body)   (the digest as 32 raw bytes)
```

for example `POST\n/v1/push\n1700000000000\n<32 bytes>`. The signature binds method, path, time and body.
Registration is signed with the key it registers (proof of possession). [`tests/fixtures/signature.json`](../tests/fixtures/signature.json)
is a complete known answer (seed, public key, server ID, request, signature); verification is strict
Ed25519 (RFC 8032, no malleable encodings).

Replay protection: a push carries a random 16-byte `request_id`; the gateway refuses an ID it has seen
within the timestamp window (kept in memory; after a restart the window still bounds a replay).

## 3. `POST /v1/servers`

Body: `{"public_key": "<32 bytes>"}`. Response `200`: `{"server_id": "...", "limits": {...}}` (the default
limits, which a per-server override may change). Registering a known key again returns the same
answer. Refused with `403 registration_closed` on gateways that only accept keys their operator added,
`403 server_blocked`, `429 rate_limited` (per client address and in total).

## 4. `POST /v1/push`

```json
{
  "request_id": "<16 bytes>",
  "provider": "apns",
  "kind": "message",
  "urgency": "high",
  "ttl_secs": 3600,
  "bound_token": "<the device token, sealed by the app and bound to this server (§6)>",
  "sealed": "<sealed wake-up>",
  "collapse_id": "<optional, 1-64 printable ASCII characters>"
}
```

`collapse_id` (optional) lets a later push of the same server replace the earlier notification instead of
stacking. The gateway sends `base64url(SHA-256(server_id ‖ 0x00 ‖ collapse_id))` (43 characters) as the
APNs `apns-collapse-id` and the FCM `collapse_key`: one server can't replace another server's notifications
on a shared device, and Apple and Google never see the value a server chose. FCM's `collapse_key` only
collapses messages not yet delivered (at most four keys per device at a time), it doesn't replace a
notification already shown.

Exactly one of `bound_token` and `token` (the raw APNs device token in hex or FCM registration token) is
set. A raw `token` is only accepted while the gateway runs with `tokens.accept_unbound` (a transition
setting, off by default, announced as `are_bound_tokens_required: false` in `/v1/info`); otherwise it is
`410 token_unbound`.

- `provider`: `apns` or `fcm`. Anything else (including `webpush`, `unifiedpush`) is `400 invalid_request`.
- `kind`: `message`, `mention`, `call`, `dismiss`, `test` (the ones `/v1/info` lists under `kinds`). It selects
  the channel: APNs VoIP topic and push type for `call`; `dismiss` (a notification was read elsewhere:
  withdraw it) is a silent push (APNs `background`, priority 5, `{aps:{content-available:1}}` plus the
  wake-up, bundle-ID topic; FCM data message at normal priority); `test` (a diagnostics push) is
  delivered like `mention`. A gateway refuses kinds it does not know (`400`); servers send only the listed
  ones. `urgency` (`normal`, `high`) the priority; `ttl_secs` is capped by the gateway.
- `sealed` is opaque to the gateway (the server seals it with the device's push key before it leaves
  the server, TeamCraft `docs/e2ee.md` §7). The gateway wraps it as the push service wants it.
- The visible alert text of an APNs notification is the gateway's, so a server cannot put its own words
  on a lock screen; the device replaces it after opening the wake-up.

Response `200`: `{"accepted": true}` once the push service accepted the wake-up.

### Errors

| HTTP | `error_code`                                                                                | What the server does                                                                                  |
|------|---------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| 400  | `invalid_request`                                                                           | Fix the request                                                                                       |
| 401  | `unknown_server`                                                                            | Register the key, then retry once                                                                     |
| 401  | `unauthorized`                                                                              | Bad, stale or missing signature or headers; check the clock                                           |
| 403  | `server_blocked`, `registration_closed`                                                     | The operator refuses this server; never delete devices because of it                                  |
| 409  | `replayed_request`                                                                          | The `request_id` was used already                                                                     |
| 413  | `payload_too_large`                                                                         | Body or wake-up over the gateway's limits                                                             |
| 410  | `token_gone`                                                                                | The push service reports the token dead: **forget the registration**                                  |
| 410  | `token_unbound`, `token_expired`, `token_invalid`, `token_revoked`, `token_server_mismatch` | The sealed token is no use for this server (§6): **forget the registration**; the app seals a new one |
| 429  | `rate_limited`, `quota_exceeded`, `token_rate_limited`                                      | Retry after `Retry-After`; nothing is deleted                                                         |
| 501  | `provider_not_configured`                                                                   | The gateway has no credentials for this provider                                                      |
| 502  | `provider_unavailable`, `provider_rejected`                                                 | Apple/Google down, or the gateway's own credentials refused; retry later                              |

`token_gone` and the sealed-token codes (all `410`) mean a device registration is dead (APNs `410`, `BadDeviceToken`,
`DeviceTokenNotForTopic`; FCM `UNREGISTERED`, `404`). Provider internals (Apple's `reason`, Google's
status) stay in the gateway's log.

## 5. `GET /v1/info`

```json
{
  "version": "1.0.0",
  "providers": ["apns", "fcm"],
  "is_registration_open": true,
  "limits": {"pushes_per_second": 50, "burst": 200, "pushes_per_day": 200000, "pushes_per_token_per_minute": 30},
  "token_key": {"key_id": "d943783749f67cb6", "algorithm": "hpke-x25519-hkdf-sha256-chacha20poly1305", "public_key": "<32 bytes>"},
  "are_bound_tokens_required": true,
  "max_token_lifetime_secs": 7776000,
  "kinds": ["message", "mention", "call", "dismiss", "test"]
}
```

Lets a server operator check that a gateway serves the provider they need, and apps get the key to seal
device tokens to (§6).

## 6. Bound device tokens

Apps never give a server a usable device token. They seal it to the gateway, bound to the server:

- **Key.** `token_key` of `/v1/info` is the gateway's current X25519 public key; `key_id` is the first 8
  bytes of its SHA-256 as 16 hex characters. Apps fetch it from the gateway itself and seal again when
  `key_id` changes or the token nears its expiry.
- **Plaintext.** UTF-8 JSON `{"v":1,"provider":"apns|fcm","server_id":"<32 hex>","expires_at_ms":<ms since the Unix
  epoch>,"token":"<raw device token>"}`; `server_id` is the ID of the server that may push to it (§1).
- **Sealing.** HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, no
  AAD, `info = len(label) || label || key_id` with the label `TeamCraft-v1 push gateway bound token`
  (one length byte, `key_id` as the 8 raw bytes).
- **Blob.** `key_id (8 bytes) || encapsulated key (32) || ciphertext`, at most 4096 bytes; standard base64 in
  JSON. [`tests/fixtures/bound_token.json`](../tests/fixtures/bound_token.json) is a known answer: a blob
  sealed to the key made from a seed, with its plaintext. Any implementation must open it.
- **Checks** (`POST /v1/push`, in this order): the key named by `key_id` exists and opens the blob
  (`token_invalid`); `server_id` is the authenticated server (`token_server_mismatch`); `provider`
  matches the request (`token_invalid`); `expires_at_ms` is in the future (`token_expired`) and not further
  than `max_token_lifetime_secs` away (`token_invalid`); the blob was not revoked (`token_revoked`).
- **Revocation.** `POST /v1/tokens/revoke` with `{"bound_token": "<blob>"}` (unauthenticated: the blob is
  the secret) answers `{"revoked": true}`; the gateway keeps the blob's SHA-256 until `expires_at_ms`.
  A blob the gateway can't open is `410 token_invalid`; callers are limited per client address (`429`).

The `server_id` a server tells its apps is the same ID as in the signature headers; a server whose key
changes has a new ID, so its apps seal again.
