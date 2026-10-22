# Gateway API (v1)

The contract between a TeamCraft server and a push gateway. JSON over HTTPS, versioned in the path
(`/v1/...`); within `v1` the API only changes compatibly (new optional fields, new error codes, new
enum values: clients treat unknown ones as errors of their HTTP status class, servers ignore unknown
fields). The JSON in [`tests/fixtures/`](../tests/fixtures/) is normative examples: this repository
and TeamCraft's server both parse and produce exactly these documents (the files are copied between
the repositories and must stay identical), including the signature known answer.

| Endpoint           | Auth      | Purpose                                                                            |
|--------------------|-----------|------------------------------------------------------------------------------------|
| `POST /v1/servers` | signature | Register a server's public key. Idempotent. Returns `server_id` and default limits |
| `POST /v1/push`    | signature | Forward one sealed wake-up to one device token                                     |
| `GET /v1/info`     | none      | Version, providers with credentials, whether registration is open, default limits  |

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
  "token": "<APNs device token (hex) or FCM registration token>",
  "sealed": "<sealed wake-up>"
}
```

- `provider`: `apns` or `fcm`. Anything else (including `webpush`, `unifiedpush`) is `400 invalid_request`.
- `kind`: `message`, `mention`, `call`. It only selects the channel (APNs: the VoIP topic and push type
  for `call`); `urgency` (`normal`, `high`) the priority; `ttl_secs` is capped by the gateway.
- `sealed` is opaque to the gateway (the server seals it with the device's push key before it leaves
  the server, TeamCraft `docs/e2ee.md` §7). The gateway wraps it as the push service wants it.
- The visible alert text of an APNs notification is the gateway's, so a server cannot put its own words
  on a lock screen; the device replaces it after opening the wake-up.

Response `200`: `{"accepted": true}` once the push service accepted the wake-up.

### Errors

| HTTP | `error_code`                                           | What the server does                                                     |
|------|--------------------------------------------------------|--------------------------------------------------------------------------|
| 400  | `invalid_request`                                      | Fix the request                                                          |
| 401  | `unknown_server`                                       | Register the key, then retry once                                        |
| 401  | `unauthorized`                                         | Bad, stale or missing signature or headers; check the clock              |
| 403  | `server_blocked`, `registration_closed`                | The operator refuses this server; never delete devices because of it     |
| 409  | `replayed_request`                                     | The `request_id` was used already                                        |
| 413  | `payload_too_large`                                    | Body or wake-up over the gateway's limits                                |
| 410  | `token_gone`                                           | The push service reports the token dead: **forget the registration**     |
| 429  | `rate_limited`, `quota_exceeded`, `token_rate_limited` | Retry after `Retry-After`; nothing is deleted                            |
| 501  | `provider_not_configured`                              | The gateway has no credentials for this provider                         |
| 502  | `provider_unavailable`, `provider_rejected`            | Apple/Google down, or the gateway's own credentials refused; retry later |

Only `token_gone` means a device registration is dead (APNs `410`, `BadDeviceToken`,
`DeviceTokenNotForTopic`; FCM `UNREGISTERED`, `404`). Provider internals (Apple's `reason`, Google's
status) stay in the gateway's log.

## 5. `GET /v1/info`

`{"version": "...", "providers": ["apns", "fcm"], "is_registration_open": true, "limits": {...}}`. Lets a
server operator check that a gateway serves the provider they need.
