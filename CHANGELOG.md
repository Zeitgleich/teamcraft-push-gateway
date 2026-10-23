# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The HTTP contract
(`/v1`, [docs/api.md](docs/api.md)) only changes compatibly within a major version.

## [Unreleased]

## [1.0.0] - unreleased

First release, for TeamCraft 1.0.

### Added

- The push gateway: signed `POST /v1/push` forwards sealed wake-ups to APNs (alerts, calls as alerts, background) and
  FCM; dead tokens come back as `410 token_gone`.
- Server registration with an Ed25519 key (`POST /v1/servers`), opaque server IDs, replay protection.
- Per-server rate, burst and daily quota, per-token limit (stricter for calls), a budget per push
  service shared by all servers, registration limits (IPv6 per /48), block list, pruning of servers
  that never push, and an operator CLI (`servers list|block|unblock|limits|allow|delete|prune`).
- Wake-up kinds `dismiss` (silent push to withdraw a notification read elsewhere) and `test`, listed in
  `/v1/info` (`kinds`), and an optional `collapse_id` (APNs `apns-collapse-id`, FCM `collapse_key`).
- **Bound device tokens**: apps seal their APNs/FCM token to a gateway key (HPKE), bound to one server and
  an expiry; servers send the sealed blob (`bound_token`) and the gateway refuses it for any other
  server, after expiry, or after revocation (`POST /v1/tokens/revoke`). Key management with
  `keys list|rotate|prune`; `tokens.accept_unbound` keeps raw tokens working for a transition (off by
  default). `/v1/info` publishes the token key.
- `/healthz` and `/metrics` on a separate listener; SQLite state; container image with signature,
  provenance attestation and SBOMs.

[Unreleased]: https://github.com/Zeitgleich/teamcraft-push-gateway/compare/v1.0.0...HEAD
