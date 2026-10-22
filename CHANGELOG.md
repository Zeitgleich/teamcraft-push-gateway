# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The HTTP contract
(`/v1`, [docs/api.md](docs/api.md)) only changes compatibly within a major version.

## [Unreleased]

## [1.0.0] - unreleased

First release, for TeamCraft 1.0.

### Added

- The push gateway: signed `POST /v1/push` forwards sealed wake-ups to APNs (alert and VoIP) and
  FCM; dead tokens come back as `410 token_gone`.
- Server registration with an Ed25519 key (`POST /v1/servers`), opaque server IDs, replay protection.
- Per-server rate, burst and daily quota, per-token limit, registration limits, block list and an
  operator CLI (`servers list|block|unblock|limits|allow`).
- `/healthz` and `/metrics` on a separate listener; SQLite state; container image with signature,
  provenance attestation and SBOMs.

[Unreleased]: https://github.com/Zeitgleich/teamcraft-push-gateway/compare/v1.0.0...HEAD
