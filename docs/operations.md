# Operating a gateway

Only the publisher of store apps (or whoever builds their own apps for a group of servers) runs a
gateway. It is one binary or container image with a small SQLite file; run it on **its own host**,
separate from every chat server, behind a TLS-terminating reverse proxy.

## Configuration

A TOML file (`--config <file>` or `TEAMCRAFT_PUSH_GATEWAY_CONFIG`) with environment overrides
`TEAMCRAFT_PUSH_GATEWAY__SECTION__KEY`; [`teamcraft-push-gateway.example.toml`](../teamcraft-push-gateway.example.toml)
lists every option with its default.

- **Credentials:** `[apns]` (the `.p8` key, key ID, team ID, bundle ID) and `[fcm]` (the Firebase service
  account key), as files or `TEAMCRAFT_PUSH_GATEWAY__APNS__KEY` / `__FCM__SERVICE_ACCOUNT`. A partial setup stops
  the start. The gateway is the only place these credentials live.
- **APNs sandbox vs production:** a token only works in the environment its build was signed for. One
  gateway serves one (`apns.use_sandbox`); run a second one for development builds.
- **Listeners:** `server.bind` is the API (dual stack, `[::]:8090`); `server.health_bind` carries
  `/healthz` and `/metrics` and defaults to loopback. Behind a reverse proxy set
  `server.client_ip_header` (the last entry counts); only the registration limits use the client address.
- **Registration:** `registration.mode = "open"` (default; any server registers its own key) or `"closed"`.

## Container

`containers/teamcraft-push-gateway.Containerfile`; images are published as
`ghcr.io/zeitgleich/teamcraft-push-gateway` (multi-arch, signed with cosign, provenance attestation and SBOMs per
release). It runs as UID 65532 with a read-only root filesystem; mount a volume at
`/var/lib/teamcraft-push-gateway` (writable for that UID) for the database. The image binds all
addresses and `HEALTHCHECK`s with `teamcraft-push-gateway healthcheck`; do not publish port 8091.

## Operator CLI

Works on the database file, also while the gateway runs (WAL mode); a block takes effect within
`database.server_cache_secs`.

```sh
teamcraft-push-gateway servers list
teamcraft-push-gateway servers block <server-id> <reason...>
teamcraft-push-gateway servers unblock <server-id>
teamcraft-push-gateway servers limits <server-id> <per-second|default> <burst|default> <per-day|default>
teamcraft-push-gateway servers allow <public-key-base64url>      # for registration.mode = "closed"
```

## Monitoring and logs

`/healthz` (database reachable) and `/metrics` (Prometheus text): `teamcraft_push_gateway_pushes_total{provider,result}`,
`..._refused_total{reason}`, `..._registrations_total`, `..._servers`. No server ID, token or payload is ever a
label or a log field. Alert on `result="rejected"` (credentials refused) and `"unavailable"`.
Logs (`RUST_LOG`, default `info`): start-up, configuration problems and provider refusals with their
status codes.

## Backups

The database holds the server list, the block list, limit overrides and 60 days of daily counters.
A lost database only makes servers register again and resets quotas; back it up (SQLite `.backup`) if
you want blocks to survive.
