# Operating a gateway

Only the publisher of store apps (or whoever builds their own apps for a group of servers) runs a
gateway. It is one binary or container image with a small SQLite file; run it on **its own host**,
separate from every chat server, behind a TLS-terminating reverse proxy.

## The publisher's deployment

The publisher of the official TeamCraft store apps runs its gateway at **https://push-gw.zeitgleich.de**
(a separate host, TLS terminated by a reverse proxy in front of `server.bind`, `registration.mode = "open"`,
the publisher's APNs key and Firebase service account as container secrets). TeamCraft servers point
`[push.gateway] url` at it; the TeamCraft deployment playbook does so by default. The binary and the image
contain no host name. An example for the publisher's configuration:

```toml
[server]
bind = "127.0.0.1:8090"          # the reverse proxy for push-gw.zeitgleich.de forwards here
health_bind = "127.0.0.1:8091"
client_ip_header = "x-forwarded-for"

[registration]
mode = "open"

[apns]
key_path = "/run/secrets/apns_key.p8"
key_id = "ABC123DEFG"
team_id = "DEF456GHIJ"
bundle_id = "com.example.teamcraft"    # the store app's bundle ID

[fcm]
service_account_path = "/run/secrets/fcm_service_account.json"
```

The TeamCraft deployment repository has an optional `push_gateway` role that installs exactly this
(rootless Podman, Quadlet, its own Caddy) on a host of its own.

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
teamcraft-push-gateway servers delete <server-id>                # it may register again (open mode)
teamcraft-push-gateway servers prune <days>                      # servers that never pushed, older than <days>
```

Servers that registered but never pushed are also pruned automatically after
`database.prune_unused_after_days` (7); blocked servers and keys added with `servers allow` are kept.

Behind a reverse proxy, set `server.client_ip_header` to the header it sets; the gateway uses the
last value (the one the proxy appended). Let the proxy also enforce request header and body
timeouts and a connection limit: the gateway itself only limits how long a request body may take.

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
