# TeamCraft push gateway

Forwards the **sealed push wake-ups** of [TeamCraft](https://github.com/Zeitgleich/TeamCraft) servers to
Apple (APNs) and Google (FCM) with the credentials of the published iOS and Android store apps, so
self-hosted servers work with the store apps. It sees device tokens and ciphertext only: it can't read
or forge a wake-up, and it never learns users, devices or keys.

Only whoever **publishes** store apps runs a gateway; a TeamCraft server just points `[push.gateway] url`
at it. Servers with self-built, self-signed apps use their own APNs/FCM credentials and need no gateway.

| Document                                 | Content                                                 |
|------------------------------------------|---------------------------------------------------------|
| [docs/design.md](docs/design.md)         | Why, threat model, limits, the SQLite decision          |
| [docs/api.md](docs/api.md)               | The versioned HTTP contract (`/v1`), signatures, errors |
| [docs/operations.md](docs/operations.md) | Configuration, container, operator CLI, monitoring      |

## Quick look

```sh
cp teamcraft-push-gateway.example.toml gateway.toml     # add the APNs and/or FCM credentials
cargo run --release -- --config gateway.toml            # serves on [::]:8090
cargo run --release -- --config gateway.toml servers list
```

Container: `podman build --format docker -f containers/teamcraft-push-gateway.Containerfile -t teamcraft-push-gateway .`
(releases publish signed multi-arch images to `ghcr.io/zeitgleich/teamcraft-push-gateway`).

## Development

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features        # local fake APNs/FCM, no network, no credentials
cargo deny check
```

Commits are signed off (`git commit -s`, Developer Certificate of Origin). Code, comments and docs are
English. The contract fixtures in `tests/fixtures/` are shared with the TeamCraft repository
(`crates/teamcraft-proto/tests/fixtures/push_gateway/`): change both together.

## License

AGPL-3.0-or-later, like TeamCraft. See [LICENSE](LICENSE). Security: [SECURITY.md](SECURITY.md). Changes:
[CHANGELOG.md](CHANGELOG.md).
