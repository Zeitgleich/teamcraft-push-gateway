# Security policy

The push gateway forwards sealed push wake-ups of TeamCraft servers to Apple and Google with the
publisher's credentials. It must never be able to read or forge a wake-up, and it holds credentials
that can push to every installation of the store apps: reports about either are especially welcome
([docs/design.md](docs/design.md) §3 is the threat model).

## Reporting a vulnerability

Please **do not** open a public issue. Report privately through GitHub's
[private vulnerability reporting](../../security/advisories/new) ("Report a vulnerability" on the
repository's Security tab), or by e-mail to opensource@zeitgleich.de.

Include what you found, how to reproduce it, the affected version or commit, and the impact you
expect. We confirm receipt within a few working days and keep you updated until a fix is released.
We credit reporters in the advisory unless you prefer otherwise.

## Supported versions

Until the first stable release, only the latest commit on `main` receives security fixes; afterwards
the latest release.

## Scope

In scope: the gateway binary, its container image and the HTTP contract ([docs/api.md](docs/api.md)).

Out of scope: denial of service through sheer traffic volume, vulnerabilities that need access to
the gateway host or its credentials, and issues in APNs, FCM or the TeamCraft server themselves
(report those to the respective project).
