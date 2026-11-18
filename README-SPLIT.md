# fastp2p

The client half of fastp2p: the NAT-aware tunnelling client for Linux, Windows,
macOS and Android, with the SOCKS5 and port-forwarding rules.

## What this repository contains

- Client source, tests, Android sources, and build scripts live directly under
  `src/`, `include/`, `tests/`, `android/`, `cmake/`, and `scripts/`.
- `common/` — the code shared with the gateway (enrollment, config merge, UTF-8
  helpers, the public bootstrap identity). The gateway keeps its own copy in the
  `fastp2p-gateway` repository.
- `scripts/tls/`, `scripts/stun/` — the certificate helper and the local STUN /
  callback-probe servers used by the integration tests.

## Related repositories

- [fastp2p-gateway](https://github.com/windows0041/fastp2p-gateway) hosts the WSS
  control plane, rule store, and web console.
- [oldfastp2p](https://github.com/windows0041/oldfastp2p) preserves the monorepo
  history.

Build commands run from the client repository root. See the [client README](README.md)
and [validation guide](VALIDATION-ZH.md).
