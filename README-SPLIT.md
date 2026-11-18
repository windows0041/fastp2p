# fastp2p

The client half of fastp2p: the NAT-aware tunnelling client for Linux, Windows,
macOS and Android, with the SOCKS5 and port-forwarding rules.

## What this repository contains

- `src/ include/ tests/ android/ cmake/ docs/ examples/ platform/ scripts/` — the
  client as it lived under the repository root in the monorepo.
- `common/` — the code shared with the gateway (enrollment, config merge, UTF-8
  helpers, the public bootstrap identity). The gateway keeps its own copy in the
  `fastp2p-gateway` repository.
- `scripts/tls/`, `scripts/stun/` — the certificate helper and the local STUN /
  callback-probe servers used by the integration tests.

## Related repositories

- `fastp2p-gateway` — the WSS control plane, rule store and web console.
- `oldfastp2p` — the previous monorepo this tree was extracted from; it is kept for
  reference and is no longer built.
