# katafract-node

This repository contains the complete code that runs on every Katafract
VPN node. It is public so users and independent security auditors can
verify our privacy claims.

**No secrets are present in this repository.** All credentials are
injected at provisioning time by Artemis and exist only in the node's
`.env` file and kernel memory.

## What runs on every node

- WireGuard — VPN tunnel (kernel module)
- Unbound — encrypted DNS resolver (DoH/DoT upstream)
- nftables — default-deny firewall
- Katafract node agent — reports health to Artemis, pulls desired state

## Audit notes

- Swap is permanently disabled — no memory is paged to disk
- No connection logs — WireGuard peer state exists in kernel memory only
- No DNS query logs — Unbound log-verbosity: 0
- RAM-only operation — all ephemeral data in tmpfs

## Bootstrap

Artemis provisions nodes automatically. Manual bootstrap:

```bash
git clone https://github.com/katafractured/katafract-node /opt/katafract
cp .env.template .env
# Edit .env with node-specific values
bash bootstrap.sh
```

## Security audit

Published at katafract.com/audits
