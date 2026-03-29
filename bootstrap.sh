#!/bin/bash
# Katafract Node Bootstrap Script
# Idempotent — safe to run multiple times
# Requires: .env populated with node-specific values

set -euo pipefail

# Load environment
if [ ! -f /opt/katafract/.env ]; then
  echo "ERROR: .env not found. Copy .env.template and populate it."
  exit 1
fi
source /opt/katafract/.env

echo "Bootstrapping node: ${NODE_ID} (${SITE} / ${REGION})"

# ── System hardening ──────────────────────────────────────────
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
  wireguard unbound unbound-host \
  prometheus-node-exporter \
  nftables fail2ban \
  curl wget jq git python3 python3-pip \
  net-tools htop

# Disable swap permanently
swapoff -a
sed -i '/swap/d' /etc/fstab
echo "Swap disabled"

# ── WireGuard ─────────────────────────────────────────────────
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# Write private key from env
echo "${WG_PRIVATE_KEY}" > /etc/wireguard/private.key
chmod 600 /etc/wireguard/private.key

# Derive public key
PUBLIC_KEY=$(echo "${WG_PRIVATE_KEY}" | wg pubkey)
echo "${PUBLIC_KEY}" > /etc/wireguard/public.key

# Generate config from template
envsubst < /opt/katafract/configs/wg0.conf.template > /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf

# Enable IP forwarding
cat >> /etc/sysctl.conf << EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
sysctl -p

systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0
echo "WireGuard started"

# ── Unbound DNS ───────────────────────────────────────────────
cp /opt/katafract/configs/unbound.conf /etc/unbound/unbound.conf

# Initial blocklist fetch
bash /opt/katafract/scripts/update-blocklist.sh

systemctl enable unbound
systemctl restart unbound
echo "Unbound started"

# ── nftables firewall ─────────────────────────────────────────
cp /opt/katafract/configs/nftables.conf /etc/nftables.conf
systemctl enable nftables
systemctl restart nftables
echo "nftables started"

# ── Prometheus node exporter ──────────────────────────────────
systemctl enable prometheus-node-exporter
systemctl start prometheus-node-exporter

# ── WireGuard metrics collector ───────────────────────────────
mkdir -p /var/lib/prometheus/node-exporter
cp /opt/katafract/scripts/wg-metrics.sh /usr/local/bin/wg-metrics.sh
chmod +x /usr/local/bin/wg-metrics.sh
echo "* * * * * root /usr/local/bin/wg-metrics.sh" > /etc/cron.d/wg-metrics

# ── Blocklist cron ────────────────────────────────────────────
echo "0 3 * * * root /opt/katafract/scripts/update-blocklist.sh" \
  > /etc/cron.d/katafract-blocklist

# ── Node agent ────────────────────────────────────────────────
pip3 install -r /opt/katafract/agent/requirements.txt --break-system-packages -q
cp /opt/katafract/agent/agent.service /etc/systemd/system/katafract-agent.service
systemctl daemon-reload
systemctl enable katafract-agent
systemctl start katafract-agent
echo "Katafract agent started"

# ── Node identity file ────────────────────────────────────────
mkdir -p /etc/katafract
cat > /etc/katafract/node.json << EOF
{
  "node_id": "${NODE_ID}",
  "site": "${SITE}",
  "region": "${REGION}",
  "sequence": ${SEQUENCE},
  "tier": "${TIER}",
  "ipv4": "${IPV4_ADDRESS}",
  "ipv6": "${IPV6_ADDRESS}",
  "ipv6_block": "${IPV6_BLOCK}",
  "public_key": "${PUBLIC_KEY}",
  "wg_port": ${WG_LISTEN_PORT},
  "bootstrapped_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo ""
echo "Bootstrap complete"
echo "  Node ID:    ${NODE_ID}"
echo "  Public key: ${PUBLIC_KEY}"
echo "  IPv4:       ${IPV4_ADDRESS}"
echo "  IPv6:       ${IPV6_ADDRESS}"
echo ""
echo "Save the public key — Artemis needs it to register this node."
