#!/bin/bash
# Katafract WraithGate Node Bootstrap
# Idempotent — safe to run multiple times on an existing node
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/katafractured/katafract-node/main/bootstrap.sh \
#     | NODE_ID=vpn-eu-03 \
#       WG_PRIVATE_KEY=<key> \
#       WG_IPV4_TUNNEL=10.10.5.1/24 \
#       WG_LISTEN_PORT=51820 \
#       HEADSCALE_PREAUTH_KEY=<key> \
#       NODE_AGENT_TOKEN=<token> \
#       bash
#
# Required env vars:
#   NODE_ID             — unique node identifier (e.g. vpn-eu-03)
#   WG_PRIVATE_KEY      — WireGuard private key (wg genkey)
#   WG_IPV4_TUNNEL      — WireGuard server interface IP/CIDR (e.g. 10.10.5.1/24)
#   WG_LISTEN_PORT      — WireGuard listen port (default: 51820)
#   HEADSCALE_PREAUTH_KEY — reusable pre-auth key from headscale
#   NODE_AGENT_TOKEN    — shared secret for heartbeat auth with artemis-api
#
# Optional:
#   ARTEMIS_API_URL     — default: http://100.64.0.1/internal/nodes/heartbeat
#   SITE                — display name (e.g. Frankfurt)
#   REGION              — region slug (e.g. eu-west)

set -euo pipefail

: "${NODE_ID:?Required}"
: "${WG_PRIVATE_KEY:?Required}"
: "${WG_IPV4_TUNNEL:=10.10.1.1/24}"
: "${WG_LISTEN_PORT:=51820}"
: "${HEADSCALE_PREAUTH_KEY:?Required}"
: "${NODE_AGENT_TOKEN:?Required}"
: "${ARTEMIS_HEARTBEAT_URL:=http://100.64.0.1/internal/nodes/heartbeat}"
: "${SITE:=$NODE_ID}"
: "${REGION:=unknown}"

WG_SERVER_IP=$(echo "$WG_IPV4_TUNNEL" | cut -d/ -f1)

echo "==> Bootstrapping WraithGate node: $NODE_ID ($SITE / $REGION)"

# ── 1. System packages ────────────────────────────────────────

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
  wireguard \
  nftables \
  fail2ban \
  curl wget jq git \
  net-tools htop \
  ca-certificates gnupg

# Disable swap
swapoff -a 2>/dev/null || true
sed -i '/swap/d' /etc/fstab

# IP forwarding
cat > /etc/sysctl.d/99-katafract.conf << 'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
sysctl -p /etc/sysctl.d/99-katafract.conf

echo "  [ok] system packages"

# ── 2. WireGuard ──────────────────────────────────────────────

mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

echo "$WG_PRIVATE_KEY" > /etc/wireguard/private.key
chmod 600 /etc/wireguard/private.key
WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)
echo "$WG_PUBLIC_KEY" > /etc/wireguard/public.key

# Detect default outbound interface
DEFAULT_IFACE=$(ip route get 1.1.1.1 | grep -oP 'dev \K\S+')

cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = ${WG_IPV4_TUNNEL}
ListenPort = ${WG_LISTEN_PORT}
PrivateKey = ${WG_PRIVATE_KEY}
PostUp   = nft add rule ip nat POSTROUTING oifname "${DEFAULT_IFACE}" masquerade
PostUp   = nft add rule ip6 nat POSTROUTING oifname "${DEFAULT_IFACE}" masquerade
PostDown = nft delete table ip nat 2>/dev/null || true
PostDown = nft delete table ip6 nat 2>/dev/null || true

# Peers added dynamically by Artemis via wg addconf
EOF
chmod 600 /etc/wireguard/wg0.conf

systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

echo "  [ok] WireGuard (interface: $WG_SERVER_IP, port: $WG_LISTEN_PORT)"

# ── 3. AdGuard Home ───────────────────────────────────────────

mkdir -p /opt/adguardhome/data

if ! command -v AdGuardHome &>/dev/null && [ ! -f /opt/adguardhome/AdGuardHome ]; then
  AGH_VER="v0.107.73"
  curl -fsSL "https://github.com/AdguardTeam/AdGuardHome/releases/download/${AGH_VER}/AdGuardHome_linux_amd64.tar.gz" \
    | tar -xz -C /tmp
  mv /tmp/AdGuardHome/AdGuardHome /opt/adguardhome/
  chmod +x /opt/adguardhome/AdGuardHome
fi

# Write config — binds only on WireGuard interface (never public)
cat > /opt/adguardhome/AdGuardHome.yaml << EOF
bind_host: ${WG_SERVER_IP}
bind_port: 3000
auth_attempt_reset_time: 0
http:
  address: ${WG_SERVER_IP}:3000
  session_ttl: 720h
users: []
language: en
theme: auto
dns:
  bind_hosts:
    - ${WG_SERVER_IP}
  port: 53
  upstream_dns:
    - https://dns.quad9.net/dns-query
    - https://cloudflare-dns.com/dns-query
  bootstrap_dns:
    - 9.9.9.9
    - 1.1.1.1
  fallback_dns:
    - 9.9.9.9
  protection_enabled: true
  blocking_mode: default
  filters_update_interval: 24
filters:
  - enabled: true
    url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: https://big.oisd.nl
    name: OISD Full
    id: 2
schema_version: 29
EOF

# Systemd unit
cat > /etc/systemd/system/adguardhome.service << 'EOF'
[Unit]
Description=AdGuard Home DNS
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/adguardhome/AdGuardHome -c /opt/adguardhome/AdGuardHome.yaml -w /opt/adguardhome/data --no-check-update
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable adguardhome
systemctl restart adguardhome

echo "  [ok] AdGuard Home (DNS on ${WG_SERVER_IP}:53)"

# ── 4. nftables firewall ──────────────────────────────────────

cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    # Loopback
    iifname "lo" accept

    # Established/related
    ct state established,related accept

    # SSH (public)
    tcp dport 22 accept

    # WireGuard (public)
    udp dport ${WG_LISTEN_PORT} accept

    # Tailscale mesh
    udp dport 41641 accept

    # ICMP
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    # DNS on WireGuard interface only
    iifname "wg0" udp dport 53 accept
    iifname "wg0" tcp dport 53 accept

    # Drop everything else
    drop
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
    # Allow WireGuard clients to forward outbound
    iifname "wg0" accept
    ct state established,related accept
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}

# NAT table created dynamically by wg-quick PostUp
EOF

systemctl enable nftables
systemctl restart nftables

echo "  [ok] nftables firewall"

# ── 5. node_exporter ─────────────────────────────────────────

if ! command -v node_exporter &>/dev/null; then
  NE_VER="1.8.2"
  curl -fsSL "https://github.com/prometheus/node_exporter/releases/download/v${NE_VER}/node_exporter-${NE_VER}.linux-amd64.tar.gz" \
    | tar -xz -C /tmp
  mv "/tmp/node_exporter-${NE_VER}.linux-amd64/node_exporter" /usr/local/bin/
  chmod +x /usr/local/bin/node_exporter
fi

cat > /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/node_exporter
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable node_exporter
systemctl restart node_exporter

echo "  [ok] node_exporter (:9100, mesh-only via firewall)"

# ── 6. Katafract heartbeat agent ─────────────────────────────

cat > /usr/local/bin/katafract-heartbeat << HBEOF
#!/usr/bin/env bash
# Katafract node heartbeat — reports WireGuard stats to Artemis
set -euo pipefail

ARTEMIS_URL="${ARTEMIS_HEARTBEAT_URL}"
TOKEN="${NODE_AGENT_TOKEN}"
NODE_ID="${NODE_ID}"
WG_IFACE="wg0"

peers=\$(wg show "\$WG_IFACE" peers 2>/dev/null | wc -l)

now=\$(date +%s)
active_peers=0
while IFS= read -r line; do
  ts=\$(echo "\$line" | awk '{print \$2}')
  if [ "\$ts" != "0" ] && [ \$((now - ts)) -le 180 ]; then
    active_peers=\$((active_peers + 1))
  fi
done < <(wg show "\$WG_IFACE" latest-handshakes 2>/dev/null)

rx_bytes=0
tx_bytes=0
while IFS=\$'\t' read -r _ rx tx; do
  rx_bytes=\$((rx_bytes + rx))
  tx_bytes=\$((tx_bytes + tx))
done < <(wg show "\$WG_IFACE" transfer 2>/dev/null)

payload=\$(cat <<JSON
{
  "node_id": "\$NODE_ID",
  "peers": \$peers,
  "active_peers": \$active_peers,
  "rx_bytes": \$rx_bytes,
  "tx_bytes": \$tx_bytes,
  "healthy": true
}
JSON
)

curl -sf -X POST "\$ARTEMIS_URL" \
  -H "Authorization: Bearer \$TOKEN" \
  -H "Content-Type: application/json" \
  -d "\$payload" \
  --max-time 10 || true
HBEOF
chmod +x /usr/local/bin/katafract-heartbeat

# Env file
cat > /etc/katafract-node.env << EOF
KATAFRACT_NODE_ID=${NODE_ID}
EOF

# Systemd timer (every 30s)
cat > /etc/systemd/system/katafract-heartbeat.service << 'EOF'
[Unit]
Description=Katafract node heartbeat
After=network-online.target wg-quick@wg0.service

[Service]
Type=oneshot
EnvironmentFile=/etc/katafract-node.env
ExecStart=/usr/local/bin/katafract-heartbeat
EOF

cat > /etc/systemd/system/katafract-heartbeat.timer << 'EOF'
[Unit]
Description=Katafract heartbeat every 30s

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable katafract-heartbeat.timer
systemctl start katafract-heartbeat.timer

echo "  [ok] katafract-heartbeat (30s timer)"

# ── 7. Tailscale / Headscale mesh enrollment ─────────────────

if ! command -v tailscale &>/dev/null; then
  curl -fsSL https://tailscale.com/install.sh | sh
fi

# Join the headscale mesh (idempotent — tailscale up is safe to re-run)
tailscale up \
  --login-server=https://mesh.katafract.io \
  --auth-key="${HEADSCALE_PREAUTH_KEY}" \
  --advertise-exit-node \
  --accept-dns=false \
  --hostname="${NODE_ID}" \
  || echo "  [warn] tailscale up returned non-zero (may already be enrolled)"

echo "  [ok] tailscale enrolled in headscale mesh"

# ── 8. Node identity summary ──────────────────────────────────

PUBLIC_IP=$(curl -sf https://api.ipify.org 2>/dev/null || echo "unknown")
MESH_IP=$(tailscale ip -4 2>/dev/null || echo "pending")

cat > /etc/katafract-node.json << EOF
{
  "node_id":    "${NODE_ID}",
  "site":       "${SITE}",
  "region":     "${REGION}",
  "public_ip":  "${PUBLIC_IP}",
  "mesh_ip":    "${MESH_IP}",
  "wg_pubkey":  "${WG_PUBLIC_KEY}",
  "wg_port":    ${WG_LISTEN_PORT},
  "wg_addr":    "${WG_SERVER_IP}",
  "bootstrapped_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo ""
echo "============================================"
echo "  Bootstrap complete: ${NODE_ID}"
echo "  WireGuard pubkey:   ${WG_PUBLIC_KEY}"
echo "  WireGuard addr:     ${WG_SERVER_IP}"
echo "  WireGuard port:     ${WG_LISTEN_PORT}"
echo "  Public IP:          ${PUBLIC_IP}"
echo "  Mesh IP:            ${MESH_IP}"
echo "============================================"
echo ""
echo "  Next: register this node in Artemis DB"
echo "  POST /internal/nodes/register with the above values"
echo ""
