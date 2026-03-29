#!/bin/bash
# Exposes WireGuard metrics to Prometheus via textfile collector
# Runs every minute via cron
# Includes per-peer active count (handshake within 180s)

PEERS=$(wg show wg0 peers 2>/dev/null | wc -l)
RX=$(wg show wg0 transfer 2>/dev/null | awk '{sum+=$2} END{print sum+0}')
TX=$(wg show wg0 transfer 2>/dev/null | awk '{sum+=$3} END{print sum+0}')

# Active peers — handshake within last 180 seconds
NOW=$(date +%s)
ACTIVE=0
while IFS=$'\t' read -r pubkey ts; do
  if [ -n "$ts" ] && [ "$ts" -gt 0 ]; then
    AGE=$(( NOW - ts ))
    if [ $AGE -le 180 ]; then
      ACTIVE=$(( ACTIVE + 1 ))
    fi
  fi
done < <(wg show wg0 latest-handshakes 2>/dev/null)

cat > /var/lib/prometheus/node-exporter/wg.prom << EOF
# HELP wg_peer_count Registered WireGuard peers
# TYPE wg_peer_count gauge
wg_peer_count{interface="wg0"} ${PEERS}

# HELP wg_active_peer_count WireGuard peers with handshake in last 180s
# TYPE wg_active_peer_count gauge
wg_active_peer_count{interface="wg0"} ${ACTIVE}

# HELP wg_bytes_received_total Total bytes received
# TYPE wg_bytes_received_total counter
wg_bytes_received_total{interface="wg0"} ${RX}

# HELP wg_bytes_sent_total Total bytes sent
# TYPE wg_bytes_sent_total counter
wg_bytes_sent_total{interface="wg0"} ${TX}
EOF
