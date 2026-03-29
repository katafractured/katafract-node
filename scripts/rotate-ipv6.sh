#!/bin/bash
# Rotates IPv6 address to a new address in the /64 block
# Called by Artemis node agent when IPv6 address is blacklisted

set -euo pipefail

NEW_IPV6="${1:-}"
if [ -z "${NEW_IPV6}" ]; then
  echo "Usage: rotate-ipv6.sh NEW_IPV6_ADDRESS"
  exit 1
fi

source /opt/katafract/.env

echo "Rotating IPv6: ${IPV6_ADDRESS} → ${NEW_IPV6}"

# Remove old IPv6 address
ip addr del "${IPV6_ADDRESS}/64" dev eth0 2>/dev/null || true

# Add new IPv6 address
ip addr add "${NEW_IPV6}/64" dev eth0

# Update .env with new address
sed -i "s/IPV6_ADDRESS=.*/IPV6_ADDRESS=${NEW_IPV6}/" /opt/katafract/.env

# Update node identity file
python3 -c "
import json
f = '/etc/katafract/node.json'
d = json.load(open(f))
d['ipv6'] = '${NEW_IPV6}'
json.dump(d, open(f,'w'), indent=2)
"

echo "IPv6 rotation complete — Artemis will update DNS records"
