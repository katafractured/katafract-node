#!/bin/bash
# Refreshes Unbound blocklist from Steven Black + Hagezi sources
# Runs daily at 3am via cron — also callable by Artemis via node agent

set -euo pipefail

BLOCKLIST_FILE="/etc/unbound/blocklist.conf"

echo "Updating blocklist..."

# Download and merge sources
curl -sf "${BLOCKLIST_URL_1:-https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts}" \
  | grep "^0\.0\.0\.0" \
  | awk '{print $2}' > /tmp/hosts1.txt

curl -sf "${BLOCKLIST_URL_2:-https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt}" \
  | grep "^0\.0\.0\.0" \
  | awk '{print $2}' >> /tmp/hosts1.txt

# Deduplicate and generate Unbound config
sort -u /tmp/hosts1.txt \
  | grep -v "^localhost$" \
  | awk '{
      print "local-zone: \"" $1 "\" redirect"
      print "local-data: \"" $1 " A 0.0.0.0\""
    }' > "${BLOCKLIST_FILE}"

rm -f /tmp/hosts1.txt

# Reload Unbound
systemctl reload unbound 2>/dev/null || true

BLOCKED=$(wc -l < "${BLOCKLIST_FILE}")
echo "Blocklist updated — $(( BLOCKED / 2 )) domains blocked"
