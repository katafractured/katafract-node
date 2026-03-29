#!/bin/bash
# Health check script — called by Artemis to verify node state
# Exits 0 if healthy, 1 if unhealthy

ERRORS=0

# WireGuard running
if ! systemctl is-active --quiet wg-quick@wg0; then
  echo "FAIL: WireGuard not running"
  ERRORS=$((ERRORS + 1))
fi

# Unbound running
if ! systemctl is-active --quiet unbound; then
  echo "FAIL: Unbound not running"
  ERRORS=$((ERRORS + 1))
fi

# DNS resolving
if ! unbound-host -t A example.com > /dev/null 2>&1; then
  echo "FAIL: DNS resolution failed"
  ERRORS=$((ERRORS + 1))
fi

# Swap disabled
if [ "$(swapon --show | wc -l)" -gt 0 ]; then
  echo "FAIL: Swap is enabled — privacy requirement violated"
  ERRORS=$((ERRORS + 1))
fi

# No query logs
if [ -f /var/log/unbound.log ]; then
  echo "WARN: Unbound log file exists — should be absent"
fi

if [ $ERRORS -eq 0 ]; then
  echo "OK: All health checks passed"
  exit 0
else
  echo "UNHEALTHY: ${ERRORS} check(s) failed"
  exit 1
fi
