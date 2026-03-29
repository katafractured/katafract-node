#!/usr/bin/env python3
"""
Katafract Node Agent
Runs as a systemd service on every VPN node.
Registers with Artemis, sends heartbeats, pulls desired state,
enforces per-peer traffic shaping thresholds.
"""

import os
import json
import time
import subprocess
import logging
from pathlib import Path
from collections import defaultdict

import requests
from dotenv import load_dotenv

load_dotenv("/opt/katafract/.env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

ARTEMIS_URL   = os.environ["ARTEMIS_API_URL"]
NODE_TOKEN    = os.environ["ARTEMIS_NODE_TOKEN"]
NODE_ID       = os.environ["NODE_ID"]
IDENTITY_FILE = Path("/etc/katafract/node.json")

HEARTBEAT_INTERVAL  = 30   # seconds
STATE_POLL_INTERVAL = 60   # seconds
ABUSE_CHECK_INTERVAL = 60  # seconds

# Traffic thresholds — overridable via desired-state from Artemis
PEER_WARN_BYTES_DAY       = int(os.environ.get("PEER_WARN_BYTES_DAY",      32_212_254_720))   # 30 GB
PEER_THROTTLE_BYTES_DAY   = int(os.environ.get("PEER_THROTTLE_BYTES_DAY", 160_000_000_000))   # ~150 GB
PEER_DISCONNECT_BYTES_DAY = int(os.environ.get("PEER_DISCONNECT_BYTES_DAY", 322_122_547_200))  # ~300 GB
PEER_SUSPEND_BYTES_DAY    = int(os.environ.get("PEER_SUSPEND_BYTES_DAY",   644_245_094_400))   # ~600 GB
THROTTLE_RATE_MBPS        = int(os.environ.get("THROTTLE_RATE_MBPS", 10))
ABUSE_SUSTAINED_MBPS      = int(os.environ.get("ABUSE_SUSTAINED_MBPS", 200))
ABUSE_SUSTAINED_SECONDS   = int(os.environ.get("ABUSE_SUSTAINED_SECONDS", 1800))

HEADERS = {
    "Authorization": f"Bearer {NODE_TOKEN}",
    "Content-Type":  "application/json",
    "X-Node-ID":     NODE_ID,
}

# In-memory per-peer tracking — resets on agent restart
# Structure: { pubkey: { "bytes_today": int, "last_bytes": int, "high_bw_since": float|None } }
peer_state: dict = defaultdict(lambda: {
    "bytes_today": 0,
    "last_bytes": 0,
    "high_bw_since": None,
    "throttled": False,
    "warned": False,
})
day_start: float = time.time()


def wg_peers() -> list[str]:
    try:
        out = subprocess.check_output(
            ["wg", "show", "wg0", "peers"], stderr=subprocess.DEVNULL
        ).decode().strip()
        return [p for p in out.splitlines() if p] if out else []
    except Exception:
        return []


def wg_transfer() -> dict[str, tuple[int, int]]:
    """Returns {pubkey: (rx_bytes, tx_bytes)}"""
    try:
        out = subprocess.check_output(
            ["wg", "show", "wg0", "transfer"], stderr=subprocess.DEVNULL
        ).decode().strip()
        result = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                result[parts[0]] = (int(parts[1]), int(parts[2]))
        return result
    except Exception:
        return {}


def wg_latest_handshakes() -> dict[str, int]:
    """Returns {pubkey: unix_timestamp_of_last_handshake}"""
    try:
        out = subprocess.check_output(
            ["wg", "show", "wg0", "latest-handshakes"], stderr=subprocess.DEVNULL
        ).decode().strip()
        result = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                result[parts[0]] = int(parts[1])
        return result
    except Exception:
        return {}


def active_peer_count() -> int:
    """Peers with a handshake in the last 180 seconds."""
    handshakes = wg_latest_handshakes()
    now = time.time()
    return sum(1 for ts in handshakes.values() if now - ts <= 180)


def get_aggregate_transfer() -> dict:
    transfers = wg_transfer()
    rx = sum(v[0] for v in transfers.values())
    tx = sum(v[1] for v in transfers.values())
    return {"rx_bytes": rx, "tx_bytes": tx}


def reset_daily_counters():
    global day_start
    log.info("Resetting daily per-peer byte counters")
    for pubkey in peer_state:
        peer_state[pubkey]["bytes_today"] = 0
        peer_state[pubkey]["warned"] = False
    day_start = time.time()


def apply_throttle(pubkey: str):
    """Apply nftables rate limit for a peer's tunnel IP."""
    try:
        # Get the tunnel IP for this peer
        out = subprocess.check_output(
            ["wg", "show", "wg0", "allowed-ips"], stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0] == pubkey and len(parts) >= 2:
                tunnel_ip = parts[1].split("/")[0]
                subprocess.run([
                    "nft", "add", "rule", "inet", "filter", "forward",
                    "ip", "saddr", tunnel_ip,
                    "limit", "rate", f"{THROTTLE_RATE_MBPS}mbytes/second", "accept"
                ], check=False)
                log.info(f"Throttled peer {pubkey[:16]}... at {THROTTLE_RATE_MBPS} Mbps (tunnel IP {tunnel_ip})")
                peer_state[pubkey]["throttled"] = True
    except Exception as e:
        log.warning(f"Throttle failed for {pubkey[:16]}...: {e}")


def remove_peer(pubkey: str, reason: str):
    """Remove a peer from WireGuard. They can reconnect — token recheck will gate re-entry."""
    try:
        subprocess.run(
            ["wg", "set", "wg0", "peer", pubkey, "remove"],
            check=False
        )
        log.info(f"Removed peer {pubkey[:16]}... reason: {reason}")
    except Exception as e:
        log.warning(f"Failed to remove peer {pubkey[:16]}...: {e}")


def report_abuse(pubkey: str, reason: str, bytes_today: int):
    """Report abuse to Artemis — may trigger token suspension."""
    try:
        requests.post(
            f"{ARTEMIS_URL}/internal/nodes/{NODE_ID}/abuse",
            json={"pubkey": pubkey, "reason": reason, "bytes_today": bytes_today},
            headers=HEADERS,
            timeout=10
        )
    except Exception as e:
        log.warning(f"Abuse report failed: {e}")


def check_peer_abuse():
    """Evaluate per-peer bandwidth and enforce thresholds."""
    global day_start

    # Reset daily counters at midnight UTC
    now = time.time()
    if now - day_start >= 86400:
        reset_daily_counters()

    transfers = wg_transfer()

    for pubkey, (rx, tx) in transfers.items():
        state = peer_state[pubkey]
        total = rx + tx

        # Calculate bytes used since last check
        delta = max(0, total - state["last_bytes"])
        state["last_bytes"] = total
        state["bytes_today"] += delta

        today = state["bytes_today"]

        # Sustained high-bandwidth detection
        elapsed_seconds = HEARTBEAT_INTERVAL
        mbps = (delta * 8) / (elapsed_seconds * 1_000_000) if elapsed_seconds > 0 else 0

        if mbps >= ABUSE_SUSTAINED_MBPS:
            if state["high_bw_since"] is None:
                state["high_bw_since"] = now
            elif now - state["high_bw_since"] >= ABUSE_SUSTAINED_SECONDS:
                log.warning(f"Peer {pubkey[:16]}... sustained {mbps:.0f} Mbps for {ABUSE_SUSTAINED_SECONDS}s — disconnecting")
                remove_peer(pubkey, f"sustained_{ABUSE_SUSTAINED_MBPS}mbps")
                report_abuse(pubkey, "sustained_bandwidth", today)
                continue
        else:
            state["high_bw_since"] = None

        # Daily byte thresholds
        if today >= PEER_SUSPEND_BYTES_DAY:
            log.warning(f"Peer {pubkey[:16]}... exceeded suspend threshold ({today / 1e9:.1f} GB/day)")
            remove_peer(pubkey, "daily_suspend_threshold")
            report_abuse(pubkey, "daily_suspend_threshold", today)

        elif today >= PEER_DISCONNECT_BYTES_DAY:
            log.warning(f"Peer {pubkey[:16]}... exceeded disconnect threshold ({today / 1e9:.1f} GB/day)")
            remove_peer(pubkey, "daily_disconnect_threshold")
            report_abuse(pubkey, "daily_disconnect_threshold", today)

        elif today >= PEER_THROTTLE_BYTES_DAY and not state["throttled"]:
            log.info(f"Peer {pubkey[:16]}... exceeded throttle threshold ({today / 1e9:.1f} GB/day)")
            apply_throttle(pubkey)
            report_abuse(pubkey, "daily_throttle_threshold", today)

        elif today >= PEER_WARN_BYTES_DAY and not state["warned"]:
            log.info(f"Peer {pubkey[:16]}... exceeded warn threshold ({today / 1e9:.1f} GB/day)")
            report_abuse(pubkey, "daily_warn_threshold", today)
            state["warned"] = True


def register():
    identity = json.loads(IDENTITY_FILE.read_text())
    try:
        r = requests.post(
            f"{ARTEMIS_URL}/internal/nodes/register",
            json=identity,
            headers=HEADERS,
            timeout=10
        )
        r.raise_for_status()
        log.info(f"Registered node {NODE_ID} with Artemis")
    except Exception as e:
        log.error(f"Registration failed: {e} — will retry on next cycle")


def send_heartbeat():
    transfer = get_aggregate_transfer()
    payload = {
        "node_id":         NODE_ID,
        "peers":           len(wg_peers()),
        "active_peers":    active_peer_count(),
        "rx_bytes":        transfer["rx_bytes"],
        "tx_bytes":        transfer["tx_bytes"],
        "healthy":         True,
    }
    try:
        r = requests.post(
            f"{ARTEMIS_URL}/internal/nodes/heartbeat",
            json=payload,
            headers=HEADERS,
            timeout=10
        )
        r.raise_for_status()
        log.debug(f"Heartbeat — peers: {payload['peers']} active: {payload['active_peers']}")
    except Exception as e:
        log.warning(f"Heartbeat failed: {e}")


def pull_and_apply_desired_state():
    try:
        r = requests.get(
            f"{ARTEMIS_URL}/internal/nodes/{NODE_ID}/desired-state",
            headers=HEADERS,
            timeout=10
        )
        r.raise_for_status()
        apply_state(r.json())
    except Exception as e:
        log.warning(f"State pull failed: {e} — continuing with current config")


def apply_state(state: dict):
    """
    Apply desired state from Artemis.
    Handles: blocklist_refresh, ipv6_rotate, drain, retire, update_thresholds
    """
    global PEER_WARN_BYTES_DAY, PEER_THROTTLE_BYTES_DAY
    global PEER_DISCONNECT_BYTES_DAY, PEER_SUSPEND_BYTES_DAY
    global THROTTLE_RATE_MBPS, ABUSE_SUSTAINED_MBPS, ABUSE_SUSTAINED_SECONDS

    action = state.get("action")

    if action == "blocklist_refresh":
        log.info("Artemis requested blocklist refresh")
        subprocess.run(["bash", "/opt/katafract/scripts/update-blocklist.sh"], check=False)

    elif action == "ipv6_rotate":
        new_ipv6 = state.get("new_ipv6")
        if new_ipv6:
            log.info(f"Artemis requested IPv6 rotation to {new_ipv6}")
            subprocess.run(
                ["bash", "/opt/katafract/scripts/rotate-ipv6.sh", new_ipv6],
                check=False
            )

    elif action == "drain":
        log.info("Artemis requested drain — closing WireGuard port to new connections")
        subprocess.run(
            ["nft", "delete", "rule", "inet", "filter", "input",
             "udp", "dport", "51820", "accept"],
            check=False
        )

    elif action == "retire":
        log.info("Artemis requested retirement — stopping WireGuard")
        subprocess.run(["systemctl", "stop", "wg-quick@wg0"], check=False)

    elif action == "update_thresholds":
        t = state.get("thresholds", {})
        if "peer_warn_bytes_day"       in t: PEER_WARN_BYTES_DAY       = t["peer_warn_bytes_day"]
        if "peer_throttle_bytes_day"   in t: PEER_THROTTLE_BYTES_DAY   = t["peer_throttle_bytes_day"]
        if "peer_disconnect_bytes_day" in t: PEER_DISCONNECT_BYTES_DAY = t["peer_disconnect_bytes_day"]
        if "peer_suspend_bytes_day"    in t: PEER_SUSPEND_BYTES_DAY    = t["peer_suspend_bytes_day"]
        if "throttle_rate_mbps"        in t: THROTTLE_RATE_MBPS        = t["throttle_rate_mbps"]
        if "abuse_sustained_mbps"      in t: ABUSE_SUSTAINED_MBPS      = t["abuse_sustained_mbps"]
        if "abuse_sustained_seconds"   in t: ABUSE_SUSTAINED_SECONDS   = t["abuse_sustained_seconds"]
        log.info(f"Thresholds updated by Artemis: {t}")

    elif action is None or action == "none":
        pass

    else:
        log.warning(f"Unknown action from Artemis: {action}")


def main():
    log.info(f"Katafract node agent starting — node: {NODE_ID}")
    register()

    last_heartbeat  = 0
    last_state_poll = 0
    last_abuse_check = 0

    while True:
        now = time.time()

        if now - last_heartbeat >= HEARTBEAT_INTERVAL:
            send_heartbeat()
            last_heartbeat = now

        if now - last_state_poll >= STATE_POLL_INTERVAL:
            pull_and_apply_desired_state()
            last_state_poll = now

        if now - last_abuse_check >= ABUSE_CHECK_INTERVAL:
            check_peer_abuse()
            last_abuse_check = now

        time.sleep(5)


if __name__ == "__main__":
    main()
