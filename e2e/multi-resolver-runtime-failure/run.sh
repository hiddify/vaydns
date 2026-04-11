#!/usr/bin/env bash
# Test: one of several UDP resolvers dies mid-flight.
# Start the tunnel with two working DNS resolvers, verify HTTP traffic works,
# kill one resolver, and verify traffic continues through the remaining one.
#
# A failing UDP resolver does not surface an error to MultiResolver (the
# per-query worker retries silently), so this test validates that the health
# state machine + round-robin selection routes around it without tearing
# down the tunnel session.
set -euo pipefail
cd "$(dirname "$0")"

cleanup() { docker compose down -v 2>/dev/null; }
trap cleanup EXIT

fetch() {
    docker compose exec -T client wget -q -O- http://localhost:7000 2>/dev/null | grep -q "Welcome to nginx"
}

echo "--- Building and starting services ---"
docker compose up -d --build

echo "--- Waiting for initial tunnel (up to 30s) ---"
for i in $(seq 1 30); do
    if fetch; then
        echo ""
        echo "--- Initial tunnel is up ---"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo ""
        docker compose logs client server dns1 dns2
        echo "=== FAIL (initial tunnel not ready) ==="
        exit 1
    fi
    printf "."
    sleep 1
done

# Snapshot the session id before the kill, to detect any reconnect later.
pre_kill_sessions=$(docker compose logs client 2>&1 | grep -c 'session .* ready' || true)

echo "--- Killing dns1 (half the queries will start dropping) ---"
docker compose kill dns1

# Give the client a moment to notice and start routing around dns1.
sleep 3

echo "--- Verifying tunnel still works through dns2 (up to 45s) ---"
ok_count=0
for i in $(seq 1 45); do
    if fetch; then
        ok_count=$((ok_count + 1))
        # Require two consecutive successes so we don't declare victory on
        # a lucky query that happened to go to dns2.
        if [ "$ok_count" -ge 2 ]; then
            post_kill_sessions=$(docker compose logs client 2>&1 | grep -c 'session .* ready' || true)
            new_sessions=$((post_kill_sessions - pre_kill_sessions))
            if [ "$new_sessions" -gt 0 ]; then
                echo ""
                echo "--- Tunnel recovered but triggered $new_sessions new session(s) — resolver failure should be isolated without a full reconnect ---"
                docker compose logs client | tail -30
                echo "=== FAIL (session was rebuilt instead of isolated) ==="
                exit 1
            fi
            echo ""
            echo "--- Tunnel survived with 0 new sessions (single-entry failure isolated) ---"
            echo "=== PASS ==="
            exit 0
        fi
    else
        ok_count=0
    fi
    printf "."
    sleep 1
done

echo ""
echo "--- Tunnel did not survive dns1 kill ---"
docker compose logs client server dns1 dns2
echo "=== FAIL ==="
exit 1
