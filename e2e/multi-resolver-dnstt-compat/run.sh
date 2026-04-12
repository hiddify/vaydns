#!/usr/bin/env bash
# Test: multi-resolver with dnstt-compat wire format.
# Verifies that -dnstt-compat (8-byte ClientID, padding prefixes, forced TXT,
# longer timeouts) works correctly when combined with multiple UDP resolvers.
# The wire format sits above the MultiResolver transport layer so there should
# be no interaction, but this test guards against regressions.
set -euo pipefail
cd "$(dirname "$0")"

cleanup() { docker compose down -v 2>/dev/null; }
trap cleanup EXIT

echo "--- Building and starting services ---"
docker compose up -d --build

# dnstt-compat uses longer timeouts (2m idle, 10s keepalive) and the tunnel
# handshake may be slower due to the larger wire overhead, so allow more time.
echo "--- Waiting for tunnel (up to 45s) ---"
for i in $(seq 1 45); do
    if docker compose exec -T client wget -q -O- http://localhost:7000 2>/dev/null | grep -q "Welcome to nginx"; then
        echo ""
        echo "=== PASS ==="
        exit 0
    fi
    printf "."
    sleep 1
done

echo ""
echo "--- Tunnel did not come up. Dumping logs ---"
docker compose logs client server dns1 dns2
echo "=== FAIL ==="
exit 1
