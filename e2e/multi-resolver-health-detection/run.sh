#!/usr/bin/env bash
# Test: health state machine detects and excludes a forging resolver.
#
# dns-forge returns NXDOMAIN for every query. The client uses
# -udp-shared-socket so there is no per-query UDP worker filtering —
# forged NXDOMAIN responses reach evaluateIncoming directly, which is
# the code path affected by the per-response decay bug.
#
# With per-query UDP (the default), the UDP worker absorbs forged
# responses and detection happens through the pending-timeout path
# instead. That path works at high query rates even without the decay fix,
# so it cannot demonstrate the bug. Shared-socket mode is required to
# exercise the evaluateIncoming accumulation path.
#
# The health state machine decays penalty counters only on the 1/sec
# health tick, not per-response. This allows invalidCount to grow at
# the response rate (~several/sec) and cross the detection threshold
# within seconds. dns-forge should be marked Down and excluded from
# round-robin. During the measurement burst, dns-forge should receive
# only occasional probe queries, not 50% of all traffic.
set -euo pipefail
cd "$(dirname "$0")"

cleanup() { docker compose down -v 2>/dev/null; }
trap cleanup EXIT

fetch() {
    docker compose exec -T client wget -q -O /dev/null http://localhost:7000 2>/dev/null
}

query_count() {
    # Count the number of DNS queries logged by a CoreDNS service.
    docker compose logs "$1" 2>&1 | grep -c 't\.example\.com' || echo 0
}

echo "--- Building and starting services ---"
docker compose up -d --build

echo "--- Waiting for tunnel (up to 30s) ---"
for i in $(seq 1 30); do
    if fetch; then
        echo ""
        echo "--- Tunnel is up ---"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo ""
        docker compose logs client server dns-good dns-forge
        echo "=== FAIL (tunnel not ready) ==="
        exit 1
    fi
    printf "."
    sleep 1
done

# Phase 1: let the health state machine observe the forging resolver.
# The pending-response timeout is 5s and the detection threshold is 8
# timeouts / 5 invalids, so ~15s should be enough for the health machine
# to mark dns-forge as Down.
echo "--- Waiting 20s for health machine to observe dns-forge ---"
# Drive some traffic during the detection window so pending IDs accumulate.
for i in $(seq 1 20); do
    fetch || true
    sleep 1
done

# Phase 2: snapshot dns-forge query count, then drive a traffic burst
# and measure how many NEW queries dns-forge receives.
count_before=$(query_count dns-forge)
echo "--- dns-forge query count before burst: $count_before ---"

echo "--- Driving 10 HTTP fetches through tunnel ---"
for i in $(seq 1 10); do
    fetch || true
    sleep 1
done

count_after=$(query_count dns-forge)
delta=$((count_after - count_before))
echo "--- dns-forge query count after burst: $count_after (delta: $delta) ---"

# Also check dns-good for comparison.
good_before_ignored=0  # not tracked, but log the total for debugging
good_total=$(query_count dns-good)
echo "--- dns-good total queries: $good_total ---"

# dns-forge should receive very few queries during the burst (only probe
# queries at ~1/sec = ~10 max), not ~50% of all traffic.
max_allowed=15
if [ "$delta" -gt "$max_allowed" ]; then
    echo "--- dns-forge received $delta queries during the burst (max allowed: $max_allowed) ---"
    echo "--- Health machine did not route away from the forging resolver (decay bug) ---"
    docker compose logs client | tail -20
    echo "=== FAIL ==="
    exit 1
fi

echo "--- dns-forge received only $delta queries during burst (≤$max_allowed); health machine routed away ---"
echo "=== PASS ==="
