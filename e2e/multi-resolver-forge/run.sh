#!/usr/bin/env bash
# Test: one resolver returns forged responses while another works.
# dns-forge always replies with NXDOMAIN (CoreDNS template plugin), simulating
# a censor or broken resolver injecting fake responses. dns-good behaves
# normally. The tunnel must work through dns-good, with the per-query UDP
# worker's forged-response filter absorbing dns-forge's NXDOMAINs and
# MultiResolver's health state machine eventually routing around it.
set -euo pipefail
cd "$(dirname "$0")"

cleanup() { docker compose down -v 2>/dev/null; }
trap cleanup EXIT

fetch() {
    docker compose exec -T client wget -q -O- http://localhost:7000 2>/dev/null | grep -q "Welcome to nginx"
}

echo "--- Building and starting services ---"
docker compose up -d --build

echo "--- Waiting for tunnel through dns-good while dns-forge injects NXDOMAINs (up to 60s) ---"
ok_count=0
for i in $(seq 1 60); do
    if fetch; then
        ok_count=$((ok_count + 1))
        # Require two consecutive successes so one lucky query doesn't pass
        # the test while the forging resolver is still in rotation.
        if [ "$ok_count" -ge 2 ]; then
            echo ""
            # Sanity check: make sure dns-forge actually saw queries, so we
            # know the tunnel was exercising the forging code path and didn't
            # only hit dns-good by chance. CoreDNS's log plugin may buffer
            # output briefly, so give it a moment to flush before grepping.
            sleep 2
            forge_logs=$(docker compose logs dns-forge 2>&1)
            if ! grep -q 'NXDOMAIN' <<<"$forge_logs"; then
                echo "--- dns-forge never served NXDOMAIN; the forging code path may not have been exercised ---"
                echo "$forge_logs"
                echo "=== FAIL (forging path not exercised) ==="
                exit 1
            fi
            nxdomain_count=$(grep -c 'NXDOMAIN' <<<"$forge_logs" || true)
            echo "--- dns-forge served $nxdomain_count NXDOMAIN responses; forging path exercised ---"

            # Verify the client-side milestone log fired with per-resolver
            # attribution: "forged DNS responses from <dns-forge-ip>: ..."
            # This proves the ForgedStats plumbing carries the resolver
            # label end-to-end and that milestone thresholds fire correctly
            # in multi-resolver mode.
            client_logs=$(docker compose logs client 2>&1)
            if ! grep -q 'forged DNS responses from 172.28.0.11' <<<"$client_logs"; then
                echo "--- Client did not log labeled forged milestone for dns-forge (172.28.0.11) ---"
                echo "$client_logs" | tail -30
                echo "=== FAIL (missing per-resolver forged milestone log) ==="
                exit 1
            fi
            milestone_line=$(grep 'forged DNS responses from 172.28.0.11' <<<"$client_logs" | tail -1)
            echo "--- Client milestone: $milestone_line ---"
            echo "--- Tunnel delivers consistent responses despite forged NXDOMAINs ---"
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
echo "--- Tunnel did not come up through dns-good ---"
docker compose logs client server dns-good dns-forge
echo "=== FAIL ==="
exit 1
