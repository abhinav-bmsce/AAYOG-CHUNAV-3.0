#!/bin/bash
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

PORT=9666
CA_CERT="certs/ca.crt"
ADMIN_CERT="certs/admin_client.crt"
ADMIN_KEY="certs/admin_client.key"

echo "================================================================="
echo "   AAYOG_CHUNAV 3.0 - HIGH-CONCURRENCY RACE CONDITION TEST       "
echo "================================================================="

# Clean past run state and start fresh
make reset-votes > /dev/null 2>&1

echo "[TEST SETUP] Launching AAYOG_CHUNAV 3.0 Server on port $PORT..."
./server $PORT --dev > server_conc_test.log 2>&1 &
SERVER_PID=$!
sleep 1

# Ensure Election 1 is ACTIVE for concurrent voting test
LOGIN_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"Admin@Aayog2026#","otp":"888999"}')
ADMIN_TOKEN=$(echo "$LOGIN_RESP" | grep -o '"token":"[^"]*' | head -n 1 | cut -d'"' -f4)
curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/election/state" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"election_id":1,"state":"ACTIVE"}' > /dev/null

cleanup() {
    echo -e "\n[TEARDOWN] Stopping test server (PID $SERVER_PID)..."
    kill -2 $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}
trap cleanup EXIT

echo "--- Generating 30 Concurrent Voter Requests (V110 - V139) ---"
# Fire 30 concurrent OTP requests and votes in parallel
CONCURRENT_DIR="/tmp/aayog_conc_$$"
mkdir -p "$CONCURRENT_DIR"

VOTE_PIDS=""
for i in $(seq 110 139); do
    (
        VID="V$i"
        CAND=$(( (i % 3) + 1 )) # Alternate candidate 1, 2, 3
        # Request OTP
        OTP_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/otp/request" \
            -H "Content-Type: application/json" \
            -d "{\"voter_id\":\"$VID\",\"election_id\":1}")
        OTP=$(echo "$OTP_RESP" | grep -o '"simulated_otp":"[^"]*"' | cut -d'"' -f4)

        # Cast Ballot
        VOTE_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/vote" \
            -H "Content-Type: application/json" \
            -d "{\"voter_id\":\"$VID\",\"candidate_id\":$CAND,\"otp\":\"$OTP\",\"election_id\":1}")

        echo "$VID:$VOTE_RESP" > "$CONCURRENT_DIR/$VID.res"
    ) &
    VOTE_PIDS="$VOTE_PIDS $!"
done

# Wait for only the worker voter requests to complete
wait $VOTE_PIDS

SUCCESS_COUNT=0
for f in "$CONCURRENT_DIR"/*.res; do
    if grep -q '"success":true' "$f"; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
done

echo "  Concurrent Voting Transactions Finished: $SUCCESS_COUNT / 30 succeeded."
rm -rf "$CONCURRENT_DIR"

if [ "$SUCCESS_COUNT" -eq 30 ]; then
    echo "  [PASS] All 30 concurrent voting transactions processed cleanly with 0 dropped ballots."
else
    echo "  [FAIL] Expected 30 successful ballots, got $SUCCESS_COUNT."
    exit 1
fi

echo -e "\n--- Testing High-Concurrency Duplicate Vote Race Condition ---"
# Launch 10 simultaneous threads attempting to vote for the SAME voter (V140) at the exact same instant
V_RACE="V140"
OTP_RACE_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/otp/request" \
    -H "Content-Type: application/json" \
    -d "{\"voter_id\":\"$V_RACE\",\"election_id\":1}")
OTP_RACE=$(echo "$OTP_RACE_RESP" | grep -o '"simulated_otp":"[^"]*"' | cut -d'"' -f4)

RACE_DIR="/tmp/aayog_race_$$"
mkdir -p "$RACE_DIR"

RACE_PIDS=""
for t in $(seq 1 10); do
    (
        R_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/vote" \
            -H "Content-Type: application/json" \
            -d "{\"voter_id\":\"$V_RACE\",\"candidate_id\":1,\"otp\":\"$OTP_RACE\",\"election_id\":1}")
        echo "$R_RESP" > "$RACE_DIR/$t.res"
    ) &
    RACE_PIDS="$RACE_PIDS $!"
done
wait $RACE_PIDS

RACE_SUCCESS=0
RACE_BLOCKED=0
for f in "$RACE_DIR"/*.res; do
    if grep -q '"success":true' "$f"; then
        RACE_SUCCESS=$((RACE_SUCCESS + 1))
    elif grep -q 'ALREADY_VOTED' "$f" || grep -q 'ERR_OTP_REQUIRED' "$f"; then
        RACE_BLOCKED=$((RACE_BLOCKED + 1))
    fi
done
rm -rf "$RACE_DIR"

echo "  Simultaneous Same-Voter Attempts: $RACE_SUCCESS accepted, $RACE_BLOCKED blocked."
if [ "$RACE_SUCCESS" -eq 1 ] && [ "$RACE_BLOCKED" -eq 9 ]; then
    echo "  [PASS] Mutex synchronization strictly prevented race-condition duplicate voting (Exactly 1 ballot recorded, 9 rejected)."
else
    echo "  [FAIL] Race condition violated: $RACE_SUCCESS accepted, $RACE_BLOCKED blocked."
    exit 1
fi

echo -e "\n--- Verifying HMAC-SHA256 Audit Ledger Chain Integrity ---"
AUDIT_VERIFY=$(curl -s --cacert "$CA_CERT" --cert "$ADMIN_CERT" --key "$ADMIN_KEY" \
    "https://127.0.0.1:$PORT/api/admin/audit/verify" -X POST)
echo "  Audit Chain Verification: $AUDIT_VERIFY"
if [[ "$AUDIT_VERIFY" == *"chain_valid\":true"* ]]; then
    echo "  [PASS] HMAC-SHA256 audit ledger remained 100% intact under concurrent load."
else
    echo "  [FAIL] Audit ledger corrupted."
    exit 1
fi

echo "================================================================="
echo "   [SUCCESS] CONCURRENCY & RACE CONDITION TESTS PASSED!          "
echo "================================================================="
