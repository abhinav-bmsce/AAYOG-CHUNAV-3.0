#!/bin/bash
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
# ==============================================================================
# Automated Verification Script for Online Voting System
# Tests authentication, single voting, duplicate prevention, and tallying.
# ==============================================================================

PORT=9090
make reset-votes > /dev/null 2>&1

echo "[TEST] Starting Server in background on port $PORT..."
./server $PORT --dev > server_test.log 2>&1 &
SERVER_PID=$!

# Wait for server to bind
sleep 1

echo "[TEST 1] Client 1 (Voter V101) casts vote for Candidate 1 (Alice Johnson)..."
# Feed menu: 1 (Cast vote), V101 (ID), 1 (Alice), 3 (Exit)
printf "1\nV101\n1\n3\n" | ./client 127.0.0.1 $PORT > client1.log 2>&1

echo "[TEST 2] Duplicate Vote Attempt: Voter V101 attempts to vote again..."
# Feed menu: 1 (Cast vote), V101 (ID), 3 (Exit)
printf "1\nV101\n3\n" | ./client 127.0.0.1 $PORT > client2_duplicate.log 2>&1

echo "[TEST 3] Unregistered Voter Attempt: Voter V999 attempts to vote..."
# Feed menu: 1 (Cast vote), V999 (ID), 3 (Exit)
printf "1\nV999\n3\n" | ./client 127.0.0.1 $PORT > client3_invalid.log 2>&1

echo "[TEST 4] Client 4 (Voter V102) casts vote for Candidate 2 (Bob Smith)..."
printf "1\nV102\n2\n3\n" | ./client 127.0.0.1 $PORT > client4.log 2>&1

echo "[TEST 5] Client 5 (Voter V103) casts vote for Candidate 1 (Alice Johnson)..."
printf "1\nV103\n1\n3\n" | ./client 127.0.0.1 $PORT > client5.log 2>&1

echo "[TEST 6] Querying Live Election Results..."
# Feed menu: 2 (View results), 3 (Exit)
printf "2\n3\n" | ./client 127.0.0.1 $PORT > results.log 2>&1

# Stop test server
kill -2 $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo "========================================================="
echo "                TEST LOG: DUPLICATE PREVENTION           "
echo "========================================================="
cat client2_duplicate.log | grep -A 2 -B 1 "ALREADY CAST A VOTE" || cat client2_duplicate.log

echo "========================================================="
echo "                TEST LOG: UNREGISTERED ID                "
echo "========================================================="
cat client3_invalid.log | grep -A 2 -B 1 "NOT registered" || cat client3_invalid.log

echo "========================================================="
echo "                TEST LOG: ELECTION RESULTS               "
echo "========================================================="
cat results.log | grep -A 15 "OFFICIAL ELECTION RESULTS" || cat results.log

echo "========================================================="
echo "                PERSISTED VOTES (votes.txt)              "
echo "========================================================="
cat votes.txt
rm -f client1.log client2_duplicate.log client3_invalid.log client4.log client5.log results.log server_test.log votes.txt

echo "========================================================="
echo "[SUCCESS] All automated test scenarios executed!"

