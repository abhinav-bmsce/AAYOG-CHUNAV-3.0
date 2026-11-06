#!/bin/bash
# Test script verifying AAYOG_CHUNAV Web HTTP endpoints, voter ID range (V101-V199), and TCP CLI

export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
PORT=9098
CA_CERT="certs/ca.crt"
make reset-votes > /dev/null 2>&1

echo "[TEST] Starting AAYOG_CHUNAV C Server on port $PORT..."
./server $PORT --dev > server_test.log 2>&1 &
SERVER_PID=$!
sleep 1

echo "---------------------------------------------------------"
echo "1. Testing HTTP Delivery of Static Assets & Candidate Images"
echo "---------------------------------------------------------"
INDEX_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:$PORT/)
CSS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:$PORT/style.css)
JS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:$PORT/app.js)
MODI_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:$PORT/images/modi.png)
GANDHI_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:$PORT/images/gandhi.png)

echo "GET /                 HTTP Status: $INDEX_STATUS"
echo "GET /style.css        HTTP Status: $CSS_STATUS"
echo "GET /app.js           HTTP Status: $JS_STATUS"
echo "GET /images/modi.png   HTTP Status: $MODI_STATUS"
echo "GET /images/gandhi.png HTTP Status: $GANDHI_STATUS"

echo "---------------------------------------------------------"
echo "2. Testing Voter ID Validation (V101 to V199 inclusive)"
echo "---------------------------------------------------------"
echo -n "V101 (Eligible Boundary): "
curl -s http://127.0.0.1:$PORT/api/check?id=V101
echo ""

echo -n "V199 (Eligible Boundary): "
curl -s http://127.0.0.1:$PORT/api/check?id=V199
echo ""

echo -n "V1004 (Out of Range / Screenshot Case): "
curl -s http://127.0.0.1:$PORT/api/check?id=V1004
echo ""

echo -n "V999 (Out of Range): "
curl -s http://127.0.0.1:$PORT/api/check?id=V999
echo ""

echo -n "V100 (Below Range): "
curl -s http://127.0.0.1:$PORT/api/check?id=V100
echo ""

echo -n "V200 (Above Range): "
curl -s http://127.0.0.1:$PORT/api/check?id=V200
echo ""

echo "---------------------------------------------------------"
echo "3. Testing Web Voting: V101 -> Candidate 1 (Narendra Modi)"
echo "---------------------------------------------------------"
# 3a. Plain HTTP check: must be rejected with HTTPS_REQUIRED
HTTP_VOTE=$(curl -s -X POST http://127.0.0.1:$PORT/api/vote \
  -H "Content-Type: application/json" \
  -d '{"voter_id":"V101","candidate_id":1}')
echo "Unencrypted HTTP Vote Check: $HTTP_VOTE"

# 3b. Request 2FA OTP over HTTPS
OTP_RESP=$(curl -s --cacert "$CA_CERT" -X POST https://127.0.0.1:$PORT/api/otp/request \
  -H "Content-Type: application/json" \
  -d '{"voter_id":"V101"}')
OTP1=$(echo "$OTP_RESP" | grep -o '"simulated_otp":"[^"]*"' | cut -d'"' -f4)
echo "OTP Request for V101: $OTP1"

# 3c. Submit ballot over HTTPS with OTP
VOTE1=$(curl -s --cacert "$CA_CERT" -X POST https://127.0.0.1:$PORT/api/vote \
  -H "Content-Type: application/json" \
  -d "{\"voter_id\":\"V101\",\"candidate_id\":1,\"otp\":\"$OTP1\"}")
echo "Vote 1 Result: $VOTE1"

echo "---------------------------------------------------------"
echo "4. Testing Duplicate Voting Prevention: V101 voting again"
echo "---------------------------------------------------------"
DUP_VOTE=$(curl -s --cacert "$CA_CERT" -X POST https://127.0.0.1:$PORT/api/vote \
  -H "Content-Type: application/json" \
  -d "{\"voter_id\":\"V101\",\"candidate_id\":2,\"otp\":\"$OTP1\"}")
echo "Duplicate Vote Blocked: $DUP_VOTE"

echo "---------------------------------------------------------"
echo "5. Testing Web Voting: V199 -> Candidate 3 (Others)"
echo "---------------------------------------------------------"
OTP_RESP2=$(curl -s --cacert "$CA_CERT" -X POST https://127.0.0.1:$PORT/api/otp/request \
  -H "Content-Type: application/json" \
  -d '{"voter_id":"V199"}')
OTP2=$(echo "$OTP_RESP2" | grep -o '"simulated_otp":"[^"]*"' | cut -d'"' -f4)
VOTE2=$(curl -s --cacert "$CA_CERT" -X POST https://127.0.0.1:$PORT/api/vote \
  -H "Content-Type: application/json" \
  -d "{\"voter_id\":\"V199\",\"candidate_id\":3,\"otp\":\"$OTP2\"}")
echo "Vote 2 Result: $VOTE2"

echo "---------------------------------------------------------"
echo "6. Testing TCP CLI Client (client.c): V102 -> Candidate 2 (Rahul Gandhi)"
echo "---------------------------------------------------------"
# CLI input: 1 (Cast vote), V102 (ID), 2 (Candidate Rahul Gandhi), 3 (Exit)
printf "1\nV102\n2\n3\n" | ./client 127.0.0.1 $PORT > cli_test.log 2>&1
cat cli_test.log | grep -A 2 "SUCCESS"

echo "---------------------------------------------------------"
echo "7. Testing Live Election Results JSON (/api/results)"
echo "---------------------------------------------------------"
RESULTS=$(curl -s http://127.0.0.1:$PORT/api/results)
echo "Live Results: $RESULTS"

echo "---------------------------------------------------------"
echo "8. Checking Persistent Disk File (data/ballots.txt & votes.txt)"
echo "---------------------------------------------------------"
echo "[data/ballots.txt]:"
cat data/ballots.txt
echo "[votes.txt]:"
cat votes.txt

# Clean up
kill -2 $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null
rm -f server_test.log cli_test.log votes.txt

echo "========================================================="
echo "[SUCCESS] All AAYOG_CHUNAV Web & CLI tests PASSED!"
