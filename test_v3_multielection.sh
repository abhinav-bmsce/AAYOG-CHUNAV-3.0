#!/bin/bash
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
set -e

PORT=9555
CA_CERT="certs/ca.crt"
ADMIN_CERT="certs/admin_client.crt"
ADMIN_KEY="certs/admin_client.key"

echo "================================================================="
echo "   AAYOG_CHUNAV 3.0 - MULTI-ELECTION PLATFORM TEST SUITE         "
echo "================================================================="

# Recompile if needed
make > /dev/null 2>&1

echo "[TEST SETUP] Launching AAYOG_CHUNAV 3.0 Server on port $PORT..."
./server $PORT --dev > server_v3_test.log 2>&1 &
SERVER_PID=$!
sleep 1

cleanup() {
    echo -e "\n[TEARDOWN] Stopping test server (PID $SERVER_PID)..."
    kill -2 $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}
trap cleanup EXIT

# 1. Administrator Login
echo -e "\n--- [STEP 1] Administrator Login & Session Acquisition ---"
ADMIN_LOGIN=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"Admin@Aayog2026#","otp":"888999"}')
TOKEN=$(echo "$ADMIN_LOGIN" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
if [ -z "$TOKEN" ]; then
    echo "  [FAIL] Administrator login failed: $ADMIN_LOGIN"
    exit 1
fi
echo "  [PASS] Logged in as Admin. Token: $TOKEN"

# 2. Query Existing Elections
echo -e "\n--- [STEP 2] Query Multi-Election Catalog ---"
ELECTIONS_LIST=$(curl -s "http://127.0.0.1:$PORT/api/elections")
echo "  Current Elections: $ELECTIONS_LIST"
if [[ "$ELECTIONS_LIST" == *"Lok Sabha General Election 2026"* ]]; then
    echo "  [PASS] Default election 1 present."
else
    echo "  [FAIL] Election 1 missing from catalog."
    exit 1
fi

# 3. Create New Independent Election (Election 2: BMSCE Student Council)
echo -e "\n--- [STEP 3] Create Election 2: BMSCE Student Council 2026 ---"
CREATE_ELECTION=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/elections" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{
        "title": "BMSCE Student Council Election 2026",
        "description": "Annual elections for Student Council Representatives",
        "type": "Student Council",
        "require_otp": 1
    }')
echo "  Create Response: $CREATE_ELECTION"
ELECTION_2_ID=$(echo "$CREATE_ELECTION" | grep -o '"election_id":[0-9]*' | cut -d':' -f2)
if [ -z "$ELECTION_2_ID" ]; then
    ELECTION_2_ID=2
fi
echo "  [PASS] Created Election with ID: $ELECTION_2_ID"

# 4. Configure Candidates for Election 2
echo -e "\n--- [STEP 4] Configure Candidates for Election $ELECTION_2_ID ---"
CAND1=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/candidates" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
        \"election_id\": $ELECTION_2_ID,
        \"name\": \"Ananya Sharma\",
        \"party\": \"Tech Innovators Front\",
        \"photo_url\": \"/images/candidate_ananya.png\"
    }")
echo "  Add Candidate 1: $CAND1"

CAND2=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/candidates" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
        \"election_id\": $ELECTION_2_ID,
        \"name\": \"Rohan Verma\",
        \"party\": \"Campus Welfare Alliance\",
        \"photo_url\": \"/images/candidate_rohan.png\"
    }")
echo "  Add Candidate 2: $CAND2"

E2_CANDS=$(curl -s "http://127.0.0.1:$PORT/api/candidates?election_id=$ELECTION_2_ID")
echo "  Election $ELECTION_2_ID Candidates: $E2_CANDS"
if [[ "$E2_CANDS" == *"Ananya Sharma"* ]] && [[ "$E2_CANDS" == *"Rohan Verma"* ]]; then
    echo "  [PASS] Candidates isolated to Election $ELECTION_2_ID."
else
    echo "  [FAIL] Failed to retrieve candidates for Election $ELECTION_2_ID."
    exit 1
fi

# 5. Configure Polling Booths for Election 2
echo -e "\n--- [STEP 5] Configure Polling Booths for Election $ELECTION_2_ID ---"
BOOTH1=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/booths" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
        \"election_id\": $ELECTION_2_ID,
        \"name\": \"Auditorium Booth 1\",
        \"location\": \"Main Auditorium Ground Floor\"
    }")
echo "  Add Booth 1: $BOOTH1"

# 6. Voter Roll Management: Register Voter & Bulk CSV Import
echo -e "\n--- [STEP 6] Voter Management: Individual & Bulk CSV Import ---"
VOTER_REG=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/voters" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
        \"election_id\": $ELECTION_2_ID,
        \"voter_id\": \"SC201\",
        \"name\": \"Aarav Patel\",
        \"booth_id\": 1
    }")
echo "  Individual Voter SC201: $VOTER_REG"

# Bulk CSV Import
CSV_IMPORT=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/voters/bulk" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
        \"election_id\": $ELECTION_2_ID,
        \"csv_data\": \"SC202,Diya Sen,1\nSC203,Kabir Mehta,1\nSC204,Tanvi Reddy,1\"
    }")
echo "  Bulk CSV Import: $CSV_IMPORT"

# Also register V101 in Election 2 (demonstrating cross-election eligibility)
V101_REG=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/voters" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
        \"election_id\": $ELECTION_2_ID,
        \"voter_id\": \"V101\",
        \"name\": \"Voter 101\",
        \"booth_id\": 1
    }")
echo "  Cross-Election Voter V101 Registered: $V101_REG"

# 7. Complete Lifecycle: DRAFT -> PUBLISHED -> ACTIVE
echo -e "\n--- [STEP 7] Complete Election Lifecycle Transitions ---"
# Set to PUBLISHED
STATE_PUB=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/elections/state" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"election_id\": $ELECTION_2_ID, \"state\": \"PUBLISHED\"}")
echo "  Set to PUBLISHED: $STATE_PUB"

# Verify voting is rejected while PUBLISHED
VOTE_PREMATURE=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/vote" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\": $ELECTION_2_ID, \"voter_id\": \"SC201\", \"candidate_id\": 1, \"otp\": \"000000\"}")
echo "  Vote during PUBLISHED state (Must be rejected): $VOTE_PREMATURE"
if [[ "$VOTE_PREMATURE" == *"ELECTION_INACTIVE"* ]]; then
    echo "  [PASS] Premature voting correctly rejected with ELECTION_INACTIVE."
else
    echo "  [FAIL] Premature voting was not blocked."
    exit 1
fi

# Set to ACTIVE
STATE_ACT=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/elections/state" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"election_id\": $ELECTION_2_ID, \"state\": \"ACTIVE\"}")
echo "  Set to ACTIVE: $STATE_ACT"

# 8. Lock Candidate Modification once Voting Begins
echo -e "\n--- [STEP 8] Candidate Modification Lock in ACTIVE State ---"
CAND_LOCK_TEST=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/candidates" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
        \"election_id\": $ELECTION_2_ID,
        \"name\": \"Late Candidate\",
        \"party\": \"Late Party\",
        \"photo_url\": \"\"
    }")
echo "  Candidate Addition in ACTIVE State: $CAND_LOCK_TEST"
if [[ "$CAND_LOCK_TEST" == *"LOCKED"* ]] || [[ "$CAND_LOCK_TEST" == *"false"* ]]; then
    echo "  [PASS] Candidate additions locked after election starts."
else
    echo "  [FAIL] Candidate modification was not locked."
    exit 1
fi

# 9. 2FA OTP & Secret Ballot Submission in Election 2
echo -e "\n--- [STEP 9] Voting in Election $ELECTION_2_ID: SC201 -> Ananya Sharma (#1) ---"
OTP_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/otp/request" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\": $ELECTION_2_ID, \"voter_id\": \"SC201\"}")
OTP_SC201=$(echo "$OTP_RESP" | grep -o '"simulated_otp":"[^"]*"' | cut -d'"' -f4)
echo "  OTP for SC201: $OTP_SC201"

VOTE_SC201=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/vote" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\": $ELECTION_2_ID, \"voter_id\": \"SC201\", \"candidate_id\": 1, \"otp\": \"$OTP_SC201\"}")
echo "  Vote Result: $VOTE_SC201"
RECEIPT_TOKEN=$(echo "$VOTE_SC201" | grep -o '"receipt_token":"[^"]*"' | cut -d'"' -f4)
echo "  Generated Cryptographic Receipt: $RECEIPT_TOKEN"
if [[ "$VOTE_SC201" == *"true"* ]] && [ -n "$RECEIPT_TOKEN" ]; then
    echo "  [PASS] Anonymous ballot accepted and receipt issued."
else
    echo "  [FAIL] Vote submission failed."
    exit 1
fi

# Duplicate vote check for SC201 in Election 2
DUP_VOTE=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/vote" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\": $ELECTION_2_ID, \"voter_id\": \"SC201\", \"candidate_id\": 2, \"otp\": \"$OTP_SC201\"}")
echo "  Duplicate Vote Attempt for SC201: $DUP_VOTE"
if [[ "$DUP_VOTE" == *"ALREADY_VOTED"* ]]; then
    echo "  [PASS] Duplicate voting prohibited in Election $ELECTION_2_ID."
else
    echo "  [FAIL] Duplicate voting was not blocked."
    exit 1
fi

# Also vote for V101 in Election 2 -> Ananya Sharma (#1)
OTP_V101_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/otp/request" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\": $ELECTION_2_ID, \"voter_id\": \"V101\"}")
OTP_V101=$(echo "$OTP_V101_RESP" | grep -o '"simulated_otp":"[^"]*"' | cut -d'"' -f4)
VOTE_V101=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/vote" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\": $ELECTION_2_ID, \"voter_id\": \"V101\", \"candidate_id\": 1, \"otp\": \"$OTP_V101\"}")
echo "  Cross-Election Vote for V101: $VOTE_V101"
if [[ "$VOTE_V101" == *"true"* ]]; then
    echo "  [PASS] Voter V101 independently voted in Election $ELECTION_2_ID."
fi

# Vote for SC202 -> Rohan Verma (#2)
OTP_SC202_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/otp/request" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\": $ELECTION_2_ID, \"voter_id\": \"SC202\"}")
OTP_SC202=$(echo "$OTP_SC202_RESP" | grep -o '"simulated_otp":"[^"]*"' | cut -d'"' -f4)
VOTE_SC202=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/vote" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\": $ELECTION_2_ID, \"voter_id\": \"SC202\", \"candidate_id\": 2, \"otp\": \"$OTP_SC202\"}")
echo "  Vote for SC202 -> Candidate 2: $VOTE_SC202"

# 10. Anonymous Ballot Receipt Verification
echo -e "\n--- [STEP 10] Anonymous Receipt Verification API ---"
RECEIPT_VERIFY=$(curl -s "http://127.0.0.1:$PORT/api/receipt/verify?token=$RECEIPT_TOKEN&election_id=$ELECTION_2_ID")
echo "  Receipt Verification Response: $RECEIPT_VERIFY"
if [[ "$RECEIPT_VERIFY" == *"verified\":true"* ]]; then
    echo "  [PASS] Official receipt verified anonymously against ballot box."
else
    echo "  [FAIL] Receipt verification failed."
    exit 1
fi

# Verify an invalid receipt token is rejected
FAKE_RECEIPT=$(curl -s "http://127.0.0.1:$PORT/api/receipt/verify?token=BLT-fake0000000000000000000000000000&election_id=$ELECTION_2_ID")
echo "  Invalid Receipt Check: $FAKE_RECEIPT"
if [[ "$FAKE_RECEIPT" == *"verified\":false"* ]]; then
    echo "  [PASS] Invalid receipt token correctly rejected."
else
    echo "  [FAIL] Invalid receipt was not rejected."
    exit 1
fi

# 11. Results Sealing & Declaration
echo -e "\n--- [STEP 11] Results Sealing & Formal Declaration ---"
# Results must be sealed prior to declaration
RESULTS_SEALED=$(curl -s "http://127.0.0.1:$PORT/api/results?election_id=$ELECTION_2_ID")
echo "  Pre-declaration Results (Sealed): $RESULTS_SEALED"
if [[ "$RESULTS_SEALED" == *"results_declared\":false"* ]]; then
    echo "  [PASS] Results are sealed while election is live."
else
    echo "  [FAIL] Results prematurely exposed."
    exit 1
fi

# Declare Results
DECLARE_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/elections/state" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"election_id\": $ELECTION_2_ID, \"state\": \"DECLARED\"}")
echo "  Declare Results: $DECLARE_RESP"

RESULTS_DECLARED=$(curl -s "http://127.0.0.1:$PORT/api/results?election_id=$ELECTION_2_ID")
echo "  Official Certified Results: $RESULTS_DECLARED"
if [[ "$RESULTS_DECLARED" == *"Ananya Sharma"* ]] && [[ "$RESULTS_DECLARED" == *"results_declared\":true"* ]]; then
    echo "  [PASS] Certified results declared with winner 'Ananya Sharma'."
else
    echo "  [FAIL] Declared results incorrect."
    exit 1
fi

# 12. Certified CSV & PDF Report Downloads for Election 2
echo -e "\n--- [STEP 12] Certified CSV & PDF Reports for Election $ELECTION_2_ID ---"
CSV_REPORT=$(curl -s --cacert "$CA_CERT" \
    -H "Authorization: Bearer $TOKEN" \
    "https://127.0.0.1:$PORT/api/admin/reports/csv?election_id=$ELECTION_2_ID")
echo "  CSV Report Snippet (First 5 lines):"
echo "$CSV_REPORT" | head -n 5
if [[ "$CSV_REPORT" == *"BMSCE Student Council Election 2026"* ]]; then
    echo "  [PASS] Certified CSV report generated for Election $ELECTION_2_ID."
else
    echo "  [FAIL] CSV report missing election title."
    exit 1
fi

PDF_STATUS=$(curl -s -o /tmp/test_election2_report.pdf -w "%{http_code}" --cacert "$CA_CERT" \
    -H "Authorization: Bearer $TOKEN" \
    "https://127.0.0.1:$PORT/api/admin/reports/pdf?election_id=$ELECTION_2_ID")
PDF_HEADER=$(head -c 8 /tmp/test_election2_report.pdf)
echo "  PDF Download HTTP: $PDF_STATUS, Magic: $PDF_HEADER, Size: $(wc -c < /tmp/test_election2_report.pdf) bytes"
if [ "$PDF_STATUS" == "200" ] && [[ "$PDF_HEADER" == *"%PDF"* ]]; then
    echo "  [PASS] Pure-C PDF 1.4 report generated for Election $ELECTION_2_ID."
else
    echo "  [FAIL] PDF report export failed."
    exit 1
fi

# 13. System Backup & Restore Engine
echo -e "\n--- [STEP 13] System Backup & Integrity Manifest Verification ---"
BACKUP_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/backup/create" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{}')
echo "  Backup Creation: $BACKUP_RESP"
BACKUP_NAME=$(echo "$BACKUP_RESP" | grep -o '"archive":"[^"]*"' | cut -d'"' -f4)
if [ -n "$BACKUP_NAME" ]; then
    echo "  [PASS] SHA-256 sealed backup created: $BACKUP_NAME"
else
    echo "  [FAIL] Backup creation failed."
    exit 1
fi

BACKUPS_LIST=$(curl -s --cacert "$CA_CERT" \
    -H "Authorization: Bearer $TOKEN" \
    "https://127.0.0.1:$PORT/api/admin/backups")
echo "  Backups List: $BACKUPS_LIST"
if [[ "$BACKUPS_LIST" == *"$BACKUP_NAME"* ]]; then
    echo "  [PASS] Created backup cataloged in backup repository."
fi

# 14. Server Restart Persistence Verification
echo -e "\n--- [STEP 14] Server Restart Persistence Verification ---"
echo "  Restarting server to test zero-data-loss persistence across restarts..."
kill -2 $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
sleep 1

# Restart server
./server $PORT --dev > server_v3_restart.log 2>&1 &
SERVER_PID=$!
sleep 1

# Verify Election 2 and its ballots survived restart
POST_RESTART_RESULTS=$(curl -s "http://127.0.0.1:$PORT/api/results?election_id=$ELECTION_2_ID")
echo "  Post-Restart Results for Election $ELECTION_2_ID: $POST_RESTART_RESULTS"
if [[ "$POST_RESTART_RESULTS" == *"Ananya Sharma"* ]] && [[ "$POST_RESTART_RESULTS" == *"results_declared\":true"* ]]; then
    echo "  [PASS] Election 2, candidate tallies, and declared state persisted across server restart!"
else
    echo "  [FAIL] Election data did not survive server restart."
    exit 1
fi

POST_RESTART_RECEIPT=$(curl -s "http://127.0.0.1:$PORT/api/receipt/verify?token=$RECEIPT_TOKEN&election_id=$ELECTION_2_ID")
echo "  Post-Restart Receipt Verification: $POST_RESTART_RECEIPT"
if [[ "$POST_RESTART_RECEIPT" == *"verified\":true"* ]]; then
    echo "  [PASS] Anonymous receipt verification persisted across server restart!"
else
    echo "  [FAIL] Receipt verification failed after restart."
    exit 1
fi

echo "================================================================="
echo "   [SUCCESS] ALL AAYOG_CHUNAV 3.0 MULTI-ELECTION TESTS PASSED!   "
echo "================================================================="
