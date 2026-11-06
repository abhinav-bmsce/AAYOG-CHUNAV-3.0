#!/bin/bash
# ==============================================================================
# test_v3_photo_results_csv.sh
# Comprehensive Automated Test for AAYOG_CHUNAV 3.0:
# 1. Candidate image upload and HTTP delivery.
# 2. Results visibility sealed during active polling (no voter leak).
# 3. Admin private monitoring of vote counts.
# 4. Election closure and voting lockout.
# 5. Result declaration with candidate tallies and percentages.
# 6. Winner identification & Tie handling.
# 7. Persistence of images and declared results across server restart.
# 8. CSV voter import, duplicate rejection, and row error reporting.
# ==============================================================================

set -e

export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

PORT=8089
SERVER_BIN="./server"
PID_FILE="/tmp/aayog_test_server_$PORT.pid"
LOG_FILE="/tmp/aayog_test_server_$PORT.log"

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

pass_count=0
fail_count=0

assert_eq() {
    local desc="$1"
    local actual="$2"
    local expected="$3"
    if [ "$actual" == "$expected" ]; then
        echo -e "${GREEN}[PASS]${NC} $desc"
        pass_count=$((pass_count + 1))
    else
        echo -e "${RED}[FAIL]${NC} $desc (Expected: '$expected', Got: '$actual')"
        fail_count=$((fail_count + 1))
    fi
}

assert_contains() {
    local desc="$1"
    local haystack="$2"
    local needle="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo -e "${GREEN}[PASS]${NC} $desc"
        pass_count=$((pass_count + 1))
    else
        echo -e "${RED}[FAIL]${NC} $desc (Could not find '$needle')"
        fail_count=$((fail_count + 1))
    fi
}

cleanup() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
    fi
}

trap cleanup EXIT

start_server() {
    export DEVELOPMENT=1
    $SERVER_BIN $PORT --dev > "$LOG_FILE" 2>&1 &
    local spid=$!
    echo "$spid" > "$PID_FILE"
    sleep 1
    # Wait for server ready
    for i in {1..20}; do
        if curl -s "http://127.0.0.1:$PORT/api/elections" >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done
}

stop_server() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
    fi
    sleep 0.5
}

echo -e "${BLUE}=== Starting AAYOG_CHUNAV 3.0 Verification Suite ===${NC}"

# 1. Compile binaries
echo "Compiling binaries..."
make clean >/dev/null
make >/dev/null
echo "Build succeeded."

# 2. Start server
start_server

# 3. Authenticate Admin
echo -e "\n${BLUE}--- Step 1: Admin Authentication ---${NC}"
LOGIN_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/admin/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"Admin@Aayog2026#","otp":"888999"}')
ADMIN_TOKEN=$(echo "$LOGIN_RESP" | grep -o '"token":"[^"]*' | head -n 1 | cut -d'"' -f4)

if [ -n "$ADMIN_TOKEN" ]; then
    echo -e "${GREEN}[PASS]${NC} Admin authenticated with session token: ${ADMIN_TOKEN:0:12}..."
    pass_count=$((pass_count + 1))
else
    echo -e "${RED}[FAIL]${NC} Admin login failed: $LOGIN_RESP"
    fail_count=$((fail_count + 1))
    exit 1
fi

AUTH_HDR="Authorization: Bearer $ADMIN_TOKEN"

# 4. Test Candidate Image Upload
echo -e "\n${BLUE}--- Step 2: Candidate Photograph Upload & Serving ---${NC}"
# 1x1 valid PNG base64 data URI
PNG_DATA_URI="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

UPLOAD_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/admin/candidate/upload_photo" \
    -H "$AUTH_HDR" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\":1,\"filename\":\"test_candidate.png\",\"image_data\":\"$PNG_DATA_URI\"}")

PHOTO_URL=$(echo "$UPLOAD_RESP" | grep -o '"photo_url":"[^"]*' | cut -d'"' -f4)
assert_contains "Upload photo response success" "$UPLOAD_RESP" '"success":true'
assert_contains "Photo URL returned under /images/" "$PHOTO_URL" "/images/cand_"

# Fetch image through static server
HTTP_IMG_CODE=$(curl -s -o /tmp/downloaded_test.png -w "%{http_code}" "http://127.0.0.1:$PORT$PHOTO_URL")
assert_eq "Uploaded image served via HTTP with status 200" "$HTTP_IMG_CODE" "200"

# Fetch default placeholder image
HTTP_PLACEHOLDER_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/images/others.png")
assert_eq "Default placeholder /images/others.png served with status 200" "$HTTP_PLACEHOLDER_CODE" "200"

# 5. Create Independent Test Election
echo -e "\n${BLUE}--- Step 3: Multi-Election Setup & Candidate Registration ---${NC}"
CREATE_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/admin/elections" \
    -H "$AUTH_HDR" \
    -H "Content-Type: application/json" \
    -d '{"title":"Test Council 2026","type":"Student Council","description":"Testing election lifecycle","require_otp":false}')

EID=$(echo "$CREATE_RESP" | grep -o '"election_id":[0-9]*' | cut -d':' -f2)
if [ -z "$EID" ]; then EID=$(echo "$CREATE_RESP" | grep -o '"id":[0-9]*' | cut -d':' -f2); fi
assert_contains "Election created successfully" "$CREATE_RESP" '"success":true'

# Add Candidate 1 with uploaded photo
CAND1_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/admin/candidates" \
    -H "$AUTH_HDR" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\":$EID,\"name\":\"Aarav Sharma\",\"party\":\"Tech Reform\",\"photo\":\"$PHOTO_URL\"}")
assert_contains "Candidate 1 registered" "$CAND1_RESP" '"success":true'

# Add Candidate 2 with default fallback photo
CAND2_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/admin/candidates" \
    -H "$AUTH_HDR" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\":$EID,\"name\":\"Diya Sen\",\"party\":\"Campus Unity\",\"photo\":\"\"}")
assert_contains "Candidate 2 registered" "$CAND2_RESP" '"success":true'

# 6. Test CSV Voter Import & Duplicate Rejection
echo -e "\n${BLUE}--- Step 4: CSV Voter Import & Duplicate Rejection ---${NC}"
CSV_PAYLOAD="T101,Rohan Verma,1
T102,Ishita Roy,1
T103,Kabir Das,1"

CSV_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/admin/voters/import?election_id=$EID" \
    -H "$AUTH_HDR" \
    -H "Content-Type: text/plain" \
    --data "$CSV_PAYLOAD")

assert_contains "CSV initial import added 3 voters" "$CSV_RESP" '"added":3'
assert_contains "CSV initial import skipped 0" "$CSV_RESP" '"skipped":0'

# Import duplicate voters + 1 new voter
CSV_DUP_PAYLOAD="T101,Rohan Verma,1
T104,Meera Nair,1
T102,Ishita Roy,1"

CSV_DUP_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/admin/voters/import?election_id=$EID" \
    -H "$AUTH_HDR" \
    -H "Content-Type: text/plain" \
    --data "$CSV_DUP_PAYLOAD")

assert_contains "CSV re-import added 1 new voter" "$CSV_DUP_RESP" '"added":1'
assert_contains "CSV re-import skipped 2 duplicates" "$CSV_DUP_RESP" '"skipped":2'
assert_contains "CSV details mentions duplicate" "$CSV_DUP_RESP" 'Duplicate'

# 7. Start Election & Test Sealed Results During Active Voting
echo -e "\n${BLUE}--- Step 5: Active Polling & Results Visibility Sealing ---${NC}"
START_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/admin/election/state" \
    -H "$AUTH_HDR" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\":$EID,\"state\":\"ACTIVE\"}")
assert_contains "Election state set to ACTIVE" "$START_RESP" '"new_state":"ACTIVE"'

# Cast Ballot 1 for Candidate 1 (Aarav Sharma) by T101
VOTE1_RESP=$(curl -s -k -X POST "https://127.0.0.1:$PORT/api/vote" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\":$EID,\"voter_id\":\"T101\",\"candidate_id\":1,\"booth_id\":1,\"otp\":\"\"}")
assert_contains "Ballot 1 cast successfully" "$VOTE1_RESP" '"success":true'

# Cast Ballot 2 for Candidate 2 (Diya Sen) by T102
VOTE2_RESP=$(curl -s -k -X POST "https://127.0.0.1:$PORT/api/vote" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\":$EID,\"voter_id\":\"T102\",\"candidate_id\":2,\"booth_id\":1,\"otp\":\"\"}")
assert_contains "Ballot 2 cast successfully" "$VOTE2_RESP" '"success":true'

# Test voter GET /api/results (WITHOUT admin token) -> MUST BE SEALED
VOTER_RESULTS_ACTIVE=$(curl -s "http://127.0.0.1:$PORT/api/results?election_id=$EID")
assert_contains "Voter results report results_declared: false" "$VOTER_RESULTS_ACTIVE" '"results_declared":false'
assert_contains "Voter results report total_votes: 2" "$VOTER_RESULTS_ACTIVE" '"total_votes":2'
assert_contains "Voter results state sealed message" "$VOTER_RESULTS_ACTIVE" 'sealed'

# Check that candidate votes are NOT leaked in /api/results or /api/candidates for voter
assert_contains "Voter results do not reveal leader standings" "$VOTER_RESULTS_ACTIVE" 'sealed until formal declaration'
VOTER_CANDS=$(curl -s "http://127.0.0.1:$PORT/api/candidates?election_id=$EID")
assert_contains "Voter candidates endpoint sets votes to 0 before declaration" "$VOTER_CANDS" '"votes":0'

# Test admin GET /api/results (WITH admin token) -> CAN PRIVATELY MONITOR
ADMIN_RESULTS_ACTIVE=$(curl -s "http://127.0.0.1:$PORT/api/results?election_id=$EID" -H "$AUTH_HDR")
assert_contains "Admin results can see total_votes: 2" "$ADMIN_RESULTS_ACTIVE" '"total_votes":2'
assert_contains "Admin results can see candidates breakdown" "$ADMIN_RESULTS_ACTIVE" '"candidates":['

# 8. Close Election & Verify Voting Lockdown
echo -e "\n${BLUE}--- Step 6: Close Election & Voting Lockdown ---${NC}"
CLOSE_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/admin/election/state" \
    -H "$AUTH_HDR" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\":$EID,\"state\":\"CLOSED\"}")
assert_contains "Election transitioned to CLOSED" "$CLOSE_RESP" '"new_state":"CLOSED"'

# Attempt to cast vote while CLOSED -> MUST BE REJECTED
VOTE_LOCKED_RESP=$(curl -s -k -X POST "https://127.0.0.1:$PORT/api/vote" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\":$EID,\"voter_id\":\"T103\",\"candidate_id\":1,\"booth_id\":1,\"otp\":\"\"}")
assert_contains "Voting rejected while election is CLOSED" "$VOTE_LOCKED_RESP" 'not currently active'

# Results for voter must STILL be sealed after closure before declaration
VOTER_RESULTS_CLOSED=$(curl -s "http://127.0.0.1:$PORT/api/results?election_id=$EID")
assert_contains "Voter results still sealed after closure" "$VOTER_RESULTS_CLOSED" '"results_declared":false'

# 9. Declare Results: Test Tie Announcement
echo -e "\n${BLUE}--- Step 7: Declare Results & Tie Handling ---${NC}"
DECLARE_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/admin/election/state" \
    -H "$AUTH_HDR" \
    -H "Content-Type: application/json" \
    -d "{\"election_id\":$EID,\"state\":\"DECLARED\"}")
assert_contains "Election state set to DECLARED" "$DECLARE_RESP" '"new_state":"DECLARED"'

# Query results as voter -> NOW UNSEALED, reports tie
VOTER_RESULTS_DECLARED=$(curl -s "http://127.0.0.1:$PORT/api/results?election_id=$EID")
assert_contains "Results declared is true" "$VOTER_RESULTS_DECLARED" '"results_declared":true'
assert_contains "Tie detected between equal highest candidates" "$VOTER_RESULTS_DECLARED" '"is_tie":true'
assert_contains "Tie announced in leader field" "$VOTER_RESULTS_DECLARED" 'TIE:'
assert_contains "Candidate 1 photo_url included in results" "$VOTER_RESULTS_DECLARED" "$PHOTO_URL"

# 10. Persistence Test Across Server Restart
echo -e "\n${BLUE}--- Step 8: Server Restart Persistence Verification ---${NC}"
echo "Stopping server..."
stop_server

echo "Restarting server on same port..."
start_server

# Verify uploaded image is still served
RESTART_IMG_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT$PHOTO_URL")
assert_eq "Candidate image survives server restart (HTTP 200)" "$RESTART_IMG_CODE" "200"

# Verify declared results and tie status survive server restart
RESTART_RESULTS=$(curl -s "http://127.0.0.1:$PORT/api/results?election_id=$EID")
assert_contains "Results remain declared after server restart" "$RESTART_RESULTS" '"results_declared":true'
assert_contains "Tie status persists after server restart" "$RESTART_RESULTS" '"is_tie":true'
assert_contains "Total votes (2) persists after server restart" "$RESTART_RESULTS" '"total_votes":2'

# Re-authenticate admin after restart
RESTART_LOGIN=$(curl -s -X POST "http://127.0.0.1:$PORT/api/admin/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"Admin@Aayog2026#","otp":"888999"}')
RESTART_TOKEN=$(echo "$RESTART_LOGIN" | grep -o '"token":"[^"]*' | head -n 1 | cut -d'"' -f4)
RESTART_AUTH="Authorization: Bearer $RESTART_TOKEN"

# Verify imported voters T101, T102, T104 persist after restart
VOTERS_LIST=$(curl -s "http://127.0.0.1:$PORT/api/admin/voters?election_id=$EID" -H "$RESTART_AUTH")
assert_contains "Voter T101 persisted after restart" "$VOTERS_LIST" '"id":"T101"'
assert_contains "Voter T102 persisted after restart" "$VOTERS_LIST" '"id":"T102"'
assert_contains "Voter T104 persisted after restart" "$VOTERS_LIST" '"id":"T104"'

# 11. Test Winner Declaration (Unequal Votes)
echo -e "\n${BLUE}--- Step 9: Clear Winner Declaration & Announcement ---${NC}"
CREATE_WIN_RESP=$(curl -s -X POST "http://127.0.0.1:$PORT/api/admin/elections" \
    -H "$RESTART_AUTH" \
    -H "Content-Type: application/json" \
    -d '{"title":"Clear Winner Election","type":"Department","description":"Winner test","require_otp":false}')
WIN_EID=$(echo "$CREATE_WIN_RESP" | grep -o '"election_id":[0-9]*' | cut -d':' -f2)
if [ -z "$WIN_EID" ]; then WIN_EID=$(echo "$CREATE_WIN_RESP" | grep -o '"id":[0-9]*' | cut -d':' -f2); fi

curl -s -X POST "http://127.0.0.1:$PORT/api/admin/candidates" -H "$RESTART_AUTH" -H "Content-Type: application/json" \
    -d "{\"election_id\":$WIN_EID,\"name\":\"Winner Candidate\",\"party\":\"Blue Party\",\"photo\":\"$PHOTO_URL\"}" >/dev/null

curl -s -X POST "http://127.0.0.1:$PORT/api/admin/candidates" -H "$RESTART_AUTH" -H "Content-Type: application/json" \
    -d "{\"election_id\":$WIN_EID,\"name\":\"Runner-up Candidate\",\"party\":\"Red Party\",\"photo\":\"/images/others.png\"}" >/dev/null

curl -s -X POST "http://127.0.0.1:$PORT/api/admin/voters/import?election_id=$WIN_EID" -H "$RESTART_AUTH" -H "Content-Type: text/plain" \
    --data "W101,Voter One,1
W102,Voter Two,1
W103,Voter Three,1" >/dev/null

curl -s -X POST "http://127.0.0.1:$PORT/api/admin/election/state" -H "$RESTART_AUTH" -H "Content-Type: application/json" \
    -d "{\"election_id\":$WIN_EID,\"state\":\"ACTIVE\"}" >/dev/null

# 2 votes for Candidate 1, 1 vote for Candidate 2
curl -s -k -X POST "https://127.0.0.1:$PORT/api/vote" -H "Content-Type: application/json" \
    -d "{\"election_id\":$WIN_EID,\"voter_id\":\"W101\",\"candidate_id\":1,\"booth_id\":1,\"otp\":\"\"}" >/dev/null
curl -s -k -X POST "https://127.0.0.1:$PORT/api/vote" -H "Content-Type: application/json" \
    -d "{\"election_id\":$WIN_EID,\"voter_id\":\"W102\",\"candidate_id\":1,\"booth_id\":1,\"otp\":\"\"}" >/dev/null
curl -s -k -X POST "https://127.0.0.1:$PORT/api/vote" -H "Content-Type: application/json" \
    -d "{\"election_id\":$WIN_EID,\"voter_id\":\"W103\",\"candidate_id\":2,\"booth_id\":1,\"otp\":\"\"}" >/dev/null

# Declare
curl -s -X POST "http://127.0.0.1:$PORT/api/admin/election/state" -H "$RESTART_AUTH" -H "Content-Type: application/json" \
    -d "{\"election_id\":$WIN_EID,\"state\":\"DECLARED\"}" >/dev/null

WINNER_RESULTS=$(curl -s "http://127.0.0.1:$PORT/api/results?election_id=$WIN_EID")
assert_contains "Clear winner identified" "$WINNER_RESULTS" '"leader":"Winner Candidate"'
assert_contains "Winner votes is 2" "$WINNER_RESULTS" '"winner_votes":2'
assert_contains "Winner margin is 1" "$WINNER_RESULTS" '"margin":1'
assert_contains "Not a tie" "$WINNER_RESULTS" '"is_tie":false'
assert_contains "Winner photo included" "$WINNER_RESULTS" '"winner_photo":'

echo -e "\n========================================================"
echo -e "TEST RESULTS SUMMARY: ${GREEN}$pass_count PASSED${NC}, ${RED}$fail_count FAILED${NC}"
echo -e "========================================================"

if [ $fail_count -gt 0 ]; then
    exit 1
fi
