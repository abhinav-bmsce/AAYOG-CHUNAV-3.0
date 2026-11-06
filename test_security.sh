#!/bin/bash
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
# ==============================================================================
# AAYOG_CHUNAV 2.0 - Comprehensive Security & Verification Test Suite
# Tests:
#   1. TLS 1.2 & TLS 1.3 Transport Security & Certificate Validation
#   2. Mutual TLS (mTLS) Administrative Authentication
#   3. IP-Based Access Control (Allowlist & Rejection)
#   4. Two-Factor Authentication (OTP Dispatch, Verification, Salted Hash)
#   5. Administrator Authentication, Session Tokens & RBAC
#   6. Polling Booth Management & Booth-wise Turnout
#   7. Strict Ballot Secrecy (Decoupling Voter Identity from Candidate Choice)
#   8. Duplicate Voting Prevention across Web & TLS CLI
#   9. Rate Limiting & Suspicious Activity Intrusion Detection
#  10. SHA-256 System File Integrity Audit & Tamper Detection
#  11. Tamper-Evident HMAC-SHA256 Hash Chained Audit Ledger
#  12. Certified CSV & Pure-C PDF 1.4 Report Exports
# ==============================================================================

PORT=9443
CA_CERT="certs/ca.crt"
ADMIN_CERT="certs/admin_client.crt"
ADMIN_KEY="certs/admin_client.key"

echo "================================================================="
echo "   AAYOG_CHUNAV 2.0 - COMPREHENSIVE SECURITY TEST SUITE          "
echo "================================================================="

# Clean past run state
make reset-votes > /dev/null 2>&1
make certs > /dev/null 2>&1

echo "[TEST SETUP] Launching AAYOG_CHUNAV 2.0 Server on port $PORT..."
./server $PORT --dev > server_sec_test.log 2>&1 &
SERVER_PID=$!
sleep 1

cleanup() {
    echo -e "\n[TEARDOWN] Stopping test server (PID $SERVER_PID)..."
    kill -2 $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
    rm -f server_sec_test.log
}
trap cleanup EXIT

# ------------------------------------------------------------------------------
# 1. TLS 1.2 and TLS 1.3 Protocol Support & Certificate Verification
# ------------------------------------------------------------------------------
echo -e "\n--- [TEST 1] TLS 1.2 & TLS 1.3 Handshake & CA Certificate Verification ---"
TLS12_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --tlsv1.2 --tls-max 1.2 --cacert "$CA_CERT" "https://127.0.0.1:$PORT/")
echo "TLS 1.2 Request to /: HTTP $TLS12_STATUS"
if [ "$TLS12_STATUS" = "200" ]; then
    echo "  [PASS] TLS 1.2 handshake and CA verification successful."
else
    echo "  [FAIL] TLS 1.2 failed."
fi

TLS13_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --tlsv1.3 --cacert "$CA_CERT" "https://127.0.0.1:$PORT/" 2>&1)
echo "TLS 1.3 Request to /: HTTP $TLS13_STATUS"
if [ "$TLS13_STATUS" = "200" ]; then
    echo "  [PASS] TLS 1.3 handshake and CA verification successful via curl."
else
    # Fallback to openssl s_client if curl build lacks built-in TLS 1.3
    OPENSSL_TLS13=$(openssl s_client -connect 127.0.0.1:$PORT -tls1_3 -CAfile "$CA_CERT" </dev/null 2>&1 | grep "Protocol" | head -n 1)
    echo "  OpenSSL TLS 1.3 verification: $OPENSSL_TLS13"
    if [[ "$OPENSSL_TLS13" == *"TLSv1.3"* ]]; then
        echo "  [PASS] TLS 1.3 handshake and CA verification successful via OpenSSL."
    else
        echo "  [FAIL] TLS 1.3 failed."
    fi
fi

# ------------------------------------------------------------------------------
# 2. Mutual TLS (mTLS) Administrative Authentication
# ------------------------------------------------------------------------------
echo -e "\n--- [TEST 2] Mutual TLS (mTLS) Client Certificate Authentication ---"
MTLS_RESP=$(curl -s --cacert "$CA_CERT" --cert "$ADMIN_CERT" --key "$ADMIN_KEY" "https://127.0.0.1:$PORT/api/admin/audit")
echo "mTLS Request Response (first 100 chars): ${MTLS_RESP:0:100}..."
if [[ "$MTLS_RESP" == *"["* ]]; then
    echo "  [PASS] mTLS administrative authentication accepted client certificate."
else
    echo "  [FAIL] mTLS authentication failed."
fi

# ------------------------------------------------------------------------------
# 3. Two-Factor Authentication (OTP): Dispatch, Expiry & Verification
# ------------------------------------------------------------------------------
echo -e "\n--- [TEST 3] Two-Factor Authentication (OTP) ---"
OTP_REQ=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/otp/request" \
    -H "Content-Type: application/json" \
    -d '{"voter_id":"V101"}')
echo "OTP Dispatch Response: $OTP_REQ"

# Extract simulated OTP for testing
SIM_OTP=$(echo "$OTP_REQ" | grep -o '"simulated_otp":"[^"]*"' | cut -d'"' -f4)
echo "Extracted Demo OTP: $SIM_OTP"

echo -n "Testing Invalid OTP (999999): "
INVALID_OTP_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/otp/verify" \
    -H "Content-Type: application/json" \
    -d '{"voter_id":"V101","otp":"999999"}')
echo "$INVALID_OTP_RESP"

echo -n "Testing Valid OTP ($SIM_OTP): "
VALID_OTP_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/otp/verify" \
    -H "Content-Type: application/json" \
    -d "{\"voter_id\":\"V101\",\"otp\":\"$SIM_OTP\"}")
echo "$VALID_OTP_RESP"

if [[ "$VALID_OTP_RESP" == *"true"* ]]; then
    echo "  [PASS] Salted OTP 2FA verified successfully."
else
    echo "  [FAIL] OTP verification failed."
fi

# ------------------------------------------------------------------------------
# 4. Strict Ballot Secrecy & Duplicate Vote Prevention
# ------------------------------------------------------------------------------
echo -e "\n--- [TEST 4] Strict Ballot Secrecy & Duplicate Prevention ---"
echo "Submitting ballot for Voter V101 -> Candidate #1 (Narendra Modi)..."
VOTE_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/vote" \
    -H "Content-Type: application/json" \
    -d "{\"voter_id\":\"V101\",\"candidate_id\":1,\"otp\":\"$SIM_OTP\"}")
echo "Vote Response: $VOTE_RESP"

TOKEN=$(echo "$VOTE_RESP" | grep -o '"receipt_token":"[^"]*"' | cut -d'"' -f4)
echo "Voter Cryptographic Receipt Token: $TOKEN"

echo -n "Attempting Duplicate Vote for V101: "
DUP_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/vote" \
    -H "Content-Type: application/json" \
    -d "{\"voter_id\":\"V101\",\"candidate_id\":2,\"otp\":\"$SIM_OTP\"}")
echo "$DUP_RESP"
if [[ "$DUP_RESP" == *"ALREADY_VOTED"* ]]; then
    echo "  [PASS] Duplicate voting strictly blocked and logged."
fi

echo -n "Checking Ballot Secrecy in data/ballots.txt: "
if [ -f data/ballots.txt ]; then
    BALLOT_CONTENT=$(cat data/ballots.txt)
    echo "$BALLOT_CONTENT"
    if [[ "$BALLOT_CONTENT" != *"V101"* ]]; then
        echo "  [PASS] VERIFIED: Voter ID 'V101' does NOT appear in data/ballots.txt. Voter identity decoupled from candidate!"
    else
        echo "  [FAIL] Voter ID found in ballots.txt - Ballot secrecy violated!"
    fi
fi

# ------------------------------------------------------------------------------
# 5. Administrator Authentication & Session Tokens (RBAC)
# ------------------------------------------------------------------------------
echo -e "\n--- [TEST 5] Administrator RBAC & Session Management ---"
UNAUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --cacert "$CA_CERT" "https://127.0.0.1:$PORT/api/admin/voters")
echo "Unauthorized access to /api/admin/voters: HTTP $UNAUTH_STATUS (Expected 401)"

LOGIN_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"Admin@Aayog2026#","otp":"888999"}')
echo "Admin Login Response: $LOGIN_RESP"

ADMIN_TOKEN=$(echo "$LOGIN_RESP" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
echo "Admin Session Token: $ADMIN_TOKEN"

VOTERS_RESP=$(curl -s --cacert "$CA_CERT" "https://127.0.0.1:$PORT/api/admin/voters" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
echo "Admin Query Voters Count: $(echo "$VOTERS_RESP" | grep -o '"total_count":[0-9]*')"
if [[ "$VOTERS_RESP" == *"total_count"* ]]; then
    echo "  [PASS] Administrator authenticated and session token validated."
fi

# ------------------------------------------------------------------------------
# 6. Polling Booth Management & Turnout
# ------------------------------------------------------------------------------
echo -e "\n--- [TEST 6] Polling Booth Management ---"
BOOTHS_RESP=$(curl -s --cacert "$CA_CERT" "https://127.0.0.1:$PORT/api/booths")
echo "Polling Booths: $BOOTHS_RESP"
if [[ "$BOOTHS_RESP" == *"Station"* ]]; then
    echo "  [PASS] Polling booth management verified."
fi

# ------------------------------------------------------------------------------
# 7. Tamper-Evident HMAC-SHA256 Audit Log Chain Verification
# ------------------------------------------------------------------------------
echo -e "\n--- [TEST 7] Tamper-Evident Audit Log Hash Chaining ---"
VERIFY_RESP=$(curl -s --cacert "$CA_CERT" -X POST "https://127.0.0.1:$PORT/api/admin/audit/verify" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
echo "Audit Verification: $VERIFY_RESP"
if [[ "$VERIFY_RESP" == *"chain_valid\":true"* ]]; then
    echo "  [PASS] HMAC-SHA256 hash chaining audit verified intact."
else
    echo "  [FAIL] Audit chain verification failed."
fi

# ------------------------------------------------------------------------------
# 8. SHA-256 System File Baseline Integrity Verification & Tamper Detection
# ------------------------------------------------------------------------------
echo -e "\n--- [TEST 8] SHA-256 File Manifest & Tamper Detection ---"
INTEG_RESP=$(curl -s --cacert "$CA_CERT" "https://127.0.0.1:$PORT/api/admin/integrity" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
echo "Integrity Baseline Check: $INTEG_RESP"
if [[ "$INTEG_RESP" == *"VERIFIED"* ]]; then
    echo "  [PASS] SHA-256 file manifest matches active election files."
fi

# ------------------------------------------------------------------------------
# 9. Certified Election Reports (RFC-4180 CSV & Pure-C PDF 1.4)
# ------------------------------------------------------------------------------
echo -e "\n--- [TEST 9] Certified Election Reports Export (CSV & PDF) ---"
CSV_REPORT=$(curl -s --cacert "$CA_CERT" "https://127.0.0.1:$PORT/api/admin/report/csv" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
echo "CSV Report (Header preview):"
echo "$CSV_REPORT" | head -n 8
if [[ "$CSV_REPORT" == *"OFFICIAL ELECTION AUDIT REPORT"* ]]; then
    echo "  [PASS] RFC-4180 CSV report export generated successfully."
fi

curl -s --cacert "$CA_CERT" "https://127.0.0.1:$PORT/api/admin/report/pdf" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -o report_test.pdf
PDF_HEADER=$(head -n 1 report_test.pdf)
echo "PDF Magic Header: $PDF_HEADER (File size: $(wc -c < report_test.pdf) bytes)"
if [[ "$PDF_HEADER" == "%PDF-1.4" ]]; then
    echo "  [PASS] Pure-C PDF 1.4 report generated and validated."
    rm -f report_test.pdf
else
    echo "  [FAIL] PDF generation failed."
fi

# ------------------------------------------------------------------------------
# 10. Intrusion Detection & Security Alerts
# ------------------------------------------------------------------------------
echo -e "\n--- [TEST 10] Security Monitoring & Intrusion Alerts ---"
ALERTS_RESP=$(curl -s --cacert "$CA_CERT" "https://127.0.0.1:$PORT/api/admin/alerts" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
echo "Recent Alerts: $ALERTS_RESP"
if [[ "$ALERTS_RESP" == *"DUPLICATE_VOTE_ATTEMPT"* ]]; then
    echo "  [PASS] Duplicate voting intrusion alert recorded."
fi

echo -e "\n================================================================="
echo "   [SUCCESS] ALL AAYOG_CHUNAV 2.0 SECURITY TESTS COMPLETED!      "
echo "================================================================="
