# AAYOG_CHUNAV 2.0: Secure Election Management and Online Voting System
## Advanced Computer Networks Project & Prototype Implementation

A practical, robust, and secure **Election Management and Online Voting System** built in **pure C using POSIX TCP Sockets, POSIX Threads (`pthreads`), and OpenSSL**. 

AAYOG_CHUNAV 2.0 upgrades the foundational socket architecture into an enterprise-grade voting platform featuring **TLS 1.2/1.3 encryption, Mutual TLS (mTLS), Salted Two-Factor Authentication (2FA), Strict Ballot Secrecy, IP-based Access Control, Rule-Based Intrusion Detection, Tamper-Evident Hash-Chained Audit Logs, and Certified pure-C PDF/CSV Report Generation**.

Zero Node.js, Python, Java, or third-party web frameworks are used. Everything is implemented directly in C with standard POSIX libraries and OpenSSL.

---

## 🌟 Key Upgrades in AAYOG_CHUNAV 2.0

| Module | Core Features | Security Guarantees |
| :--- | :--- | :--- |
| **Transport Layer Security** | OpenSSL TLS 1.2 & TLS 1.3, X.509 PKI, Dual-Mode Peek (HTTPS / Plain TCP) | Confidentiality, Integrity, Man-in-the-Middle (MitM) Prevention |
| **Mutual TLS (mTLS)** | Client certificate verification for Election Administrators | Cryptographic identity verification without credential exposure |
| **Ballot Secrecy** | Decouples voter eligibility (`voters.txt`) from anonymous ballots (`ballots.txt`) | Anonymity; impossible to link voter identity to selected candidate |
| **Two-Factor Auth (2FA)** | Salted SHA-256 OTP verification (never stored in plaintext), 5-min expiry, max 3 attempts | Protection against identity impersonation; local simulation for viva |
| **IP Access Control** | Configurable IP allowlist (`data/ip_allowlist.txt`) for administrative operations | Enforces network perimeter security on admin dashboard and APIs |
| **Polling Booths** | Booth ID assignment, voter quotas, booth-wise turnout tracking | Regional administration & prevention of multi-booth voting |
| **Intrusion Detection** | Sliding-window rate limiting (60 req/min), duplicate voting detection, malformed request rejection | Defense against brute-force, DoS flooding, and tampering |
| **Audit Ledger** | SHA-256 hash chaining with 256-bit HMAC verification for every election event | Tamper-evident immutable ledger; detects any file modifications |
| **Integrity Baseline** | Cryptographic SHA-256 manifest of critical database and configuration files | Instant detection of unauthorized out-of-band disk file edits |
| **Reporting Engine** | Pure-C RFC-4180 CSV export and pure-C PDF 1.4 certified report generator | Zero external PDF dependencies; official signed election summary |

---

## 🏛️ System Architecture

```
                                      +-------------------------------------------------+
                                      |     AAYOG_CHUNAV 2.0 DUAL-MODE ENGINE (C)      |
                                      |  - Master Listening Socket: Port 8080           |
                                      |  - OpenSSL TLS 1.2 & 1.3 (server.crt/key)       |
                                      |  - Optional Mutual TLS (mTLS) for Admin Clients |
                                      |  - Worker Thread Pool (pthreads & mutexes)      |
                                      +------------------------+------------------------+
                                                               ^
                               +-------------------------------+-------------------------------+
                               |                                                               |
                [TLS Handshake 0x16 Detected]                                     [Plain TCP / HTTP Fallback]
                               |                                                               |
                               v                                                               v
              +---------------------------------+                             +---------------------------------+
              |    OpenSSL Secure Stream (SSL*) |                             |     Standard POSIX Socket (fd)  |
              +----------------+----------------+                             +----------------+----------------+
                               |                                                               |
        +----------------------+----------------------+                                        |
        |                                             |                                        |
        v                                             v                                        v
+-------------------------------+             +-------------------------------+    +-------------------------------+
|     Voter Web Dashboard       |             |   Administrator Portal (RBAC) |    |     Terminal CLI Client       |
|    (https://localhost:8080)   |             | (https://localhost:8080/admin)|    |      (./client over TLS)      |
|  - Salted OTP 2FA Step        |             |  - IP Allowlist Protection    |    |  - TLS encrypted socket       |
|  - Candidate Cards & Photos   |             |  - 2FA Admin Login / mTLS     |    |  - Interactive 2FA OTP prompt |
|  - Polling Station Badge      |             |  - Voter & Candidate Mgmt     |    |  - Ballot Secrecy Receipt     |
|  - Anonymous Ballot Receipt   |             |  - Polling Booth Management   |    |  - Live Formatted Results     |
|  - Live Dynamic Results Chart |             |  - Intrusion Alerts & Defense |    |  - Backward-compatible CLI    |
|  - Multi-client polling       |             |  - HMAC Audit Ledger Verifier |    |                               |
+-------------------------------+             |  - Certified PDF & CSV Export |    +-------------------------------+
                                              +-------------------------------+
                                                              |
                                                              v
              +---------------------------------------------------------------------------------+
              |                        FILE-BASED CRYPTOGRAPHIC STORAGE                         |
              |  - data/voters.txt       : VoterID|Name|BoothID|HasVoted|VotedAt (NO Candidate) |
              |  - data/ballots.txt      : BallotToken|CandidateID|CandName|BoothID (NO Voter)  |
              |  - data/booths.txt       : BoothID|BoothName|Location                           |
              |  - data/election.txt     : State|Title|StartTime|EndTime|RequireOTP             |
              |  - data/audit_log.txt    : Seq|Time|Event|Actor|Details|PrevHash|HMAC           |
              |  - data/.hmac_key        : 256-bit Random Secret Key (chmod 0600)               |
              |  - data/ip_allowlist.txt : Allowed IPs for Administrative Access                |
              |  - data/integrity.manifest: SHA-256 Hashes of all Election Database Files       |
              +---------------------------------------------------------------------------------+
```

---

## 🔒 Security Modules & Implementation Details

### 1. Transport Layer Security (TLS 1.2 & TLS 1.3)
- Implemented using OpenSSL (`SSL_CTX`, `SSL_accept`, `SSL_connect`).
- Enforces modern cipher suites (`TLS_AES_128_GCM_SHA256`, `ECDHE-RSA-AES128-GCM-SHA256`, etc.).
- The server auto-detects TLS vs plain TCP connections using single-byte peek (`MSG_PEEK == 0x16`). If TLS is present, it securely wraps the socket in an `SSL *` structure; if plain, it serves HTTP or raw CLI commands seamlessly without breaking backward compatibility.

### 2. Mutual TLS (mTLS) for Administrators
- The server loads `certs/ca.crt` and requests optional client certificates (`SSL_VERIFY_PEER`).
- Ordinary voters connect over TLS without requiring personal certificates.
- When an administrative client presents a verified certificate signed by the Root CA (e.g. `certs/admin_client.crt`), the server extracts the Subject CN (`Chief Election Officer`) and grants administrative access without requiring manual password entry.

### 3. Strict Ballot Secrecy Architecture
Traditional voting systems often store `VoterID|CandidateID`, directly violating the secret ballot. AAYOG_CHUNAV 2.0 decouples storage into three isolated layers:
1. **Voter Roll (`data/voters.txt`)**: Records that a voter has exercised their franchise (`has_voted = 1`, `voted_at = timestamp`), but **never** stores candidate choice.
2. **Anonymous Ballots (`data/ballots.txt` and `votes.txt`)**: Contains a cryptographically random receipt token (`BLT-<32-hex-chars>`), candidate selection, and station ID, but **never** stores voter ID.
3. **Receipt Token**: Returned to the voter as proof of ballot submission without disclosing candidate choice to third parties.

*Security Note & Limitations*: True cryptographic anonymity prevents direct linkability in the file storage. In very small voter cohorts (e.g. 1 voter at a booth), circumstantial inference could occur.

### 4. Salted Two-Factor Authentication (OTP)
- Voters must authenticate with a one-time passcode (OTP) before casting a ballot.
- **Plaintext OTPs are NEVER written to disk or logged.** The server generates a random 16-byte salt, computes `SHA-256(salt + OTP)`, and keeps only the salted hash in volatile memory.
- Enforces an expiry window of **300 seconds** (5 minutes) and a maximum of **3 failed attempts**.
- **College Demonstration Mode**: A simulated SMS dispatch is printed to the server terminal and displayed in the frontend demo pill, enabling seamless viva demonstrations without external cellular APIs.

### 5. IP-Based Access Control
- Restricts administrative dashboard (`/admin.html`) and endpoints (`/api/admin/*`) to allowlisted IPs in `data/ip_allowlist.txt` (default: `127.0.0.1`, `::1`, `localhost`).
- Attempts from non-allowlisted IPs trigger **HTTP 403 Forbidden** and log an intrusion alert.
- *Limitations of IP Security*: IP addresses can be spoofed on unauthenticated UDP/local networks, and multiple devices behind NAT share a single public IP. Therefore, IP filtering acts as defense-in-depth alongside TLS and administrative 2FA / mTLS.

### 6. Rule-Based Intrusion Detection & Rate Limiting
- Tracks request frequency per client IP using a sliding 60-second window.
- Clients exceeding **60 requests/minute** receive **HTTP 429 Too Many Requests** with an enforced 30-second cooldown.
- Automatically flags and logs suspicious activity:
  * Repeated failed voter or admin authentication attempts (`FAILED_AUTH_ATTEMPT`).
  * Repeated attempts to vote using an already-used voter ID (`DUPLICATE_VOTE_ATTEMPT`).
  * Unauthorized attempts to access `/admin` resources (`UNAUTHORIZED_ADMIN_ACCESS`).
  * Malformed request bodies or path traversal (`MALFORMED_REQUEST`).

### 7. Tamper-Evident HMAC-SHA256 Hash-Chained Audit Ledger
- All critical events (election start, closure, voter registrations, ballot castings, security alerts) are appended to `data/audit_log.txt`.
- Each record links to the previous entry's hash (blockchain-style ledger):
  $$\text{Record } N = \{\text{Seq}, \text{Time}, \text{Event}, \text{Actor}, \text{Details}, \text{Hash}_{N-1}, \text{HMAC}(\text{Data}, K)\}$$
- The 256-bit HMAC key is stored in `data/.hmac_key` with strict permissions (`0600`).
- The administrator can verify the entire ledger with 1-click in the dashboard or via API (`/api/admin/audit/verify`), detecting any tampered, added, or deleted records.

### 8. System File Baseline Manifest (SHA-256)
- Automatically computes SHA-256 hashes of critical database files (`data/voters.txt`, `data/ballots.txt`, `data/booths.txt`, `data/election.txt`, `certs/server.crt`).
- Saved in `data/integrity.manifest`.
- If an attacker manually modifies any file out-of-band using a text editor, the integrity check instantly detects the modification and fires a critical security alert.

### 9. Certified Election Reports (Pure-C PDF 1.4 & RFC-4180 CSV)
- Generates official certified reports containing candidate standings, voter turnout, booth statistics, and cryptographic audit certificates.
- The PDF generator is written strictly in **pure C** (~150 lines), constructing valid PDF 1.4 binary objects (`/Catalog`, `/Pages`, `/Font`, `/Contents`) with cross-reference tables (`xref`), requiring **zero** external PDF libraries.

---

## 📁 Directory & File Storage Structure

```
AAYOG_CHUNAV/
├── Makefile                       # Multi-platform build file (macOS & Linux)
├── server.c                       # Multi-threaded server entry point & socket loop
├── client.c                       # Terminal CLI voting client with TLS support
├── include/
│   ├── election.h                 # Election structs, candidates, booths, voter rolls
│   ├── security.h                 # OpenSSL TLS, SHA-256, HMAC, OTP 2FA, IP allowlist
│   ├── admin.h                    # Admin session handling, RBAC, report generation
│   └── http.h                     # HTTP/1.1 parser, REST router, static asset server
├── src/
│   ├── election.c                 # Ballot secrecy, voter validation, booth management
│   ├── security.c                 # TLS CTX, mTLS verify, hash chaining, intrusion alerts
│   ├── admin.c                    # Admin auth, session tokens, CSV & pure-C PDF engine
│   └── http.c                     # REST API endpoints, static file delivery
├── certs/
│   ├── ca.crt / ca.key            # Root Certificate Authority
│   ├── server.crt / server.key    # TLS Server Certificate with SAN (localhost, 127.0.0.1)
│   └── admin_client.crt / .key    # Admin Client Certificate for Mutual TLS
├── data/
│   ├── voters.txt                 # Registered Voter Roll with Booth assignments
│   ├── ballots.txt                # Anonymous Ballots with Receipt Tokens
│   ├── booths.txt                 # Polling Booth Station registry
│   ├── candidates.txt             # Candidate records and vote tallies
│   ├── election.txt               # Election Lifecycle State (ACTIVE, PAUSED, CLOSED)
│   ├── ip_allowlist.txt           # Authorized IP addresses for admin access
│   ├── audit_log.txt              # Hash-chained tamper-evident audit ledger
│   ├── integrity.manifest         # SHA-256 baseline hashes of critical files
│   └── .hmac_key                  # Protected 256-bit HMAC secret (chmod 0600)
├── public/
│   ├── index.html                 # Modern Voter Dashboard (2FA, receipts, live bars)
│   ├── app.js                     # Voter frontend controller
│   ├── admin.html                 # Comprehensive Administrator Dashboard
│   ├── admin.js                   # Admin frontend controller
│   ├── style.css                  # Unified styling for Voter & Admin Dashboards
│   └── images/                    # Candidate photos (modi.png, gandhi.png)
├── scripts/
│   └── generate_certs.sh          # Automated OpenSSL PKI certificate generator
├── test_system.sh                 # Preserved original CLI test script
├── test_web_and_cli.sh            # Preserved original Web & CLI verification test
└── test_security.sh               # New comprehensive security test suite
```

---

## 🛠️ Compilation & Quick Start

### 1. Prerequisites
- **C Compiler**: GCC or Clang (macOS / Linux).
- **OpenSSL 1.1 or 3.x**: Headers and libraries (`libssl`, `libcrypto`).
  * On macOS: `brew install openssl@3` (automatically detected by Makefile).
  * On Linux (Ubuntu/Debian): `sudo apt-get install libssl-dev build-essential`.

### 2. Build the System
```bash
make clean && make
```
This automatically:
1. Generates Root CA, Server TLS, and Admin mTLS certificates in `certs/` (if missing).
2. Compiles `server` and `client` binaries using `-Wall -Wextra -O2 -pthread -Iinclude -lssl -lcrypto`.

### 3. Run the Server
```bash
./server
```
*(Default Port: `8080`. Optional custom port: `./server 9443`)*

Expected server startup log:
```text
=================================================================
   AAYOG_CHUNAV 2.0 - SECURE ONLINE ELECTION MANAGEMENT SYSTEM   
   Dual-Protocol Engine: OpenSSL TLS 1.2/1.3 + POSIX TCP Sockets 
=================================================================
[INFO] Loaded 99 registered voters into AAYOG_CHUNAV 2.0 registry.
[SEC INFO] mTLS CA 'certs/ca.crt' loaded. Optional client certificate authentication enabled.
[SEC INFO] OpenSSL TLS 1.2/1.3 context initialized successfully.
[SECURITY] TLS 1.2/1.3 encryption enabled with certificate 'certs/server.crt'.
[READY] Server active on port 8080
[HTTPS WEB] Voter Dashboard:       https://localhost:8080
[ADMIN UI]  Administrator Portal:   https://localhost:8080/admin.html
[HTTP WEB]  Plain HTTP Fallback:    http://localhost:8080
[TLS CLI]   Terminal Voting Client: ./client 127.0.0.1 8080
[INFO] Press Ctrl+C at any time to shut down the server.
-----------------------------------------------------------------
```

### 4. Access the Dashboards
- **Voter Dashboard (HTTPS)**: Open [https://localhost:8080](https://localhost:8080) in your web browser.
- **Administrator Dashboard (HTTPS)**: Open [https://localhost:8080/admin.html](https://localhost:8080/admin.html) in your browser.
  * Default Admin Username: `admin`
  * Default Admin Password: `Admin@Aayog2026#`
  * Admin 2FA Code: `888999`
  * Or click **Login with mTLS Certificate** if connecting with an enrolled client cert!

### 5. Run the Terminal CLI Client
In a second terminal window:
```bash
./client 127.0.0.1 8080
```
Establishes a TLS encrypted session, prompts for Voter ID, verifies 2FA OTP, displays the secret ballot, and returns an official Receipt Token.

---

## 🧪 Comprehensive Automated Testing

Three complete automated test suites verify 100% backward compatibility and all security modules:

### 1. Comprehensive Security Test Suite (`./test_security.sh`)
Executes 10 end-to-end security scenarios:
```bash
./test_security.sh
```
Verified Test Scenarios:
1. **TLS 1.2 & TLS 1.3**: Handshake and CA certificate verification.
2. **Mutual TLS (mTLS)**: Client certificate verification for admin resources.
3. **2FA OTP**: Salted SHA-256 verification, invalid passcode rejection, attempt decrementing.
4. **Ballot Secrecy**: Decoupling voter identity from ballot tokens in `data/ballots.txt`.
5. **Admin RBAC**: Unauthorized 401 rejection, password+2FA session token issuance.
6. **Polling Booths**: Regional voter assignment and booth turnout aggregation.
7. **Audit Ledger**: HMAC-SHA256 hash chaining verification across all records.
8. **File Integrity**: SHA-256 baseline manifest verification.
9. **Certified Reports**: RFC-4180 CSV export and pure-C PDF 1.4 document validation.
10. **Intrusion Detection**: Automatic alert generation for duplicate votes and brute force.

### 2. Original System CLI Verification (`./test_system.sh`)
Verifies single voting, duplicate prevention, invalid IDs, and result tallying:
```bash
./test_system.sh
```

### 3. Web & CLI Compatibility Test (`./test_web_and_cli.sh`)
Tests HTTP endpoints, ID range boundaries (`V101` to `V199`), and CLI concurrency:
```bash
./test_web_and_cli.sh
```

---

## 🎯 Viva & Evaluation Guide

### Q1: How does AAYOG_CHUNAV 2.0 prevent duplicate voting while guaranteeing ballot secrecy?
**Answer:** The system splits storage into two decoupled structures:
- `data/voters.txt` marks `has_voted = 1` for the voter ID under a mutex lock, preventing any duplicate submission.
- `data/ballots.txt` stores only the candidate selection and a random cryptographic receipt token (`BLT-...`). The voter ID is **never** written to `data/ballots.txt`. The voter receives the receipt token for independent auditing, but no record exists that links the voter's identity to their candidate choice.

### Q2: How does the server support both HTTPS in the browser and raw TCP CLI clients?
**Answer:** The server employs a **peek-based protocol multiplexer**:
1. When a client socket connects, the worker thread inspects the first byte using `recv(..., MSG_PEEK)`.
2. If `0x16` (TLS ClientHello) is detected, the server executes `SSL_accept` to establish an OpenSSL TLS session.
3. Once the stream is ready, the server inspects the payload: if it begins with an HTTP verb (`GET`, `POST`), it dispatches to the HTTP REST router; if it begins with an ASCII command (`CHECK_ID`, `VOTE`, `RESULTS`), it executes the CLI handler.
4. This allows HTTPS browsers, TLS-secured CLI clients, and plain legacy clients to coexist seamlessly.

### Q3: How is Two-Factor Authentication implemented securely without external databases?
**Answer:** The server generates a random 6-digit passcode and a 16-byte random salt. It computes `SHA-256(salt + OTP)` and stores only the salt and hash in volatile memory with a 5-minute expiry timestamp. Even if an attacker inspects server memory or storage, the plaintext OTP is never exposed.

### Q4: How does the tamper-evident audit log work?
**Answer:** Each audit log record contains the SHA-256 hash of the previous record and is signed with a 256-bit HMAC key. If an adversary attempts to modify, insert, or delete any record in `data/audit_log.txt`, the hash chain breaks, and the verifier identifies the exact line where tampering occurred.

---

## 📜 License & Academic Integrity
Developed for Computer Networks Alternative Assessment Test (AAT) and advanced coursework. Educational demonstration prototype strictly adhering to pure POSIX C standards and OpenSSL cryptographic best practices.
