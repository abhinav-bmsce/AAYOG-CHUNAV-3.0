# Computer Networks Viva Voce Preparation Guide: AAYOG_CHUNAV 2.0
## Secure Election Management and Online Voting System

Comprehensive viva questions, answers, and technical explanations covering **POSIX TCP Sockets, OpenSSL TLS 1.2/1.3, Mutual TLS (mTLS), Concurrency, Ballot Secrecy, Salted 2FA, and Cryptographic Hash Chaining**.

---

### Q1: What is AAYOG_CHUNAV 2.0 and what makes it unique?
**Answer:**  
AAYOG_CHUNAV 2.0 is a secure election management and online voting platform where the backend is developed strictly in **pure C** using **POSIX TCP Sockets, POSIX Threads (`pthreads`), and OpenSSL**. It supports:
1. An encrypted **HTTPS Web Dashboard** for voters with Two-Factor Authentication (OTP).
2. A separate **Administrator Portal** with Role-Based Access Control, live monitoring, voter management, and booth tracking.
3. An interactive **TLS-secured terminal CLI client (`client.c`)**.
4. Zero third-party web frameworks (no Node.js, Python, or external databases).

---

### Q2: How does the C server support both HTTPS in a browser and raw TCP CLI clients on the same port?
**Answer:**  
The server employs **single-byte socket peeking**:
1. When a client connects, the worker thread inspects the first incoming byte using `recv(client_sock, &peek, 1, MSG_PEEK)`.
2. If `peek == 0x16`, it is an OpenSSL TLS `ClientHello` record. The server initializes an `SSL *` object and executes `SSL_accept()`.
3. If `peek != 0x16`, the connection is unencrypted plain TCP.
4. Once the transport is ready, the server checks the payload: if it begins with an HTTP verb (`GET`, `POST`), it dispatches to the HTTP REST router; if it begins with an ASCII command (`CHECK_ID`, `VOTE`), it invokes the CLI protocol handler.

---

### Q3: How does AAYOG_CHUNAV 2.0 guarantee Ballot Secrecy while preventing duplicate voting?
**Answer:**  
The system decouples voter eligibility from cast ballots into two isolated files:
1. **Voter Roll (`data/voters.txt`)**: Stores `VoterID|Name|BoothID|HasVoted|VotedAt`. It tracks whether a voter has exercised their franchise to prevent double-voting under a mutex lock, but **never** stores which candidate they selected.
2. **Anonymous Ballots (`data/ballots.txt`)**: Stores `BallotToken|CandidateID|CandidateName|BoothID|Timestamp`. It records the votes cast, but **never** stores the voter ID.
3. **Receipt Token (`BLT-...`)**: Generated using cryptographically random bytes via OpenSSL `RAND_bytes()` and given to the voter as proof of voting without linking their identity to their candidate choice.

---

### Q4: How is Two-Factor Authentication (2FA) implemented securely without external databases?
**Answer:**  
When a voter requests an OTP:
1. The server generates a random 6-digit passcode and a 16-byte random salt using `RAND_bytes()`.
2. It computes the cryptographic hash:
   $$\text{Hash} = \text{SHA-256}(\text{Salt} \parallel \text{OTP})$$
3. The server stores only the salt and the hash in volatile memory with a 300-second (5-minute) expiry and a 3-attempt limit.
4. The plaintext OTP is **never** written to persistent storage or logged, protecting against credential theft even if disk files are compromised.

---

### Q5: What is Mutual TLS (mTLS) and how is it used in this project?
**Answer:**  
In standard TLS, only the server proves its identity with a certificate. In **Mutual TLS (mTLS)**, both the server and the client authenticate each other:
1. The server loads the Root CA (`certs/ca.crt`) and enables `SSL_VERIFY_PEER`.
2. Ordinary voters connect without client certificates and authenticate via 2FA.
3. Administrative clients present an X.509 client certificate (`certs/admin_client.crt`) signed by the Root CA.
4. The server inspects the peer certificate using `SSL_get_peer_certificate()`, verifies the digital signature, extracts the Subject Common Name (`Chief Election Officer`), and grants administrative access.

---

### Q6: What are the security benefits and limitations of IP-Based Access Control?
**Answer:**  
- **Benefits:** Provides network perimeter defense by restricting administrative endpoints to allowlisted IPs (e.g. `127.0.0.1`, `::1`).
- **Limitations:**
  1. On unencrypted or local networks, IP headers can be spoofed.
  2. Devices behind Network Address Translation (NAT) share the same public IP.
  3. Dynamic IP reassignment (DHCP) can lock out legitimate administrators.
  4. For this reason, IP filtering is implemented as defense-in-depth alongside TLS and administrative 2FA / mTLS.

---

### Q7: How does the tamper-evident audit ledger work?
**Answer:**  
Every critical election event is appended to `data/audit_log.txt` using **SHA-256 hash chaining and HMAC authentication**:
- Each record includes the sequence number, timestamp, event type, actor, details, and the SHA-256 hash of the immediately preceding record.
- The entire entry is signed using a protected 256-bit secret key (`data/.hmac_key`).
- If an attacker alters even a single character in any past log record, the hash chain breaks, and `audit_log_verify_chain()` flags the exact line that was tampered with.

---

### Q8: How does the server generate official PDF reports in pure C without external libraries?
**Answer:**  
The PDF file format is a structured ASCII and binary stream. AAYOG_CHUNAV 2.0 constructs a compliant **PDF 1.4** document directly in C:
1. Defines the document Catalog (`/Type /Catalog /Pages 2 0 R`).
2. Creates the Page Tree and Page Object with standard Type 1 fonts (`/Helvetica`, `/Helvetica-Bold`, `/Courier`).
3. Formats textual streams using PostScript operators (`BT`, `Tf`, `Td`, `Tj`, `ET`) to print certified candidate standings, booth turnout, and HMAC verification seals.
4. Generates a valid cross-reference table (`xref`) with exact byte offsets and document trailer (`trailer << /Root ... >> startxref`).

---

### Q9: How is race-condition prevention guaranteed across multi-threaded clients?
**Answer:**  
When multiple HTTP requests and CLI socket threads execute concurrently, shared memory structures (voter roll, candidate tallies, audit logs) are protected by POSIX mutex locks (`pthread_mutex_t`):
```c
pthread_mutex_lock(&election_mutex);
/* Atomic Section: verify eligibility -> mark voted -> record anonymous ballot */
pthread_mutex_unlock(&election_mutex);
```
This guarantees atomicity and linearizability across all concurrent client connections.

---

### Q10: How does the system defend against Denial of Service (DoS) and Brute-Force attacks?
**Answer:**  
The server implements **sliding-window rate limiting**:
- Tracks request counts per client IP over a 60-second window.
- If a client exceeds 60 requests/minute, it receives **HTTP 429 Too Many Requests** with an enforced 30-second cooldown.
- Failed authentication attempts and duplicate voting attempts are tracked, triggering intrusion detection alerts (`FAILED_AUTH_ATTEMPT`, `DUPLICATE_VOTE_ATTEMPT`) viewable in real-time on the administrator dashboard.
