# Academic Project Report: AAYOG_CHUNAV 2.0
## Secure Election Management and Online Voting System Using C, POSIX TCP Sockets, OpenSSL & Web Dashboard

**Project Title:** AAYOG_CHUNAV 2.0  
**Course:** Computer Networks (Alternative Assessment Tool - AAT / Coursework Project)  
**Implementation Language:** Pure C (POSIX Sockets, Pthreads, OpenSSL) with HTML5/CSS3/JavaScript Frontend  
**Compatibility:** macOS & Linux  

---

## 1. Executive Summary & Abstract

**AAYOG_CHUNAV 2.0** is an enterprise-grade, secure election management and online voting prototype implemented in **pure C** using **POSIX TCP sockets**, **POSIX threads (`pthreads`)**, and **OpenSSL**. 

While preserving the core POSIX network architecture and multi-threaded socket server from version 1.0, version 2.0 introduces cryptographic and systemic enhancements designed to meet modern election security standards:
1. **Transport Layer Security (TLS 1.2 & TLS 1.3)**: High-security cipher suites encrypt all browser HTTPS and CLI TCP socket traffic.
2. **Mutual TLS (mTLS)**: Cryptographic client certificate validation for Chief Election Officers and administrators.
3. **Strict Ballot Secrecy**: Decouples voter identity from cast ballots into two isolated files (`data/voters.txt` and `data/ballots.txt`), eliminating identity-to-choice linkability while retaining duplicate prevention and cryptographic receipt tokens (`BLT-...`).
4. **Salted Two-Factor Authentication (2FA)**: Dynamic 6-digit OTP verification where plaintext passcodes are **never** stored on disk; salted SHA-256 hashes are verified in volatile memory with 5-minute expiry and attempt thresholds.
5. **IP-Based Access Control**: Configurable IP allowlist (`data/ip_allowlist.txt`) guarding administrative dashboards and endpoints.
6. **Polling Booth Management**: Multi-station architecture tracking assigned voters and booth-wise turnout.
7. **Rule-Based Intrusion Detection**: Sliding-window rate limiting (60 req/min) and detection of failed logins, duplicate voting, and malformed requests.
8. **Tamper-Evident HMAC-SHA256 Audit Ledger**: Hash-chained event log providing mathematical proof of record immutability.
9. **SHA-256 System File Baseline Manifest**: Real-time detection of unauthorized out-of-band disk file tampering.
10. **Certified Report Generation**: Pure-C RFC-4180 CSV export and pure-C PDF 1.4 document engine with zero external third-party dependencies.

---

## 2. Network Architecture & OSI/TCP Mapping

| OSI Layer | Protocol / Technology Used | Implementation Detail |
| :--- | :--- | :--- |
| **Application Layer** | HTTPS, HTTP/1.1, Custom ASCII CLI Protocol | Handled in C via string tokenization and JSON serialization |
| **Presentation / Security Layer** | OpenSSL TLS 1.2 & 1.3, SHA-256, HMAC, X.509 PKI | Cryptographic encapsulation via `SSL_read()`, `SSL_write()`, and `EVP` APIs |
| **Session Layer** | POSIX Sockets & OpenSSL Session State | File descriptors managed with `accept()`, `SSL_accept()`, `SSL_connect()` |
| **Transport Layer** | TCP (Transmission Control Protocol) | Full-duplex byte stream via `SOCK_STREAM` with `SO_REUSEADDR` & receive timeouts |
| **Network Layer** | IPv4 & IPv6 (`AF_INET`, `AF_INET6`) | IP addressing via `htons(8080)` and `inet_ntop()` for access control |
| **Data Link & Physical** | Loopback / Ethernet / 802.11 Wi-Fi | Handled transparently by kernel network stack |

---

## 3. Cryptographic Modules & Mathematical Security Guarantees

### A. Ballot Secrecy Architecture
In traditional implementations, storing `VoterID|CandidateID` creates an indisputable link between an individual and their vote. AAYOG_CHUNAV 2.0 solves this by decomposing state across two independent files:
- **Eligibility Record (`data/voters.txt`)**:
  $$\text{VoterID} \parallel \text{Name} \parallel \text{BoothID} \parallel \text{HasVoted} \parallel \text{Timestamp}$$
- **Anonymous Ballot Record (`data/ballots.txt`)**:
  $$\text{BallotToken} \parallel \text{CandidateID} \parallel \text{CandidateName} \parallel \text{BoothID} \parallel \text{Timestamp}$$

Where $\text{BallotToken} = \text{"BLT-"} \parallel \text{Hex}(\text{RAND\_bytes}(16))$.  
Because the ballot file contains no voter identity and the voter file contains no candidate choice, mathematical linkability is broken, providing provable ballot secrecy while preserving atomic duplicate prevention.

### B. Two-Factor Authentication with Salted SHA-256
To prevent identity spoofing during remote voting:
1. When a voter requests an OTP, the server generates a 6-digit random number $C \in [100000, 999999]$ and a 16-byte random salt $S$.
2. The server computes:
   $$H = \text{SHA-256}(S \parallel C)$$
3. The server stores only $\{ \text{VoterID}, S, H, T_{\text{create}}, \text{AttemptsLeft} \}$ in volatile memory.
4. Plaintext $C$ is transmitted to the voter (simulated on console in viva demo) and never committed to persistent storage.

### C. Tamper-Evident Hash-Chained Audit Ledger
Every election event $i$ is appended to `data/audit_log.txt`:
$$\text{Entry}_i = \{ i, \text{Timestamp}_i, \text{Event}_i, \text{Actor}_i, \text{Details}_i, H_{i-1}, M_i \}$$
Where:
$$H_0 = 0^{64}$$
$$H_i = \text{Hex}(\text{HMAC-SHA256}(\text{Entry}_i, K))$$
$$M_i = H_i$$
Here, $K$ is a 256-bit cryptographically random key stored with `chmod 0600`. Any retroactive alteration, insertion, or deletion of a record invalidates the hash chain and is immediately flagged by `audit_log_verify_chain()`.

---

## 4. Verification and Test Results

The platform was subjected to rigorous end-to-end verification through three test harnesses:

1. **Security Test Suite (`./test_security.sh`)**:
   - TLS 1.2 / 1.3 handshake: **PASSED** (HTTP 200)
   - mTLS administrative certificate authentication: **PASSED**
   - Salted OTP 2FA verification & attempt limitation: **PASSED**
   - Strict Ballot Secrecy verification in `data/ballots.txt`: **PASSED**
   - Duplicate vote blocking: **PASSED** (HTTP 409 Conflict)
   - Polling booth management: **PASSED**
   - HMAC-SHA256 hash chaining audit verification: **PASSED**
   - SHA-256 file baseline manifest audit: **PASSED**
   - Pure-C PDF 1.4 report generation: **PASSED** (Magic header `%PDF-1.4`)
   - Intrusion detection and alert generation: **PASSED**

2. **System CLI Verification (`./test_system.sh`)**:
   - Single voting, duplicate prevention, and election tally: **100% PASSED**.

3. **Web & CLI Concurrency Suite (`./test_web_and_cli.sh`)**:
   - Static asset delivery, voter roll boundaries (V101-V199), and live REST endpoints: **100% PASSED**.

---

## 5. Conclusion & Coursework Alignment

AAYOG_CHUNAV 2.0 demonstrates that high-performance, cryptographically sound election management systems can be constructed strictly in **pure C and POSIX socket standards** without bloating the architecture with third-party web frameworks. The system offers a complete educational template for network programming, transport layer security, cryptographic hashing, and concurrent systems design.
