/**
 * ============================================================================
 * Title:       AAYOG_CHUNAV 2.0 - Security Header
 * File:        include/security.h
 * Description: TLS 1.2/1.3 OpenSSL wrappers, mTLS certificate verification,
 *              SHA-256 file integrity, HMAC-based audit log chaining,
 *              salted OTP 2FA verification, IP allowlists, and intrusion detection.
 * ============================================================================
 */

#ifndef SECURITY_H
#define SECURITY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define OTP_LENGTH 6
#define OTP_EXPIRY_SECONDS 300
#define OTP_MAX_ATTEMPTS 3
#define MAX_IP_ALLOWLIST 64
#define MAX_SECURITY_ALERTS 100
#define RATE_LIMIT_WINDOW_SEC 60
#define RATE_LIMIT_MAX_REQUESTS 240

/* Suspicious Activity Record */
typedef struct {
    char id[16];
    char timestamp[32];
    char alert_type[32];
    char ip_address[46];
    char details[128];
    char severity[16]; /* LOW, MEDIUM, HIGH, CRITICAL */
} SecurityAlert;

/* TLS Context Initializers */
SSL_CTX *security_init_server_ssl_ctx(const char *cert_file, const char *key_file, const char *ca_file);
SSL_CTX *security_init_client_ssl_ctx(const char *ca_file, const char *client_cert, const char *client_key);
int security_verify_admin_cert(SSL *ssl, char *out_subject_cn, size_t max_len);

/* Cryptographic Hashes */
int security_sha256_hex(const unsigned char *data, size_t len, char *out_hex);
int security_sha256_string(const char *str, char *out_hex);
int security_file_sha256(const char *filepath, char *out_hex);
int security_hmac_sha256(const char *key, size_t key_len, const char *data, size_t data_len, char *out_hex);

/* Tamper-Evident Audit Logging with SHA-256 Hash Chaining & HMAC */
void audit_log_init(void);
int audit_log_record(const char *event_type, const char *severity, const char *actor, const char *details);
int audit_log_verify_chain(int *out_total, int *out_tampered_index);
void audit_log_get_recent_json(char *output, size_t max_len, int limit);

/* 2FA & OTP Management (Salted SHA-256, NEVER plaintext in storage) */
int security_is_dev_mode(void);
void security_set_dev_mode(int enable);
int security_generate_voter_otp(const char *voter_id, char *out_plain_otp);
int security_verify_voter_otp(const char *voter_id, const char *input_otp);
int security_is_voter_otp_verified(const char *voter_id);
void security_clear_voter_otp(const char *voter_id);
int security_get_simulated_otp(const char *voter_id, char *out_otp);
int security_generate_voter_election_otp(const char *voter_id, int election_id, char *out_plain_otp);
int security_verify_voter_election_otp(const char *voter_id, int election_id, const char *input_otp);
int security_is_voter_election_otp_verified(const char *voter_id, int election_id);
void security_clear_voter_election_otp(const char *voter_id, int election_id);
int security_get_simulated_election_otp(const char *voter_id, int election_id, char *out_otp);

/* IP-Based Access Control */
void security_load_ip_allowlist(void);
int security_is_ip_allowed_admin(const char *ip_addr);
int security_add_ip_allowlist(const char *ip_addr);
void security_get_ip_allowlist_json(char *output, size_t max_len);

/* Rate Limiting & Suspicious Activity Detection */
int security_check_rate_limit(const char *ip_addr);
void security_record_alert(const char *alert_type, const char *severity, const char *ip_addr, const char *details);
void security_record_failed_auth(const char *ip_addr, const char *id);
void security_record_duplicate_vote(const char *ip_addr, const char *id);
void security_record_unauthorized_admin(const char *ip_addr, const char *path);
void security_record_malformed_request(const char *ip_addr, const char *info);
void security_get_alerts_json(char *output, size_t max_len);

/* System File Integrity & Baseline Manifest */
int security_save_baseline_manifest(void);
int security_verify_file_integrity(char *out_report, size_t max_len);

#endif /* SECURITY_H */

