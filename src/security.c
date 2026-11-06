/**
 * ============================================================================
 * Title:       AAYOG_CHUNAV 2.0 - Security Implementation
 * File:        src/security.c
 * Description: TLS 1.2/1.3 context configuration, mTLS verification,
 *              tamper-evident HMAC audit log chaining, salted 2FA OTP,
 *              IP allowlisting, rate limiting, and SHA-256 file integrity.
 * ============================================================================
 */

#include "security.h"
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#define HMAC_KEY_FILE "data/.hmac_key"
#define AUDIT_LOG_FILE "data/audit_log.txt"
#define IP_ALLOWLIST_FILE "data/ip_allowlist.txt"
#define MANIFEST_FILE "data/integrity.manifest"
#define MAX_IP_TRACKERS 256

/* OTP Record in Memory (Salted Hash only) */
typedef struct {
    char voter_id[32];
    char salt[33];
    char hash[65];
    char simulated_otp[8]; /* College Demonstration Simulation ONLY */
    time_t created_at;
    int attempts_left;
    int is_verified;
    int is_active;
} OtpRecord;

/* IP Rate Limiting Tracker */
typedef struct {
    char ip[46];
    int request_count;
    time_t window_start;
    time_t blocked_until;
} IpTracker;

/* Global Security State */
static pthread_mutex_t sec_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t audit_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t otp_mutex = PTHREAD_MUTEX_INITIALIZER;

static int g_dev_mode = 0;

int security_is_dev_mode(void) {
    if (g_dev_mode) return 1;
    const char *env = getenv("AAYOG_ENV");
    if (env && (strcasecmp(env, "development") == 0 || strcasecmp(env, "dev") == 0)) {
        return 1;
    }
    const char *dev = getenv("AAYOG_DEV");
    if (dev && (strcmp(dev, "1") == 0 || strcasecmp(dev, "true") == 0)) {
        return 1;
    }
    const char *dev_mode = getenv("AAYOG_DEVELOPMENT_MODE");
    if (dev_mode && (strcmp(dev_mode, "1") == 0 || strcasecmp(dev_mode, "true") == 0)) {
        return 1;
    }
    return 0;
}

void security_set_dev_mode(int enable) {
    g_dev_mode = enable ? 1 : 0;
}

static unsigned char hmac_secret[32];
static int hmac_initialized = 0;

static OtpRecord otp_table[MAX_SECURITY_ALERTS * 10];
static int otp_count = 0;

static char ip_allowlist[MAX_IP_ALLOWLIST][46];
static int ip_allowlist_count = 0;

static IpTracker ip_trackers[MAX_IP_TRACKERS];
static int tracker_count = 0;

static SecurityAlert alerts[MAX_SECURITY_ALERTS];
static int alert_count = 0;
static int alert_id_seq = 1;

/* OpenSSL Verification Callback for Optional Peer Verification */
static int verify_callback_optional(int preverify_ok, X509_STORE_CTX *ctx) {
    (void)preverify_ok;
    (void)ctx;
    /* Always allow the TLS handshake to complete for both voters and admins.
     * Administrative client certificates are verified post-handshake in
     * security_verify_admin_cert() by checking SSL_get_verify_result(ssl) == X509_V_OK.
     * This prevents ERR_SSL_PROTOCOL_ERROR for ordinary browsers without client certs.
     */
    return 1;
}

/**
 * Initializes Server OpenSSL TLS Context (TLS 1.2 & TLS 1.3 enforced)
 */
SSL_CTX *security_init_server_ssl_ctx(const char *cert_file, const char *key_file, const char *ca_file) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "[SEC ERROR] Unable to create TLS SSL_CTX\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /* Enforce TLS 1.2 minimum and TLS 1.3 maximum */
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
        fprintf(stderr, "[SEC ERROR] Failed to enforce TLS 1.2/1.3 protocol versions\n");
    }

    /* Configure high-security cipher suites */
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:HIGH:!aNULL:!MD5:!RC4:!3DES");
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");

    /* Load Server Certificate */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[SEC ERROR] Failed to load server certificate '%s'\n", cert_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Load Server Private Key */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[SEC ERROR] Failed to load server private key '%s'\n", key_file);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Validate Private Key matches Certificate */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[SEC ERROR] Server private key does not match certificate public key!\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Load CA Certificate for optional Mutual TLS (mTLS) */
    if (ca_file && access(ca_file, R_OK) == 0) {
        if (!SSL_CTX_load_verify_locations(ctx, ca_file, NULL)) {
            fprintf(stderr, "[SEC WARN] Failed to load CA certificate '%s'\n", ca_file);
        } else {
            /* Set verify to peer without FAIL_IF_NO_PEER_CERT so ordinary voters can connect without certs */
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback_optional);
            /* Advise clients of authorized CAs */
            STACK_OF(X509_NAME) *ca_list = SSL_load_client_CA_file(ca_file);
            if (ca_list) {
                SSL_CTX_set_client_CA_list(ctx, ca_list);
            }
            printf("[SEC INFO] mTLS CA '%s' loaded. Optional client certificate authentication enabled.\n", ca_file);
        }
    }

    printf("[SEC INFO] OpenSSL TLS 1.2/1.3 context initialized successfully.\n");
    return ctx;
}

/**
 * Initializes Client OpenSSL TLS Context for CLI client
 */
SSL_CTX *security_init_client_ssl_ctx(const char *ca_file, const char *client_cert, const char *client_key) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) return NULL;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* Load CA certificate to verify server */
    if (ca_file && access(ca_file, R_OK) == 0) {
        if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL)) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    /* Load Client Certificate if provided (mTLS) */
    if (client_cert && client_key && access(client_cert, R_OK) == 0 && access(client_key, R_OK) == 0) {
        SSL_CTX_use_certificate_file(ctx, client_cert, SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM);
    }

    return ctx;
}

/**
 * Checks if client presented a valid, verified mTLS certificate and extracts Subject CN
 */
int security_verify_admin_cert(SSL *ssl, char *out_subject_cn, size_t max_len) {
    if (!ssl) return 0;

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) return 0; /* Client did not supply a certificate */

    long verify_res = SSL_get_verify_result(ssl);
    if (verify_res != X509_V_OK) {
        X509_free(cert);
        return 0;
    }

    if (out_subject_cn && max_len > 0) {
        X509_NAME *sub = X509_get_subject_name(cert);
        if (X509_NAME_get_text_by_NID(sub, NID_commonName, out_subject_cn, (int)max_len) < 0) {
            strncpy(out_subject_cn, "Verified Admin Certificate", max_len - 1);
            out_subject_cn[max_len - 1] = '\0';
        }
    }

    X509_free(cert);
    return 1;
}

/**
 * Computes SHA-256 hex digest for arbitrary byte buffer
 */
int security_sha256_hex(const unsigned char *data, size_t len, char *out_hex) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(out_hex + (i * 2), "%02x", hash[i]);
    }
    out_hex[hash_len * 2] = '\0';
    return 0;
}

/**
 * Computes SHA-256 hex digest for string
 */
int security_sha256_string(const char *str, char *out_hex) {
    if (!str) return -1;
    return security_sha256_hex((const unsigned char *)str, strlen(str), out_hex);
}

/**
 * Computes SHA-256 hex digest for a disk file
 */
int security_file_sha256(const char *filepath, char *out_hex) {
    FILE *f = fopen(filepath, "rb");
    if (!f) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(f);
        return -1;
    }

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    unsigned char buf[8192];
    size_t bytes = 0;
    while ((bytes = fread(buf, 1, sizeof(buf), f)) > 0) {
        EVP_DigestUpdate(ctx, buf, bytes);
    }
    fclose(f);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(out_hex + (i * 2), "%02x", hash[i]);
    }
    out_hex[hash_len * 2] = '\0';
    return 0;
}

/**
 * Computes HMAC-SHA256 hex digest
 */
int security_hmac_sha256(const char *key, size_t key_len, const char *data, size_t data_len, char *out_hex) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    HMAC(EVP_sha256(), key, (int)key_len, (const unsigned char *)data, data_len, digest, &digest_len);

    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(out_hex + (i * 2), "%02x", digest[i]);
    }
    out_hex[digest_len * 2] = '\0';
    return 0;
}

/**
 * Initializes HMAC secret key and audit log subsystem
 */
void audit_log_init(void) {
    pthread_mutex_lock(&audit_mutex);

    FILE *f = fopen(HMAC_KEY_FILE, "rb");
    if (f) {
        size_t r = fread(hmac_secret, 1, sizeof(hmac_secret), f);
        fclose(f);
        if (r == sizeof(hmac_secret)) {
            hmac_initialized = 1;
        }
    }

    if (!hmac_initialized) {
        if (RAND_bytes(hmac_secret, sizeof(hmac_secret)) != 1) {
            /* Fallback pseudo-random */
            for (size_t i = 0; i < sizeof(hmac_secret); i++) {
                hmac_secret[i] = (unsigned char)(rand() % 256);
            }
        }
        f = fopen(HMAC_KEY_FILE, "wb");
        if (f) {
            fwrite(hmac_secret, 1, sizeof(hmac_secret), f);
            fclose(f);
            chmod(HMAC_KEY_FILE, 0600);
            hmac_initialized = 1;
            printf("[SEC INFO] Generated fresh 256-bit HMAC key in '%s'.\n", HMAC_KEY_FILE);
        }
    }

    /* Ensure audit_log.txt exists */
    if (access(AUDIT_LOG_FILE, F_OK) != 0) {
        FILE *af = fopen(AUDIT_LOG_FILE, "w");
        if (af) {
            fprintf(af, "# AAYOG_CHUNAV 2.0 Tamper-Evident Hash-Chained Audit Log\n");
            fprintf(af, "# Format: SEQ|TIMESTAMP|EVENT|SEVERITY|ACTOR|DETAILS|PREV_HASH|HMAC\n");
            fclose(af);
            chmod(AUDIT_LOG_FILE, 0640);
        }
    }

    pthread_mutex_unlock(&audit_mutex);
}

/**
 * Appends a tamper-evident record to audit log with SHA-256 hash chaining and HMAC
 */
int audit_log_record(const char *event_type, const char *severity, const char *actor, const char *details) {
    pthread_mutex_lock(&audit_mutex);

    if (!hmac_initialized) {
        pthread_mutex_unlock(&audit_mutex);
        audit_log_init();
        pthread_mutex_lock(&audit_mutex);
    }

    FILE *f = fopen(AUDIT_LOG_FILE, "r");
    char prev_hash[65] = "0000000000000000000000000000000000000000000000000000000000000000";
    int seq = 1;

    if (f) {
        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            if (line[0] == '#' || strlen(line) < 10) continue;
            char *last_pipe = strrchr(line, '|');
            if (last_pipe) {
                *last_pipe = '\0';
                if (last_pipe + 1) {
                    char hmac_token[65] = {0};
                    sscanf(last_pipe + 1, "%64s", hmac_token);
                    if (strlen(hmac_token) == 64) {
                        strncpy(prev_hash, hmac_token, 64);
                        prev_hash[64] = '\0';
                    }
                }
                seq++;
            }
        }
        fclose(f);
    }

    /* Generate current timestamp */
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    /* Construct payload to sign */
    char sign_payload[1024];
    snprintf(sign_payload, sizeof(sign_payload), "%d|%s|%s|%s|%s|%s|%s",
             seq, timestamp, event_type, severity, actor, details, prev_hash);

    char hmac_digest[65];
    security_hmac_sha256((const char *)hmac_secret, sizeof(hmac_secret),
                         sign_payload, strlen(sign_payload), hmac_digest);

    /* Append to log */
    FILE *out = fopen(AUDIT_LOG_FILE, "a");
    if (out) {
        fprintf(out, "%d|%s|%s|%s|%s|%s|%s|%s\n",
                seq, timestamp, event_type, severity, actor, details, prev_hash, hmac_digest);
        fclose(out);
    }

    pthread_mutex_unlock(&audit_mutex);
    return 0;
}

/**
 * Verifies integrity of the entire audit log hash chain.
 * Returns 1 if 100% valid; returns 0 if tampered and sets *out_tampered_index.
 */
int audit_log_verify_chain(int *out_total, int *out_tampered_index) {
    pthread_mutex_lock(&audit_mutex);

    FILE *f = fopen(AUDIT_LOG_FILE, "r");
    if (!f) {
        pthread_mutex_unlock(&audit_mutex);
        if (out_total) *out_total = 0;
        if (out_tampered_index) *out_tampered_index = 0;
        return 1;
    }

    char expected_prev_hash[65] = "0000000000000000000000000000000000000000000000000000000000000000";
    char line[1024];
    int count = 0;
    int tampered_idx = -1;

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || strlen(line) < 10) continue;

        char line_copy[1024];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';

        char *tokens[8];
        char *ptr = line_copy;
        int t_idx = 0;

        while (t_idx < 8 && ptr) {
            tokens[t_idx++] = ptr;
            char *next = strchr(ptr, '|');
            if (next) {
                *next = '\0';
                ptr = next + 1;
            } else {
                ptr = NULL;
            }
        }

        if (t_idx != 8) continue;
        count++;

        int seq = atoi(tokens[0]);
        const char *timestamp = tokens[1];
        const char *event_type = tokens[2];
        const char *severity = tokens[3];
        const char *actor = tokens[4];
        const char *details = tokens[5];
        const char *record_prev_hash = tokens[6];
        char record_hmac[65] = {0};
        sscanf(tokens[7], "%64s", record_hmac);

        /* 1. Verify PrevHash links to expected previous HMAC */
        if (strcmp(record_prev_hash, expected_prev_hash) != 0) {
            tampered_idx = seq;
            break;
        }

        /* 2. Recompute HMAC and verify signature */
        char sign_payload[1024];
        snprintf(sign_payload, sizeof(sign_payload), "%d|%s|%s|%s|%s|%s|%s",
                 seq, timestamp, event_type, severity, actor, details, record_prev_hash);

        char computed_hmac[65];
        security_hmac_sha256((const char *)hmac_secret, sizeof(hmac_secret),
                             sign_payload, strlen(sign_payload), computed_hmac);

        if (strcmp(record_hmac, computed_hmac) != 0) {
            tampered_idx = seq;
            break;
        }

        strncpy(expected_prev_hash, record_hmac, sizeof(expected_prev_hash) - 1);
    }
    fclose(f);
    pthread_mutex_unlock(&audit_mutex);

    if (out_total) *out_total = count;
    if (out_tampered_index) *out_tampered_index = tampered_idx;

    return (tampered_idx == -1);
}

/**
 * Returns recent audit log entries formatted as JSON
 */
void audit_log_get_recent_json(char *output, size_t max_len, int limit) {
    pthread_mutex_lock(&audit_mutex);

    FILE *f = fopen(AUDIT_LOG_FILE, "r");
    if (!f) {
        snprintf(output, max_len, "[]");
        pthread_mutex_unlock(&audit_mutex);
        return;
    }

    char lines[200][512];
    int line_count = 0;
    char buf[512];

    while (fgets(buf, sizeof(buf), f)) {
        if (buf[0] == '#' || strlen(buf) < 10) continue;
        buf[strcspn(buf, "\r\n")] = '\0';
        if (line_count < 200) {
            strncpy(lines[line_count++], buf, sizeof(lines[0]) - 1);
        } else {
            /* Ring shift */
            for (int i = 0; i < 199; i++) {
                strcpy(lines[i], lines[i + 1]);
            }
            strncpy(lines[199], buf, sizeof(lines[0]) - 1);
        }
    }
    fclose(f);
    pthread_mutex_unlock(&audit_mutex);

    int start = (line_count > limit) ? (line_count - limit) : 0;
    size_t written = snprintf(output, max_len, "[");

    for (int i = line_count - 1; i >= start; i--) {
        char line_copy[512];
        strncpy(line_copy, lines[i], sizeof(line_copy) - 1);

        char *toks[8];
        char *p = line_copy;
        int t = 0;
        while (t < 8 && p) {
            toks[t++] = p;
            char *next = strchr(p, '|');
            if (next) { *next = '\0'; p = next + 1; }
            else { p = NULL; }
        }
        if (t != 8) continue;

        char item[600];
        snprintf(item, sizeof(item),
                 "%s{\"seq\":%d,\"time\":\"%s\",\"event\":\"%s\",\"severity\":\"%s\",\"actor\":\"%s\",\"details\":\"%s\",\"prev_hash\":\"%s\",\"hmac\":\"%s\"}",
                 (i < line_count - 1) ? "," : "",
                 atoi(toks[0]), toks[1], toks[2], toks[3], toks[4], toks[5], toks[6], toks[7]);

        if (written + strlen(item) < max_len - 4) {
            written += snprintf(output + written, max_len - written, "%s", item);
        } else {
            break;
        }
    }
    strncat(output, "]", max_len - strlen(output) - 1);
}

static void make_otp_key(const char *voter_id, int election_id, char *out_key, size_t max_len) {
    if (!voter_id || !out_key) return;
    if (election_id > 0) {
        snprintf(out_key, max_len, "%s#%d", voter_id, election_id);
    } else {
        snprintf(out_key, max_len, "%s", voter_id);
    }
}

/**
 * Generates random 6-digit OTP, salts and stores SHA-256 hash (never plain in storage).
 * Returns plain OTP solely for simulated SMS dispatch in college demonstration.
 */
int security_generate_voter_election_otp(const char *voter_id, int election_id, char *out_plain_otp) {
    if (!voter_id || strlen(voter_id) == 0) return -1;

    char otp_key[64];
    make_otp_key(voter_id, election_id, otp_key, sizeof(otp_key));

    pthread_mutex_lock(&otp_mutex);

    /* Generate 6-digit numeric OTP */
    unsigned int rand_num = 0;
    if (RAND_bytes((unsigned char *)&rand_num, sizeof(rand_num)) != 1) {
        rand_num = (unsigned int)rand();
    }
    int code = 100000 + (rand_num % 900000);
    char plain_code[8];
    snprintf(plain_code, sizeof(plain_code), "%06d", code);

    /* Generate 16-byte random salt */
    unsigned char salt_bytes[16];
    RAND_bytes(salt_bytes, sizeof(salt_bytes));
    char salt_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(salt_hex + (i * 2), "%02x", salt_bytes[i]);
    }
    salt_hex[32] = '\0';

    /* Compute SHA256(salt + code) */
    char salt_and_code[64];
    snprintf(salt_and_code, sizeof(salt_and_code), "%s%s", salt_hex, plain_code);
    char hash_hex[65];
    security_sha256_string(salt_and_code, hash_hex);

    /* Update or insert record in OTP table */
    int slot = -1;
    for (int i = 0; i < otp_count; i++) {
        if (strcasecmp(otp_table[i].voter_id, otp_key) == 0) {
            slot = i;
            break;
        }
    }
    if (slot == -1) {
        if (otp_count < (int)(sizeof(otp_table) / sizeof(otp_table[0]))) {
            slot = otp_count++;
        } else {
            slot = 0; /* Ring wrap */
        }
    }

    strncpy(otp_table[slot].voter_id, otp_key, sizeof(otp_table[slot].voter_id) - 1);
    strncpy(otp_table[slot].salt, salt_hex, sizeof(otp_table[slot].salt) - 1);
    strncpy(otp_table[slot].hash, hash_hex, sizeof(otp_table[slot].hash) - 1);
    strncpy(otp_table[slot].simulated_otp, plain_code, sizeof(otp_table[slot].simulated_otp) - 1);
    otp_table[slot].created_at = time(NULL);
    otp_table[slot].attempts_left = OTP_MAX_ATTEMPTS;
    otp_table[slot].is_verified = 0;
    otp_table[slot].is_active = 1;

    if (out_plain_otp) {
        strcpy(out_plain_otp, plain_code);
    }

    pthread_mutex_unlock(&otp_mutex);

    if (security_is_dev_mode()) {
        /* In explicitly enabled DEVELOPMENT mode, display generated OTP in server console */
        if (election_id > 0) {
            printf("[DEMO OTP – DEVELOPMENT ONLY] 📱 Simulation for Voter '%s' (Election #%d): OTP is [%s] (Expires in %ds)\n",
                   voter_id, election_id, plain_code, OTP_EXPIRY_SECONDS);
        } else {
            printf("[DEMO OTP – DEVELOPMENT ONLY] 📱 Simulation for Voter '%s': OTP is [%s] (Expires in %ds)\n",
                   voter_id, plain_code, OTP_EXPIRY_SECONDS);
        }
    } else {
        /* In production, never expose OTPs in logs */
        printf("[2FA DISPATCH] SMS/Email dispatched to registered contact for Voter '%s' (Production Mode: OTP withheld)\n",
               voter_id);
    }

    return 0;
}

int security_generate_voter_otp(const char *voter_id, char *out_plain_otp) {
    return security_generate_voter_election_otp(voter_id, 0, out_plain_otp);
}

/**
 * Verifies submitted OTP against salted hash
 */
int security_verify_voter_election_otp(const char *voter_id, int election_id, const char *input_otp) {
    if (!voter_id || !input_otp) return -1;

    char otp_key[64];
    make_otp_key(voter_id, election_id, otp_key, sizeof(otp_key));

    pthread_mutex_lock(&otp_mutex);

    for (int i = 0; i < otp_count; i++) {
        if (otp_table[i].is_active &&
            (strcasecmp(otp_table[i].voter_id, otp_key) == 0 ||
             (election_id > 0 && strcasecmp(otp_table[i].voter_id, voter_id) == 0))) {
            /* Check expiry */
            time_t now = time(NULL);
            if (difftime(now, otp_table[i].created_at) > OTP_EXPIRY_SECONDS) {
                otp_table[i].is_active = 0;
                pthread_mutex_unlock(&otp_mutex);
                return -2; /* Expired */
            }

            /* Check remaining attempts */
            if (otp_table[i].attempts_left <= 0) {
                otp_table[i].is_active = 0;
                pthread_mutex_unlock(&otp_mutex);
                return -3; /* Max attempts exceeded */
            }

            /* Compute SHA256(salt + input_otp) */
            char salt_and_code[64];
            snprintf(salt_and_code, sizeof(salt_and_code), "%s%s", otp_table[i].salt, input_otp);
            char computed_hash[65];
            security_sha256_string(salt_and_code, computed_hash);

            if (strcmp(computed_hash, otp_table[i].hash) == 0) {
                otp_table[i].is_verified = 1;
                pthread_mutex_unlock(&otp_mutex);
                return 0; /* Verified successfully! */
            } else {
                otp_table[i].attempts_left--;
                int left = otp_table[i].attempts_left;
                if (left <= 0) {
                    otp_table[i].is_active = 0;
                }
                pthread_mutex_unlock(&otp_mutex);
                return left; /* Return remaining attempts */
            }
        }
    }

    pthread_mutex_unlock(&otp_mutex);
    return -1; /* No OTP requested */
}

int security_verify_voter_otp(const char *voter_id, const char *input_otp) {
    return security_verify_voter_election_otp(voter_id, 0, input_otp);
}

int security_is_voter_election_otp_verified(const char *voter_id, int election_id) {
    if (!voter_id) return 0;
    char otp_key[64];
    make_otp_key(voter_id, election_id, otp_key, sizeof(otp_key));

    pthread_mutex_lock(&otp_mutex);
    for (int i = 0; i < otp_count; i++) {
        if (otp_table[i].is_active &&
            (strcasecmp(otp_table[i].voter_id, otp_key) == 0 ||
             (election_id > 0 && strcasecmp(otp_table[i].voter_id, voter_id) == 0))) {
            int v = otp_table[i].is_verified;
            pthread_mutex_unlock(&otp_mutex);
            return v;
        }
    }
    pthread_mutex_unlock(&otp_mutex);
    return 0;
}

int security_is_voter_otp_verified(const char *voter_id) {
    return security_is_voter_election_otp_verified(voter_id, 0);
}

void security_clear_voter_election_otp(const char *voter_id, int election_id) {
    if (!voter_id) return;
    char otp_key[64];
    make_otp_key(voter_id, election_id, otp_key, sizeof(otp_key));

    pthread_mutex_lock(&otp_mutex);
    for (int i = 0; i < otp_count; i++) {
        if (strcasecmp(otp_table[i].voter_id, otp_key) == 0 ||
            strcasecmp(otp_table[i].voter_id, voter_id) == 0) {
            otp_table[i].is_active = 0;
            otp_table[i].is_verified = 0;
            break;
        }
    }
    pthread_mutex_unlock(&otp_mutex);
}

void security_clear_voter_otp(const char *voter_id) {
    security_clear_voter_election_otp(voter_id, 0);
}

int security_get_simulated_election_otp(const char *voter_id, int election_id, char *out_otp) {
    if (!voter_id || !out_otp) return 0;
    char otp_key[64];
    make_otp_key(voter_id, election_id, otp_key, sizeof(otp_key));

    pthread_mutex_lock(&otp_mutex);
    for (int i = 0; i < otp_count; i++) {
        if (otp_table[i].is_active &&
            (strcasecmp(otp_table[i].voter_id, otp_key) == 0 ||
             (election_id > 0 && strcasecmp(otp_table[i].voter_id, voter_id) == 0))) {
            strcpy(out_otp, otp_table[i].simulated_otp);
            pthread_mutex_unlock(&otp_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&otp_mutex);
    return 0;
}

int security_get_simulated_otp(const char *voter_id, char *out_otp) {
    if (!voter_id || !out_otp) return 0;
    pthread_mutex_lock(&otp_mutex);
    for (int i = 0; i < otp_count; i++) {
        if (otp_table[i].is_active && strcasecmp(otp_table[i].voter_id, voter_id) == 0) {
            strncpy(out_otp, otp_table[i].simulated_otp, 7);
            out_otp[7] = '\0';
            pthread_mutex_unlock(&otp_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&otp_mutex);
    return 0;
}

/**
 * Validates IP address syntax (IPv4, IPv6, localhost, or subnet prefix)
 */
static int is_valid_ip_address(const char *ip) {
    if (!ip || *ip == '\0') return 0;
    if (strcmp(ip, "localhost") == 0) return 1;

    struct in_addr a4;
    if (inet_pton(AF_INET, ip, &a4) == 1) return 1;

    struct in6_addr a6;
    if (inet_pton(AF_INET6, ip, &a6) == 1) return 1;

    /* Check for subnet prefix e.g. "192.168.1." */
    size_t len = strlen(ip);
    if (len > 1 && ip[len - 1] == '.') {
        char test_ip[64];
        snprintf(test_ip, sizeof(test_ip), "%s1", ip);
        if (inet_pton(AF_INET, test_ip, &a4) == 1) return 1;
    }

    return 0;
}

/**
 * Loads administrative IP allowlist from disk
 */
void security_load_ip_allowlist(void) {
    pthread_mutex_lock(&sec_mutex);
    ip_allowlist_count = 0;

    FILE *f = fopen(IP_ALLOWLIST_FILE, "r");
    if (!f) {
        /* Default allowlist */
        strncpy(ip_allowlist[0], "127.0.0.1", 45);
        strncpy(ip_allowlist[1], "::1", 45);
        strncpy(ip_allowlist[2], "localhost", 45);
        ip_allowlist_count = 3;

        f = fopen(IP_ALLOWLIST_FILE, "w");
        if (f) {
            fprintf(f, "# AAYOG_CHUNAV Administrative IP Allowlist\n");
            fprintf(f, "# Only listed IPs can access administrative dashboards and APIs\n");
            fprintf(f, "127.0.0.1\n::1\nlocalhost\n");
            fclose(f);
        }
        pthread_mutex_unlock(&sec_mutex);
        return;
    }

    char line[64];
    while (fgets(line, sizeof(line), f) && ip_allowlist_count < MAX_IP_ALLOWLIST) {
        char *start = line;
        while (*start && isspace((unsigned char)*start)) start++;
        if (*start == '#' || *start == '\0') continue;
        char *end = start + strlen(start) - 1;
        while (end > start && isspace((unsigned char)*end)) *end-- = '\0';

        strncpy(ip_allowlist[ip_allowlist_count], start, 45);
        ip_allowlist[ip_allowlist_count][45] = '\0';
        ip_allowlist_count++;
    }
    fclose(f);
    pthread_mutex_unlock(&sec_mutex);
}

/**
 * Checks whether an incoming client IP is authorized for administrative endpoints
 */
int security_is_ip_allowed_admin(const char *ip_addr) {
    if (!ip_addr) return 0;

    /* Normalize IPv4-mapped IPv6 address (::ffff:127.0.0.1 -> 127.0.0.1) */
    const char *norm_ip = ip_addr;
    if (strncmp(norm_ip, "::ffff:", 7) == 0) {
        norm_ip += 7;
    }

    pthread_mutex_lock(&sec_mutex);
    if (ip_allowlist_count == 0) {
        pthread_mutex_unlock(&sec_mutex);
        security_load_ip_allowlist();
        pthread_mutex_lock(&sec_mutex);
    }

    for (int i = 0; i < ip_allowlist_count; i++) {
        const char *allowed = ip_allowlist[i];

        /* Exact string match */
        if (strcmp(allowed, norm_ip) == 0) {
            pthread_mutex_unlock(&sec_mutex);
            return 1;
        }

        /* Localhost alias resolution: localhost == 127.0.0.1 or ::1 */
        if (strcmp(allowed, "localhost") == 0) {
            if (strcmp(norm_ip, "127.0.0.1") == 0 || strcmp(norm_ip, "::1") == 0) {
                pthread_mutex_unlock(&sec_mutex);
                return 1;
            }
        }
        if (strcmp(norm_ip, "localhost") == 0) {
            if (strcmp(allowed, "127.0.0.1") == 0 || strcmp(allowed, "::1") == 0) {
                pthread_mutex_unlock(&sec_mutex);
                return 1;
            }
        }

        /* Check prefix match (e.g., 192.168.1.) */
        size_t len = strlen(allowed);
        if (len > 0 && allowed[len - 1] == '.' && strncmp(allowed, norm_ip, len) == 0) {
            pthread_mutex_unlock(&sec_mutex);
            return 1;
        }
    }

    pthread_mutex_unlock(&sec_mutex);
    return 0;
}

/**
 * Adds an IP address to the administrative allowlist with format validation and duplicate rejection
 * Return codes:
 *   1 : Added successfully
 *   0 : Duplicate (IP already present in allowlist)
 *  -1 : Invalid IP address format
 *  -2 : Allowlist capacity reached (MAX_IP_ALLOWLIST)
 */
int security_add_ip_allowlist(const char *raw_ip) {
    if (!raw_ip) return -1;

    /* Trim whitespace */
    char clean_ip[64] = {0};
    const char *start = raw_ip;
    while (*start && isspace((unsigned char)*start)) start++;
    if (*start == '\0') return -1;

    strncpy(clean_ip, start, sizeof(clean_ip) - 1);
    char *end = clean_ip + strlen(clean_ip) - 1;
    while (end > clean_ip && isspace((unsigned char)*end)) *end-- = '\0';

    /* Validate format */
    if (!is_valid_ip_address(clean_ip)) {
        return -1;
    }

    /* Normalize IPv4-mapped IPv6 */
    const char *norm_ip = clean_ip;
    if (strncmp(norm_ip, "::ffff:", 7) == 0) {
        norm_ip += 7;
    }

    pthread_mutex_lock(&sec_mutex);
    if (ip_allowlist_count == 0) {
        pthread_mutex_unlock(&sec_mutex);
        security_load_ip_allowlist();
        pthread_mutex_lock(&sec_mutex);
    }

    /* Check for duplicates */
    for (int i = 0; i < ip_allowlist_count; i++) {
        if (strcmp(ip_allowlist[i], norm_ip) == 0) {
            pthread_mutex_unlock(&sec_mutex);
            return 0; /* Duplicate */
        }
        /* Check localhost alias duplicate */
        if ((strcmp(norm_ip, "127.0.0.1") == 0 || strcmp(norm_ip, "::1") == 0) &&
            strcmp(ip_allowlist[i], norm_ip) == 0) {
            pthread_mutex_unlock(&sec_mutex);
            return 0; /* Duplicate */
        }
    }

    if (ip_allowlist_count < MAX_IP_ALLOWLIST) {
        strncpy(ip_allowlist[ip_allowlist_count++], norm_ip, 45);
        ip_allowlist[ip_allowlist_count - 1][45] = '\0';

        FILE *f = fopen(IP_ALLOWLIST_FILE, "a");
        if (f) {
            fprintf(f, "%s\n", norm_ip);
            fclose(f);
        }
        pthread_mutex_unlock(&sec_mutex);

        char audit_msg[128];
        snprintf(audit_msg, sizeof(audit_msg), "Added allowed admin IP: %s", norm_ip);
        audit_log_record("CONFIG_IP_ALLOWLIST_ADD", "LOW", "ADMIN", audit_msg);

        return 1;
    }

    pthread_mutex_unlock(&sec_mutex);
    return -2;
}

void security_get_ip_allowlist_json(char *output, size_t max_len) {
    pthread_mutex_lock(&sec_mutex);
    size_t w = snprintf(output, max_len, "[");
    for (int i = 0; i < ip_allowlist_count; i++) {
        char item[64];
        snprintf(item, sizeof(item), "%s\"%s\"", (i > 0) ? "," : "", ip_allowlist[i]);
        if (w + strlen(item) < max_len - 4) {
            w += snprintf(output + w, max_len - w, "%s", item);
        }
    }
    strncat(output, "]", max_len - strlen(output) - 1);
    pthread_mutex_unlock(&sec_mutex);
}

/**
 * Sliding window rate limiting: max 60 req/min per IP
 */
int security_check_rate_limit(const char *ip_addr) {
    if (!ip_addr) return 1;
    if (security_is_dev_mode()) return 1; /* In development mode, do not throttle developer testing */

    pthread_mutex_lock(&sec_mutex);
    time_t now = time(NULL);

    int idx = -1;
    for (int i = 0; i < tracker_count; i++) {
        if (strcmp(ip_trackers[i].ip, ip_addr) == 0) {
            idx = i;
            break;
        }
    }

    if (idx == -1) {
        if (tracker_count < MAX_IP_TRACKERS) {
            idx = tracker_count++;
        } else {
            idx = 0; /* Wrap */
        }
        strncpy(ip_trackers[idx].ip, ip_addr, sizeof(ip_trackers[idx].ip) - 1);
        ip_trackers[idx].request_count = 1;
        ip_trackers[idx].window_start = now;
        ip_trackers[idx].blocked_until = 0;
        pthread_mutex_unlock(&sec_mutex);
        return 1;
    }

    /* Check if temporarily blocked */
    if (ip_trackers[idx].blocked_until > now) {
        pthread_mutex_unlock(&sec_mutex);
        return 0; /* Blocked */
    }

    /* Reset window if expired */
    if (difftime(now, ip_trackers[idx].window_start) >= RATE_LIMIT_WINDOW_SEC) {
        ip_trackers[idx].window_start = now;
        ip_trackers[idx].request_count = 1;
        pthread_mutex_unlock(&sec_mutex);
        return 1;
    }

    ip_trackers[idx].request_count++;
    if (ip_trackers[idx].request_count > RATE_LIMIT_MAX_REQUESTS) {
        ip_trackers[idx].blocked_until = now + 30; /* 30-second cooldown */
        pthread_mutex_unlock(&sec_mutex);

        security_record_alert("RATE_LIMIT_EXCEEDED", "MEDIUM", ip_addr,
                              "Exceeded 60 requests/minute threshold; 30s cooldown enforced.");
        return 0;
    }

    pthread_mutex_unlock(&sec_mutex);
    return 1;
}

/**
 * Records an intrusion detection alert in memory and audit log
 */
void security_record_alert(const char *alert_type, const char *severity, const char *ip_addr, const char *details) {
    pthread_mutex_lock(&sec_mutex);

    int slot = (alert_count < MAX_SECURITY_ALERTS) ? alert_count++ : (alert_id_seq % MAX_SECURITY_ALERTS);

    snprintf(alerts[slot].id, sizeof(alerts[slot].id), "ALT-%04d", alert_id_seq++);
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(alerts[slot].timestamp, sizeof(alerts[slot].timestamp), "%Y-%m-%d %H:%M:%S", t);
    strncpy(alerts[slot].alert_type, alert_type, sizeof(alerts[slot].alert_type) - 1);
    strncpy(alerts[slot].ip_address, ip_addr ? ip_addr : "UNKNOWN", sizeof(alerts[slot].ip_address) - 1);
    strncpy(alerts[slot].details, details ? details : "", sizeof(alerts[slot].details) - 1);
    strncpy(alerts[slot].severity, severity, sizeof(alerts[slot].severity) - 1);

    pthread_mutex_unlock(&sec_mutex);

    /* Also persist into tamper-evident audit log */
    audit_log_record(alert_type, severity, ip_addr ? ip_addr : "SYSTEM", details ? details : "");
}

void security_record_failed_auth(const char *ip_addr, const char *id) {
    char det[128];
    snprintf(det, sizeof(det), "Failed authentication attempt for Voter ID/User: '%s'", id ? id : "unknown");
    security_record_alert("FAILED_AUTH_ATTEMPT", "HIGH", ip_addr, det);
}

void security_record_duplicate_vote(const char *ip_addr, const char *id) {
    char det[128];
    snprintf(det, sizeof(det), "Duplicate vote attempt blocked for Voter ID: '%s'", id ? id : "unknown");
    security_record_alert("DUPLICATE_VOTE_ATTEMPT", "HIGH", ip_addr, det);
}

void security_record_unauthorized_admin(const char *ip_addr, const char *path) {
    char det[128];
    snprintf(det, sizeof(det), "Unauthorized attempt to access admin resource: '%s'", path ? path : "/admin");
    security_record_alert("UNAUTHORIZED_ADMIN_ACCESS", "CRITICAL", ip_addr, det);
}

void security_record_malformed_request(const char *ip_addr, const char *info) {
    char det[128];
    snprintf(det, sizeof(det), "Malformed or suspicious request syntax: '%s'", info ? info : "");
    security_record_alert("MALFORMED_REQUEST", "LOW", ip_addr, det);
}

void security_get_alerts_json(char *output, size_t max_len) {
    pthread_mutex_lock(&sec_mutex);

    size_t w = snprintf(output, max_len, "[");
    for (int i = alert_count - 1; i >= 0; i--) {
        char item[350];
        snprintf(item, sizeof(item),
                 "%s{\"id\":\"%s\",\"timestamp\":\"%s\",\"type\":\"%s\",\"severity\":\"%s\",\"ip\":\"%s\",\"details\":\"%s\"}",
                 (i < alert_count - 1) ? "," : "",
                 alerts[i].id, alerts[i].timestamp, alerts[i].alert_type,
                 alerts[i].severity, alerts[i].ip_address, alerts[i].details);
        if (w + strlen(item) < max_len - 4) {
            w += snprintf(output + w, max_len - w, "%s", item);
        } else {
            break;
        }
    }
    strncat(output, "]", max_len - strlen(output) - 1);
    pthread_mutex_unlock(&sec_mutex);
}

/**
 * Creates / updates baseline SHA-256 manifest of election files
 */
int security_save_baseline_manifest(void) {
    const char *files[] = {
        "data/voters.txt",
        "data/ballots.txt",
        "data/booths.txt",
        "data/election.txt",
        "certs/server.crt",
        NULL
    };

    FILE *mf = fopen(MANIFEST_FILE, "w");
    if (!mf) return -1;

    fprintf(mf, "# AAYOG_CHUNAV 2.0 SHA-256 Baseline Integrity Manifest\n");

    for (int i = 0; files[i] != NULL; i++) {
        if (access(files[i], F_OK) == 0) {
            char hash[65] = {0};
            if (security_file_sha256(files[i], hash) == 0) {
                fprintf(mf, "%s|%s\n", files[i], hash);
            }
        }
    }
    fclose(mf);
    chmod(MANIFEST_FILE, 0640);
    return 0;
}

/**
 * Verifies system file hashes against baseline manifest to detect out-of-band file tampering
 */
int security_verify_file_integrity(char *out_report, size_t max_len) {
    FILE *mf = fopen(MANIFEST_FILE, "r");
    if (!mf) {
        /* If no manifest yet, generate baseline */
        security_save_baseline_manifest();
        snprintf(out_report, max_len, "{\"status\":\"BASELINE_CREATED\",\"message\":\"Initial cryptographic baseline generated.\",\"files\":[]}");
        return 1;
    }

    char line[256];
    int all_ok = 1;
    char files_json[2048] = {0};
    int file_cnt = 0;

    while (fgets(line, sizeof(line), mf)) {
        if (line[0] == '#' || strlen(line) < 10) continue;
        char filepath[128] = {0};
        char expected_hash[65] = {0};
        char *pipe = strchr(line, '|');
        if (!pipe) continue;

        *pipe = '\0';
        strncpy(filepath, line, sizeof(filepath) - 1);
        sscanf(pipe + 1, "%64s", expected_hash);

        char actual_hash[65] = {0};
        int file_exists = (security_file_sha256(filepath, actual_hash) == 0);
        int match = (file_exists && strcmp(expected_hash, actual_hash) == 0);

        if (!match) all_ok = 0;

        char item[512];
        snprintf(item, sizeof(item),
                 "%s{\"path\":\"%s\",\"expected\":\"%s\",\"actual\":\"%s\",\"match\":%s}",
                 (file_cnt++ > 0) ? "," : "",
                 filepath, expected_hash, file_exists ? actual_hash : "FILE_MISSING",
                 match ? "true" : "false");
        strncat(files_json, item, sizeof(files_json) - strlen(files_json) - 1);
    }
    fclose(mf);

    snprintf(out_report, max_len,
             "{\"status\":\"%s\",\"intact\":%s,\"files\":[%s]}",
             all_ok ? "VERIFIED" : "TAMPER_DETECTED",
             all_ok ? "true" : "false",
             files_json);

    if (!all_ok) {
        security_record_alert("FILE_INTEGRITY_VIOLATION", "CRITICAL", "LOCAL_FS",
                              "One or more critical election files failed cryptographic SHA-256 verification!");
    }

    return all_ok;
}
