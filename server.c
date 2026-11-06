/**
 * ============================================================================
 * Title:       AAYOG_CHUNAV 3.0 - Secure Multi-Election Management & Voting System
 * File:        server.c
 * Description: Multi-threaded server using POSIX TCP sockets, Pthreads, OpenSSL
 *              TLS 1.2/1.3, and optional mTLS authentication.
 *              Serves:
 *                1. HTTPS/HTTP Web Frontend (Multi-Election Voter & Admin Dashboards)
 *                2. TLS/TCP Terminal CLI Voting Clients (client.c)
 *              Enforces Multi-Election Isolation, Role-Based Access Control,
 *              Ballot Secrecy, IP Allowlists, Two-Factor Authentication, Rate
 *              Limiting, and SHA-256 Audit Integrity.
 * Compatibility: macOS and Linux (POSIX compliant)
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "election.h"
#include "security.h"
#include "admin.h"
#include "http.h"

#define DEFAULT_PORT 8080
#define BUFFER_SIZE 16384
#define HTTP_REQ_BUFFER_SIZE (2 * 1024 * 1024)
#define SERVER_CERT "certs/server.crt"
#define SERVER_KEY  "certs/server.key"
#define CA_CERT     "certs/ca.crt"

static int server_socket = -1;
static SSL_CTX *server_ssl_ctx = NULL;

/* Client worker argument */
typedef struct {
    int socket_fd;
    char client_ip[46];
} ClientContext;

/* Forward declarations */
void *handle_client_worker(void *arg);
void handle_cli_command(Connection *conn, const char *cmd);
void sigint_handler(int sig);

/**
 * Worker thread handling a single client connection (HTTP, HTTPS, or raw TCP CLI)
 */
void *handle_client_worker(void *arg) {
    ClientContext *ctx = (ClientContext *)arg;
    int client_sock = ctx->socket_fd;
    char client_ip[46];
    strncpy(client_ip, ctx->client_ip, sizeof(client_ip) - 1);
    client_ip[sizeof(client_ip) - 1] = '\0';
    free(ctx);

    Connection conn;
    memset(&conn, 0, sizeof(conn));
    conn.socket_fd = client_sock;
    strncpy(conn.client_ip, client_ip, sizeof(conn.client_ip) - 1);

    /* Set socket receive timeout so inactive connections do not tie up threads */
    /* Enable SO_LINGER so socket close waits for pending data acknowledgment and performs graceful FIN-ACK */
    struct linger sl = { .l_onoff = 1, .l_linger = 3 };
    setsockopt(client_sock, SOL_SOCKET, SO_LINGER, (const char *)&sl, sizeof(sl));

    struct timeval tv;
    tv.tv_sec = 30; /* 30-second keep-alive timeout for persistent browser & CLI connections */
    tv.tv_usec = 0;
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    /* 1. Peek the first byte to detect TLS vs Plain Text connection */
    unsigned char peek_byte = 0;
    ssize_t peek_len = recv(client_sock, &peek_byte, 1, MSG_PEEK);

    if (peek_len > 0 && peek_byte == 0x16 && server_ssl_ctx) {
        /* TLS Handshake Record (ClientHello starts with 0x16) */
        conn.is_tls = 1;
        conn.ssl = SSL_new(server_ssl_ctx);
        if (!conn.ssl) {
            close(client_sock);
            return NULL;
        }

        SSL_set_fd(conn.ssl, client_sock);

        int accept_res = SSL_accept(conn.ssl);
        if (accept_res <= 0) {
            /* TLS Handshake failed (e.g. browser probe, certificate rejection) */
            SSL_free(conn.ssl);
            close(client_sock);
            return NULL;
        }

        /* Check for Mutual TLS (mTLS) client certificate */
        if (security_verify_admin_cert(conn.ssl, conn.client_cn, sizeof(conn.client_cn))) {
            conn.is_mtls_admin = 1;
            printf("[mTLS AUTH] Administrative client certificate verified for '%s' (IP: %s)\n",
                   conn.client_cn, conn.client_ip);
        }
    } else {
        /* Plain TCP connection (Standard HTTP or legacy plain CLI) */
        conn.is_tls = 0;
        conn.ssl = NULL;
    }

    char *buffer = malloc(HTTP_REQ_BUFFER_SIZE);
    if (!buffer) {
        if (conn.ssl) { SSL_shutdown(conn.ssl); SSL_free(conn.ssl); }
        close(client_sock);
        return NULL;
    }

    /* Connection read loop */
    while (1) {
        memset(buffer, 0, HTTP_REQ_BUFFER_SIZE);
        ssize_t bytes = http_read_full_request(&conn, buffer, HTTP_REQ_BUFFER_SIZE - 1);

        if (bytes <= 0) {
            break; /* Client closed connection or timeout */
        }
        buffer[bytes] = '\0';

        /* Case 1: HTTP/1.1 Request (Browser Dashboard or REST API) */
        if (strncmp(buffer, "GET ", 4) == 0 ||
            strncmp(buffer, "POST ", 5) == 0 ||
            strncmp(buffer, "HEAD ", 5) == 0 ||
            strncmp(buffer, "OPTIONS ", 8) == 0 ||
            strncmp(buffer, "PUT ", 4) == 0 ||
            strncmp(buffer, "DELETE ", 7) == 0) {
            http_handle_request(&conn, buffer, (size_t)bytes);
            if (conn.should_close) {
                break;
            }
            continue; /* Keep HTTP connection open for subsequent requests */
        }

        /* Case 2: Custom TCP CLI Command Protocol (client.c) */
        handle_cli_command(&conn, buffer);
    }

    /* Teardown session cleanly */
    if (conn.is_tls && conn.ssl) {
        SSL_shutdown(conn.ssl);
        SSL_free(conn.ssl);
        conn.ssl = NULL;
    }
    close(client_sock);
    free(buffer);
    return NULL;
}

/**
 * Handles raw TCP CLI commands for client.c (Both over TLS and plain TCP)
 */
void handle_cli_command(Connection *conn, const char *raw_cmd) {
    char cmd[BUFFER_SIZE];
    strncpy(cmd, raw_cmd, sizeof(cmd) - 1);
    cmd[sizeof(cmd) - 1] = '\0';

    /* Trim whitespace */
    char *p = cmd;
    while (*p && isspace((unsigned char)*p)) p++;
    int len = (int)strlen(p);
    while (len > 0 && isspace((unsigned char)p[len - 1])) {
        p[len - 1] = '\0';
        len--;
    }
    if (len == 0) return;

    char response[BUFFER_SIZE] = {0};

    int election_id = conn->selected_election_id;
    if (election_id <= 0) {
        election_id = election_get_active_id();
        if (election_id <= 0) election_id = 1;
    }

    /* Command: ELECTIONS */
    if (strcmp(p, "ELECTIONS") == 0) {
        snprintf(response, sizeof(response), "ELECTIONS_START\n");
        ElectionSummary sums[MAX_ELECTIONS];
        int count = election_get_all_summaries(sums, MAX_ELECTIONS);
        for (int i = 0; i < count; i++) {
            char item[256];
            snprintf(item, sizeof(item), "%d. %s [%s] - Status: %s%s\n",
                     sums[i].id, sums[i].title, sums[i].type,
                     sums[i].state_str,
                     (sums[i].id == election_id) ? " (SELECTED)" : "");
            strncat(response, item, sizeof(response) - strlen(response) - 1);
        }
        strncat(response, "ELECTIONS_END\n", sizeof(response) - strlen(response) - 1);
    }
    /* Command: SELECT_ELECTION <id> */
    else if (strncmp(p, "SELECT_ELECTION ", 16) == 0) {
        int target_id = atoi(p + 16);
        ElectionSummary el;
        if (election_get_summary(target_id, &el) == 0) {
            conn->selected_election_id = target_id;
            snprintf(response, sizeof(response), "ELECTION_SELECTED %d %s\n", el.id, el.title);
        } else {
            snprintf(response, sizeof(response), "ERR_INVALID_ELECTION Election ID %d not found.\n", target_id);
        }
    }
    /* Command 1: CHECK_ID <voter_id> */
    else if (strncmp(p, "CHECK_ID ", 9) == 0) {
        char vid[ID_LEN] = {0};
        strncpy(vid, p + 9, ID_LEN - 1);
        while (strlen(vid) > 0 && isspace((unsigned char)vid[strlen(vid) - 1])) {
            vid[strlen(vid) - 1] = '\0';
        }

        Voter v;
        int status = election_check_voter_status(election_id, vid, &v);
        if (status == 0) {
            snprintf(response, sizeof(response), "STATUS_ELIGIBLE Booth: %d\n", v.booth_id);
        } else if (status == 1) {
            snprintf(response, sizeof(response), "STATUS_VOTED\n");
        } else {
            snprintf(response, sizeof(response), "STATUS_NOT_FOUND\n");
        }
    }
    /* Command 2: REQUEST_OTP <voter_id> */
    else if (strncmp(p, "REQUEST_OTP ", 12) == 0) {
        char vid[ID_LEN] = {0};
        strncpy(vid, p + 12, ID_LEN - 1);
        while (strlen(vid) > 0 && isspace((unsigned char)vid[strlen(vid) - 1])) {
            vid[strlen(vid) - 1] = '\0';
        }

        Voter v;
        int status = election_check_voter_status(election_id, vid, &v);
        if (status == 0) {
            char plain_otp[8];
            security_generate_voter_election_otp(vid, election_id, plain_otp);
            if (security_is_dev_mode()) {
                snprintf(response, sizeof(response), "OTP_DISPATCHED %s\n", plain_otp);
            } else {
                snprintf(response, sizeof(response), "OTP_DISPATCHED\n");
            }
        } else {
            snprintf(response, sizeof(response), "ERR_NOT_ELIGIBLE\n");
        }
    }
    /* Command 3: VERIFY_OTP <voter_id> <otp> */
    else if (strncmp(p, "VERIFY_OTP ", 11) == 0) {
        char vid[ID_LEN] = {0};
        char otp[16] = {0};
        if (sscanf(p + 11, "%31s %15s", vid, otp) == 2) {
            int res = security_verify_voter_election_otp(vid, election_id, otp);
            if (res == 0) {
                snprintf(response, sizeof(response), "OTP_VERIFIED\n");
            } else {
                snprintf(response, sizeof(response), "ERR_INVALID_OTP\n");
            }
        } else {
            snprintf(response, sizeof(response), "ERR_MALFORMED\n");
        }
    }
    /* Command 4: CANDIDATES */
    else if (strcmp(p, "CANDIDATES") == 0) {
        snprintf(response, sizeof(response), "CANDIDATES_START\n");
        int count = election_get_candidate_count(election_id);
        for (int i = 0; i < count; i++) {
            Candidate c;
            if (election_get_candidate_by_index(election_id, i, &c) == 0) {
                char item[128];
                snprintf(item, sizeof(item), "%d. %s (%s)\n", c.id, c.name, c.party);
                strncat(response, item, sizeof(response) - strlen(response) - 1);
            }
        }
        strncat(response, "CANDIDATES_END\n", sizeof(response) - strlen(response) - 1);
    }
    /* Command 5: VOTE <voter_id> <candidate_id> [otp] */
    else if (strncmp(p, "VOTE ", 5) == 0) {
        char vid[ID_LEN] = {0};
        int cand_id = 0;
        char otp[16] = {0};
        int args = sscanf(p + 5, "%31s %d %15s", vid, &cand_id, otp);

        if (args >= 2) {
            ElectionSummary el;
            int require_otp = 1;
            if (election_get_summary(election_id, &el) == 0) {
                require_otp = el.require_otp;
            }

            if (require_otp) {
                if (args >= 3 && strlen(otp) > 0) {
                    security_verify_voter_election_otp(vid, election_id, otp);
                }
                if (!security_is_voter_election_otp_verified(vid, election_id)) {
                    snprintf(response, sizeof(response), "ERR_OTP_REQUIRED 2FA verification required.\n");
                    conn_write(conn, response, strlen(response));
                    return;
                }
            }

            char token[TOKEN_LEN] = {0};
            char cand_name[NAME_LEN] = {0};
            int res = election_cast_ballot(election_id, vid, cand_id, 0, token, cand_name);

            if (res == 0) {
                security_clear_voter_election_otp(vid, election_id);
                snprintf(response, sizeof(response),
                         "SUCCESS Ballot accepted for %s! [Receipt: %s]\n", cand_name, token);
                /* BALLOT SECRECY: Never log voter ID with candidate choice! */
                printf("[BALLOT ACCEPTED] Anonymous ballot recorded for Election #%d. Receipt token: %s\n",
                       election_id, token);
            } else if (res == -1) {
                snprintf(response, sizeof(response), "ERR_INVALID_ID Voter ID '%s' is not registered.\n", vid);
            } else if (res == -2) {
                snprintf(response, sizeof(response), "ERR_ALREADY_VOTED Duplicate vote blocked for '%s'.\n", vid);
                security_record_duplicate_vote(conn->client_ip, vid);
            } else if (res == -10) {
                snprintf(response, sizeof(response), "ERR_INACTIVE Election is currently not active for voting.\n");
            } else {
                snprintf(response, sizeof(response), "ERR_INVALID_CANDIDATE Invalid candidate selection.\n");
            }
        } else {
            snprintf(response, sizeof(response), "ERR_MALFORMED Invalid VOTE syntax.\n");
        }
    }
    /* Command: VERIFY_RECEIPT <token> */
    else if (strncmp(p, "VERIFY_RECEIPT ", 15) == 0) {
        char token[TOKEN_LEN] = {0};
        strncpy(token, p + 15, sizeof(token) - 1);
        while (strlen(token) > 0 && isspace((unsigned char)token[strlen(token) - 1])) {
            token[strlen(token) - 1] = '\0';
        }

        int b_id = 0;
        char b_time[64] = {0};
        char b_title[128] = {0};
        if (election_verify_receipt(election_id, token, &b_id, b_time, b_title) == 0) {
            snprintf(response, sizeof(response),
                     "RECEIPT_VERIFIED Token: %s Status: RECORDED_IN_BALLOT_BOX Booth: %d Time: %s Election: %s\n",
                     token, b_id, b_time, b_title);
        } else {
            snprintf(response, sizeof(response), "RECEIPT_NOT_FOUND Token '%s' not found.\n", token);
        }
    }
    /* Command 6: RESULTS */
    else if (strcmp(p, "RESULTS") == 0) {
        char results_table[BUFFER_SIZE - 64];
        election_generate_results_text(election_id, results_table, sizeof(results_table));
        snprintf(response, sizeof(response), "RESULTS_START%sRESULTS_END\n", results_table);
    }
    /* Command 7: BOOTHS */
    else if (strcmp(p, "BOOTHS") == 0) {
        snprintf(response, sizeof(response), "BOOTHS_START\n");
        int count = election_get_booth_count(election_id);
        for (int i = 0; i < count; i++) {
            PollingBooth pb;
            if (election_get_booth_by_index(election_id, i, &pb) == 0) {
                char item[128];
                snprintf(item, sizeof(item), "%d. %s [%s] - Registered: %d, Cast: %d\n",
                         pb.id, pb.name, pb.location, pb.total_registered, pb.votes_cast);
                strncat(response, item, sizeof(response) - strlen(response) - 1);
            }
        }
        strncat(response, "BOOTHS_END\n", sizeof(response) - strlen(response) - 1);
    }
    /* Command 8: EXIT */
    else if (strcmp(p, "EXIT") == 0) {
        snprintf(response, sizeof(response), "GOODBYE\n");
        conn_write(conn, response, strlen(response));
        return;
    } else {
        snprintf(response, sizeof(response), "ERR_UNKNOWN_COMMAND Unrecognized request.\n");
    }

    conn_write(conn, response, strlen(response));
}

/**
 * Signal handler for graceful shutdown
 */
void sigint_handler(int sig) {
    (void)sig;
    printf("\n[SHUTDOWN] Intercepted termination signal. Closing AAYOG_CHUNAV 2.0 server...\n");

    if (server_socket != -1) {
        close(server_socket);
        server_socket = -1;
    }
    if (server_ssl_ctx) {
        SSL_CTX_free(server_ssl_ctx);
        server_ssl_ctx = NULL;
    }

    audit_log_record("SYSTEM_SHUTDOWN", "LOW", "KERNEL", "Server shutdown gracefully");
    security_save_baseline_manifest();

    printf("[SHUTDOWN] Server shutdown complete. Goodbye!\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    int port = DEFAULT_PORT;
    int dev_flag = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dev") == 0 || strcmp(argv[i], "-dev") == 0 ||
            strcasecmp(argv[i], "development") == 0 || strcasecmp(argv[i], "dev") == 0) {
            dev_flag = 1;
        } else {
            int p = atoi(argv[i]);
            if (p > 1024 && p <= 65535) {
                port = p;
            }
        }
    }

    if (dev_flag) {
        security_set_dev_mode(1);
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    signal(SIGPIPE, SIG_IGN);

    printf("=================================================================\n");
    printf("   AAYOG_CHUNAV 3.0 - SECURE MULTI-ELECTION PLATFORM & VOTING    \n");
    printf("   Dual-Protocol Engine: OpenSSL TLS 1.2/1.3 + POSIX TCP Sockets \n");
    printf("=================================================================\n");
    if (security_is_dev_mode()) {
        printf("[MODE]      DEVELOPMENT MODE EXPLICITLY ENABLED\n");
        printf("[DEMO OTP]  Generated OTPs will be displayed in console & browser for testing.\n");
    } else {
        printf("[MODE]      PRODUCTION MODE (Secure OTP delivery; OTPs hidden from logs & API)\n");
    }

    /* 1. Initialize Subsystems */
    election_init();
    admin_init();
    security_load_ip_allowlist();

    /* 2. Initialize OpenSSL Server Context */
    server_ssl_ctx = security_init_server_ssl_ctx(SERVER_CERT, SERVER_KEY, CA_CERT);
    if (!server_ssl_ctx) {
        fprintf(stderr, "[WARN] Could not initialize TLS context from '%s'. Falling back to plain TCP.\n", SERVER_CERT);
    } else {
        printf("[SECURITY] TLS 1.2/1.3 encryption enabled with certificate '%s'.\n", SERVER_CERT);
    }

    /* 3. Create Master Listening Socket (Dual-Stack IPv6 and IPv4) */
    int is_v6 = 1;
    server_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_socket < 0) {
        /* Fall back to IPv4-only if system has IPv6 disabled */
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        is_v6 = 0;
        if (server_socket < 0) {
            perror("[FATAL] socket() creation failed");
            exit(EXIT_FAILURE);
        }
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[WARN] setsockopt(SO_REUSEADDR) failed");
    }

    if (is_v6) {
        /* Disable IPV6_V6ONLY so IPv4-mapped connections (::ffff:127.0.0.1) can bind to the same port */
        int no = 0;
        setsockopt(server_socket, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));

        struct sockaddr_in6 server_addr6;
        memset(&server_addr6, 0, sizeof(server_addr6));
        server_addr6.sin6_family = AF_INET6;
        server_addr6.sin6_addr = in6addr_any;
        server_addr6.sin6_port = htons(port);

        if (bind(server_socket, (struct sockaddr *)&server_addr6, sizeof(server_addr6)) < 0) {
            perror("[WARN] Dual-stack bind(AF_INET6) failed, falling back to AF_INET");
            close(server_socket);
            server_socket = socket(AF_INET, SOCK_STREAM, 0);
            is_v6 = 0;
            if (server_socket < 0) {
                perror("[FATAL] fallback socket() failed");
                exit(EXIT_FAILURE);
            }
            setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        }
    }

    if (!is_v6) {
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("[FATAL] bind() failed");
            close(server_socket);
            exit(EXIT_FAILURE);
        }
    }

    if (listen(server_socket, 32) < 0) {
        perror("[FATAL] listen() failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("[READY] Server active on port %d (%s)\n", port, is_v6 ? "Dual-Stack IPv6/IPv4" : "IPv4");
    printf("[HTTPS WEB] Voter Dashboard:       https://localhost:%d\n", port);
    printf("[ADMIN UI]  Administrator Portal:   https://localhost:%d/admin.html\n", port);
    printf("[HTTP WEB]  Plain HTTP Fallback:    http://localhost:%d\n", port);
    printf("[TLS CLI]   Terminal Voting Client: ./client 127.0.0.1 %d\n", port);
    printf("[INFO] Press Ctrl+C at any time to shut down the server.\n");
    printf("-----------------------------------------------------------------\n");

    /* Initialize thread attribute with 4MB stack to prevent stack exhaustion */
    pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setstacksize(&thread_attr, 4 * 1024 * 1024);

    /* 4. Accept Loop */
    while (1) {
        struct sockaddr_storage client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_sock = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            continue;
        }

        ClientContext *ctx = malloc(sizeof(ClientContext));
        if (!ctx) {
            close(client_sock);
            continue;
        }

        ctx->socket_fd = client_sock;
        memset(ctx->client_ip, 0, sizeof(ctx->client_ip));

        if (client_addr.ss_family == AF_INET) {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&client_addr;
            inet_ntop(AF_INET, &s4->sin_addr, ctx->client_ip, sizeof(ctx->client_ip));
        } else if (client_addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&client_addr;
            inet_ntop(AF_INET6, &s6->sin6_addr, ctx->client_ip, sizeof(ctx->client_ip));
            /* Normalize IPv4-mapped IPv6 address (::ffff:127.0.0.1 -> 127.0.0.1) */
            if (strncmp(ctx->client_ip, "::ffff:", 7) == 0) {
                memmove(ctx->client_ip, ctx->client_ip + 7, strlen(ctx->client_ip + 7) + 1);
            }
        } else {
            strncpy(ctx->client_ip, "127.0.0.1", sizeof(ctx->client_ip) - 1);
        }

        pthread_t thread_id;
        if (pthread_create(&thread_id, &thread_attr, handle_client_worker, (void *)ctx) != 0) {
            perror("[ERROR] pthread_create() failed");
            close(client_sock);
            free(ctx);
        } else {
            pthread_detach(thread_id);
        }
    }

    pthread_attr_destroy(&thread_attr);
    close(server_socket);
    return 0;
}
