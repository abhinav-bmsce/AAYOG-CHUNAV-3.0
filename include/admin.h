/**
 * ============================================================================
 * Title:       AAYOG_CHUNAV 3.0 - Administration & Report Generator Header
 * File:        include/admin.h
 * Description: Administrator authentication, RBAC, session management,
 *              audit reporting, CSV and pure-C PDF report generation,
 *              and cryptographic backup & recovery.
 * ============================================================================
 */

#ifndef ADMIN_H
#define ADMIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "election.h"

#define ADMIN_DEFAULT_USER "admin"
#define ADMIN_DEFAULT_PASS "Admin@Aayog2026#"
#define ADMIN_SESSION_LEN 64
#define ADMIN_SESSION_TIMEOUT 7200 /* 2 hours */

/* Admin Session structure */
typedef struct {
    char token[ADMIN_SESSION_LEN];
    char username[32];
    time_t created_at;
    time_t last_active;
    int is_active;
    int authenticated_via_mtls;
} AdminSession;

/* Admin Management functions */
void admin_init(void);
int admin_authenticate(const char *username, const char *password, const char *otp_or_token,
                       int is_mtls, char *out_session_token);
int admin_validate_session(const char *token);
void admin_logout(const char *token);
int admin_is_setup(void);
int admin_setup_credentials(const char *username, const char *password, const char *otp_pin);
int admin_change_password(const char *token, const char *old_pass, const char *new_pass);

/* Report Generators */
int admin_generate_election_csv_report(int election_id, char *out_buf, size_t max_len);
int admin_generate_election_pdf_report(int election_id, unsigned char **out_pdf_data, size_t *out_pdf_len);
int admin_generate_csv_report(char *out_buf, size_t max_len);
int admin_generate_pdf_report(unsigned char **out_pdf_data, size_t *out_pdf_len);

/* Backup & Recovery */
int admin_create_backup(char *out_backup_name, size_t max_name);
int admin_list_backups_json(char *out_json, size_t max_len);
int admin_restore_backup(const char *backup_name);

#endif /* ADMIN_H */
