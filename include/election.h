/**
 * ============================================================================
 * Title:       AAYOG_CHUNAV 3.0 - Multi-Election Core Header
 * File:        include/election.h
 * Description: Multi-election engine, lifecycle states, candidate management,
 *              polling booths, voter rolls, anonymous ballot secrecy,
 *              analytics, and cryptographic receipt verification.
 * ============================================================================
 */

#ifndef ELECTION_H
#define ELECTION_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#define MAX_ELECTIONS 32
#define MAX_VOTERS_PER_ELECTION 3000
#define MAX_CANDIDATES_PER_ELECTION 32
#define MAX_BOOTHS_PER_ELECTION 32
#define MAX_BALLOTS_PER_ELECTION 5000

/* Legacy compatibility limits */
#define MAX_VOTERS MAX_VOTERS_PER_ELECTION
#define MAX_CANDIDATES MAX_CANDIDATES_PER_ELECTION
#define MAX_BOOTHS MAX_BOOTHS_PER_ELECTION
#define MAX_BALLOTS MAX_BALLOTS_PER_ELECTION

#define ID_LEN 32
#define NAME_LEN 64
#define PARTY_LEN 64
#define DESC_LEN 256
#define TYPE_LEN 64
#define PHOTO_LEN 128
#define TOKEN_LEN 65
#define TIMESTAMP_LEN 32

/* Election Lifecycle States */
typedef enum {
    ELECTION_DRAFT       = 0, /* Created, configuring candidates & voters */
    ELECTION_PUBLISHED   = 1, /* Visible to voters, voting not yet started */
    ELECTION_ACTIVE      = 2, /* Voting is live */
    ELECTION_PAUSED      = 3, /* Temporarily paused, voting rejected */
    ELECTION_CLOSED      = 4, /* Voting concluded, ballots sealed */
    ELECTION_DECLARED    = 5, /* Results officially declared & public */
    ELECTION_ARCHIVED    = 6  /* Archived for historical audit */
} ElectionState;

/* Candidate details and tally */
typedef struct {
    int id;
    int election_id;
    char name[NAME_LEN];
    char party[PARTY_LEN];
    char photo_url[PHOTO_LEN];
    int votes;
} Candidate;

/* Polling Booth */
typedef struct {
    int id;
    int election_id;
    char name[NAME_LEN];
    char location[NAME_LEN];
    int total_registered;
    int votes_cast;
} PollingBooth;

/* Registered Voter (Ballot Secrecy: NO candidate selection stored here!) */
typedef struct {
    char id[ID_LEN];
    int election_id;
    char name[NAME_LEN];
    int booth_id;
    int has_voted; /* 0 = eligible, 1 = already voted */
    char voted_at[TIMESTAMP_LEN]; /* Decoupled date/session to prevent timestamp correlation */
} Voter;

/* Anonymous Ballot Record (Ballot Secrecy: NO voter identity stored here!) */
typedef struct {
    char token[TOKEN_LEN];
    int election_id;
    int candidate_id;
    char candidate_name[NAME_LEN];
    int booth_id;
    char timestamp[TIMESTAMP_LEN];
} AnonymousBallot;

/* Election Entity */
typedef struct {
    int id;
    char title[NAME_LEN];
    char description[DESC_LEN];
    char type[TYPE_LEN]; /* General, College, Department, Club, Student Council */
    ElectionState state;
    time_t start_time;
    time_t end_time;
    int require_otp;
    int results_declared;
    
    int candidate_count;
    Candidate candidates[MAX_CANDIDATES_PER_ELECTION];
    
    int booth_count;
    PollingBooth booths[MAX_BOOTHS_PER_ELECTION];
    
    int voter_count;
    Voter voters[MAX_VOTERS_PER_ELECTION];
    
    int ballot_count;
    AnonymousBallot ballots[MAX_BALLOTS_PER_ELECTION];
    
    /* Calculated results & statistics */
    char winner_name[NAME_LEN];
    char winner_party[PARTY_LEN];
    int winner_votes;
    char runner_up_name[NAME_LEN];
    int runner_up_votes;
    int margin_of_victory;
    int is_tie;
} Election;

/* Summary representation for listing */
typedef struct {
    int id;
    char title[NAME_LEN];
    char description[DESC_LEN];
    char type[TYPE_LEN];
    ElectionState state;
    char state_str[24];
    time_t start_time;
    time_t end_time;
    int require_otp;
    int results_declared;
    int candidate_count;
    int booth_count;
    int voter_count;
    int ballot_count;
    float turnout_pct;
    char winner_name[NAME_LEN];
    int is_tie;
} ElectionSummary;

/* Backward compatibility typedef for single election info */
typedef struct {
    char title[NAME_LEN];
    ElectionState state;
    time_t start_time;
    time_t end_time;
    int require_otp;
} ElectionInfo;

/* Global state synchronization mutex */
extern pthread_mutex_t election_mutex;

/* Engine Initialization & Core Persistence */
void election_init(void);
void election_save_all(void);
void election_save_election(int election_id);
const char *election_state_to_str(ElectionState state);
ElectionState election_str_to_state(const char *str);

/* Multi-Election Lifecycle Management */
int election_get_count(void);
int election_get_active_id(void);
void election_set_active_id(int id);
int election_get_summary(int election_id, ElectionSummary *out_sum);
int election_get_all_summaries(ElectionSummary *out_summaries, int max_out);
int election_get_by_id(int election_id, Election *out_election);
int election_create(const char *title, const char *description, const char *type,
                    time_t start_time, time_t end_time, int require_otp, int *out_id);
int election_update_details(int election_id, const char *title, const char *description,
                            const char *type, time_t start_time, time_t end_time, int require_otp);
int election_set_state(int election_id, ElectionState new_state);
int election_declare_results(int election_id);
int election_delete_draft(int election_id);
void election_calculate_results(Election *el);

/* Candidate Management */
int election_add_candidate(int election_id, const char *name, const char *party, const char *photo_url, int *out_cand_id);
int election_update_candidate(int election_id, int candidate_id, const char *name, const char *party, const char *photo_url);
int election_delete_candidate(int election_id, int candidate_id);
int election_get_candidate_count(int election_id);
int election_get_candidate_by_id(int election_id, int candidate_id, Candidate *out_cand);
int election_get_candidate_by_index(int election_id, int idx, Candidate *out_cand);

/* Polling Booth Management */
int election_add_booth(int election_id, int id, const char *name, const char *location);
int election_update_booth(int election_id, int id, const char *name, const char *location);
int election_delete_booth(int election_id, int id);
int election_get_booth_count(int election_id);
int election_get_booth_by_id(int election_id, int id, PollingBooth *out_booth);
int election_get_booth_by_index(int election_id, int idx, PollingBooth *out_booth);

/* Voter Management */
int election_is_valid_voter_id_format(const char *id);
int election_add_voter(int election_id, const char *voter_id, const char *name, int booth_id);
int election_import_voters_csv(int election_id, const char *csv_content, int *out_added, int *out_skipped);
int election_import_voters_csv_detailed(int election_id, const char *csv_content, int *out_added, int *out_skipped, char *out_details, size_t max_details_len);
int election_delete_voter(int election_id, const char *voter_id);
int election_check_voter_status(int election_id, const char *voter_id, Voter *out_voter);
int election_get_voters_count(int election_id);
int election_get_voter_by_index(int election_id, int idx, Voter *out_voter);
int election_search_voters(int election_id, const char *query, Voter *out_results, int max_results);

/* Voting logic with Strict Ballot Secrecy & Anonymous Receipts */
int election_cast_ballot(int election_id, const char *voter_id, int candidate_id, int booth_id,
                         char *out_receipt_token, char *out_cand_name);
int election_verify_receipt(int election_id, const char *token, int *out_booth_id, char *out_timestamp, char *out_election_title);

/* Analytics, Results & Reports */
void election_get_analytics_json(int election_id, char *output, size_t max_len);
void election_generate_results_json(int election_id, char *output, size_t max_len, int is_admin);
void election_generate_results_text(int election_id, char *output, size_t max_len);
void election_generate_monitoring_json(int election_id, char *output, size_t max_len);

/* Legacy Single-Election Wrappers (Ensures 100% backward compatibility for existing scripts) */
int legacy_election_get_state(void);
const char *legacy_election_get_state_str(void);
int legacy_election_set_state(ElectionState new_state);
ElectionInfo legacy_election_get_info(void);
int legacy_election_check_voter_status(const char *id, Voter *out_voter);
int legacy_election_add_voter(const char *id, const char *name, int booth_id);
int legacy_election_import_voters_csv(const char *csv_content, int *out_added, int *out_skipped);
int legacy_election_get_voters_count(void);
int legacy_election_get_candidate_count(void);
int legacy_election_get_candidate_by_id(int id, Candidate *out_cand);
int legacy_election_get_candidate_by_index(int idx, Candidate *out_cand);
int legacy_election_get_booth_count(void);
int legacy_election_get_booth_by_id(int id, PollingBooth *out_booth);
int legacy_election_get_booth_by_index(int idx, PollingBooth *out_booth);
int legacy_election_cast_ballot(const char *voter_id, int candidate_id, int booth_id,
                                char *out_receipt_token, char *out_cand_name);
void legacy_election_generate_results_json(char *output, size_t max_len);
void legacy_election_generate_results_text(char *output, size_t max_len);

#endif /* ELECTION_H */
