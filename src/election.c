/**
 * ============================================================================
 * Title:       AAYOG_CHUNAV 3.0 - Multi-Election Engine
 * File:        src/election.c
 * Description: Multi-election lifecycle management, candidate administration,
 *              election-scoped voter rolls, polling booths, anonymous ballot
 *              secrecy, cryptographic receipts, live analytics, and data migration.
 * ============================================================================
 */

#include "election.h"
#include "security.h"
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define MASTER_ELECTIONS_FILE "data/elections.txt"
#define LEGACY_VOTERS_FILE    "data/voters.txt"
#define LEGACY_BALLOTS_FILE   "data/ballots.txt"
#define LEGACY_BOOTHS_FILE    "data/booths.txt"
#define LEGACY_CANDS_FILE     "data/candidates.txt"
#define LEGACY_STATE_FILE     "data/election.txt"
#define LEGACY_VOTES_FILE     "votes.txt"

static Election elections[MAX_ELECTIONS];
static int election_count = 0;
static int active_election_id = 1;

pthread_mutex_t election_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Forward declarations */
static void str_trim(char *str);
static void migrate_v2_data_if_needed(void);
static void load_all_elections(void);
static void load_single_election_data(Election *el);
static void save_election_meta_file(void);
static void sync_legacy_files_for_election_1(void);

static void str_trim(char *str) {
    if (!str) return;
    char *p = str;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != str) memmove(str, p, strlen(p) + 1);

    int len = (int)strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[len - 1] = '\0';
        len--;
    }
}

const char *election_state_to_str(ElectionState state) {
    switch (state) {
        case ELECTION_DRAFT:     return "DRAFT";
        case ELECTION_PUBLISHED: return "PUBLISHED";
        case ELECTION_ACTIVE:    return "ACTIVE";
        case ELECTION_PAUSED:    return "PAUSED";
        case ELECTION_CLOSED:    return "CLOSED";
        case ELECTION_DECLARED:  return "DECLARED";
        case ELECTION_ARCHIVED:  return "ARCHIVED";
        default:                 return "DRAFT";
    }
}

ElectionState election_str_to_state(const char *str) {
    if (!str) return ELECTION_DRAFT;
    if (strcasecmp(str, "PUBLISHED") == 0) return ELECTION_PUBLISHED;
    if (strcasecmp(str, "ACTIVE") == 0)    return ELECTION_ACTIVE;
    if (strcasecmp(str, "PAUSED") == 0)    return ELECTION_PAUSED;
    if (strcasecmp(str, "CLOSED") == 0)    return ELECTION_CLOSED;
    if (strcasecmp(str, "DECLARED") == 0)  return ELECTION_DECLARED;
    if (strcasecmp(str, "ARCHIVED") == 0)  return ELECTION_ARCHIVED;
    return ELECTION_DRAFT;
}

/**
 * Initializes the Multi-Election Engine, runs data migration if needed,
 * and loads all elections into memory.
 */
void election_init(void) {
    pthread_mutex_lock(&election_mutex);

    mkdir("data", 0755);
    mkdir("data/backups", 0755);
    mkdir("data/elections", 0755);

    migrate_v2_data_if_needed();
    load_all_elections();

    /* Find active election */
    active_election_id = 1;
    for (int i = 0; i < election_count; i++) {
        if (elections[i].state == ELECTION_ACTIVE) {
            active_election_id = elections[i].id;
            break;
        }
    }

    pthread_mutex_unlock(&election_mutex);

    audit_log_init();
    audit_log_record("SYSTEM_INIT", "LOW", "KERNEL", "AAYOG_CHUNAV 3.0 Multi-Election Engine Initialized");
    security_save_baseline_manifest();
}

/**
 * Migrates existing v2.0 data (Lok Sabha election) into Election #1
 * without deleting or modifying any historical records.
 */
static void migrate_v2_data_if_needed(void) {
    mkdir("data/election_1", 0755);

    if (access(MASTER_ELECTIONS_FILE, F_OK) != 0) {
        printf("[MIGRATION] Initializing AAYOG_CHUNAV 3.0 Master Elections Registry...\n");

        char title[NAME_LEN] = "Lok Sabha General Election 2026";
        char desc[DESC_LEN] = "National Parliamentary General Election 2026 for Lok Sabha";
        char type[TYPE_LEN] = "General";
        char state_str[32] = "ACTIVE";
        long long start_t = (long long)time(NULL);
        long long end_t = start_t + 86400 * 7;
        int req_otp = 1;
        int declared = 0;

        /* Check if v2 election.txt exists */
        if (access(LEGACY_STATE_FILE, F_OK) == 0) {
            FILE *sf = fopen(LEGACY_STATE_FILE, "r");
            if (sf) {
                char sline[256];
                if (fgets(sline, sizeof(sline), sf)) {
                    str_trim(sline);
                    sscanf(sline, "%31[^|]|%63[^|]|%lld|%lld|%d",
                           state_str, title, &start_t, &end_t, &req_otp);
                }
                fclose(sf);
            }
        }

        /* Write initial master elections.txt */
        FILE *mf = fopen(MASTER_ELECTIONS_FILE, "w");
        if (mf) {
            fprintf(mf, "# AAYOG_CHUNAV 3.0 Master Elections Registry\n");
            fprintf(mf, "# ID|Title|Type|State|StartTime|EndTime|RequireOTP|ResultsDeclared|Description\n");
            fprintf(mf, "1|%s|%s|%s|%lld|%lld|%d|%d|%s\n",
                    title, type, state_str, start_t, end_t, req_otp, declared, desc);
            fclose(mf);
        }

        /* Copy existing v2 files to data/election_1/ */
        const char *src_dst[][2] = {
            { LEGACY_CANDS_FILE,   "data/election_1/candidates.txt" },
            { LEGACY_BOOTHS_FILE,  "data/election_1/booths.txt" },
            { LEGACY_VOTERS_FILE,  "data/election_1/voters.txt" },
            { LEGACY_BALLOTS_FILE, "data/election_1/ballots.txt" },
            { LEGACY_STATE_FILE,   "data/election_1/election.txt" },
            { NULL, NULL }
        };

        for (int i = 0; src_dst[i][0] != NULL; i++) {
            if (access(src_dst[i][0], F_OK) == 0 && access(src_dst[i][1], F_OK) != 0) {
                FILE *in = fopen(src_dst[i][0], "rb");
                FILE *out = fopen(src_dst[i][1], "wb");
                if (in && out) {
                    char buf[4096];
                    size_t n;
                    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
                        fwrite(buf, 1, n, out);
                    }
                }
                if (in) fclose(in);
                if (out) fclose(out);
            }
        }
        printf("[MIGRATION] Historical Election #1 preserved and linked successfully.\n");
    }
}

/**
 * Loads all registered elections and their child collections from disk.
 */
static void load_all_elections(void) {
    election_count = 0;
    FILE *mf = fopen(MASTER_ELECTIONS_FILE, "r");
    if (!mf) return;

    char line[512];
    while (fgets(line, sizeof(line), mf) && election_count < MAX_ELECTIONS) {
        str_trim(line);
        if (line[0] == '#' || line[0] == '\0') continue;

        int id = 0, req_otp = 1, declared = 0;
        char title[NAME_LEN] = {0};
        char type[TYPE_LEN] = {0};
        char state_str[32] = {0};
        long long start_t = 0, end_t = 0;
        char desc[DESC_LEN] = {0};

        int parsed = sscanf(line, "%d|%63[^|]|%63[^|]|%31[^|]|%lld|%lld|%d|%d|%255[^\n]",
                            &id, title, type, state_str, &start_t, &end_t, &req_otp, &declared, desc);

        if (parsed >= 4) {
            Election *el = &elections[election_count];
            memset(el, 0, sizeof(Election));
            el->id = id;
            strncpy(el->title, title, NAME_LEN - 1);
            strncpy(el->type, type, TYPE_LEN - 1);
            strncpy(el->description, (strlen(desc) > 0) ? desc : title, DESC_LEN - 1);
            el->state = election_str_to_state(state_str);
            el->start_time = (time_t)start_t;
            el->end_time = (time_t)end_t;
            el->require_otp = req_otp;
            el->results_declared = declared;

            load_single_election_data(el);
            election_calculate_results(el);
            election_count++;
        }
    }
    fclose(mf);
    printf("[INFO] Loaded %d election(s) into AAYOG_CHUNAV 3.0 Platform.\n", election_count);
}

/**
 * Loads candidates, booths, voters, and ballots for a specific election.
 */
static void load_single_election_data(Election *el) {
    char dir[128];
    snprintf(dir, sizeof(dir), "data/election_%d", el->id);
    mkdir(dir, 0755);

    /* 1. Candidates */
    char cand_path[256];
    snprintf(cand_path, sizeof(cand_path), "%s/candidates.txt", dir);
    if (access(cand_path, F_OK) != 0 && el->id == 1 && access(LEGACY_CANDS_FILE, F_OK) == 0) {
        snprintf(cand_path, sizeof(cand_path), "%s", LEGACY_CANDS_FILE);
    }

    el->candidate_count = 0;
    FILE *cf = fopen(cand_path, "r");
    if (cf) {
        char line[256];
        while (fgets(line, sizeof(line), cf) && el->candidate_count < MAX_CANDIDATES_PER_ELECTION) {
            str_trim(line);
            if (line[0] == '#' || line[0] == '\0') continue;
            int cid = 0, cvotes = 0;
            char cname[NAME_LEN] = {0}, cparty[PARTY_LEN] = {0}, cphoto[PHOTO_LEN] = {0};
            if (sscanf(line, "%d|%63[^|]|%63[^|]|%d|%127[^\n]", &cid, cname, cparty, &cvotes, cphoto) >= 3 ||
                sscanf(line, "%d|%63[^|]|%63[^|]|%d", &cid, cname, cparty, &cvotes) >= 3) {
                Candidate *c = &el->candidates[el->candidate_count++];
                c->id = cid;
                c->election_id = el->id;
                strncpy(c->name, cname, NAME_LEN - 1);
                strncpy(c->party, cparty, PARTY_LEN - 1);
                strncpy(c->photo_url, (strlen(cphoto) > 0) ? cphoto : "/images/others.png", PHOTO_LEN - 1);
                c->votes = 0; /* Will be computed from verified ballots */
            }
        }
        fclose(cf);
    } else if (el->id == 1) {
        /* Default Candidates for Election 1 */
        el->candidate_count = 3;
        el->candidates[0] = (Candidate){1, 1, "Narendra Modi", "Bharatiya Janata Party (BJP)", "/images/modi.png", 0};
        el->candidates[1] = (Candidate){2, 1, "Rahul Gandhi", "Indian National Congress (INC)", "/images/gandhi.png", 0};
        el->candidates[2] = (Candidate){3, 1, "Others", "Independent / Other Parties", "/images/others.png", 0};
    }

    /* 2. Booths */
    char booth_path[256];
    snprintf(booth_path, sizeof(booth_path), "%s/booths.txt", dir);
    if (access(booth_path, F_OK) != 0 && el->id == 1 && access(LEGACY_BOOTHS_FILE, F_OK) == 0) {
        snprintf(booth_path, sizeof(booth_path), "%s", LEGACY_BOOTHS_FILE);
    }

    el->booth_count = 0;
    FILE *bf = fopen(booth_path, "r");
    if (bf) {
        char line[256];
        while (fgets(line, sizeof(line), bf) && el->booth_count < MAX_BOOTHS_PER_ELECTION) {
            str_trim(line);
            if (line[0] == '#' || line[0] == '\0') continue;
            int bid = 0;
            char bname[NAME_LEN] = {0}, bloc[NAME_LEN] = {0};
            if (sscanf(line, "%d|%63[^|]|%63[^\n]", &bid, bname, bloc) >= 2) {
                PollingBooth *b = &el->booths[el->booth_count++];
                b->id = bid;
                b->election_id = el->id;
                strncpy(b->name, bname, NAME_LEN - 1);
                strncpy(b->location, bloc, NAME_LEN - 1);
                b->total_registered = 0;
                b->votes_cast = 0;
            }
        }
        fclose(bf);
    } else if (el->id == 1) {
        el->booth_count = 3;
        el->booths[0] = (PollingBooth){1, 1, "Central Polling Station 1", "Main Hall, New Delhi", 0, 0};
        el->booths[1] = (PollingBooth){2, 1, "North Campus Polling Station 2", "Arts Faculty, Delhi", 0, 0};
        el->booths[2] = (PollingBooth){3, 1, "South District Polling Station 3", "Community Center, Delhi", 0, 0};
    }

    /* 3. Voters */
    char voter_path[256];
    snprintf(voter_path, sizeof(voter_path), "%s/voters.txt", dir);
    if (access(voter_path, F_OK) != 0 && el->id == 1 && access(LEGACY_VOTERS_FILE, F_OK) == 0) {
        snprintf(voter_path, sizeof(voter_path), "%s", LEGACY_VOTERS_FILE);
    }

    el->voter_count = 0;
    FILE *vf = fopen(voter_path, "r");
    if (vf) {
        char line[256];
        while (fgets(line, sizeof(line), vf) && el->voter_count < MAX_VOTERS_PER_ELECTION) {
            str_trim(line);
            if (line[0] == '#' || line[0] == '\0') continue;
            char vid[ID_LEN] = {0}, vname[NAME_LEN] = {0}, voted_at[TIMESTAMP_LEN] = "NONE";
            int booth_id = 1, has_voted = 0;

            char *saveptr = NULL;
            char *tok = strtok_r(line, "|", &saveptr);
            if (tok) strncpy(vid, tok, ID_LEN - 1);
            tok = strtok_r(NULL, "|", &saveptr);
            if (tok) strncpy(vname, tok, NAME_LEN - 1);
            tok = strtok_r(NULL, "|", &saveptr);
            if (tok) booth_id = atoi(tok);
            tok = strtok_r(NULL, "|", &saveptr);
            if (tok) has_voted = atoi(tok);
            tok = strtok_r(NULL, "|", &saveptr);
            if (tok) strncpy(voted_at, tok, TIMESTAMP_LEN - 1);

            Voter *v = &el->voters[el->voter_count++];
            strncpy(v->id, vid, ID_LEN - 1);
            v->election_id = el->id;
            strncpy(v->name, (strlen(vname) > 0) ? vname : vid, NAME_LEN - 1);
            v->booth_id = (booth_id > 0) ? booth_id : 1;
            v->has_voted = has_voted;
            strncpy(v->voted_at, voted_at, TIMESTAMP_LEN - 1);

            /* Increment booth registered count */
            for (int b = 0; b < el->booth_count; b++) {
                if (el->booths[b].id == v->booth_id) {
                    el->booths[b].total_registered++;
                    break;
                }
            }
        }
        fclose(vf);
    } else if (el->id == 1) {
        /* Default seed for Election 1 (V101 to V199) */
        for (int i = 101; i <= 199 && el->voter_count < MAX_VOTERS_PER_ELECTION; i++) {
            Voter *v = &el->voters[el->voter_count++];
            snprintf(v->id, sizeof(v->id), "V%d", i);
            v->election_id = 1;
            snprintf(v->name, sizeof(v->name), "Voter %d", i);
            v->booth_id = ((i - 101) % 3) + 1;
            v->has_voted = 0;
            strcpy(v->voted_at, "NONE");

            for (int b = 0; b < el->booth_count; b++) {
                if (el->booths[b].id == v->booth_id) {
                    el->booths[b].total_registered++;
                    break;
                }
            }
        }
    }

    /* 4. Anonymous Ballots */
    char ballot_path[256];
    snprintf(ballot_path, sizeof(ballot_path), "%s/ballots.txt", dir);
    if (access(ballot_path, F_OK) != 0 && el->id == 1 && access(LEGACY_BALLOTS_FILE, F_OK) == 0) {
        snprintf(ballot_path, sizeof(ballot_path), "%s", LEGACY_BALLOTS_FILE);
    }

    el->ballot_count = 0;
    FILE *bal_f = fopen(ballot_path, "r");
    if (bal_f) {
        char line[256];
        while (fgets(line, sizeof(line), bal_f) && el->ballot_count < MAX_BALLOTS_PER_ELECTION) {
            str_trim(line);
            if (line[0] == '#' || line[0] == '\0') continue;
            char token[TOKEN_LEN] = {0}, cand_name[NAME_LEN] = {0}, btime[TIMESTAMP_LEN] = {0};
            int cand_id = 0, booth_id = 1;

            if (sscanf(line, "%64[^|]|%d|%63[^|]|%d|%31[^\n]",
                       token, &cand_id, cand_name, &booth_id, btime) >= 3) {
                AnonymousBallot *ab = &el->ballots[el->ballot_count++];
                strncpy(ab->token, token, TOKEN_LEN - 1);
                ab->election_id = el->id;
                ab->candidate_id = cand_id;
                strncpy(ab->candidate_name, cand_name, NAME_LEN - 1);
                ab->booth_id = booth_id;
                strncpy(ab->timestamp, btime, TIMESTAMP_LEN - 1);

                /* Add vote tally to candidate */
                for (int c = 0; c < el->candidate_count; c++) {
                    if (el->candidates[c].id == cand_id) {
                        el->candidates[c].votes++;
                        break;
                    }
                }
                /* Add vote to booth */
                for (int b = 0; b < el->booth_count; b++) {
                    if (el->booths[b].id == booth_id) {
                        el->booths[b].votes_cast++;
                        break;
                    }
                }
            }
        }
        fclose(bal_f);
    }

    election_save_election(el->id);
}

/**
 * Persists an election and all its child files to disk.
 */
void election_save_election(int election_id) {
    Election *el = NULL;
    for (int i = 0; i < election_count; i++) {
        if (elections[i].id == election_id) {
            el = &elections[i];
            break;
        }
    }
    if (!el) return;

    char dir[128];
    snprintf(dir, sizeof(dir), "data/election_%d", el->id);
    mkdir(dir, 0755);

    /* 1. Election State File */
    char s_path[256];
    snprintf(s_path, sizeof(s_path), "%s/election.txt", dir);
    FILE *sf = fopen(s_path, "w");
    if (sf) {
        fprintf(sf, "%s|%s|%lld|%lld|%d|%d|%s\n",
                election_state_to_str(el->state), el->title,
                (long long)el->start_time, (long long)el->end_time,
                el->require_otp, el->results_declared, el->type);
        fflush(sf);
        fsync(fileno(sf));
        fclose(sf);
    }

    /* 2. Candidates */
    char c_path[256];
    snprintf(c_path, sizeof(c_path), "%s/candidates.txt", dir);
    FILE *cf = fopen(c_path, "w");
    if (cf) {
        fprintf(cf, "# Candidates: ID|Name|Party|Votes|PhotoURL\n");
        for (int i = 0; i < el->candidate_count; i++) {
            fprintf(cf, "%d|%s|%s|%d|%s\n",
                    el->candidates[i].id, el->candidates[i].name,
                    el->candidates[i].party, el->candidates[i].votes,
                    el->candidates[i].photo_url);
        }
        fflush(cf);
        fsync(fileno(cf));
        fclose(cf);
    }

    /* 3. Booths */
    char b_path[256];
    snprintf(b_path, sizeof(b_path), "%s/booths.txt", dir);
    FILE *bf = fopen(b_path, "w");
    if (bf) {
        fprintf(bf, "# Polling Booths: ID|Name|Location\n");
        for (int i = 0; i < el->booth_count; i++) {
            fprintf(bf, "%d|%s|%s\n",
                    el->booths[i].id, el->booths[i].name, el->booths[i].location);
        }
        fflush(bf);
        fsync(fileno(bf));
        fclose(bf);
    }

    /* 4. Voters */
    char v_path[256];
    snprintf(v_path, sizeof(v_path), "%s/voters.txt", dir);
    FILE *vf = fopen(v_path, "w");
    if (vf) {
        fprintf(vf, "# Registered Voter Roll: VoterID|Name|BoothID|HasVoted|VotedAt\n");
        for (int i = 0; i < el->voter_count; i++) {
            fprintf(vf, "%s|%s|%d|%d|%s\n",
                    el->voters[i].id, el->voters[i].name,
                    el->voters[i].booth_id, el->voters[i].has_voted,
                    el->voters[i].voted_at);
        }
        fflush(vf);
        fsync(fileno(vf));
        fclose(vf);
    }

    /* 5. Ballots */
    char bal_path[256];
    snprintf(bal_path, sizeof(bal_path), "%s/ballots.txt", dir);
    FILE *bal_f = fopen(bal_path, "w");
    if (bal_f) {
        fprintf(bal_f, "# Anonymous Ballots: Token|CandidateID|CandidateName|BoothID|Timestamp\n");
        for (int i = 0; i < el->ballot_count; i++) {
            fprintf(bal_f, "%s|%d|%s|%d|%s\n",
                    el->ballots[i].token, el->ballots[i].candidate_id,
                    el->ballots[i].candidate_name, el->ballots[i].booth_id,
                    el->ballots[i].timestamp);
        }
        fflush(bal_f);
        fsync(fileno(bal_f));
        fclose(bal_f);
    }

    /* If Election #1, synchronize legacy files so old scripts never break */
    if (el->id == 1) {
        sync_legacy_files_for_election_1();
    }

    save_election_meta_file();
}

static void sync_legacy_files_for_election_1(void) {
    Election *el = &elections[0];
    if (election_count <= 0 || el->id != 1) return;

    /* Legacy voters.txt */
    FILE *vf = fopen(LEGACY_VOTERS_FILE, "w");
    if (vf) {
        fprintf(vf, "# Registered Voter Roll: VoterID|Name|BoothID|HasVoted|VotedAt\n");
        for (int i = 0; i < el->voter_count; i++) {
            fprintf(vf, "%s|%s|%d|%d|%s\n",
                    el->voters[i].id, el->voters[i].name,
                    el->voters[i].booth_id, el->voters[i].has_voted,
                    el->voters[i].voted_at);
        }
        fflush(vf);
        fsync(fileno(vf));
        fclose(vf);
    }

    /* Legacy ballots.txt & votes.txt */
    FILE *bf = fopen(LEGACY_BALLOTS_FILE, "w");
    FILE *vf_legacy = fopen(LEGACY_VOTES_FILE, "w");
    for (int i = 0; i < el->ballot_count; i++) {
        if (bf) {
            fprintf(bf, "%s|%d|%s|%d|%s\n",
                    el->ballots[i].token, el->ballots[i].candidate_id,
                    el->ballots[i].candidate_name, el->ballots[i].booth_id,
                    el->ballots[i].timestamp);
        }
        if (vf_legacy) {
            fprintf(vf_legacy, "%s|%d|%s|%d|%s\n",
                    el->ballots[i].token, el->ballots[i].candidate_id,
                    el->ballots[i].candidate_name, el->ballots[i].booth_id,
                    el->ballots[i].timestamp);
        }
    }
    if (bf) { fflush(bf); fsync(fileno(bf)); fclose(bf); }
    if (vf_legacy) { fflush(vf_legacy); fsync(fileno(vf_legacy)); fclose(vf_legacy); }

    /* Legacy candidates.txt */
    FILE *cf = fopen(LEGACY_CANDS_FILE, "w");
    if (cf) {
        for (int i = 0; i < el->candidate_count; i++) {
            fprintf(cf, "%d|%s|%s|%d\n",
                    el->candidates[i].id, el->candidates[i].name,
                    el->candidates[i].party, el->candidates[i].votes);
        }
        fflush(cf);
        fsync(fileno(cf));
        fclose(cf);
    }

    /* Legacy election.txt */
    FILE *sf = fopen(LEGACY_STATE_FILE, "w");
    if (sf) {
        fprintf(sf, "%s|%s|%lld|%lld|%d\n",
                election_state_to_str(el->state), el->title,
                (long long)el->start_time, (long long)el->end_time,
                el->require_otp);
        fflush(sf);
        fsync(fileno(sf));
        fclose(sf);
    }
}

static void save_election_meta_file(void) {
    FILE *mf = fopen(MASTER_ELECTIONS_FILE, "w");
    if (!mf) return;

    fprintf(mf, "# AAYOG_CHUNAV 3.0 Master Elections Registry\n");
    fprintf(mf, "# ID|Title|Type|State|StartTime|EndTime|RequireOTP|ResultsDeclared|Description\n");

    for (int i = 0; i < election_count; i++) {
        fprintf(mf, "%d|%s|%s|%s|%lld|%lld|%d|%d|%s\n",
                elections[i].id, elections[i].title, elections[i].type,
                election_state_to_str(elections[i].state),
                (long long)elections[i].start_time, (long long)elections[i].end_time,
                elections[i].require_otp, elections[i].results_declared,
                elections[i].description);
    }
    fflush(mf);
    fsync(fileno(mf));
    fclose(mf);
}

void election_save_all(void) {
    save_election_meta_file();
    for (int i = 0; i < election_count; i++) {
        election_save_election(elections[i].id);
    }
}

/**
 * Calculates election results: tallies candidate votes, determines winner,
 * runner-up, victory margin, and detects ties.
 */
void election_calculate_results(Election *el) {
    if (!el) return;

    /* Reset tallies */
    for (int c = 0; c < el->candidate_count; c++) {
        el->candidates[c].votes = 0;
    }
    for (int b = 0; b < el->booth_count; b++) {
        el->booths[b].votes_cast = 0;
    }

    /* Count from immutable ballots */
    for (int i = 0; i < el->ballot_count; i++) {
        int cid = el->ballots[i].candidate_id;
        int bid = el->ballots[i].booth_id;

        for (int c = 0; c < el->candidate_count; c++) {
            if (el->candidates[c].id == cid) {
                el->candidates[c].votes++;
                break;
            }
        }
        for (int b = 0; b < el->booth_count; b++) {
            if (el->booths[b].id == bid) {
                el->booths[b].votes_cast++;
                break;
            }
        }
    }

    /* Determine Leader & Runner-Up */
    int top1_idx = -1, top2_idx = -1;
    for (int c = 0; c < el->candidate_count; c++) {
        if (top1_idx == -1 || el->candidates[c].votes > el->candidates[top1_idx].votes) {
            top2_idx = top1_idx;
            top1_idx = c;
        } else if (top2_idx == -1 || el->candidates[c].votes > el->candidates[top2_idx].votes) {
            top2_idx = c;
        }
    }

    if (top1_idx != -1 && el->candidate_count > 0) {
        if (top2_idx != -1 && el->candidates[top1_idx].votes == el->candidates[top2_idx].votes && el->candidates[top1_idx].votes > 0) {
            el->is_tie = 1;
            snprintf(el->winner_name, sizeof(el->winner_name), "TIE: %s & %s",
                     el->candidates[top1_idx].name, el->candidates[top2_idx].name);
            strcpy(el->winner_party, "Multiple Parties");
            el->winner_votes = el->candidates[top1_idx].votes;
            strncpy(el->runner_up_name, el->candidates[top2_idx].name, NAME_LEN - 1);
            el->runner_up_votes = el->candidates[top2_idx].votes;
            el->margin_of_victory = 0;
        } else {
            el->is_tie = 0;
            strncpy(el->winner_name, el->candidates[top1_idx].name, NAME_LEN - 1);
            strncpy(el->winner_party, el->candidates[top1_idx].party, PARTY_LEN - 1);
            el->winner_votes = el->candidates[top1_idx].votes;
            if (top2_idx != -1) {
                strncpy(el->runner_up_name, el->candidates[top2_idx].name, NAME_LEN - 1);
                el->runner_up_votes = el->candidates[top2_idx].votes;
                el->margin_of_victory = el->winner_votes - el->runner_up_votes;
            } else {
                strcpy(el->runner_up_name, "None");
                el->runner_up_votes = 0;
                el->margin_of_victory = el->winner_votes;
            }
        }
    } else {
        strcpy(el->winner_name, "None");
        strcpy(el->winner_party, "None");
        el->winner_votes = 0;
        strcpy(el->runner_up_name, "None");
        el->runner_up_votes = 0;
        el->margin_of_victory = 0;
        el->is_tie = 0;
    }
}

/* =========================================================================
 * MULTI-ELECTION LIFECYCLE MANAGEMENT
 * ========================================================================= */

int election_get_count(void) {
    pthread_mutex_lock(&election_mutex);
    int c = election_count;
    pthread_mutex_unlock(&election_mutex);
    return c;
}

int election_get_active_id(void) {
    pthread_mutex_lock(&election_mutex);
    int aid = active_election_id;
    pthread_mutex_unlock(&election_mutex);
    return aid;
}

void election_set_active_id(int id) {
    pthread_mutex_lock(&election_mutex);
    for (int i = 0; i < election_count; i++) {
        if (elections[i].id == id) {
            active_election_id = id;
            break;
        }
    }
    pthread_mutex_unlock(&election_mutex);
}

static Election *find_election_locked(int id) {
    if (id <= 0) id = active_election_id;
    for (int i = 0; i < election_count; i++) {
        if (elections[i].id == id) return &elections[i];
    }
    return NULL;
}

int election_get_by_id(int election_id, Election *out_election) {
    if (!out_election) return -1;
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }
    *out_election = *el;
    pthread_mutex_unlock(&election_mutex);
    return 0;
}

int election_get_summary(int election_id, ElectionSummary *out_sum) {
    if (!out_sum) return -1;
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }

    out_sum->id = el->id;
    strncpy(out_sum->title, el->title, NAME_LEN - 1);
    strncpy(out_sum->description, el->description, DESC_LEN - 1);
    strncpy(out_sum->type, el->type, TYPE_LEN - 1);
    out_sum->state = el->state;
    strncpy(out_sum->state_str, election_state_to_str(el->state), sizeof(out_sum->state_str) - 1);
    out_sum->start_time = el->start_time;
    out_sum->end_time = el->end_time;
    out_sum->require_otp = el->require_otp;
    out_sum->results_declared = el->results_declared;
    out_sum->candidate_count = el->candidate_count;
    out_sum->booth_count = el->booth_count;
    out_sum->voter_count = el->voter_count;
    out_sum->ballot_count = el->ballot_count;
    out_sum->turnout_pct = (el->voter_count > 0) ? ((float)el->ballot_count / el->voter_count) * 100.0f : 0.0f;
    strncpy(out_sum->winner_name, el->winner_name, NAME_LEN - 1);
    out_sum->is_tie = el->is_tie;

    pthread_mutex_unlock(&election_mutex);
    return 0;
}

int election_get_all_summaries(ElectionSummary *out_summaries, int max_out) {
    if (!out_summaries || max_out <= 0) return 0;
    pthread_mutex_lock(&election_mutex);
    int count = (election_count < max_out) ? election_count : max_out;
    for (int i = 0; i < count; i++) {
        Election *el = &elections[i];
        out_summaries[i].id = el->id;
        strncpy(out_summaries[i].title, el->title, NAME_LEN - 1);
        strncpy(out_summaries[i].description, el->description, DESC_LEN - 1);
        strncpy(out_summaries[i].type, el->type, TYPE_LEN - 1);
        out_summaries[i].state = el->state;
        strncpy(out_summaries[i].state_str, election_state_to_str(el->state), sizeof(out_summaries[i].state_str) - 1);
        out_summaries[i].start_time = el->start_time;
        out_summaries[i].end_time = el->end_time;
        out_summaries[i].require_otp = el->require_otp;
        out_summaries[i].results_declared = el->results_declared;
        out_summaries[i].candidate_count = el->candidate_count;
        out_summaries[i].booth_count = el->booth_count;
        out_summaries[i].voter_count = el->voter_count;
        out_summaries[i].ballot_count = el->ballot_count;
        out_summaries[i].turnout_pct = (el->voter_count > 0) ? ((float)el->ballot_count / el->voter_count) * 100.0f : 0.0f;
        strncpy(out_summaries[i].winner_name, el->winner_name, NAME_LEN - 1);
        out_summaries[i].is_tie = el->is_tie;
    }
    pthread_mutex_unlock(&election_mutex);
    return count;
}

/**
 * Creates a new Election instance with its own isolated data directory.
 */
int election_create(const char *title, const char *description, const char *type,
                    time_t start_time, time_t end_time, int require_otp, int *out_id) {
    if (!title || strlen(title) == 0) return -1;

    pthread_mutex_lock(&election_mutex);

    if (election_count >= MAX_ELECTIONS) {
        pthread_mutex_unlock(&election_mutex);
        return -2; /* Capacity reached */
    }

    /* Determine next ID */
    int next_id = 1;
    for (int i = 0; i < election_count; i++) {
        if (elections[i].id >= next_id) next_id = elections[i].id + 1;
    }

    Election *el = &elections[election_count];
    memset(el, 0, sizeof(Election));
    el->id = next_id;
    strncpy(el->title, title, NAME_LEN - 1);
    strncpy(el->description, description ? description : title, DESC_LEN - 1);
    strncpy(el->type, type ? type : "General", TYPE_LEN - 1);
    el->state = ELECTION_DRAFT;
    el->start_time = (start_time > 0) ? start_time : time(NULL);
    el->end_time = (end_time > 0) ? end_time : (el->start_time + 86400 * 3);
    el->require_otp = require_otp;
    el->results_declared = 0;

    /* Add default Booth #1 */
    el->booth_count = 1;
    el->booths[0] = (PollingBooth){ 1, next_id, "Main Campus Station 1", "Auditorium Hall", 0, 0 };

    election_count++;

    /* Save to disk */
    election_save_election(next_id);
    save_election_meta_file();

    if (out_id) *out_id = next_id;

    pthread_mutex_unlock(&election_mutex);

    char audit_det[128];
    snprintf(audit_det, sizeof(audit_det), "Created election #%d: '%s' (%s)", next_id, title, type);
    audit_log_record("ELECTION_CREATED", "HIGH", "ADMIN", audit_det);
    security_save_baseline_manifest();

    return 0;
}

/**
 * Updates election details before voting starts.
 */
int election_update_details(int election_id, const char *title, const char *description,
                            const char *type, time_t start_time, time_t end_time, int require_otp) {
    pthread_mutex_lock(&election_mutex);

    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }

    /* Lock modification once voting starts */
    if (el->state != ELECTION_DRAFT && el->state != ELECTION_PUBLISHED) {
        pthread_mutex_unlock(&election_mutex);
        return -2; /* Locked once voting begins */
    }

    if (title && strlen(title) > 0) strncpy(el->title, title, NAME_LEN - 1);
    if (description) strncpy(el->description, description, DESC_LEN - 1);
    if (type) strncpy(el->type, type, TYPE_LEN - 1);
    if (start_time > 0) el->start_time = start_time;
    if (end_time > 0) el->end_time = end_time;
    el->require_otp = require_otp;

    election_save_election(el->id);

    pthread_mutex_unlock(&election_mutex);

    char audit_det[128];
    snprintf(audit_det, sizeof(audit_det), "Updated election details for #%d ('%s')", el->id, el->title);
    audit_log_record("ELECTION_UPDATED", "MEDIUM", "ADMIN", audit_det);
    return 0;
}

/**
 * Updates lifecycle state for an election.
 */
int election_set_state(int election_id, ElectionState new_state) {
    pthread_mutex_lock(&election_mutex);

    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }

    /* Cannot start election without at least 2 candidates and 1 booth */
    if (new_state == ELECTION_ACTIVE) {
        if (el->candidate_count < 2) {
            pthread_mutex_unlock(&election_mutex);
            return -3; /* At least 2 candidates required */
        }
        if (el->booth_count < 1) {
            pthread_mutex_unlock(&election_mutex);
            return -4; /* At least 1 booth required */
        }
        if (el->start_time == 0) el->start_time = time(NULL);
        active_election_id = el->id;
    } else if (new_state == ELECTION_CLOSED) {
        if (el->end_time == 0) el->end_time = time(NULL);
        election_calculate_results(el);
    } else if (new_state == ELECTION_DECLARED) {
        el->results_declared = 1;
        election_calculate_results(el);
    }

    el->state = new_state;
    election_save_election(el->id);

    pthread_mutex_unlock(&election_mutex);

    char audit_det[128];
    snprintf(audit_det, sizeof(audit_det), "Election #%d state transitioned to %s", el->id, election_state_to_str(new_state));
    audit_log_record("ELECTION_STATE_CHANGE", "HIGH", "ADMIN", audit_det);
    security_save_baseline_manifest();

    return 0;
}

int election_declare_results(int election_id) {
    return election_set_state(election_id, ELECTION_DECLARED);
}

int election_delete_draft(int election_id) {
    pthread_mutex_lock(&election_mutex);
    int idx = -1;
    for (int i = 0; i < election_count; i++) {
        if (elections[i].id == election_id) {
            idx = i;
            break;
        }
    }
    if (idx == -1) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }

    /* Only draft elections may be deleted */
    if (elections[idx].state != ELECTION_DRAFT) {
        pthread_mutex_unlock(&election_mutex);
        return -2; /* Cannot delete active/published/archived elections */
    }

    /* Shift remaining */
    for (int i = idx; i < election_count - 1; i++) {
        elections[i] = elections[i + 1];
    }
    election_count--;

    save_election_meta_file();
    pthread_mutex_unlock(&election_mutex);

    char audit_det[64];
    snprintf(audit_det, sizeof(audit_det), "Deleted draft election #%d", election_id);
    audit_log_record("ELECTION_DELETED", "MEDIUM", "ADMIN", audit_det);

    return 0;
}

/* =========================================================================
 * CANDIDATE MANAGEMENT (ELECTION-SCOPED)
 * ========================================================================= */

int election_add_candidate(int election_id, const char *name, const char *party, const char *photo_url, int *out_cand_id) {
    if (!name || strlen(name) == 0) return -1;

    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }

    /* Rule: Lock modifications once voting begins */
    if (el->state != ELECTION_DRAFT && el->state != ELECTION_PUBLISHED) {
        pthread_mutex_unlock(&election_mutex);
        return -2; /* Election is active or closed */
    }

    if (el->candidate_count >= MAX_CANDIDATES_PER_ELECTION) {
        pthread_mutex_unlock(&election_mutex);
        return -3;
    }

    /* Unique ID */
    int next_cid = 1;
    for (int i = 0; i < el->candidate_count; i++) {
        if (el->candidates[i].id >= next_cid) next_cid = el->candidates[i].id + 1;
    }

    Candidate *c = &el->candidates[el->candidate_count++];
    c->id = next_cid;
    c->election_id = el->id;
    strncpy(c->name, name, NAME_LEN - 1);
    strncpy(c->party, party ? party : "Independent", PARTY_LEN - 1);
    strncpy(c->photo_url, (photo_url && strlen(photo_url) > 0) ? photo_url : "/images/others.png", PHOTO_LEN - 1);
    c->votes = 0;

    if (out_cand_id) *out_cand_id = next_cid;

    election_save_election(el->id);
    pthread_mutex_unlock(&election_mutex);

    char audit_det[128];
    snprintf(audit_det, sizeof(audit_det), "Added candidate '%s' to Election #%d", name, el->id);
    audit_log_record("CANDIDATE_ADDED", "LOW", "ADMIN", audit_det);

    return 0;
}

int election_update_candidate(int election_id, int candidate_id, const char *name, const char *party, const char *photo_url) {
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }

    if (el->state != ELECTION_DRAFT && el->state != ELECTION_PUBLISHED) {
        pthread_mutex_unlock(&election_mutex);
        return -2;
    }

    int found = 0;
    for (int i = 0; i < el->candidate_count; i++) {
        if (el->candidates[i].id == candidate_id) {
            if (name && strlen(name) > 0) strncpy(el->candidates[i].name, name, NAME_LEN - 1);
            if (party && strlen(party) > 0) strncpy(el->candidates[i].party, party, PARTY_LEN - 1);
            if (photo_url && strlen(photo_url) > 0) strncpy(el->candidates[i].photo_url, photo_url, PHOTO_LEN - 1);
            found = 1;
            break;
        }
    }

    if (!found) {
        pthread_mutex_unlock(&election_mutex);
        return -3;
    }

    election_save_election(el->id);
    pthread_mutex_unlock(&election_mutex);
    return 0;
}

int election_delete_candidate(int election_id, int candidate_id) {
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }

    if (el->state != ELECTION_DRAFT && el->state != ELECTION_PUBLISHED) {
        pthread_mutex_unlock(&election_mutex);
        return -2;
    }

    int idx = -1;
    for (int i = 0; i < el->candidate_count; i++) {
        if (el->candidates[i].id == candidate_id) {
            idx = i;
            break;
        }
    }

    if (idx == -1) {
        pthread_mutex_unlock(&election_mutex);
        return -3;
    }

    for (int i = idx; i < el->candidate_count - 1; i++) {
        el->candidates[i] = el->candidates[i + 1];
    }
    el->candidate_count--;

    election_save_election(el->id);
    pthread_mutex_unlock(&election_mutex);
    return 0;
}

int election_get_candidate_count(int election_id) {
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    int c = el ? el->candidate_count : 0;
    pthread_mutex_unlock(&election_mutex);
    return c;
}

int election_get_candidate_by_id(int election_id, int candidate_id, Candidate *out_cand) {
    if (!out_cand) return -1;
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }
    for (int i = 0; i < el->candidate_count; i++) {
        if (el->candidates[i].id == candidate_id) {
            *out_cand = el->candidates[i];
            pthread_mutex_unlock(&election_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&election_mutex);
    return -1;
}

int election_get_candidate_by_index(int election_id, int idx, Candidate *out_cand) {
    if (!out_cand) return -1;
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el || idx < 0 || idx >= el->candidate_count) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }
    *out_cand = el->candidates[idx];
    pthread_mutex_unlock(&election_mutex);
    return 0;
}

/* =========================================================================
 * POLLING BOOTH MANAGEMENT (ELECTION-SCOPED)
 * ========================================================================= */

int election_add_booth(int election_id, int id, const char *name, const char *location) {
    if (!name || strlen(name) == 0) return -1;

    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }

    if (el->state != ELECTION_DRAFT && el->state != ELECTION_PUBLISHED) {
        pthread_mutex_unlock(&election_mutex);
        return -2;
    }

    if (el->booth_count >= MAX_BOOTHS_PER_ELECTION) {
        pthread_mutex_unlock(&election_mutex);
        return -3;
    }

    /* Assign or validate booth ID */
    int bid = id;
    if (bid <= 0) {
        bid = 1;
        for (int i = 0; i < el->booth_count; i++) {
            if (el->booths[i].id >= bid) bid = el->booths[i].id + 1;
        }
    } else {
        /* Check duplicate booth ID within this election */
        for (int i = 0; i < el->booth_count; i++) {
            if (el->booths[i].id == bid) {
                pthread_mutex_unlock(&election_mutex);
                return -4; /* Duplicate booth ID */
            }
        }
    }

    PollingBooth *b = &el->booths[el->booth_count++];
    b->id = bid;
    b->election_id = el->id;
    strncpy(b->name, name, NAME_LEN - 1);
    strncpy(b->location, location ? location : "Designated Voting Station", NAME_LEN - 1);
    b->total_registered = 0;
    b->votes_cast = 0;

    election_save_election(el->id);
    pthread_mutex_unlock(&election_mutex);

    char audit_det[128];
    snprintf(audit_det, sizeof(audit_det), "Added booth #%d ('%s') to Election #%d", bid, name, el->id);
    audit_log_record("BOOTH_ADDED", "LOW", "ADMIN", audit_det);

    return 0;
}

int election_update_booth(int election_id, int id, const char *name, const char *location) {
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }

    if (el->state != ELECTION_DRAFT && el->state != ELECTION_PUBLISHED) {
        pthread_mutex_unlock(&election_mutex);
        return -2;
    }

    int found = 0;
    for (int i = 0; i < el->booth_count; i++) {
        if (el->booths[i].id == id) {
            if (name && strlen(name) > 0) strncpy(el->booths[i].name, name, NAME_LEN - 1);
            if (location && strlen(location) > 0) strncpy(el->booths[i].location, location, NAME_LEN - 1);
            found = 1;
            break;
        }
    }

    if (!found) {
        pthread_mutex_unlock(&election_mutex);
        return -3;
    }

    election_save_election(el->id);
    pthread_mutex_unlock(&election_mutex);
    return 0;
}

int election_delete_booth(int election_id, int id) {
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }

    if (el->state != ELECTION_DRAFT && el->state != ELECTION_PUBLISHED) {
        pthread_mutex_unlock(&election_mutex);
        return -2;
    }

    int idx = -1;
    for (int i = 0; i < el->booth_count; i++) {
        if (el->booths[i].id == id) {
            idx = i;
            break;
        }
    }

    if (idx == -1) {
        pthread_mutex_unlock(&election_mutex);
        return -3;
    }

    for (int i = idx; i < el->booth_count - 1; i++) {
        el->booths[i] = el->booths[i + 1];
    }
    el->booth_count--;

    election_save_election(el->id);
    pthread_mutex_unlock(&election_mutex);
    return 0;
}

int election_get_booth_count(int election_id) {
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    int c = el ? el->booth_count : 0;
    pthread_mutex_unlock(&election_mutex);
    return c;
}

int election_get_booth_by_id(int election_id, int id, PollingBooth *out_booth) {
    if (!out_booth) return -1;
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }
    for (int i = 0; i < el->booth_count; i++) {
        if (el->booths[i].id == id) {
            *out_booth = el->booths[i];
            pthread_mutex_unlock(&election_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&election_mutex);
    return -1;
}

int election_get_booth_by_index(int election_id, int idx, PollingBooth *out_booth) {
    if (!out_booth) return -1;
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el || idx < 0 || idx >= el->booth_count) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }
    *out_booth = el->booths[idx];
    pthread_mutex_unlock(&election_mutex);
    return 0;
}

/* =========================================================================
 * VOTER MANAGEMENT (ELECTION-SCOPED)
 * ========================================================================= */

int election_is_valid_voter_id_format(const char *id) {
    if (!id) return 0;
    size_t len = strlen(id);
    if (len < 3 || len > 16) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isalnum((unsigned char)id[i]) && id[i] != '-' && id[i] != '_') {
            return 0;
        }
    }
    return 1;
}

int election_add_voter(int election_id, const char *voter_id, const char *name, int booth_id) {
    if (!election_is_valid_voter_id_format(voter_id)) return -1;

    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }

    /* Prevent duplicate registration within this specific election */
    for (int i = 0; i < el->voter_count; i++) {
        if (strcasecmp(el->voters[i].id, voter_id) == 0) {
            pthread_mutex_unlock(&election_mutex);
            return -2; /* Already registered in this election */
        }
    }

    if (el->voter_count >= MAX_VOTERS_PER_ELECTION) {
        pthread_mutex_unlock(&election_mutex);
        return -3;
    }

    int actual_booth = (booth_id > 0) ? booth_id : 1;

    Voter *v = &el->voters[el->voter_count++];
    strncpy(v->id, voter_id, ID_LEN - 1);
    v->election_id = el->id;
    if (name && strlen(name) > 0) {
        strncpy(v->name, name, NAME_LEN - 1);
    } else {
        snprintf(v->name, NAME_LEN, "Voter %s", voter_id);
    }
    v->booth_id = actual_booth;
    v->has_voted = 0;
    strcpy(v->voted_at, "NONE");

    /* Increment booth counter */
    for (int b = 0; b < el->booth_count; b++) {
        if (el->booths[b].id == actual_booth) {
            el->booths[b].total_registered++;
            break;
        }
    }

    election_save_election(el->id);
    pthread_mutex_unlock(&election_mutex);

    char audit_det[128];
    snprintf(audit_det, sizeof(audit_det), "Registered voter '%s' into Election #%d (Booth #%d)", voter_id, el->id, actual_booth);
    audit_log_record("VOTER_REGISTRATION", "LOW", "ADMIN", audit_det);

    return 0;
}

int election_import_voters_csv_detailed(int election_id, const char *csv_content,
                                        int *out_added, int *out_skipped,
                                        char *out_details, size_t max_details_len) {
    if (out_details && max_details_len > 0) out_details[0] = '\0';
    if (!csv_content) return -1;

    int added = 0, skipped = 0;
    char *copy = strdup(csv_content);
    if (!copy) return -1;

    int row_num = 0;
    size_t d_len = 0;

    char *saveptr_line = NULL;
    char *line = strtok_r(copy, "\r\n", &saveptr_line);
    while (line) {
        row_num++;
        str_trim(line);
        if (line[0] != '#' && strlen(line) > 0) {
            char vid[ID_LEN] = {0}, vname[NAME_LEN] = {0};
            int booth_id = 1;

            char *saveptr_tok = NULL;
            char *tok = strtok_r(line, ",|", &saveptr_tok);
            if (tok) { str_trim(tok); strncpy(vid, tok, ID_LEN - 1); }
            tok = strtok_r(NULL, ",|", &saveptr_tok);
            if (tok) { str_trim(tok); strncpy(vname, tok, NAME_LEN - 1); }
            tok = strtok_r(NULL, ",|", &saveptr_tok);
            if (tok) { booth_id = atoi(tok); }

            /* Skip header rows */
            if (strcasecmp(vid, "VoterID") == 0 || strcasecmp(vid, "ID") == 0 ||
                strcasecmp(vid, "voter_id") == 0) {
                line = strtok_r(NULL, "\r\n", &saveptr_line);
                continue;
            }

            if (!election_is_valid_voter_id_format(vid)) {
                skipped++;
                if (out_details && d_len < max_details_len - 128) {
                    d_len += snprintf(out_details + d_len, max_details_len - d_len,
                                      "%sRow %d: '%s' has invalid Voter ID format (must be 3-16 alphanumeric characters)",
                                      (d_len > 0) ? "; " : "", row_num, vid);
                }
            } else {
                int res = election_add_voter(election_id, vid, vname, booth_id);
                if (res == 0) {
                    added++;
                } else if (res == -2) {
                    skipped++;
                    if (out_details && d_len < max_details_len - 128) {
                        d_len += snprintf(out_details + d_len, max_details_len - d_len,
                                          "%sRow %d: '%s' is already registered (Duplicate voter ID in this election)",
                                          (d_len > 0) ? "; " : "", row_num, vid);
                    }
                } else {
                    skipped++;
                    if (out_details && d_len < max_details_len - 128) {
                        d_len += snprintf(out_details + d_len, max_details_len - d_len,
                                          "%sRow %d: '%s' registration failed (code %d)",
                                          (d_len > 0) ? "; " : "", row_num, vid, res);
                    }
                }
            }
        }
        line = strtok_r(NULL, "\r\n", &saveptr_line);
    }
    free(copy);

    if (out_added) *out_added = added;
    if (out_skipped) *out_skipped = skipped;
    return 0;
}

int election_import_voters_csv(int election_id, const char *csv_content, int *out_added, int *out_skipped) {
    return election_import_voters_csv_detailed(election_id, csv_content, out_added, out_skipped, NULL, 0);
}

int election_delete_voter(int election_id, const char *voter_id) {
    if (!voter_id) return -1;

    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }

    if (el->state != ELECTION_DRAFT && el->state != ELECTION_PUBLISHED) {
        pthread_mutex_unlock(&election_mutex);
        return -2;
    }

    int idx = -1;
    for (int i = 0; i < el->voter_count; i++) {
        if (strcasecmp(el->voters[i].id, voter_id) == 0) {
            idx = i;
            break;
        }
    }

    if (idx == -1) {
        pthread_mutex_unlock(&election_mutex);
        return -3;
    }

    int b_id = el->voters[idx].booth_id;
    for (int b = 0; b < el->booth_count; b++) {
        if (el->booths[b].id == b_id && el->booths[b].total_registered > 0) {
            el->booths[b].total_registered--;
            break;
        }
    }

    for (int i = idx; i < el->voter_count - 1; i++) {
        el->voters[i] = el->voters[i + 1];
    }
    el->voter_count--;

    election_save_election(el->id);
    pthread_mutex_unlock(&election_mutex);
    return 0;
}

int election_check_voter_status(int election_id, const char *voter_id, Voter *out_voter) {
    if (!voter_id) return -1;

    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }

    for (int i = 0; i < el->voter_count; i++) {
        if (strcasecmp(el->voters[i].id, voter_id) == 0) {
            if (out_voter) *out_voter = el->voters[i];
            int status = el->voters[i].has_voted ? 1 : 0;
            pthread_mutex_unlock(&election_mutex);
            return status;
        }
    }

    pthread_mutex_unlock(&election_mutex);
    return -1; /* Not found */
}

int election_get_voters_count(int election_id) {
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    int c = el ? el->voter_count : 0;
    pthread_mutex_unlock(&election_mutex);
    return c;
}

int election_get_voter_by_index(int election_id, int idx, Voter *out_voter) {
    if (!out_voter) return -1;
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el || idx < 0 || idx >= el->voter_count) {
        pthread_mutex_unlock(&election_mutex);
        return -1;
    }
    *out_voter = el->voters[idx];
    pthread_mutex_unlock(&election_mutex);
    return 0;
}

int election_search_voters(int election_id, const char *query, Voter *out_results, int max_results) {
    if (!out_results || max_results <= 0) return 0;

    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return 0;
    }

    int found = 0;
    for (int i = 0; i < el->voter_count && found < max_results; i++) {
        if (!query || strlen(query) == 0 ||
            strcasestr(el->voters[i].id, query) ||
            strcasestr(el->voters[i].name, query)) {
            out_results[found++] = el->voters[i];
        }
    }

    pthread_mutex_unlock(&election_mutex);
    return found;
}

/* =========================================================================
 * VOTING LOGIC WITH STRICT BALLOT SECRECY & ANONYMOUS RECEIPTS
 * ========================================================================= */

int election_cast_ballot(int election_id, const char *voter_id, int candidate_id, int booth_id,
                         char *out_receipt_token, char *out_cand_name) {
    if (!voter_id) return -1;

    pthread_mutex_lock(&election_mutex);

    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        return -10;
    }

    /* 1. Check Election Active State */
    if (el->state != ELECTION_ACTIVE) {
        pthread_mutex_unlock(&election_mutex);
        return -10; /* Election is NOT ACTIVE (e.g. DRAFT, PAUSED, CLOSED) */
    }

    /* 2. Check Candidate Validity in this Election */
    int cand_idx = -1;
    for (int i = 0; i < el->candidate_count; i++) {
        if (el->candidates[i].id == candidate_id) {
            cand_idx = i;
            break;
        }
    }
    if (cand_idx == -1) {
        pthread_mutex_unlock(&election_mutex);
        return -3; /* Invalid candidate */
    }

    /* 3. Check Voter Status in this Election */
    int voter_idx = -1;
    for (int i = 0; i < el->voter_count; i++) {
        if (strcasecmp(el->voters[i].id, voter_id) == 0) {
            voter_idx = i;
            break;
        }
    }
    if (voter_idx == -1) {
        pthread_mutex_unlock(&election_mutex);
        return -1; /* Voter not registered in this election */
    }
    if (el->voters[voter_idx].has_voted) {
        pthread_mutex_unlock(&election_mutex);
        return -2; /* Already voted in this election - duplicate blocked */
    }

    int actual_booth = (booth_id > 0) ? booth_id : el->voters[voter_idx].booth_id;

    /* 4. Generate Cryptographically Secure Anonymous Receipt Token (BLT-XXXXX) */
    unsigned char rand_bytes[16];
    if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1) {
        for (int i = 0; i < 16; i++) rand_bytes[i] = (unsigned char)(rand() % 256);
    }
    char token_hex[33];
    for (int i = 0; i < 16; i++) sprintf(token_hex + (i * 2), "%02x", rand_bytes[i]);
    token_hex[32] = '\0';

    char receipt_token[TOKEN_LEN];
    snprintf(receipt_token, sizeof(receipt_token), "BLT-%s", token_hex);

    /* 5. Separate Storage Step A: Mark Voter as Voted (NO candidate selection stored!)
     * Decouple timestamp to date-only so correlation by identical second is impossible. */
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char voter_date[TIMESTAMP_LEN];
    strftime(voter_date, sizeof(voter_date), "%Y-%m-%d", t);

    el->voters[voter_idx].has_voted = 1;
    strncpy(el->voters[voter_idx].voted_at, voter_date, TIMESTAMP_LEN - 1);

    /* 6. Separate Storage Step B: Store Anonymous Ballot (NO voter ID stored!)
     * Decouple exact timestamp with jitter to prevent cross-table timing analysis. */
    int jitter = (rand() % 300) - 150;
    time_t jittered_time = now + jitter;
    struct tm *jt = localtime(&jittered_time);
    char ballot_timestamp[TIMESTAMP_LEN];
    strftime(ballot_timestamp, sizeof(ballot_timestamp), "%Y-%m-%d %H:%M:%S", jt);

    if (el->ballot_count < MAX_BALLOTS_PER_ELECTION) {
        AnonymousBallot *ab = &el->ballots[el->ballot_count++];
        strncpy(ab->token, receipt_token, TOKEN_LEN - 1);
        ab->election_id = el->id;
        ab->candidate_id = candidate_id;
        strncpy(ab->candidate_name, el->candidates[cand_idx].name, NAME_LEN - 1);
        ab->booth_id = actual_booth;
        strncpy(ab->timestamp, ballot_timestamp, TIMESTAMP_LEN - 1);
    }

    /* 7. Increment Tallies */
    el->candidates[cand_idx].votes++;
    for (int b = 0; b < el->booth_count; b++) {
        if (el->booths[b].id == actual_booth) {
            el->booths[b].votes_cast++;
            break;
        }
    }

    election_calculate_results(el);
    election_save_election(el->id);

    if (out_receipt_token) {
        strncpy(out_receipt_token, receipt_token, TOKEN_LEN - 1);
        out_receipt_token[TOKEN_LEN - 1] = '\0';
    }
    if (out_cand_name) {
        strncpy(out_cand_name, el->candidates[cand_idx].name, NAME_LEN - 1);
    }

    pthread_mutex_unlock(&election_mutex);

    /* 8. Tamper-Evident Audit Record (Logs anonymous token & booth ONLY, zero voter choice linkage) */
    char audit_det[128];
    snprintf(audit_det, sizeof(audit_det), "Ballot cast in Election #%d at Booth #%d, Token %s", el->id, actual_booth, receipt_token);
    audit_log_record("BALLOT_CAST", "LOW", "VOTING_CLIENT", audit_det);
    security_save_baseline_manifest();

    return 0;
}

/**
 * Verifies whether an anonymous receipt token exists in an election's ballot box.
 * Guarantees Ballot Secrecy: returns confirmation WITHOUT revealing candidate choice.
 */
int election_verify_receipt(int election_id, const char *token, int *out_booth_id, char *out_timestamp, char *out_election_title) {
    if (!token || strlen(token) == 0) return 0;

    pthread_mutex_lock(&election_mutex);

    for (int e = 0; e < election_count; e++) {
        if (election_id > 0 && elections[e].id != election_id) continue;

        Election *el = &elections[e];
        for (int i = 0; i < el->ballot_count; i++) {
            if (strcmp(el->ballots[i].token, token) == 0) {
                if (out_booth_id) *out_booth_id = el->ballots[i].booth_id;
                if (out_timestamp) strncpy(out_timestamp, el->ballots[i].timestamp, TIMESTAMP_LEN - 1);
                if (out_election_title) strncpy(out_election_title, el->title, NAME_LEN - 1);
                pthread_mutex_unlock(&election_mutex);
                return 1; /* Valid ballot verified */
            }
        }
    }

    pthread_mutex_unlock(&election_mutex);
    return 0; /* Not found */
}

/* =========================================================================
 * ANALYTICS & RESULTS REPORTING
 * ========================================================================= */

void election_generate_results_json(int election_id, char *output, size_t max_len, int is_admin) {
    pthread_mutex_lock(&election_mutex);

    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        snprintf(output, max_len, "{\"error\":\"ELECTION_NOT_FOUND\"}");
        return;
    }

    election_calculate_results(el);

    int total_votes = el->ballot_count;
    int remaining = el->voter_count - el->ballot_count;
    if (remaining < 0) remaining = 0;
    float turnout = (el->voter_count > 0) ? ((float)total_votes / el->voter_count) * 100.0f : 0.0f;

    /* If results are not declared and requester is NOT admin, keep candidate counts secret */
    if (!is_admin && !el->results_declared) {
        snprintf(output, max_len,
                 "{\"election_id\":%d,\"election_title\":\"%s\",\"type\":\"%s\",\"election_status\":\"%s\",\"results_declared\":false,"
                 "\"total_votes\":%d,\"total_registered\":%d,\"remaining_voters\":%d,\"turnout_pct\":%.1f,"
                 "\"message\":\"Official election results are sealed until formal declaration by the Election Commission.\"}",
                 el->id, el->title, el->type, election_state_to_str(el->state),
                 total_votes, el->voter_count, remaining, turnout);
        pthread_mutex_unlock(&election_mutex);
        return;
    }

    char winner_photo[256] = "/images/others.png";
    for (int i = 0; i < el->candidate_count; i++) {
        if (strcmp(el->candidates[i].name, el->winner_name) == 0 && strlen(el->candidates[i].photo_url) > 0) {
            strncpy(winner_photo, el->candidates[i].photo_url, sizeof(winner_photo) - 1);
            break;
        }
    }

    size_t w = snprintf(output, max_len,
        "{\"election_id\":%d,\"election_title\":\"%s\",\"type\":\"%s\",\"total_votes\":%d,\"total_registered\":%d,\"remaining_voters\":%d,\"turnout_pct\":%.1f,\"election_status\":\"%s\",\"results_declared\":%s,\"leader\":\"%s\",\"leader_party\":\"%s\",\"winner_votes\":%d,\"winner_photo\":\"%s\",\"runner_up\":\"%s\",\"runner_up_votes\":%d,\"margin\":%d,\"is_tie\":%s,\"candidates\":[",
        el->id, el->title, el->type, total_votes, el->voter_count, remaining, turnout,
        election_state_to_str(el->state), el->results_declared ? "true" : "false",
        el->winner_name, el->winner_party, el->winner_votes, winner_photo,
        el->runner_up_name, el->runner_up_votes, el->margin_of_victory,
        el->is_tie ? "true" : "false");

    for (int i = 0; i < el->candidate_count; i++) {
        float pct = (total_votes > 0) ? ((float)el->candidates[i].votes / total_votes) * 100.0f : 0.0f;
        char item[256];
        snprintf(item, sizeof(item),
                 "%s{\"id\":%d,\"name\":\"%s\",\"party\":\"%s\",\"photo_url\":\"%s\",\"votes\":%d,\"percentage\":%.1f}",
                 (i > 0) ? "," : "",
                 el->candidates[i].id, el->candidates[i].name, el->candidates[i].party,
                 el->candidates[i].photo_url, el->candidates[i].votes, pct);
        if (w + strlen(item) < max_len - 16) {
            w += snprintf(output + w, max_len - w, "%s", item);
        }
    }
    strncat(output, "]}", max_len - strlen(output) - 1);

    pthread_mutex_unlock(&election_mutex);
}

void election_generate_results_text(int election_id, char *output, size_t max_len) {
    pthread_mutex_lock(&election_mutex);

    Election *el = find_election_locked(election_id);
    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        snprintf(output, max_len, "Election not found.\n");
        return;
    }

    election_calculate_results(el);

    int total_votes = el->ballot_count;
    float turnout = (el->voter_count > 0) ? ((float)total_votes / el->voter_count) * 100.0f : 0.0f;

    size_t w = snprintf(output, max_len,
        "\nElection: %s [%s]\nStatus:   %s (Results %s)\nTurnout:  %d / %d (%.1f%%)\n---------------------------------------------------------\nID  Candidate Name       Party                          Votes   Share   \n---------------------------------------------------------\n",
        el->title, el->type, election_state_to_str(el->state),
        el->results_declared ? "DECLARED" : "SEALED",
        total_votes, el->voter_count, turnout);

    for (int i = 0; i < el->candidate_count; i++) {
        float share = (total_votes > 0) ? ((float)el->candidates[i].votes / total_votes) * 100.0f : 0.0f;
        char line[256];
        snprintf(line, sizeof(line), "%-3d %-20s %-30s %-7d %5.1f%%\n",
                 el->candidates[i].id, el->candidates[i].name, el->candidates[i].party,
                 el->candidates[i].votes, share);
        if (w + strlen(line) < max_len - 128) {
            w += snprintf(output + w, max_len - w, "%s", line);
        }
    }

    char footer[256];
    if (el->is_tie) {
        snprintf(footer, sizeof(footer), "---------------------------------------------------------\nOutcome:  %s with %d votes!\n",
                 el->winner_name, el->winner_votes);
    } else {
        snprintf(footer, sizeof(footer), "---------------------------------------------------------\nLeader:   %s (%s) with %d votes (Margin: %d)!\n",
                 el->winner_name, el->winner_party, el->winner_votes, el->margin_of_victory);
    }
    strncat(output, footer, max_len - strlen(output) - 1);

    pthread_mutex_unlock(&election_mutex);
}

void election_get_analytics_json(int election_id, char *output, size_t max_len) {
    pthread_mutex_lock(&election_mutex);

    int total_elections = election_count;
    int active_cnt = 0, upcoming_cnt = 0, closed_cnt = 0;

    for (int i = 0; i < election_count; i++) {
        if (elections[i].state == ELECTION_ACTIVE) active_cnt++;
        else if (elections[i].state == ELECTION_DRAFT || elections[i].state == ELECTION_PUBLISHED) upcoming_cnt++;
        else closed_cnt++;
    }

    Election *el = find_election_locked(election_id);
    if (!el && election_count > 0) el = &elections[0];

    if (!el) {
        pthread_mutex_unlock(&election_mutex);
        snprintf(output, max_len, "{\"total_elections\":0,\"active_elections\":0,\"upcoming_elections\":0,\"completed_elections\":0}");
        return;
    }

    election_calculate_results(el);

    int total_votes = el->ballot_count;
    int remaining = el->voter_count - el->ballot_count;
    if (remaining < 0) remaining = 0;
    float turnout = (el->voter_count > 0) ? ((float)total_votes / el->voter_count) * 100.0f : 0.0f;

    size_t w = snprintf(output, max_len,
        "{\"total_elections\":%d,\"active_elections\":%d,\"upcoming_elections\":%d,\"completed_elections\":%d,"
        "\"election\":{\"id\":%d,\"title\":\"%s\",\"type\":\"%s\",\"description\":\"%s\",\"state\":\"%s\","
        "\"start_time\":%lld,\"end_time\":%lld,\"require_otp\":%s,\"results_declared\":%s,"
        "\"total_registered\":%d,\"total_votes\":%d,\"remaining_voters\":%d,\"turnout_pct\":%.1f,"
        "\"winner_name\":\"%s\",\"winner_party\":\"%s\",\"winner_votes\":%d,"
        "\"runner_up_name\":\"%s\",\"runner_up_votes\":%d,\"margin\":%d,\"is_tie\":%s,"
        "\"candidates\":[",
        total_elections, active_cnt, upcoming_cnt, closed_cnt,
        el->id, el->title, el->type, el->description, election_state_to_str(el->state),
        (long long)el->start_time, (long long)el->end_time,
        el->require_otp ? "true" : "false", el->results_declared ? "true" : "false",
        el->voter_count, total_votes, remaining, turnout,
        el->winner_name, el->winner_party, el->winner_votes,
        el->runner_up_name, el->runner_up_votes, el->margin_of_victory,
        el->is_tie ? "true" : "false");

    for (int i = 0; i < el->candidate_count; i++) {
        float pct = (total_votes > 0) ? ((float)el->candidates[i].votes / total_votes) * 100.0f : 0.0f;
        char item[256];
        snprintf(item, sizeof(item),
                 "%s{\"id\":%d,\"name\":\"%s\",\"party\":\"%s\",\"votes\":%d,\"percentage\":%.1f}",
                 (i > 0) ? "," : "",
                 el->candidates[i].id, el->candidates[i].name, el->candidates[i].party,
                 el->candidates[i].votes, pct);
        if (w + strlen(item) < max_len - 512) {
            w += snprintf(output + w, max_len - w, "%s", item);
        }
    }

    w += snprintf(output + w, max_len - w, "],\"booths\":[");
    for (int i = 0; i < el->booth_count; i++) {
        float b_turnout = (el->booths[i].total_registered > 0) ?
            ((float)el->booths[i].votes_cast / el->booths[i].total_registered) * 100.0f : 0.0f;
        char item[256];
        snprintf(item, sizeof(item),
                 "%s{\"id\":%d,\"name\":\"%s\",\"location\":\"%s\",\"registered\":%d,\"votes_cast\":%d,\"turnout_pct\":%.1f}",
                 (i > 0) ? "," : "",
                 el->booths[i].id, el->booths[i].name, el->booths[i].location,
                 el->booths[i].total_registered, el->booths[i].votes_cast, b_turnout);
        if (w + strlen(item) < max_len - 64) {
            w += snprintf(output + w, max_len - w, "%s", item);
        }
    }
    strncat(output, "]}}", max_len - strlen(output) - 1);

    pthread_mutex_unlock(&election_mutex);
}

void election_generate_monitoring_json(int election_id, char *output, size_t max_len) {
    election_get_analytics_json(election_id, output, max_len);
}

/* =========================================================================
 * LEGACY SINGLE-ELECTION WRAPPERS (Preserves 100% backward compatibility)
 * ========================================================================= */

int legacy_election_get_state(void) {
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(active_election_id);
    int s = el ? el->state : ELECTION_ACTIVE;
    pthread_mutex_unlock(&election_mutex);
    return s;
}

const char *legacy_election_get_state_str(void) {
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(active_election_id);
    const char *s = el ? election_state_to_str(el->state) : "ACTIVE";
    pthread_mutex_unlock(&election_mutex);
    return s;
}

int legacy_election_set_state(ElectionState new_state) {
    return election_set_state(active_election_id, new_state);
}

ElectionInfo legacy_election_get_info(void) {
    ElectionInfo info;
    memset(&info, 0, sizeof(info));
    pthread_mutex_lock(&election_mutex);
    Election *el = find_election_locked(active_election_id);
    if (el) {
        strncpy(info.title, el->title, NAME_LEN - 1);
        info.state = el->state;
        info.start_time = el->start_time;
        info.end_time = el->end_time;
        info.require_otp = el->require_otp;
    }
    pthread_mutex_unlock(&election_mutex);
    return info;
}

int legacy_election_check_voter_status(const char *id, Voter *out_voter) {
    return election_check_voter_status(active_election_id, id, out_voter);
}

int legacy_election_add_voter(const char *id, const char *name, int booth_id) {
    return election_add_voter(active_election_id, id, name, booth_id);
}

int legacy_election_import_voters_csv(const char *csv_content, int *out_added, int *out_skipped) {
    return election_import_voters_csv(active_election_id, csv_content, out_added, out_skipped);
}

int legacy_election_get_voters_count(void) {
    return election_get_voters_count(active_election_id);
}

int legacy_election_get_candidate_count(void) {
    return election_get_candidate_count(active_election_id);
}

int legacy_election_get_candidate_by_id(int id, Candidate *out_cand) {
    return election_get_candidate_by_id(active_election_id, id, out_cand);
}

int legacy_election_get_candidate_by_index(int idx, Candidate *out_cand) {
    return election_get_candidate_by_index(active_election_id, idx, out_cand);
}

int legacy_election_get_booth_count(void) {
    return election_get_booth_count(active_election_id);
}

int legacy_election_get_booth_by_id(int id, PollingBooth *out_booth) {
    return election_get_booth_by_id(active_election_id, id, out_booth);
}

int legacy_election_get_booth_by_index(int idx, PollingBooth *out_booth) {
    return election_get_booth_by_index(active_election_id, idx, out_booth);
}

int legacy_election_cast_ballot(const char *voter_id, int candidate_id, int booth_id,
                                char *out_receipt_token, char *out_cand_name) {
    return election_cast_ballot(active_election_id, voter_id, candidate_id, booth_id, out_receipt_token, out_cand_name);
}

void legacy_election_generate_results_json(char *output, size_t max_len) {
    election_generate_results_json(active_election_id, output, max_len, 1);
}

void legacy_election_generate_results_text(char *output, size_t max_len) {
    election_generate_results_text(active_election_id, output, max_len);
}
