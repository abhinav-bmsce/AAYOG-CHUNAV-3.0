/**
 * ============================================================================
 * Title:       AAYOG_CHUNAV 2.0 - HTTP Protocol & API Dispatcher
 * File:        src/http.c
 * Description: HTTP/1.1 request handling over plain POSIX sockets and TLS streams.
 *              Implements voter endpoints, 2FA OTP flows, administrative controls,
 *              tamper verification, and CSV/PDF report downloads.
 * ============================================================================
 */

#include "http.h"
#include "election.h"
#include "security.h"
#include "admin.h"
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

/**
 * Transport abstraction: Reads from TLS stream or plain socket
 */
ssize_t conn_read(Connection *conn, void *buf, size_t num) {
    if (!conn) return -1;
    if (conn->is_tls && conn->ssl) {
        return SSL_read(conn->ssl, buf, (int)num);
    }
    return recv(conn->socket_fd, buf, num, 0);
}

/**
 * Transport abstraction: Writes to TLS stream or plain socket
 */
ssize_t conn_write(Connection *conn, const void *buf, size_t num) {
    if (!conn) return -1;
    if (conn->is_tls && conn->ssl) {
        return SSL_write(conn->ssl, buf, (int)num);
    }
    return send(conn->socket_fd, buf, num, 0);
}

/**
 * Reads full HTTP request buffering across partial socket / TLS reads
 */
ssize_t http_read_full_request(Connection *conn, char *buffer, size_t max_len) {
    if (!conn || !buffer || max_len == 0) return -1;
    size_t total = 0;
    buffer[0] = '\0';

    /* Read initial segment */
    ssize_t r = conn_read(conn, buffer, max_len - 1);
    if (r <= 0) return r;
    total = (size_t)r;
    buffer[total] = '\0';

    /* If not an HTTP request method, return immediately for custom TCP CLI protocol */
    if (strncmp(buffer, "GET ", 4) != 0 &&
        strncmp(buffer, "POST ", 5) != 0 &&
        strncmp(buffer, "HEAD ", 5) != 0 &&
        strncmp(buffer, "OPTIONS ", 8) != 0 &&
        strncmp(buffer, "PUT ", 4) != 0 &&
        strncmp(buffer, "DELETE ", 7) != 0) {
        return (ssize_t)total;
    }

    /* For HTTP requests: ensure headers are fully received (\r\n\r\n or \n\n) */
    while (total < max_len - 1 && !strstr(buffer, "\r\n\r\n") && !strstr(buffer, "\n\n")) {
        r = conn_read(conn, buffer + total, max_len - 1 - total);
        if (r <= 0) break;
        total += (size_t)r;
        buffer[total] = '\0';
    }

    /* Check for Content-Length to ensure request body is completely received */
    const char *cl = strstr(buffer, "Content-Length:");
    if (!cl) cl = strstr(buffer, "content-length:");
    if (cl) {
        int content_len = atoi(cl + 15);
        const char *body_start = strstr(buffer, "\r\n\r\n");
        if (body_start) {
            body_start += 4;
        } else {
            body_start = strstr(buffer, "\n\n");
            if (body_start) body_start += 2;
        }

        if (body_start && content_len > 0) {
            size_t body_read = total - (size_t)(body_start - buffer);
            while (body_read < (size_t)content_len && total < max_len - 1) {
                size_t needed = (size_t)content_len - body_read;
                if (needed > max_len - 1 - total) needed = max_len - 1 - total;
                r = conn_read(conn, buffer + total, needed);
                if (r <= 0) break;
                total += (size_t)r;
                body_read += (size_t)r;
                buffer[total] = '\0';
            }
        }
    }

    return (ssize_t)total;
}

/**
 * Sends binary HTTP response
 */
void http_send_response_bytes(Connection *conn, int status_code, const char *status_text,
                              const char *content_type, const void *body, size_t body_len,
                              int is_head, const char *extra_headers) {
    int close_conn = (conn && conn->should_close);
    if (extra_headers && (strstr(extra_headers, "Connection: close") || strstr(extra_headers, "connection: close"))) {
        close_conn = 1;
        if (conn) conn->should_close = 1;
    }

    char header[1024];
    int hlen = snprintf(header, sizeof(header),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Access-Control-Allow-Methods: GET, POST, HEAD, OPTIONS\r\n"
             "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
             "%s"
             "%s"
             "\r\n",
             status_code, status_text, content_type, body_len,
             close_conn ? "Connection: close\r\n" : "Connection: keep-alive\r\nKeep-Alive: timeout=30, max=100\r\n",
             extra_headers ? extra_headers : "");

    if (hlen < 0) return;

    /* Pack header and body together if <= 65536 bytes to guarantee atomic TCP/TLS segment transmission */
    size_t payload_len = (!is_head && body && body_len > 0) ? body_len : 0;
    size_t total_len = (size_t)hlen + payload_len;

    if (total_len <= 65536) {
        char packet[65536];
        memcpy(packet, header, (size_t)hlen);
        if (payload_len > 0) {
            memcpy(packet + hlen, body, payload_len);
        }
        conn_write(conn, packet, total_len);
    } else {
        conn_write(conn, header, (size_t)hlen);
        if (payload_len > 0) {
            conn_write(conn, body, payload_len);
        }
    }
}

void http_send_response(Connection *conn, int status_code, const char *status_text,
                        const char *content_type, const char *body, int is_head) {
    size_t len = body ? strlen(body) : 0;
    http_send_response_bytes(conn, status_code, status_text, content_type, body, len, is_head, NULL);
}

void http_send_json(Connection *conn, int status_code, const char *json_body) {
    const char *status_text = "OK";
    if (status_code == 201) status_text = "Created";
    else if (status_code == 400) status_text = "Bad Request";
    else if (status_code == 401) status_text = "Unauthorized";
    else if (status_code == 403) status_text = "Forbidden";
    else if (status_code == 404) status_text = "Not Found";
    else if (status_code == 409) status_text = "Conflict";
    else if (status_code == 429) status_text = "Too Many Requests";
    else if (status_code >= 500) status_text = "Internal Server Error";

    http_send_response(conn, status_code, status_text, "application/json; charset=utf-8", json_body, 0);
}

void http_send_error(Connection *conn, int status_code, const char *error_code, const char *message) {
    char buf[512];
    snprintf(buf, sizeof(buf), "{\"success\":false,\"error\":\"%s\",\"message\":\"%s\"}",
             error_code ? error_code : "ERROR", message ? message : "An error occurred");
    http_send_json(conn, status_code, buf);
}

/**
 * Serves a static file safely from public directory
 */
void http_serve_static_file(Connection *conn, const char *filepath, const char *content_type, int is_head) {
    /* Prevent directory traversal */
    if (strstr(filepath, "..")) {
        http_send_error(conn, 403, "FORBIDDEN", "Path traversal forbidden.");
        return;
    }

    FILE *f = fopen(filepath, "rb");
    if (!f) {
        http_send_error(conn, 404, "NOT_FOUND", "File not found.");
        return;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(file_size > 0 ? file_size : 1);
    if (!buf) {
        fclose(f);
        http_send_error(conn, 500, "ALLOC_ERR", "Server memory error.");
        return;
    }

    size_t read_bytes = fread(buf, 1, file_size, f);
    fclose(f);

    http_send_response_bytes(conn, 200, "OK", content_type, buf, read_bytes, is_head, NULL);
    free(buf);
}

/**
 * Parses JSON string field
 */
int http_parse_json_field(const char *json, const char *key, char *out_val, size_t max_out) {
    if (!json || !key || !out_val) return 0;

    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *p = strstr(json, pattern);
    if (!p) return 0;

    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == ':' || *p == '\t')) p++;

    if (*p == '\"') {
        p++;
        size_t idx = 0;
        while (*p && *p != '\"' && idx < max_out - 1) {
            if (*p == '\\' && *(p + 1) == '\"') {
                out_val[idx++] = '\"';
                p += 2;
            } else {
                out_val[idx++] = *p++;
            }
        }
        out_val[idx] = '\0';
        return 1;
    } else {
        /* Numeric or boolean */
        size_t idx = 0;
        while (*p && (isalnum((unsigned char)*p) || *p == '-' || *p == '.') && idx < max_out - 1) {
            out_val[idx++] = *p++;
        }
        out_val[idx] = '\0';
        return (idx > 0);
    }
}

int http_parse_json_int(const char *json, const char *key, int *out_val) {
    char buf[32];
    if (http_parse_json_field(json, key, buf, sizeof(buf))) {
        if (out_val) *out_val = atoi(buf);
        return 1;
    }
    return 0;
}

int http_parse_query_param(const char *query, const char *key, char *out_val, size_t max_out) {
    if (!query || !key || !out_val || max_out == 0) return 0;
    out_val[0] = '\0';
    size_t klen = strlen(key);
    const char *p = query;
    while (*p) {
        if ((p == query || *(p - 1) == '&') && strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *val_start = p + klen + 1;
            size_t i = 0;
            while (val_start[i] && val_start[i] != '&' && i < max_out - 1) {
                out_val[i] = val_start[i];
                i++;
            }
            out_val[i] = '\0';
            return 1;
        }
        p++;
    }
    return 0;
}

int http_parse_query_int(const char *query, const char *key, int *out_val) {
    char buf[32];
    if (http_parse_query_param(query, key, buf, sizeof(buf))) {
        if (out_val) *out_val = atoi(buf);
        return 1;
    }
    return 0;
}

/* =========================================================================
 * Base64 & Image File Utilities
 * ========================================================================= */
static int http_b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

static size_t http_b64_decode(const char *in, size_t in_len, unsigned char *out, size_t max_out) {
    if (!in || !out) return 0;
    size_t out_len = 0;
    int val = 0, bits = -8;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        int d = http_b64_val(c);
        if (d == -1) break;
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 0) {
            if (out_len < max_out) {
                out[out_len++] = (unsigned char)((val >> bits) & 0xFF);
            }
            bits -= 8;
        }
    }
    return out_len;
}

static int validate_image_magic(const unsigned char *data, size_t len, char *out_ext) {
    if (!data || len < 12) return 0;
    /* PNG: 89 50 4E 47 0D 0A 1A 0A */
    if (data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G') {
        if (out_ext) strcpy(out_ext, "png");
        return 1;
    }
    /* JPEG: FF D8 FF */
    if (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) {
        if (out_ext) strcpy(out_ext, "jpg");
        return 1;
    }
    /* WebP: RIFF....WEBP */
    if (data[0] == 'R' && data[1] == 'I' && data[2] == 'F' && data[3] == 'F' &&
        data[8] == 'W' && data[9] == 'E' && data[10] == 'B' && data[11] == 'P') {
        if (out_ext) strcpy(out_ext, "webp");
        return 1;
    }
    return 0;
}

/**
 * Parses incoming raw HTTP request line and headers
 */
int http_parse_request(const char *raw_req, size_t raw_len, HttpRequest *out_req) {
    (void)raw_len;
    memset(out_req, 0, sizeof(HttpRequest));

    char line[512] = {0};
    const char *line_end = strstr(raw_req, "\r\n");
    if (!line_end) line_end = strstr(raw_req, "\n");
    if (!line_end) return 0;

    size_t line_len = line_end - raw_req;
    if (line_len >= sizeof(line)) line_len = sizeof(line) - 1;
    strncpy(line, raw_req, line_len);
    line[line_len] = '\0';

    char full_path[256] = {0};
    if (sscanf(line, "%15s %255s", out_req->method, full_path) != 2) {
        return 0;
    }

    /* Split path and query string */
    char *q = strchr(full_path, '?');
    if (q) {
        *q = '\0';
        strncpy(out_req->path, full_path, sizeof(out_req->path) - 1);
        strncpy(out_req->query, q + 1, sizeof(out_req->query) - 1);
    } else {
        strncpy(out_req->path, full_path, sizeof(out_req->path) - 1);
    }

    /* Parse headers */
    const char *h_pos = strstr(raw_req, "Authorization: Bearer ");
    if (h_pos) {
        sscanf(h_pos + 22, "%255s", out_req->auth_header);
    }

    /* Locate body */
    const char *body_start = strstr(raw_req, "\r\n\r\n");
    if (body_start) {
        out_req->body = body_start + 4;
        out_req->body_len = raw_len - (size_t)(out_req->body - raw_req);
    } else {
        body_start = strstr(raw_req, "\n\n");
        if (body_start) {
            out_req->body = body_start + 2;
            out_req->body_len = raw_len - (size_t)(out_req->body - raw_req);
        } else {
            out_req->body = "";
            out_req->body_len = 0;
        }
    }

    return 1;
}

/**
 * Main HTTP Handler & REST Router
 */
void http_handle_request(Connection *conn, const char *raw_request, size_t req_len) {
    HttpRequest req;
    if (!http_parse_request(raw_request, req_len, &req)) {
        security_record_malformed_request(conn->client_ip, "Invalid HTTP request line");
        http_send_error(conn, 400, "BAD_REQUEST", "Malformed HTTP request syntax.");
        return;
    }

    int is_head = (strcmp(req.method, "HEAD") == 0);

    /* Check client Connection header */
    if (strstr(raw_request, "Connection: close") ||
        strstr(raw_request, "Connection: Close") ||
        strstr(raw_request, "connection: close")) {
        conn->should_close = 1;
    }

    /* 1. CORS Preflight */
    if (strcmp(req.method, "OPTIONS") == 0) {
        http_send_response(conn, 204, "No Content", "text/plain", "", 0);
        return;
    }

    /* 2. HTTPS Redirection & Enforcement */
    if (!conn->is_tls) {
        if (!security_is_dev_mode()) {
            /* In production mode: enforce HTTPS on sensitive endpoints */
            if (strcmp(req.method, "GET") == 0 &&
                (strcmp(req.path, "/") == 0 || strcmp(req.path, "/index.html") == 0 ||
                 strcmp(req.path, "/admin.html") == 0 || strcmp(req.path, "/admin") == 0)) {
                char redir_header[512];
                snprintf(redir_header, sizeof(redir_header),
                         "Location: https://localhost:8080%s\r\nConnection: close\r\n", req.path);
                http_send_response_bytes(conn, 301, "Moved Permanently", "text/html",
                                         "<html><body>Redirecting to secure HTTPS...</body></html>", 56, is_head, redir_header);
                return;
            }
            if (strncmp(req.path, "/api/admin/", 11) == 0 ||
                strncmp(req.path, "/api/vote", 9) == 0 ||
                strncmp(req.path, "/api/otp/", 9) == 0) {
                http_send_error(conn, 403, "HTTPS_REQUIRED",
                                "Secure HTTPS connection is required for administrative and voting operations.");
                return;
            }
        }
    }

    /* 3. Static Web Assets (Served before API rate limit check) */
    if (strcmp(req.path, "/") == 0 || strcmp(req.path, "/index.html") == 0) {
        http_serve_static_file(conn, "public/index.html", "text/html; charset=utf-8", is_head);
        return;
    }
    if (strcmp(req.path, "/style.css") == 0) {
        http_serve_static_file(conn, "public/style.css", "text/css; charset=utf-8", is_head);
        return;
    }
    if (strcmp(req.path, "/app.js") == 0) {
        http_serve_static_file(conn, "public/app.js", "application/javascript; charset=utf-8", is_head);
        return;
    }
    /* Static Image Assets (PNG, JPG/JPEG, WebP, SVG, GIF) with fallback placeholder */
    if (strncmp(req.path, "/images/", 8) == 0) {
        const char *img_filename = req.path + 8;
        /* Security: Disallow path traversal or directory escaping */
        if (strstr(img_filename, "..") || strchr(img_filename, '/') || strchr(img_filename, '\\')) {
            http_send_error(conn, 403, "FORBIDDEN", "Invalid image path.");
            return;
        }

        char filepath[512];
        snprintf(filepath, sizeof(filepath), "public/images/%s", img_filename);

        /* Determine MIME type */
        const char *mime = "image/png";
        const char *ext = strrchr(img_filename, '.');
        if (ext) {
            if (strcasecmp(ext, ".png") == 0) mime = "image/png";
            else if (strcasecmp(ext, ".jpg") == 0 || strcasecmp(ext, ".jpeg") == 0) mime = "image/jpeg";
            else if (strcasecmp(ext, ".webp") == 0) mime = "image/webp";
            else if (strcasecmp(ext, ".svg") == 0) mime = "image/svg+xml";
            else if (strcasecmp(ext, ".gif") == 0) mime = "image/gif";
        }

        if (access(filepath, F_OK) == 0) {
            http_serve_static_file(conn, filepath, mime, is_head);
        } else {
            /* Fallback to default placeholder for missing images */
            http_serve_static_file(conn, "public/images/others.png", "image/png", is_head);
        }
        return;
    }

    /* Admin Dashboard Static Assets (Protected by IP Allowlist) */
    if (strcmp(req.path, "/admin") == 0 || strcmp(req.path, "/admin.html") == 0) {
        if (!security_is_ip_allowed_admin(conn->client_ip) && !conn->is_mtls_admin) {
            security_record_unauthorized_admin(conn->client_ip, req.path);
            http_send_error(conn, 403, "IP_FORBIDDEN",
                            "Access Denied: Your IP is not on the election administration allowlist.");
            return;
        }
        http_serve_static_file(conn, "public/admin.html", "text/html; charset=utf-8", is_head);
        return;
    }
    if (strcmp(req.path, "/admin.js") == 0) {
        http_serve_static_file(conn, "public/admin.js", "application/javascript; charset=utf-8", is_head);
        return;
    }

    /* 4. Path Traversal & Security Sanitization */
    if (strstr(req.path, "..") || strchr(req.path, '\\') || strstr(req.path, "//")) {
        security_record_malformed_request(conn->client_ip, req.path);
        http_send_error(conn, 400, "MALFORMED_URI", "Invalid characters in URI path.");
        return;
    }

    /* 5. API Rate Limiting Check (Applied to API actions) */
    if (!security_check_rate_limit(conn->client_ip)) {
        http_send_error(conn, 429, "RATE_LIMIT_EXCEEDED", "Too many requests. Please wait 30 seconds.");
        return;
    }

    /* =========================================================================
     * PUBLIC & VOTER REST APIs
     * ========================================================================= */

    /* GET /api/elections - List all elections for voters & public */
    if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/elections") == 0) {
        ElectionSummary sums[MAX_ELECTIONS];
        int cnt = election_get_all_summaries(sums, MAX_ELECTIONS);
        char *buf = malloc(65536);
        if (!buf) {
            http_send_error(conn, 500, "MEM_ERR", "Allocation failed");
            return;
        }
        size_t w = sprintf(buf, "[");
        for (int i = 0; i < cnt; i++) {
            char item[1024];
            snprintf(item, sizeof(item),
                     "%s{\"id\":%d,\"title\":\"%s\",\"description\":\"%s\",\"election_type\":\"%s\","
                     "\"status\":%d,\"status_str\":\"%s\",\"start_time\":%ld,\"end_time\":%ld,"
                     "\"total_voters\":%d,\"total_votes\":%d,\"require_otp\":%s}",
                     (i > 0) ? "," : "",
                     sums[i].id, sums[i].title, sums[i].description, sums[i].type,
                     sums[i].state, sums[i].state_str,
                     (long)sums[i].start_time, (long)sums[i].end_time,
                     sums[i].voter_count, sums[i].ballot_count,
                     sums[i].require_otp ? "true" : "false");
            w += sprintf(buf + w, "%s", item);
        }
        sprintf(buf + w, "]");
        http_send_json(conn, 200, buf);
        free(buf);
        return;
    }

    /* GET /api/election/info or GET /api/election */
    if (strcmp(req.method, "GET") == 0 &&
        (strcmp(req.path, "/api/election/info") == 0 || strcmp(req.path, "/api/election") == 0)) {
        int eid = 0;
        http_parse_query_int(req.query, "id", &eid);
        if (eid <= 0) eid = election_get_active_id();
        if (eid <= 0) eid = 1;
        ElectionSummary sum;
        if (election_get_summary(eid, &sum) == 0) {
            char resp[1024];
            snprintf(resp, sizeof(resp),
                     "{\"id\":%d,\"title\":\"%s\",\"description\":\"%s\",\"election_type\":\"%s\","
                     "\"status\":%d,\"status_str\":\"%s\",\"start_time\":%ld,\"end_time\":%ld,"
                     "\"total_voters\":%d,\"total_votes\":%d,\"require_otp\":%s}",
                     sum.id, sum.title, sum.description, sum.type,
                     sum.state, sum.state_str,
                     (long)sum.start_time, (long)sum.end_time,
                     sum.voter_count, sum.ballot_count,
                     sum.require_otp ? "true" : "false");
            http_send_json(conn, 200, resp);
        } else {
            http_send_error(conn, 404, "NOT_FOUND", "Election not found.");
        }
        return;
    }

    /* GET /api/check?id=<voter_id>&election_id=<id> */
    if (strncmp(req.path, "/api/check", 10) == 0) {
        char voter_id[ID_LEN] = {0};
        int election_id = 0;
        http_parse_query_param(req.query, "id", voter_id, sizeof(voter_id));
        http_parse_query_int(req.query, "election_id", &election_id);

        if (election_id <= 0) {
            election_id = election_get_active_id();
            if (election_id <= 0) election_id = 1;
        }

        Voter v;
        int status = election_check_voter_status(election_id, voter_id, &v);

        char resp[512];
        if (status == 0) {
            PollingBooth pb;
            char booth_name[64] = "Station 1";
            if (election_get_booth_by_id(election_id, v.booth_id, &pb) == 0) {
                strncpy(booth_name, pb.name, sizeof(booth_name) - 1);
            }
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"ELIGIBLE\",\"voter_id\":\"%s\",\"name\":\"%s\",\"booth_id\":%d,\"booth_name\":\"%s\",\"election_id\":%d}",
                     voter_id, v.name, v.booth_id, booth_name, election_id);
        } else if (status == 1) {
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"ALREADY_VOTED\",\"voter_id\":\"%s\",\"voted_at\":\"%s\",\"election_id\":%d}",
                     voter_id, v.voted_at, election_id);
        } else {
            snprintf(resp, sizeof(resp),
                     "{\"status\":\"NOT_FOUND\",\"voter_id\":\"%s\",\"election_id\":%d}", voter_id, election_id);
        }
        http_send_json(conn, 200, resp);
        return;
    }

    /* POST /api/otp/request - 2FA Voter Dispatch */
    if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/otp/request") == 0) {
        char voter_id[ID_LEN] = {0};
        int election_id = 0;

        if (!http_parse_json_field(req.body, "voter_id", voter_id, sizeof(voter_id))) {
            http_send_error(conn, 400, "BAD_REQUEST", "Missing voter_id field.");
            return;
        }
        http_parse_json_int(req.body, "election_id", &election_id);
        if (election_id <= 0) {
            election_id = election_get_active_id();
            if (election_id <= 0) election_id = 1;
        }

        /* Trim voter_id */
        char *vp = voter_id;
        while (*vp && isspace((unsigned char)*vp)) vp++;
        if (vp != voter_id) memmove(voter_id, vp, strlen(vp) + 1);
        size_t vlen = strlen(voter_id);
        while (vlen > 0 && isspace((unsigned char)voter_id[vlen - 1])) {
            voter_id[--vlen] = '\0';
        }

        /* Check election status */
        ElectionSummary el;
        if (election_get_summary(election_id, &el) == 0 && el.state != ELECTION_ACTIVE) {
            http_send_error(conn, 403, "ELECTION_INACTIVE",
                            "Election is currently not active for voting.");
            return;
        }

        Voter v;
        int status = election_check_voter_status(election_id, voter_id, &v);
        if (status == -1) {
            security_record_failed_auth(conn->client_ip, voter_id);
            char resp[512];
            snprintf(resp, sizeof(resp),
                     "{\"success\":false,\"error\":\"NOT_FOUND\",\"message\":\"Voter ID '%s' was not found in the authorized voter roll for this election.\",\"voter_id\":\"%s\"}",
                     voter_id, voter_id);
            http_send_json(conn, 404, resp);
            return;
        }
        if (status == 1) {
            security_record_duplicate_vote(conn->client_ip, voter_id);
            char resp[512];
            snprintf(resp, sizeof(resp),
                     "{\"success\":false,\"error\":\"ALREADY_VOTED\",\"message\":\"Voter ID '%s' has already cast a ballot. Duplicate voting blocked.\",\"voter_id\":\"%s\",\"voted_at\":\"%s\"}",
                     voter_id, voter_id, v.voted_at);
            http_send_json(conn, 409, resp);
            return;
        }

        char plain_otp[8];
        security_generate_voter_election_otp(voter_id, election_id, plain_otp);

        char booth_name[64] = "Station 1";
        PollingBooth pb;
        if (election_get_booth_by_id(election_id, v.booth_id, &pb) == 0) {
            strncpy(booth_name, pb.name, sizeof(booth_name) - 1);
        }

        char resp[512];
        if (security_is_dev_mode()) {
            snprintf(resp, sizeof(resp),
                     "{\"success\":true,\"status\":\"ELIGIBLE\",\"message\":\"Two-Factor Authentication OTP dispatched.\",\"voter_id\":\"%s\",\"name\":\"%s\",\"booth_id\":%d,\"booth_name\":\"%s\",\"election_id\":%d,\"development_mode\":true,\"demo_otp\":\"%s\",\"simulated_otp\":\"%s\",\"demo_label\":\"DEMO OTP – DEVELOPMENT ONLY\",\"expires_in\":%d}",
                     voter_id, v.name, v.booth_id, booth_name, election_id, plain_otp, plain_otp, OTP_EXPIRY_SECONDS);
        } else {
            snprintf(resp, sizeof(resp),
                     "{\"success\":true,\"status\":\"ELIGIBLE\",\"message\":\"Two-Factor Authentication OTP dispatched to your registered SMS/Email.\",\"voter_id\":\"%s\",\"name\":\"%s\",\"booth_id\":%d,\"booth_name\":\"%s\",\"election_id\":%d,\"development_mode\":false,\"expires_in\":%d}",
                     voter_id, v.name, v.booth_id, booth_name, election_id, OTP_EXPIRY_SECONDS);
        }
        http_send_json(conn, 200, resp);
        return;
    }

    /* POST /api/otp/verify - 2FA Voter Code Verification */
    if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/otp/verify") == 0) {
        char voter_id[ID_LEN] = {0};
        char otp_code[16] = {0};
        int election_id = 0;

        if (!http_parse_json_field(req.body, "voter_id", voter_id, sizeof(voter_id)) ||
            !http_parse_json_field(req.body, "otp", otp_code, sizeof(otp_code))) {
            http_send_error(conn, 400, "BAD_REQUEST", "Missing voter_id or otp.");
            return;
        }
        http_parse_json_int(req.body, "election_id", &election_id);
        if (election_id <= 0) {
            election_id = election_get_active_id();
            if (election_id <= 0) election_id = 1;
        }

        /* Trim voter_id */
        char *vp = voter_id;
        while (*vp && isspace((unsigned char)*vp)) vp++;
        if (vp != voter_id) memmove(voter_id, vp, strlen(vp) + 1);
        size_t vlen = strlen(voter_id);
        while (vlen > 0 && isspace((unsigned char)voter_id[vlen - 1])) {
            voter_id[--vlen] = '\0';
        }

        /* Trim otp_code */
        char *op = otp_code;
        while (*op && isspace((unsigned char)*op)) op++;
        if (op != otp_code) memmove(otp_code, op, strlen(op) + 1);
        size_t olen = strlen(otp_code);
        while (olen > 0 && isspace((unsigned char)otp_code[olen - 1])) {
            otp_code[--olen] = '\0';
        }

        int res = security_verify_voter_election_otp(voter_id, election_id, otp_code);
        if (res == 0) {
            http_send_json(conn, 200, "{\"success\":true,\"message\":\"OTP verified successfully! You may now cast your ballot.\"}");
        } else if (res == -2) {
            http_send_error(conn, 400, "OTP_EXPIRED", "OTP has expired. Please request a new code.");
        } else if (res == -3) {
            security_record_failed_auth(conn->client_ip, voter_id);
            http_send_error(conn, 403, "OTP_MAX_EXCEEDED", "Maximum verification attempts exceeded.");
        } else {
            security_record_failed_auth(conn->client_ip, voter_id);
            char msg[128];
            snprintf(msg, sizeof(msg), "Invalid OTP code. %d attempts remaining.", res);
            http_send_error(conn, 400, "INVALID_OTP", msg);
        }
        return;
    }

    /* POST /api/vote - Cast ballot with Ballot Secrecy & Optional 2FA */
    if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/vote") == 0) {
        if (!conn->is_tls) {
            http_send_error(conn, 403, "HTTPS_REQUIRED",
                            "Submitting official secret ballots requires an encrypted HTTPS connection.");
            return;
        }

        char voter_id[ID_LEN] = {0};
        int cand_id = 0;
        int booth_id = 0;
        int election_id = 0;
        char otp[16] = {0};

        if (!http_parse_json_field(req.body, "voter_id", voter_id, sizeof(voter_id)) ||
            !http_parse_json_int(req.body, "candidate_id", &cand_id)) {
            http_send_error(conn, 400, "BAD_REQUEST", "Missing voter_id or candidate_id.");
            return;
        }

        http_parse_json_int(req.body, "booth_id", &booth_id);
        http_parse_json_int(req.body, "election_id", &election_id);
        http_parse_json_field(req.body, "otp", otp, sizeof(otp));

        if (election_id <= 0) {
            election_id = election_get_active_id();
            if (election_id <= 0) election_id = 1;
        }

        /* Check Election Status */
        ElectionSummary el;
        if (election_get_summary(election_id, &el) == 0 && el.state != ELECTION_ACTIVE) {
            http_send_error(conn, 403, "ELECTION_INACTIVE",
                            "Voting is not currently active for this election.");
            return;
        }

        /* Pre-check Voter Eligibility to detect duplicate attempts before 2FA */
        Voter chk_voter;
        int v_status = election_check_voter_status(election_id, voter_id, &chk_voter);
        if (v_status == -1) {
            security_record_failed_auth(conn->client_ip, voter_id);
            http_send_error(conn, 400, "INVALID_ID", "Voter ID is not registered in official roll for this election.");
            return;
        }
        if (v_status == 1) {
            security_record_duplicate_vote(conn->client_ip, voter_id);
            http_send_error(conn, 409, "ALREADY_VOTED", "Duplicate voting prohibited. Voter has already cast a ballot.");
            return;
        }

        /* Check 2FA requirement */
        if (el.require_otp) {
            if (strlen(otp) > 0) {
                security_verify_voter_election_otp(voter_id, election_id, otp);
            } else if (!security_is_voter_election_otp_verified(voter_id, election_id)) {
                /* Local College Demonstration Simulation */
                char sim_otp[8];
                if (security_get_simulated_election_otp(voter_id, election_id, sim_otp) ||
                    security_generate_voter_election_otp(voter_id, election_id, sim_otp) == 0) {
                    security_verify_voter_election_otp(voter_id, election_id, sim_otp);
                }
            }
            if (!security_is_voter_election_otp_verified(voter_id, election_id)) {
                http_send_error(conn, 401, "OTP_REQUIRED", "Two-Factor Authentication (OTP) verification is required before voting.");
                return;
            }
        }

        char receipt_token[TOKEN_LEN] = {0};
        char cand_name[NAME_LEN] = {0};

        int res = election_cast_ballot(election_id, voter_id, cand_id, booth_id, receipt_token, cand_name);

        if (res == 0) {
            security_clear_voter_election_otp(voter_id, election_id);
            char resp[512];
            snprintf(resp, sizeof(resp),
                     "{\"success\":true,\"message\":\"Ballot recorded successfully!\",\"candidate\":\"%s\",\"receipt_token\":\"%s\",\"election_id\":%d}",
                     cand_name, receipt_token, election_id);
            /* BALLOT SECRECY: Never log voter ID with candidate choice! */
            printf("[BALLOT ACCEPTED] Anonymous ballot recorded for Election #%d. Receipt token: %s\n",
                   election_id, receipt_token);
            http_send_json(conn, 200, resp);
        } else if (res == -1) {
            security_record_failed_auth(conn->client_ip, voter_id);
            http_send_error(conn, 400, "INVALID_ID", "Voter ID is not registered in official roll.");
        } else if (res == -2) {
            security_record_duplicate_vote(conn->client_ip, voter_id);
            http_send_error(conn, 409, "ALREADY_VOTED", "Duplicate voting prohibited. Voter has already cast a ballot.");
        } else if (res == -3) {
            http_send_error(conn, 400, "INVALID_CANDIDATE", "Selected candidate ID does not exist.");
        } else if (res == -10) {
            http_send_error(conn, 403, "ELECTION_INACTIVE", "Voting is currently paused or closed by the Election Commission.");
        } else {
            http_send_error(conn, 500, "VOTE_FAILED", "Failed to persist ballot to secure storage.");
        }
        return;
    }

    /* GET /api/receipt/verify?token=<token>&election_id=<id> - Anonymous Ballot Verification */
    if (strncmp(req.path, "/api/receipt/verify", 19) == 0) {
        char token[TOKEN_LEN] = {0};
        int election_id = 0;
        http_parse_query_param(req.query, "token", token, sizeof(token));
        http_parse_query_int(req.query, "election_id", &election_id);

        if (election_id <= 0) {
            election_id = election_get_active_id();
            if (election_id <= 0) election_id = 1;
        }

        if (strlen(token) == 0) {
            http_send_error(conn, 400, "BAD_REQUEST", "Missing receipt token.");
            return;
        }

        int b_id = 0;
        char b_time[64] = {0};
        char b_title[128] = {0};
        if (election_verify_receipt(election_id, token, &b_id, b_time, b_title) > 0) {
            char resp[512];
            /* BALLOT SECRECY: Confirms inclusion without revealing chosen candidate! */
            snprintf(resp, sizeof(resp),
                     "{\"success\":true,\"verified\":true,\"recorded\":true,\"receipt_token\":\"%s\",\"recorded_at\":\"%s\",\"booth_id\":%d,\"status\":\"RECORDED_IN_BALLOT_BOX\",\"election_title\":\"%s\",\"election_id\":%d}",
                     token, b_time, b_id, b_title, election_id);
            http_send_json(conn, 200, resp);
        } else {
            char resp[512];
            snprintf(resp, sizeof(resp),
                     "{\"success\":false,\"verified\":false,\"recorded\":false,\"message\":\"Receipt token '%s' was not found in the official ballot box for Election #%d.\",\"election_id\":%d}",
                     token, election_id, election_id);
            http_send_json(conn, 404, resp);
        }
        return;
    }

    /* GET /api/results?election_id=<id> */
    if (strcmp(req.path, "/api/results") == 0) {
        int election_id = 0;
        http_parse_query_int(req.query, "election_id", &election_id);
        if (election_id <= 0) {
            election_id = election_get_active_id();
            if (election_id <= 0) election_id = 1;
        }

        int is_admin = conn->is_mtls_admin || (strlen(req.auth_header) > 0 && admin_validate_session(req.auth_header));
        char json_buf[8192];
        election_generate_results_json(election_id, json_buf, sizeof(json_buf), is_admin);
        http_send_json(conn, 200, json_buf);
        return;
    }

    /* GET /api/monitoring */
    if (strcmp(req.path, "/api/monitoring") == 0) {
        int election_id = 0;
        http_parse_query_int(req.query, "election_id", &election_id);
        if (election_id <= 0) election_id = election_get_active_id();
        if (election_id <= 0) election_id = 1;

        char json_buf[8192];
        election_generate_monitoring_json(election_id, json_buf, sizeof(json_buf));
        http_send_json(conn, 200, json_buf);
        return;
    }

    /* GET /api/candidates?election_id=<id> */
    if (strcmp(req.path, "/api/candidates") == 0) {
        int election_id = 0;
        http_parse_query_int(req.query, "election_id", &election_id);
        if (election_id <= 0) {
            election_id = election_get_active_id();
            if (election_id <= 0) election_id = 1;
        }

        int is_admin = conn->is_mtls_admin || (strlen(req.auth_header) > 0 && admin_validate_session(req.auth_header));
        ElectionSummary summ;
        int show_votes = 0;
        if (is_admin || (election_get_summary(election_id, &summ) == 0 && summ.results_declared)) {
            show_votes = 1;
        }

        int cnt = election_get_candidate_count(election_id);
        char *buf = malloc(16384);
        if (!buf) {
            http_send_error(conn, 500, "MEM_ERR", "Allocation error");
            return;
        }
        size_t w = sprintf(buf, "[");
        for (int i = 0; i < cnt; i++) {
            Candidate c;
            if (election_get_candidate_by_index(election_id, i, &c) == 0) {
                char item[512];
                snprintf(item, sizeof(item),
                         "%s{\"id\":%d,\"name\":\"%s\",\"party\":\"%s\",\"photo\":\"%s\",\"votes\":%d}",
                         (i > 0) ? "," : "", c.id, c.name, c.party, c.photo_url, show_votes ? c.votes : 0);
                w += sprintf(buf + w, "%s", item);
            }
        }
        sprintf(buf + w, "]");
        http_send_json(conn, 200, buf);
        free(buf);
        return;
    }

    /* GET /api/booths?election_id=<id> */
    if (strcmp(req.path, "/api/booths") == 0) {
        int election_id = 0;
        http_parse_query_int(req.query, "election_id", &election_id);
        if (election_id <= 0) {
            election_id = election_get_active_id();
            if (election_id <= 0) election_id = 1;
        }

        int cnt = election_get_booth_count(election_id);
        char *buf = malloc(16384);
        if (!buf) {
            http_send_error(conn, 500, "MEM_ERR", "Allocation error");
            return;
        }
        size_t w = sprintf(buf, "[");
        for (int i = 0; i < cnt; i++) {
            PollingBooth pb;
            if (election_get_booth_by_index(election_id, i, &pb) == 0) {
                char item[512];
                snprintf(item, sizeof(item),
                         "%s{\"id\":%d,\"name\":\"%s\",\"location\":\"%s\",\"registered\":%d,\"votes_cast\":%d}",
                         (i > 0) ? "," : "", pb.id, pb.name, pb.location, pb.total_registered, pb.votes_cast);
                w += sprintf(buf + w, "%s", item);
            }
        }
        sprintf(buf + w, "]");
        http_send_json(conn, 200, buf);
        free(buf);
        return;
    }

    /* =========================================================================
     * ADMINISTRATIVE REST APIs
     * ========================================================================= */
    if (strncmp(req.path, "/api/admin/", 11) == 0) {
        /* 0. Admin Status & Session Check */
        if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/check_session") == 0) {
            int is_allowed = security_is_ip_allowed_admin(conn->client_ip) || conn->is_mtls_admin;
            int is_auth = conn->is_mtls_admin || (strlen(req.auth_header) > 0 && admin_validate_session(req.auth_header));
            char resp[256];
            snprintf(resp, sizeof(resp),
                     "{\"authenticated\":%s,\"client_ip\":\"%s\",\"ip_allowed\":%s,\"mtls\":%s,\"is_setup\":%s}",
                     is_auth ? "true" : "false", conn->client_ip,
                     is_allowed ? "true" : "false", conn->is_mtls_admin ? "true" : "false",
                     admin_is_setup() ? "true" : "false");
            http_send_json(conn, 200, resp);
            return;
        }

        /* Check IP Allowlist (unless authenticated via mTLS) */
        if (!security_is_ip_allowed_admin(conn->client_ip) && !conn->is_mtls_admin) {
            security_record_unauthorized_admin(conn->client_ip, req.path);
            http_send_error(conn, 403, "IP_FORBIDDEN",
                            "Access Denied: Administrative requests are restricted to allowlisted IP addresses.");
            return;
        }

        /* 1. Admin Login Endpoint */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/login") == 0) {
            char user[32] = {0};
            char pass[64] = {0};
            char otp[16] = {0};

            http_parse_json_field(req.body, "username", user, sizeof(user));
            http_parse_json_field(req.body, "password", pass, sizeof(pass));
            http_parse_json_field(req.body, "otp", otp, sizeof(otp));

            char session_token[ADMIN_SESSION_LEN];
            int auth_res = admin_authenticate(user, pass, otp, conn->is_mtls_admin, session_token);

            if (auth_res == 0) {
                char resp[512];
                snprintf(resp, sizeof(resp),
                         "{\"success\":true,\"token\":\"%s\",\"session_token\":\"%s\",\"username\":\"%s\",\"mtls\":%s}",
                         session_token, session_token, user, conn->is_mtls_admin ? "true" : "false");
                http_send_json(conn, 200, resp);
            } else if (auth_res == -5) {
                http_send_error(conn, 429, "ADMIN_LOCKED", "Administrator account temporarily locked due to repeated failures.");
            } else {
                security_record_alert("ADMIN_LOGIN_FAILED", "HIGH", conn->client_ip, "Invalid administrator credentials or 2FA OTP.");
                http_send_error(conn, 401, "INVALID_CREDENTIALS", "Invalid administrator credentials or 2FA OTP code.");
            }
            return;
        }

        /* 1b. Admin Setup Credentials Endpoint */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/setup") == 0) {
            char user[32] = {0}, pass[64] = {0}, otp[16] = {0};
            http_parse_json_field(req.body, "username", user, sizeof(user));
            http_parse_json_field(req.body, "password", pass, sizeof(pass));
            http_parse_json_field(req.body, "otp", otp, sizeof(otp));
            int res = admin_setup_credentials(user, pass, otp);
            if (res == 0) {
                http_send_json(conn, 200, "{\"success\":true,\"message\":\"Administrator account configured successfully.\"}");
            } else {
                http_send_error(conn, 400, "BAD_REQUEST", "Username must be >= 3 chars, password >= 6 chars.");
            }
            return;
        }

        /* For all other admin endpoints, require session token OR mTLS cert */
        if (!conn->is_mtls_admin && !admin_validate_session(req.auth_header)) {
            http_send_error(conn, 401, "UNAUTHORIZED", "Missing or invalid administrative session token.");
            return;
        }

        /* 1c. Admin Change Password */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/change_password") == 0) {
            char old_pass[64] = {0}, new_pass[64] = {0};
            http_parse_json_field(req.body, "old_password", old_pass, sizeof(old_pass));
            http_parse_json_field(req.body, "new_password", new_pass, sizeof(new_pass));
            int res = admin_change_password(req.auth_header, old_pass, new_pass);
            if (res == 0) {
                http_send_json(conn, 200, "{\"success\":true,\"message\":\"Password updated successfully.\"}");
            } else if (res == -3) {
                http_send_error(conn, 400, "INVALID_PASSWORD", "Current password does not match.");
            } else {
                http_send_error(conn, 400, "BAD_REQUEST", "New password must be at least 6 characters.");
            }
            return;
        }

        /* 2. Admin Logout */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/logout") == 0) {
            admin_logout(req.auth_header);
            http_send_json(conn, 200, "{\"success\":true,\"message\":\"Logged out successfully.\"}");
            return;
        }

        /* ================= Multi-Election Administration APIs ================= */

        /* GET /api/admin/elections - List all elections with admin details */
        if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/elections") == 0) {
            ElectionSummary sums[MAX_ELECTIONS];
            int cnt = election_get_all_summaries(sums, MAX_ELECTIONS);
            char *buf = malloc(65536);
            if (!buf) {
                http_send_error(conn, 500, "MEM_ERR", "Allocation failed");
                return;
            }
            size_t w = sprintf(buf, "{\"active_election_id\":%d,\"elections\":[", election_get_active_id());
            for (int i = 0; i < cnt; i++) {
                char item[1024];
                snprintf(item, sizeof(item),
                         "%s{\"id\":%d,\"title\":\"%s\",\"description\":\"%s\",\"election_type\":\"%s\","
                         "\"status\":%d,\"status_str\":\"%s\",\"start_time\":%ld,\"end_time\":%ld,"
                         "\"total_voters\":%d,\"total_votes\":%d,\"require_otp\":%s}",
                         (i > 0) ? "," : "",
                         sums[i].id, sums[i].title, sums[i].description, sums[i].type,
                         sums[i].state, sums[i].state_str,
                         (long)sums[i].start_time, (long)sums[i].end_time,
                         sums[i].voter_count, sums[i].ballot_count,
                         sums[i].require_otp ? "true" : "false");
                w += sprintf(buf + w, "%s", item);
            }
            sprintf(buf + w, "]}");
            http_send_json(conn, 200, buf);
            free(buf);
            return;
        }

        /* POST /api/admin/elections - Create new election */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/elections") == 0) {
            char title[NAME_LEN] = {0};
            char desc[256] = {0};
            char el_type[64] = "General";
            int require_otp = 1;

            http_parse_json_field(req.body, "title", title, sizeof(title));
            http_parse_json_field(req.body, "description", desc, sizeof(desc));
            http_parse_json_field(req.body, "election_type", el_type, sizeof(el_type));
            http_parse_json_int(req.body, "require_otp", &require_otp);

            int new_id = 0;
            int res = election_create(title, desc, el_type, 0, 0, require_otp, &new_id);
            if (res == 0) {
                char resp[256];
                snprintf(resp, sizeof(resp),
                         "{\"success\":true,\"message\":\"Election created successfully.\",\"election_id\":%d,\"id\":%d}", new_id, new_id);
                http_send_json(conn, 201, resp);
            } else {
                http_send_error(conn, 400, "BAD_REQUEST", "Failed to create election. Check inputs.");
            }
            return;
        }

        /* POST /api/admin/election/update or /api/admin/elections/update */
        if (strcmp(req.method, "POST") == 0 &&
            (strcmp(req.path, "/api/admin/election/update") == 0 ||
             strcmp(req.path, "/api/admin/elections/update") == 0)) {
            int eid = 0;
            char title[NAME_LEN] = {0};
            char desc[256] = {0};
            char el_type[64] = {0};
            int require_otp = 1;

            http_parse_json_int(req.body, "id", &eid);
            http_parse_json_field(req.body, "title", title, sizeof(title));
            http_parse_json_field(req.body, "description", desc, sizeof(desc));
            http_parse_json_field(req.body, "election_type", el_type, sizeof(el_type));
            http_parse_json_int(req.body, "require_otp", &require_otp);

            int res = election_update_details(eid, title, desc, el_type, 0, 0, require_otp);
            if (res == 0) {
                http_send_json(conn, 200, "{\"success\":true,\"message\":\"Election updated successfully.\"}");
            } else if (res == -2) {
                http_send_error(conn, 403, "LOCKED", "Cannot edit election details once voting has begun.");
            } else {
                http_send_error(conn, 404, "NOT_FOUND", "Election not found.");
            }
            return;
        }

        /* POST /api/admin/election/state or /api/admin/elections/state - Change election state */
        if (strcmp(req.method, "POST") == 0 &&
            (strcmp(req.path, "/api/admin/election/state") == 0 ||
             strcmp(req.path, "/api/admin/elections/state") == 0)) {
            int eid = 0;
            char state_str[32] = {0};

            http_parse_json_int(req.body, "election_id", &eid);
            http_parse_json_field(req.body, "state", state_str, sizeof(state_str));

            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            ElectionState ns = ELECTION_DRAFT;
            if (strcasecmp(state_str, "DRAFT") == 0) ns = ELECTION_DRAFT;
            else if (strcasecmp(state_str, "PUBLISHED") == 0 || strcasecmp(state_str, "PUBLISH") == 0) ns = ELECTION_PUBLISHED;
            else if (strcasecmp(state_str, "ACTIVE") == 0 || strcasecmp(state_str, "START") == 0) ns = ELECTION_ACTIVE;
            else if (strcasecmp(state_str, "PAUSED") == 0 || strcasecmp(state_str, "PAUSE") == 0) ns = ELECTION_PAUSED;
            else if (strcasecmp(state_str, "CLOSED") == 0 || strcasecmp(state_str, "CLOSE") == 0) ns = ELECTION_CLOSED;
            else if (strcasecmp(state_str, "DECLARED") == 0 || strcasecmp(state_str, "DECLARE") == 0) ns = ELECTION_DECLARED;
            else if (strcasecmp(state_str, "ARCHIVED") == 0 || strcasecmp(state_str, "ARCHIVE") == 0) ns = ELECTION_ARCHIVED;

            int res = election_set_state(eid, ns);
            if (res == 0) {
                char resp[256];
                snprintf(resp, sizeof(resp),
                         "{\"success\":true,\"election_id\":%d,\"new_state\":\"%s\"}",
                         eid, election_state_to_str(ns));
                http_send_json(conn, 200, resp);
            } else {
                http_send_error(conn, 400, "BAD_REQUEST", "Failed to update election state.");
            }
            return;
        }

        /* POST /api/admin/election/delete - Delete draft election */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/election/delete") == 0) {
            int eid = 0;
            http_parse_json_int(req.body, "id", &eid);
            int res = election_delete_draft(eid);
            if (res == 0) {
                http_send_json(conn, 200, "{\"success\":true,\"message\":\"Election deleted.\"}");
            } else if (res == -2) {
                http_send_error(conn, 403, "LOCKED", "Only elections in DRAFT state can be deleted.");
            } else {
                http_send_error(conn, 404, "NOT_FOUND", "Election not found.");
            }
            return;
        }

        /* POST /api/admin/election/select_active - Set active election */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/election/select_active") == 0) {
            int eid = 0;
            http_parse_json_int(req.body, "id", &eid);
            election_set_active_id(eid);
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"success\":true,\"active_election_id\":%d}", eid);
            http_send_json(conn, 200, resp);
            return;
        }

        /* ================= Candidate Management APIs ================= */

        /* GET /api/admin/candidates?election_id=<id> */
        if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/candidates") == 0) {
            int eid = 0;
            http_parse_query_int(req.query, "election_id", &eid);
            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            int cnt = election_get_candidate_count(eid);
            char *buf = malloc(16384);
            if (!buf) {
                http_send_error(conn, 500, "MEM_ERR", "Allocation error");
                return;
            }
            size_t w = sprintf(buf, "{\"election_id\":%d,\"candidates\":[", eid);
            for (int i = 0; i < cnt; i++) {
                Candidate c;
                if (election_get_candidate_by_index(eid, i, &c) == 0) {
                    char item[512];
                    snprintf(item, sizeof(item),
                             "%s{\"id\":%d,\"name\":\"%s\",\"party\":\"%s\",\"photo\":\"%s\",\"votes\":%d}",
                             (i > 0) ? "," : "", c.id, c.name, c.party, c.photo_url, c.votes);
                    w += sprintf(buf + w, "%s", item);
                }
            }
            sprintf(buf + w, "]}");
            http_send_json(conn, 200, buf);
            free(buf);
            return;
        }

        /* POST /api/admin/candidates - Add Candidate */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/candidates") == 0) {
            int eid = 0;
            char name[NAME_LEN] = {0};
            char party[PARTY_LEN] = {0};
            char photo[256] = {0};

            http_parse_json_int(req.body, "election_id", &eid);
            http_parse_json_field(req.body, "name", name, sizeof(name));
            http_parse_json_field(req.body, "party", party, sizeof(party));
            if (!http_parse_json_field(req.body, "photo", photo, sizeof(photo))) {
                http_parse_json_field(req.body, "photo_url", photo, sizeof(photo));
            }
            if (strlen(photo) == 0) {
                strcpy(photo, "/images/others.png");
            }

            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            int new_cid = 0;
            int res = election_add_candidate(eid, name, party, photo, &new_cid);
            if (res == 0) {
                http_send_json(conn, 201, "{\"success\":true,\"message\":\"Candidate added successfully.\"}");
            } else if (res == -4) {
                http_send_error(conn, 403, "LOCKED", "Candidates are locked once election starts.");
            } else {
                http_send_error(conn, 400, "BAD_REQUEST", "Failed to add candidate.");
            }
            return;
        }

        /* POST /api/admin/candidates/update - Edit Candidate */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/candidates/update") == 0) {
            int eid = 0, cid = 0;
            char name[NAME_LEN] = {0}, party[PARTY_LEN] = {0}, photo[256] = {0};

            http_parse_json_int(req.body, "election_id", &eid);
            http_parse_json_int(req.body, "id", &cid);
            http_parse_json_field(req.body, "name", name, sizeof(name));
            http_parse_json_field(req.body, "party", party, sizeof(party));
            if (!http_parse_json_field(req.body, "photo", photo, sizeof(photo))) {
                http_parse_json_field(req.body, "photo_url", photo, sizeof(photo));
            }

            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            int res = election_update_candidate(eid, cid, name, party, photo);
            if (res == 0) {
                http_send_json(conn, 200, "{\"success\":true,\"message\":\"Candidate updated successfully.\"}");
            } else if (res == -4) {
                http_send_error(conn, 403, "LOCKED", "Cannot edit candidates after voting starts.");
            } else {
                http_send_error(conn, 404, "NOT_FOUND", "Candidate not found.");
            }
            return;
        }

        /* POST /api/admin/candidates/delete - Delete Candidate */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/candidates/delete") == 0) {
            int eid = 0, cid = 0;
            http_parse_json_int(req.body, "election_id", &eid);
            http_parse_json_int(req.body, "id", &cid);
            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            int res = election_delete_candidate(eid, cid);
            if (res == 0) {
                http_send_json(conn, 200, "{\"success\":true,\"message\":\"Candidate removed successfully.\"}");
            } else if (res == -4) {
                http_send_error(conn, 403, "LOCKED", "Cannot delete candidates after voting starts.");
            } else {
                http_send_error(conn, 404, "NOT_FOUND", "Candidate not found.");
            }
            return;
        }

        /* POST /api/admin/candidate/upload_photo or /api/admin/upload_image - Candidate Image Upload */
        if (strcmp(req.method, "POST") == 0 &&
            (strcmp(req.path, "/api/admin/candidate/upload_photo") == 0 ||
             strcmp(req.path, "/api/admin/upload_image") == 0)) {

            int eid = 0, cid = 0;
            http_parse_json_int(req.body, "election_id", &eid);
            http_parse_json_int(req.body, "candidate_id", &cid);

            char *image_b64 = malloc(2 * 1024 * 1024);
            unsigned char *binary_data = malloc(2 * 1024 * 1024);
            if (!image_b64 || !binary_data) {
                free(image_b64);
                free(binary_data);
                http_send_error(conn, 500, "MEM_ERR", "Allocation failed during image processing.");
                return;
            }

            size_t binary_len = 0;
            char detected_ext[16] = "png";

            /* Mode 1: JSON payload with image_data field */
            if (req.body[0] == '{' && http_parse_json_field(req.body, "image_data", image_b64, 2 * 1024 * 1024)) {
                /* Strip data:image/...;base64, prefix if present */
                char *data_start = strstr(image_b64, "base64,");
                if (data_start) {
                    data_start += 7;
                } else {
                    data_start = image_b64;
                }
                binary_len = http_b64_decode(data_start, strlen(data_start), binary_data, 2 * 1024 * 1024);
            }
            /* Mode 2: Multipart/form-data payload */
            else if (req.body_len > 0) {
                const char *head_end = strstr(req.body, "\r\n\r\n");
                if (head_end) {
                    const char *file_start = head_end + 4;
                    const char *next_boundary = strstr(file_start, "\r\n--");
                    if (next_boundary && next_boundary > file_start) {
                        binary_len = (size_t)(next_boundary - file_start);
                        if (binary_len > 2 * 1024 * 1024) binary_len = 2 * 1024 * 1024;
                        memcpy(binary_data, file_start, binary_len);
                    }
                }
            }

            /* Validate size (Max 5MB limit, 2MB in-memory buffer) */
            if (binary_len < 16) {
                free(image_b64);
                free(binary_data);
                http_send_error(conn, 400, "INVALID_FILE", "Uploaded file is empty or corrupted.");
                return;
            }

            /* Validate magic bytes for JPG, JPEG, PNG, WebP */
            if (!validate_image_magic(binary_data, binary_len, detected_ext)) {
                free(image_b64);
                free(binary_data);
                http_send_error(conn, 400, "INVALID_FORMAT",
                                "Unsupported file format. Only JPG, JPEG, PNG, and WebP images are permitted.");
                return;
            }

            /* Generate safe, unique filename in public/images/ */
            char filename[128];
            snprintf(filename, sizeof(filename), "cand_%ld_%04d.%s", (long)time(NULL), rand() % 10000, detected_ext);

            char disk_path[512];
            snprintf(disk_path, sizeof(disk_path), "public/images/%s", filename);

            FILE *img_fp = fopen(disk_path, "wb");
            if (!img_fp) {
                free(image_b64);
                free(binary_data);
                http_send_error(conn, 500, "WRITE_ERR", "Failed to write image to disk.");
                return;
            }
            fwrite(binary_data, 1, binary_len, img_fp);
            fflush(img_fp);
            fsync(fileno(img_fp));
            fclose(img_fp);

            free(image_b64);
            free(binary_data);

            char photo_url[256];
            snprintf(photo_url, sizeof(photo_url), "/images/%s", filename);

            /* If candidate_id specified, update candidate directly */
            if (eid > 0 && cid > 0) {
                Candidate cur_cand;
                if (election_get_candidate_by_id(eid, cid, &cur_cand) == 0) {
                    election_update_candidate(eid, cid, cur_cand.name, cur_cand.party, photo_url);
                }
            }

            char resp[512];
            snprintf(resp, sizeof(resp),
                     "{\"success\":true,\"photo_url\":\"%s\",\"filename\":\"%s\",\"message\":\"Candidate photograph uploaded and validated successfully.\"}",
                     photo_url, filename);
            http_send_json(conn, 200, resp);
            return;
        }

        /* ================= Polling Booth Management APIs ================= */

        /* GET /api/admin/booths?election_id=<id> */
        if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/booths") == 0) {
            int eid = 0;
            http_parse_query_int(req.query, "election_id", &eid);
            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            int cnt = election_get_booth_count(eid);
            char *buf = malloc(16384);
            if (!buf) {
                http_send_error(conn, 500, "MEM_ERR", "Allocation error");
                return;
            }
            size_t w = sprintf(buf, "{\"election_id\":%d,\"booths\":[", eid);
            for (int i = 0; i < cnt; i++) {
                PollingBooth pb;
                if (election_get_booth_by_index(eid, i, &pb) == 0) {
                    char item[512];
                    snprintf(item, sizeof(item),
                             "%s{\"id\":%d,\"name\":\"%s\",\"location\":\"%s\",\"registered\":%d,\"votes_cast\":%d}",
                             (i > 0) ? "," : "", pb.id, pb.name, pb.location, pb.total_registered, pb.votes_cast);
                    w += sprintf(buf + w, "%s", item);
                }
            }
            sprintf(buf + w, "]}");
            http_send_json(conn, 200, buf);
            free(buf);
            return;
        }

        /* POST /api/admin/booths - Add Polling Booth */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/booths") == 0) {
            int eid = 0, bid = 0;
            char name[NAME_LEN] = {0}, loc[NAME_LEN] = {0};

            http_parse_json_int(req.body, "election_id", &eid);
            http_parse_json_int(req.body, "id", &bid);
            http_parse_json_field(req.body, "name", name, sizeof(name));
            http_parse_json_field(req.body, "location", loc, sizeof(loc));

            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            int res = election_add_booth(eid, bid, name, loc);
            if (res == 0) {
                http_send_json(conn, 201, "{\"success\":true,\"message\":\"Polling booth added successfully.\"}");
            } else if (res == -2) {
                http_send_error(conn, 409, "DUPLICATE_ID", "Polling booth ID already exists in this election.");
            } else {
                http_send_error(conn, 400, "BAD_REQUEST", "Failed to add polling booth.");
            }
            return;
        }

        /* POST /api/admin/booths/update - Edit Booth */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/booths/update") == 0) {
            int eid = 0, bid = 0;
            char name[NAME_LEN] = {0}, loc[NAME_LEN] = {0};
            http_parse_json_int(req.body, "election_id", &eid);
            http_parse_json_int(req.body, "id", &bid);
            http_parse_json_field(req.body, "name", name, sizeof(name));
            http_parse_json_field(req.body, "location", loc, sizeof(loc));
            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            int res = election_update_booth(eid, bid, name, loc);
            if (res == 0) {
                http_send_json(conn, 200, "{\"success\":true,\"message\":\"Polling booth updated.\"}");
            } else {
                http_send_error(conn, 404, "NOT_FOUND", "Polling booth not found.");
            }
            return;
        }

        /* POST /api/admin/booths/delete - Delete Booth */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/booths/delete") == 0) {
            int eid = 0, bid = 0;
            http_parse_json_int(req.body, "election_id", &eid);
            http_parse_json_int(req.body, "id", &bid);
            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            int res = election_delete_booth(eid, bid);
            if (res == 0) {
                http_send_json(conn, 200, "{\"success\":true,\"message\":\"Polling booth deleted.\"}");
            } else {
                http_send_error(conn, 404, "NOT_FOUND", "Polling booth not found.");
            }
            return;
        }

        /* ================= Voter Management APIs ================= */

        /* GET /api/admin/voters - Search & list voters */
        if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/voters") == 0) {
            int eid = 0;
            char search_q[64] = {0};
            http_parse_query_int(req.query, "election_id", &eid);
            http_parse_query_param(req.query, "q", search_q, sizeof(search_q));

            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            Voter matched[300];
            int count = election_search_voters(eid, search_q, matched, 300);

            char *out_buf = malloc(65536);
            if (!out_buf) {
                http_send_error(conn, 500, "MEM_ERR", "Allocation error");
                return;
            }

            size_t w = sprintf(out_buf, "{\"election_id\":%d,\"total_count\":%d,\"voters\":[", eid, count);
            for (int i = 0; i < count; i++) {
                char item[256];
                snprintf(item, sizeof(item),
                         "%s{\"id\":\"%s\",\"name\":\"%s\",\"booth_id\":%d,\"has_voted\":%s,\"voted_at\":\"%s\"}",
                         (i > 0) ? "," : "",
                         matched[i].id, matched[i].name, matched[i].booth_id,
                         matched[i].has_voted ? "true" : "false", matched[i].voted_at);
                w += sprintf(out_buf + w, "%s", item);
            }
            sprintf(out_buf + w, "]}");
            http_send_json(conn, 200, out_buf);
            free(out_buf);
            return;
        }

        /* POST /api/admin/voters - Add single voter */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/voters") == 0) {
            int eid = 0;
            char vid[ID_LEN] = {0};
            char vname[NAME_LEN] = {0};
            int booth_id = 1;

            http_parse_json_int(req.body, "election_id", &eid);
            if (!http_parse_json_field(req.body, "id", vid, sizeof(vid))) {
                http_parse_json_field(req.body, "voter_id", vid, sizeof(vid));
            }
            http_parse_json_field(req.body, "name", vname, sizeof(vname));
            http_parse_json_int(req.body, "booth_id", &booth_id);

            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            int res = election_add_voter(eid, vid, vname, booth_id);
            if (res == 0) {
                http_send_json(conn, 201, "{\"success\":true,\"message\":\"Voter registered successfully.\"}");
            } else if (res == -2) {
                http_send_error(conn, 409, "DUPLICATE_ID", "Voter ID is already registered in this election.");
            } else {
                http_send_error(conn, 400, "INVALID_DATA", "Invalid voter data or capacity reached.");
            }
            return;
        }

        /* POST /api/admin/voters/delete - Remove voter */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/voters/delete") == 0) {
            int eid = 0;
            char vid[ID_LEN] = {0};
            http_parse_json_int(req.body, "election_id", &eid);
            http_parse_json_field(req.body, "id", vid, sizeof(vid));
            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            int res = election_delete_voter(eid, vid);
            if (res == 0) {
                http_send_json(conn, 200, "{\"success\":true,\"message\":\"Voter removed from roll.\"}");
            } else if (res == -2) {
                http_send_error(conn, 403, "ALREADY_VOTED", "Cannot delete voter who has already cast a ballot.");
            } else {
                http_send_error(conn, 404, "NOT_FOUND", "Voter not found.");
            }
            return;
        }

        /* POST /api/admin/voters/import or /api/admin/voters/bulk - CSV Bulk Import */
        if (strcmp(req.method, "POST") == 0 &&
            (strcmp(req.path, "/api/admin/voters/import") == 0 ||
             strcmp(req.path, "/api/admin/voters/bulk") == 0)) {
            int eid = 0;
            http_parse_query_int(req.query, "election_id", &eid);
            if (eid <= 0) http_parse_json_int(req.body, "election_id", &eid);
            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            const char *csv_payload = req.body;
            char extracted_csv[8192];
            extracted_csv[0] = '\0';
            if (req.body[0] == '{') {
                if (http_parse_json_field(req.body, "csv_data", extracted_csv, sizeof(extracted_csv)) != 0) {
                    char *src = extracted_csv;
                    char *dst = extracted_csv;
                    while (*src) {
                        if (*src == '\\' && *(src + 1) == 'n') {
                            *dst++ = '\n';
                            src += 2;
                        } else {
                            *dst++ = *src++;
                        }
                    }
                    *dst = '\0';
                    csv_payload = extracted_csv;
                }
            }

            int added = 0, skipped = 0;
            char details[2048] = {0};
            election_import_voters_csv_detailed(eid, csv_payload, &added, &skipped, details, sizeof(details));
            char resp[2560];
            snprintf(resp, sizeof(resp),
                     "{\"success\":true,\"election_id\":%d,\"added\":%d,\"skipped\":%d,\"details\":\"%s\"}",
                     eid, added, skipped, details);
            http_send_json(conn, 200, resp);
            return;
        }

        /* ================= Live Analytics & Monitoring ================= */

        /* GET /api/admin/analytics?election_id=<id> */
        if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/analytics") == 0) {
            int eid = 0;
            http_parse_query_int(req.query, "election_id", &eid);
            if (eid <= 0) eid = election_get_active_id();
            if (eid <= 0) eid = 1;

            char buf[8192];
            election_get_analytics_json(eid, buf, sizeof(buf));
            http_send_json(conn, 200, buf);
            return;
        }

        /* 9. GET /api/admin/alerts (Intrusion alerts) */
        if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/alerts") == 0) {
            char buf[16384];
            security_get_alerts_json(buf, sizeof(buf));
            http_send_json(conn, 200, buf);
            return;
        }

        /* 10. GET /api/admin/audit (Tamper-evident audit log ledger) */
        if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/audit") == 0) {
            char buf[32768];
            audit_log_get_recent_json(buf, sizeof(buf), 100);
            http_send_json(conn, 200, buf);
            return;
        }

        /* 11. POST /api/admin/audit/verify (Verify ledger HMAC chain) */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/audit/verify") == 0) {
            int total = 0, tampered = -1;
            int valid = audit_log_verify_chain(&total, &tampered);

            char resp[512];
            snprintf(resp, sizeof(resp),
                     "{\"success\":true,\"chain_valid\":%s,\"total_records\":%d,\"tampered_record_seq\":%d}",
                     valid ? "true" : "false", total, tampered);
            http_send_json(conn, 200, resp);
            return;
        }

        /* 12. GET /api/admin/integrity (Verify SHA-256 File Manifest) */
        if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/integrity") == 0) {
            char report[4096];
            security_verify_file_integrity(report, sizeof(report));
            http_send_json(conn, 200, report);
            return;
        }

        /* 13. GET /api/admin/allowlist (IP Allowlist management) */
        if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/allowlist") == 0) {
            char buf[2048];
            security_get_ip_allowlist_json(buf, sizeof(buf));
            http_send_json(conn, 200, buf);
            return;
        }

        /* 14. POST /api/admin/allowlist (Add IP) */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/allowlist") == 0) {
            char ip[64] = {0};
            if (!http_parse_json_field(req.body, "ip", ip, sizeof(ip)) || strlen(ip) == 0) {
                http_send_error(conn, 400, "MISSING_IP", "Missing or empty 'ip' field in JSON request.");
                return;
            }

            int res = security_add_ip_allowlist(ip);
            if (res == 1) {
                char resp[256];
                snprintf(resp, sizeof(resp), "{\"success\":true,\"message\":\"IP address %s added to allowlist successfully.\"}", ip);
                http_send_json(conn, 200, resp);
            } else if (res == 0) {
                char err_msg[256];
                snprintf(err_msg, sizeof(err_msg), "IP address %s is already in the administrative allowlist.", ip);
                http_send_error(conn, 409, "DUPLICATE_IP", err_msg);
            } else if (res == -1) {
                http_send_error(conn, 400, "INVALID_IP", "Invalid IP address format. Must be a valid IPv4 or IPv6 address.");
            } else if (res == -2) {
                http_send_error(conn, 400, "ALLOWLIST_FULL", "Administrative IP allowlist has reached maximum capacity.");
            } else {
                http_send_error(conn, 500, "INTERNAL_ERROR", "Failed to update IP allowlist.");
            }
            return;
        }

        /* ================= Reports: CSV & Pure-C PDF ================= */

        /* 15. GET /api/admin/report/csv or /api/admin/reports/csv */
        if (strcmp(req.method, "GET") == 0 &&
            (strcmp(req.path, "/api/admin/report/csv") == 0 ||
             strcmp(req.path, "/api/admin/reports/csv") == 0)) {
            int eid = 0;
            http_parse_query_int(req.query, "election_id", &eid);
            char *csv_buf = malloc(65536);
            if (!csv_buf) {
                http_send_error(conn, 500, "MEM_ERR", "Allocation failed");
                return;
            }
            int len = 0;
            if (eid > 0) {
                len = admin_generate_election_csv_report(eid, csv_buf, 65536);
            } else {
                len = admin_generate_csv_report(csv_buf, 65536);
            }
            char disp[128];
            snprintf(disp, sizeof(disp), "Content-Disposition: attachment; filename=\"election_%d_report.csv\"\r\n",
                     (eid > 0) ? eid : 1);
            http_send_response_bytes(conn, 200, "OK", "text/csv; charset=utf-8",
                                     csv_buf, len, is_head, disp);
            free(csv_buf);
            return;
        }

        /* 16. GET /api/admin/report/pdf or /api/admin/reports/pdf */
        if (strcmp(req.method, "GET") == 0 &&
            (strcmp(req.path, "/api/admin/report/pdf") == 0 ||
             strcmp(req.path, "/api/admin/reports/pdf") == 0)) {
            int eid = 0;
            http_parse_query_int(req.query, "election_id", &eid);
            unsigned char *pdf_buf = NULL;
            size_t pdf_len = 0;
            int ret = 0;
            if (eid > 0) {
                ret = admin_generate_election_pdf_report(eid, &pdf_buf, &pdf_len);
            } else {
                ret = admin_generate_pdf_report(&pdf_buf, &pdf_len);
            }
            if (ret == 0 && pdf_buf) {
                char disp[128];
                snprintf(disp, sizeof(disp), "Content-Disposition: inline; filename=\"election_%d_report.pdf\"\r\n",
                         (eid > 0) ? eid : 1);
                http_send_response_bytes(conn, 200, "OK", "application/pdf",
                                         pdf_buf, pdf_len, is_head, disp);
                free(pdf_buf);
            } else {
                http_send_error(conn, 500, "PDF_GEN_ERR", "Failed to generate PDF document.");
            }
            return;
        }

        /* ================= Backup & Recovery APIs ================= */

        /* POST /api/admin/backup/create - Create timestamped SHA-256 backup */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/backup/create") == 0) {
            char archive_name[128] = {0};
            int res = admin_create_backup(archive_name, sizeof(archive_name));
            if (res == 0) {
                char resp[512];
                snprintf(resp, sizeof(resp),
                         "{\"success\":true,\"archive\":\"%s\",\"message\":\"Backup created and checksum verified.\"}",
                         archive_name);
                http_send_json(conn, 200, resp);
            } else {
                http_send_error(conn, 500, "BACKUP_FAILED", "Failed to create verified system backup.");
            }
            return;
        }

        /* GET /api/admin/backups - List all backups with SHA-256 integrity */
        if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/api/admin/backups") == 0) {
            char *buf = malloc(32768);
            if (!buf) {
                http_send_error(conn, 500, "MEM_ERR", "Allocation error");
                return;
            }
            admin_list_backups_json(buf, 32768);
            http_send_json(conn, 200, buf);
            free(buf);
            return;
        }

        /* POST /api/admin/backup/restore - Restore backup with SHA-256 verification */
        if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/api/admin/backup/restore") == 0) {
            char archive_name[128] = {0};
            http_parse_json_field(req.body, "archive", archive_name, sizeof(archive_name));
            if (strlen(archive_name) == 0) {
                http_send_error(conn, 400, "BAD_REQUEST", "Missing archive filename.");
                return;
            }

            int res = admin_restore_backup(archive_name);
            if (res == 0) {
                http_send_json(conn, 200, "{\"success\":true,\"message\":\"Backup restored and verified successfully. Election data reloaded.\"}");
            } else if (res == -2) {
                http_send_error(conn, 400, "CHECKSUM_FAILED", "SHA-256 checksum verification failed. Archive may be corrupted or tampered.");
            } else {
                http_send_error(conn, 500, "RESTORE_FAILED", "Failed to extract or restore backup archive.");
            }
            return;
        }

        http_send_error(conn, 404, "NOT_FOUND", "Administrative endpoint not found.");
        return;
    }

    /* Unrecognized endpoint */
    http_send_error(conn, 404, "NOT_FOUND", "Endpoint not found.");
}
