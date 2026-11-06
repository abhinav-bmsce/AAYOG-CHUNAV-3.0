/**
 * ============================================================================
 * Title:       AAYOG_CHUNAV 2.0 - HTTP & TLS Protocol Dispatcher Header
 * File:        include/http.h
 * Description: HTTP/1.1 request handling over POSIX sockets & OpenSSL TLS streams.
 * ============================================================================
 */

#ifndef HTTP_H
#define HTTP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>

/* Connection wrapper supporting both plain socket and TLS */
typedef struct {
    int socket_fd;
    SSL *ssl;
    char client_ip[46];
    int is_tls;
    int is_mtls_admin;
    char client_cn[64];
    int should_close;
    int selected_election_id;
} Connection;

/* HTTP Request representation */
typedef struct {
    char method[16];
    char path[256];
    char query[256];
    char content_type[64];
    size_t content_length;
    char auth_header[256];
    const char *body;
    size_t body_len;
} HttpRequest;

/* Transport abstraction for unified read/write and partial read handling */
ssize_t conn_read(Connection *conn, void *buf, size_t num);
ssize_t conn_write(Connection *conn, const void *buf, size_t num);
ssize_t http_read_full_request(Connection *conn, char *buffer, size_t max_len);

/* Response helpers */
void http_send_response_bytes(Connection *conn, int status_code, const char *status_text,
                              const char *content_type, const void *body, size_t body_len,
                              int is_head, const char *extra_headers);
void http_send_response(Connection *conn, int status_code, const char *status_text,
                        const char *content_type, const char *body, int is_head);
void http_send_json(Connection *conn, int status_code, const char *json_body);
void http_send_error(Connection *conn, int status_code, const char *error_code, const char *message);

/* Static file server */
void http_serve_static_file(Connection *conn, const char *filepath, const char *content_type, int is_head);

/* Request Parser and Router */
int http_parse_request(const char *raw_req, size_t raw_len, HttpRequest *out_req);
int http_parse_json_field(const char *json, const char *key, char *out_val, size_t max_out);
int http_parse_json_int(const char *json, const char *key, int *out_val);

/* Main HTTP Dispatcher */
void http_handle_request(Connection *conn, const char *raw_request, size_t req_len);

#endif /* HTTP_H */

