/*
 * The client that reaches captcha providers and Anubis: non blocking requests
 * built on the event loop and the TLS machinery of nginx.
 */

#include "ngx_http_waf_module.h"

static void ngx_http_waf_fetch_read(ngx_event_t* rev);


static void ngx_http_waf_fetch_write(ngx_event_t* wev);


static void ngx_http_waf_fetch_resolved(ngx_resolver_ctx_t* rc);


static ngx_int_t ngx_http_waf_fetch_connect(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx,
    struct sockaddr* sockaddr, socklen_t socklen);


static ngx_int_t ngx_http_waf_fetch_anubis_head(ngx_http_request_t* r,
    ngx_http_waf_ctx_t* ctx);


static void ngx_http_waf_fetch_note_error(ngx_http_waf_ctx_t* ctx,
    ngx_http_waf_fetch_error_t error, ngx_err_t err, ngx_uint_t detail);


static void ngx_http_waf_fetch_note_timeout(ngx_http_waf_ctx_t* ctx);


static ngx_http_waf_fetch_error_t ngx_http_waf_fetch_io_error(
    ngx_err_t error, ngx_http_waf_fetch_error_t fallback);


static void ngx_http_waf_fetch_log_failure(ngx_http_request_t* r,
    ngx_http_waf_ctx_t* ctx);


/* -------------------------------------------------------------------------
 * The captcha provider request.
 *
 * The request is parked and the provider is reached with a small non blocking
 * client of our own: connect, send the POST, read until the provider closes the
 * connection (the request is HTTP/1.0 with `Connection: close`), then hand the
 * answer back to the machine.
 * ---------------------------------------------------------------------- */

/** Timeout of one provider request, in milliseconds. */
#define NGX_HTTP_WAF_FETCH_TIMEOUT 5000

/** The answer of a provider has to be much smaller than this. */
#define NGX_HTTP_WAF_FETCH_BUFFER 8192


static const char* ngx_http_waf_fetch_stage(ngx_http_waf_fetch_error_t error)
{
    switch (error) {
    case NGX_HTTP_WAF_FETCH_ERROR_ENDPOINT:
        return "config";
    case NGX_HTTP_WAF_FETCH_ERROR_RESOLVER_CONFIG:
    case NGX_HTTP_WAF_FETCH_ERROR_RESOLVER:
        return "resolve";
    case NGX_HTTP_WAF_FETCH_ERROR_CONNECT:
    case NGX_HTTP_WAF_FETCH_ERROR_CONNECT_TIMEOUT:
        return "connect";
    case NGX_HTTP_WAF_FETCH_ERROR_TLS_HANDSHAKE:
    case NGX_HTTP_WAF_FETCH_ERROR_TLS_TIMEOUT:
    case NGX_HTTP_WAF_FETCH_ERROR_TLS_VERIFY:
    case NGX_HTTP_WAF_FETCH_ERROR_TLS_HOST:
        return "tls";
    case NGX_HTTP_WAF_FETCH_ERROR_SEND:
    case NGX_HTTP_WAF_FETCH_ERROR_SEND_TIMEOUT:
        return "send";
    case NGX_HTTP_WAF_FETCH_ERROR_RECEIVE:
    case NGX_HTTP_WAF_FETCH_ERROR_RECEIVE_TIMEOUT:
        return "receive";
    case NGX_HTTP_WAF_FETCH_ERROR_RESPONSE:
    case NGX_HTTP_WAF_FETCH_ERROR_RESPONSE_TOO_LARGE:
    case NGX_HTTP_WAF_FETCH_ERROR_STATUS:
        return "response";
    case NGX_HTTP_WAF_FETCH_ERROR_NONE:
    case NGX_HTTP_WAF_FETCH_ERROR_INTERNAL:
        return "internal";
    }

    return "internal";
}


static const char* ngx_http_waf_fetch_cause(ngx_http_waf_fetch_error_t error)
{
    switch (error) {
    case NGX_HTTP_WAF_FETCH_ERROR_ENDPOINT:
        return "endpoint_not_configured";
    case NGX_HTTP_WAF_FETCH_ERROR_RESOLVER_CONFIG:
        return "resolver_not_configured";
    case NGX_HTTP_WAF_FETCH_ERROR_RESOLVER:
        return "resolution_failed";
    case NGX_HTTP_WAF_FETCH_ERROR_CONNECT:
        return "connect_failed";
    case NGX_HTTP_WAF_FETCH_ERROR_CONNECT_TIMEOUT:
        return "connect_timeout";
    case NGX_HTTP_WAF_FETCH_ERROR_TLS_HANDSHAKE:
        return "tls_handshake_failed";
    case NGX_HTTP_WAF_FETCH_ERROR_TLS_TIMEOUT:
        return "tls_handshake_timeout";
    case NGX_HTTP_WAF_FETCH_ERROR_TLS_VERIFY:
        return "certificate_verify_failed";
    case NGX_HTTP_WAF_FETCH_ERROR_TLS_HOST:
        return "certificate_host_mismatch";
    case NGX_HTTP_WAF_FETCH_ERROR_SEND:
        return "send_failed";
    case NGX_HTTP_WAF_FETCH_ERROR_SEND_TIMEOUT:
        return "send_timeout";
    case NGX_HTTP_WAF_FETCH_ERROR_RECEIVE:
        return "receive_failed";
    case NGX_HTTP_WAF_FETCH_ERROR_RECEIVE_TIMEOUT:
        return "receive_timeout";
    case NGX_HTTP_WAF_FETCH_ERROR_RESPONSE:
        return "invalid_response";
    case NGX_HTTP_WAF_FETCH_ERROR_RESPONSE_TOO_LARGE:
        return "response_too_large";
    case NGX_HTTP_WAF_FETCH_ERROR_STATUS:
        return "unusable_status";
    case NGX_HTTP_WAF_FETCH_ERROR_NONE:
    case NGX_HTTP_WAF_FETCH_ERROR_INTERNAL:
        return "internal_error";
    }

    return "internal_error";
}


static const char* ngx_http_waf_fetch_hint(ngx_http_waf_fetch_error_t error)
{
    switch (error) {
    case NGX_HTTP_WAF_FETCH_ERROR_ENDPOINT:
        return "configure the provider endpoint before enabling the inspection";
    case NGX_HTTP_WAF_FETCH_ERROR_RESOLVER_CONFIG:
        return "add resolver 127.0.0.11 valid=10s ipv6=off or use a resolvable host";
    case NGX_HTTP_WAF_FETCH_ERROR_RESOLVER:
        return "configure resolver 127.0.0.11 valid=10s ipv6=off and check the service name";
    case NGX_HTTP_WAF_FETCH_ERROR_CONNECT:
        return "check that the service is running on this port and shares a reachable network";
    case NGX_HTTP_WAF_FETCH_ERROR_CONNECT_TIMEOUT:
        return "check the backend address, network route, firewall and listen port";
    case NGX_HTTP_WAF_FETCH_ERROR_TLS_HANDSHAKE:
    case NGX_HTTP_WAF_FETCH_ERROR_TLS_TIMEOUT:
        return "check the URL scheme, TLS support, trusted CA and certificate hostname";
    case NGX_HTTP_WAF_FETCH_ERROR_TLS_VERIFY:
    case NGX_HTTP_WAF_FETCH_ERROR_TLS_HOST:
        return "install the issuing CA and verify that the URL host matches the certificate";
    case NGX_HTTP_WAF_FETCH_ERROR_SEND:
    case NGX_HTTP_WAF_FETCH_ERROR_SEND_TIMEOUT:
        return "check that the backend accepts HTTP and remains reachable";
    case NGX_HTTP_WAF_FETCH_ERROR_RECEIVE:
    case NGX_HTTP_WAF_FETCH_ERROR_RECEIVE_TIMEOUT:
        return "check backend health, response time and whether it closes the connection";
    case NGX_HTTP_WAF_FETCH_ERROR_RESPONSE:
    case NGX_HTTP_WAF_FETCH_ERROR_RESPONSE_TOO_LARGE:
        return "check that the configured URL is the Anubis or captcha HTTP API";
    case NGX_HTTP_WAF_FETCH_ERROR_STATUS:
        return "check BASE_PREFIX and the inspection endpoint; it returned an unusable status";
    case NGX_HTTP_WAF_FETCH_ERROR_NONE:
    case NGX_HTTP_WAF_FETCH_ERROR_INTERNAL:
        return "check Nginx memory pressure and the surrounding error log";
    }

    return "check Nginx memory pressure and the surrounding error log";
}


static void ngx_http_waf_fetch_note_error(ngx_http_waf_ctx_t* ctx,
    ngx_http_waf_fetch_error_t error, ngx_err_t err, ngx_uint_t detail)
{
    if (ctx == NULL || ctx->fetch.failure != NGX_HTTP_WAF_FETCH_ERROR_NONE) {
        return;
    }

    ctx->fetch.failure = error;
    ctx->fetch.failure_errno = err;
    ctx->fetch.failure_detail = detail;
}


static void ngx_http_waf_fetch_note_timeout(ngx_http_waf_ctx_t* ctx)
{
    if (ctx == NULL) {
        return;
    }

    switch (ctx->fetch.phase) {
    case NGX_HTTP_WAF_FETCH_PHASE_CONNECT:
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_CONNECT_TIMEOUT, NGX_ETIMEDOUT, 0);
        break;
    case NGX_HTTP_WAF_FETCH_PHASE_HANDSHAKE:
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_TLS_TIMEOUT, NGX_ETIMEDOUT, 0);
        break;
    case NGX_HTTP_WAF_FETCH_PHASE_SEND:
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_SEND_TIMEOUT, NGX_ETIMEDOUT, 0);
        break;
    case NGX_HTTP_WAF_FETCH_PHASE_IDLE:
    case NGX_HTTP_WAF_FETCH_PHASE_RECEIVE:
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_RECEIVE_TIMEOUT, NGX_ETIMEDOUT, 0);
        break;
    }
}


static ngx_http_waf_fetch_error_t ngx_http_waf_fetch_io_error(
    ngx_err_t error, ngx_http_waf_fetch_error_t fallback)
{
    switch (error) {
    case NGX_ECONNREFUSED:
    case NGX_EHOSTUNREACH:
    case NGX_ENETUNREACH:
        return NGX_HTTP_WAF_FETCH_ERROR_CONNECT;
    default:
        return fallback;
    }
}


static void ngx_http_waf_fetch_log_failure(ngx_http_request_t* r,
    ngx_http_waf_ctx_t* ctx)
{
    ngx_http_waf_endpoint_t* api;
    ngx_uint_t blocked, status;
    ngx_str_t endpoint, provider;
    ngx_err_t error;
    ngx_log_t* log;
    ngx_uint_t level;
    const char* resolved;
    const char* policy;
    u_char errstr[NGX_MAX_ERROR_STR];
    u_char* errstr_end;
    size_t errstr_len;

    if (ctx == NULL || ctx->fetch.failure == NGX_HTTP_WAF_FETCH_ERROR_NONE
        || ctx->fetch.failure_logged)
    {
        return;
    }

    ctx->fetch.failure_logged = 1;
    api = ctx->fetch.api;

    if (ctx->fetch.anubis
        || (ctx->step != NULL
            && ctx->step->kind == NGX_WAF_STEP_KIND_HTTP_REQUEST
            && ctx->step->pending.request_kind
               == NGX_WAF_HTTP_REQUEST_KIND_ANUBIS))
    {
        ngx_str_set(&provider, "anubis");
    } else {
        ngx_str_set(&provider, "captcha");
    }

    if (api != NULL && api->url.len != 0) {
        endpoint = api->url;
    } else {
        ngx_str_set(&endpoint, "<unconfigured>");
    }

    if (api == NULL) {
        resolved = "unknown";
    } else {
        resolved = api->resolved ? "yes" : "no";
    }

    blocked = ctx->step != NULL
              && ctx->step->kind == NGX_WAF_STEP_KIND_RESPONSE
              && ctx->step->decision.blocked;
    status = ctx->step != NULL
             && ctx->step->kind == NGX_WAF_STEP_KIND_RESPONSE
             ? (ngx_uint_t) ctx->step->decision.status : 0;

    policy = blocked ? "fail-closed" : "fail-open";
    level = blocked || ctx->step == NULL
            || ctx->step->kind == NGX_WAF_STEP_KIND_INTERNAL_ERROR
            ? NGX_LOG_ERR : NGX_LOG_WARN;
    log = r->connection->log;
    error = ctx->fetch.failure_errno;

    if (error != 0) {
        errstr_end = ngx_strerror(error, errstr, sizeof(errstr));
        errstr_len = errstr_end - errstr;
    } else {
        errstr_len = 0;
    }

    ngx_log_error(level, log, 0,
        "ngx_waf: backend request failed provider=%V endpoint=\"%V\" "
        "stage=%s cause=%s resolved_at_startup=%s error=\"%*s\" detail=%ui "
        "policy=%s status=%ui hint=\"%s\"",
        &provider,
        &endpoint,
        ngx_http_waf_fetch_stage(ctx->fetch.failure),
        ngx_http_waf_fetch_cause(ctx->fetch.failure),
        resolved,
        errstr_len,
        errstr,
        ctx->fetch.failure_detail,
        policy,
        status,
        ngx_http_waf_fetch_hint(ctx->fetch.failure));
}


static void ngx_http_waf_fetch_noop(ngx_event_t* ev) {
    (void) ev;
}


/**
 * The peer the provider request is sent to.  `ngx_event_connect_peer()`
 * requires this callback, it hands back the address that was resolved when the
 * configuration was read.
 */
static ngx_int_t ngx_http_waf_get_peer(ngx_peer_connection_t* pc, void* data) {
    ngx_http_waf_ctx_t* ctx = data;

    pc->sockaddr = ctx->fetch.sockaddr;
    pc->socklen = ctx->fetch.socklen;
    pc->name = &ctx->fetch.host;

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_fetch_connect_test(ngx_http_waf_ctx_t* ctx,
    ngx_connection_t* c) {
    int       err;
    socklen_t len = sizeof(int);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void*) &err, &len) == -1) {
        err = ngx_socket_errno;
    }

    if (err) {
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_CONNECT, err, 0);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/**
 * Hand the provider connection back to the worker.
 *
 * A https provider owns an SSL object, it has to be released before the
 * connection (that is what `ngx_ssl_shutdown()` does, the module does not wait
 * for the close alert of the peer).  The pointer of the context is cleared
 * first: the connection is in the free list of the worker afterwards and may
 * serve another request before this one is destroyed.
 */
static void ngx_http_waf_fetch_close(ngx_http_waf_ctx_t* ctx) {
    ngx_connection_t* c = ctx->fetch.connection;

    if (c == NULL) {
        return;
    }

    ctx->fetch.connection = NULL;

    if (c->ssl != NULL) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;
        (void) ngx_ssl_shutdown(c);
    }

    ngx_close_connection(c);
}


/**
 * Close the provider connection of a request that is being destroyed; it is
 * registered as a pool cleanup so a client that gives up does not leak it.
 */
static void ngx_http_waf_fetch_cleanup(void* data) {
    ngx_http_waf_fetch_close(data);
}


/**
 * The tail of one provider request the core left: stop its timers, hand the
 * connection back to the worker and forget the buffers, which belong to that
 * one request.
 */
static void ngx_http_waf_fetch_settle(ngx_http_waf_ctx_t* ctx) {
    ngx_connection_t* c = ctx->fetch.connection;

    if (c != NULL) {
        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }
        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
    }

    ctx->fetch.finished = 1;

    ngx_http_waf_fetch_close(ctx);

    /* The buffers belong to one provider request: a machine that starts
     * another one builds its own. */
    ctx->fetch.request = NULL;
    ctx->fetch.response = NULL;
}


/**
 * Wake the parked request up from an event: the phases are re-entered so that
 * the phase handler applies the new step.  Nothing to do while the drive loop
 * is still on the stack, that loop applies the step itself.
 */
static void ngx_http_waf_fetch_wake(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx) {
    if (ctx->fetch.in_drive) {
        return;
    }

    ngx_http_finalize_request(r, NGX_DONE);
    ngx_http_core_run_phases(r);
}


/**
 * Hand the bytes of the answer read so far to the machine.  Returns 1 when it
 * left the HTTP step (the request was settled), 0 when it still waits for the
 * rest of the same answer.  The caller returns either way: the request may be
 * gone once the machine settled.
 */
ngx_uint_t ngx_http_waf_fetch_feed(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx,
    ngx_uint_t eof)
{
    ngx_waf_event_t event;
    ngx_buf_t* b = ctx->fetch.response;

    ngx_memzero(&event, sizeof(ngx_waf_event_t));

    event.kind = NGX_WAF_EVENT_KIND_HTTP_DATA;
    event.data.data = b->pos;
    event.data.len = (size_t) (b->last - b->pos);
    event.eof = eof != 0;

    ngx_http_waf_resume(r, ctx, &event);

    if (ctx->step != NULL && ctx->step->kind == NGX_WAF_STEP_KIND_HTTP_REQUEST) {
        /* the same provider request waits for the rest of the answer */
        return 0;
    }

    ngx_http_waf_fetch_settle(ctx);
    ngx_http_waf_fetch_wake(r, ctx);

    return 1;
}


/**
 * The provider request failed before an answer could be read: the machine
 * settles it as a failed attempt.
 */
void ngx_http_waf_fetch_failed(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx) {
    ngx_waf_event_t event;

    if (ctx == NULL) {
        return;
    }

    ngx_http_waf_fetch_note_error(
        ctx, NGX_HTTP_WAF_FETCH_ERROR_INTERNAL, 0, 0);

    ngx_memzero(&event, sizeof(ngx_waf_event_t));
    event.kind = NGX_WAF_EVENT_KIND_HTTP_FAILED;

    ngx_http_waf_resume(r, ctx, &event);

    ngx_http_waf_fetch_log_failure(r, ctx);

    ngx_http_waf_fetch_settle(ctx);
    ngx_http_waf_fetch_wake(r, ctx);
}


/**
 * Check the name the verified provider certificate has to carry: a DNS name
 * through the helper of nginx, an IP literal through the check of the library
 * (nginx' helper only looks at DNS names).
 */
static ngx_int_t ngx_http_waf_fetch_check_name(ngx_connection_t* c, ngx_str_t* host) {
#ifdef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
    u_char addr6[16];

    if (ngx_inet_addr(host->data, host->len) != INADDR_NONE
        || (host->len != 0
            && ngx_inet6_addr(host->data, host->len, addr6) == NGX_OK))
    {
        X509* cert = SSL_get_peer_certificate(c->ssl->connection);
        int ok;

        if (cert == NULL) {
            return NGX_ERROR;
        }

        /* the host of the endpoint is NUL terminated, see the configuration */
        ok = X509_check_ip_asc(cert, (char*) host->data, 0);
        X509_free(cert);

        return ok == 1 ? NGX_OK : NGX_ERROR;
    }
#endif

    return ngx_ssl_check_host(c, host);
}


/**
 * The TLS handshake of a provider request is finished: send the request.
 * nginx calls this through `c->ssl->handler`.
 */
static void ngx_http_waf_fetch_ssl_done(ngx_connection_t* c) {
    ngx_http_request_t* r = c->data;
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_loc_conf_t* conf;
    long rc;

    if (ctx == NULL || ctx->fetch.request == NULL || ctx->fetch.finished) {
        return;
    }

    /*
     * nginx calls this handler when the handshake timed out or failed as well,
     * and then `c->send` is still the raw socket: sending the request would put
     * the token and the secret on the wire in clear text, and the TLS bytes the
     * peer sends back would be parsed as an answer.
     */
    if (c->ssl == NULL || !c->ssl->handshaked || c->timedout || c->error) {
        ngx_http_waf_fetch_note_error(
            ctx,
            c->timedout ? NGX_HTTP_WAF_FETCH_ERROR_TLS_TIMEOUT
                        : NGX_HTTP_WAF_FETCH_ERROR_TLS_HANDSHAKE,
            c->timedout ? NGX_ETIMEDOUT : 0, 0);
        ngx_http_waf_fetch_failed(r, ctx);
        return;
    }

    /*
     * `SSL_VERIFY_PEER` lets the library refuse a certificate it cannot
     * verify during the handshake; the check is repeated here like nginx does
     * for an upstream connection.  The request is only written once the chain
     * and the name of the provider were accepted.
     */
    rc = SSL_get_verify_result(c->ssl->connection);

    if (rc != X509_V_OK) {
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_TLS_VERIFY, 0, (ngx_uint_t) rc);
        ngx_http_waf_fetch_failed(r, ctx);
        return;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (conf == NULL || ctx->fetch.api == NULL
        || ngx_http_waf_fetch_check_name(c, &ctx->fetch.api->host) != NGX_OK)
    {
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_TLS_HOST, 0, 0);
        ngx_http_waf_fetch_failed(r, ctx);
        return;
    }

    ctx->fetch.handshake_done = 1;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    c->read->handler = ngx_http_waf_fetch_read;
    c->write->handler = ngx_http_waf_fetch_write;

    ctx->fetch.phase = NGX_HTTP_WAF_FETCH_PHASE_SEND;
    ngx_http_waf_fetch_write(c->write);
}


static ngx_int_t ngx_http_waf_fetch_status(ngx_http_request_t* r,
    ngx_http_waf_ctx_t* ctx, uint16_t status)
{
    ngx_waf_event_t event;

    if (!((status >= 200 && status < 300) || status == 401
          || status == 403 || status == 307))
    {
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_STATUS, 0, status);
    }

    ngx_memzero(&event, sizeof(ngx_waf_event_t));
    event.kind = NGX_WAF_EVENT_KIND_HTTP_STATUS;
    event.status = status;

    ngx_http_waf_resume(r, ctx, &event);
    ngx_http_waf_fetch_log_failure(r, ctx);
    ngx_http_waf_fetch_settle(ctx);
    ngx_http_waf_fetch_wake(r, ctx);

    return NGX_OK;
}


static void ngx_http_waf_remove_client_risk_headers(ngx_http_request_t* r)
{
    ngx_list_part_t* part = &r->headers_in.headers.part;
    ngx_table_elt_t* header = part->elts;
    ngx_uint_t i;

    for ( ;; ) {
        for (i = 0; i < part->nelts; i++) {
            if (header[i].key.len >= sizeof("X-Anubis-") - 1
                && ngx_strncasecmp(header[i].key.data, (u_char*) "X-Anubis-",
                                   sizeof("X-Anubis-") - 1) == 0)
            {
                header[i].hash = 0;
            }
        }
        if (part->next == NULL) {
            break;
        }
        part = part->next;
        header = part->elts;
    }
}


static ngx_int_t ngx_http_waf_fetch_anubis_head(ngx_http_request_t* r,
    ngx_http_waf_ctx_t* ctx)
{
    ngx_buf_t* b = ctx->fetch.response;
    ngx_buf_t probe;
    ngx_http_status_t status;
    u_char* end = NULL;
    u_char* p;
    ngx_int_t rc;

    for (p = b->pos; p + 3 < b->last; p++) {
        if (p[0] == CR && p[1] == LF && p[2] == CR && p[3] == LF) {
            end = p + 4;
            break;
        }
    }

    if (end == NULL) {
        if (b->last == b->end) {
            ngx_http_waf_fetch_note_error(
                ctx, NGX_HTTP_WAF_FETCH_ERROR_RESPONSE_TOO_LARGE, 0, 0);
            return NGX_ERROR;
        }
        return NGX_AGAIN;
    }

    probe = *b;
    probe.last = end;
    ngx_memzero(&status, sizeof(ngx_http_status_t));
    rc = ngx_http_parse_status_line(r, &probe, &status);
    if (rc != NGX_OK || status.code < 100 || status.code > 599) {
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_RESPONSE, 0, 0);
        return NGX_ERROR;
    }

    return ngx_http_waf_fetch_status(r, ctx, (uint16_t) status.code);
}


static void ngx_http_waf_fetch_read(ngx_event_t* rev) {
    ngx_connection_t* c = rev->data;
    ngx_http_request_t* r = c->data;
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_buf_t* b;
    ngx_int_t rc;
    ssize_t n;

    if (ctx == NULL || ctx->step == NULL || ctx->fetch.response == NULL || ctx->fetch.finished) {
        return;
    }

    if (rev->timedout) {
        ngx_http_waf_fetch_note_timeout(ctx);
        ngx_http_waf_fetch_failed(r, ctx);
        return;
    }

    b = ctx->fetch.response;

    for ( ;; ) {
        n = c->recv(c, b->last, b->end - b->last);

        if (n > 0) {
            b->last += n;

            if (ctx->fetch.anubis) {
                rc = ngx_http_waf_fetch_anubis_head(r, ctx);
                if (rc == NGX_AGAIN) {
                    continue;
                }
                if (rc == NGX_ERROR) {
                    ngx_http_waf_fetch_failed(r, ctx);
                }
                return;
            }

            if (b->last == b->end) {
                /* a provider answer bigger than the buffer is not one we can use */
                ngx_http_waf_fetch_note_error(
                    ctx, NGX_HTTP_WAF_FETCH_ERROR_RESPONSE_TOO_LARGE, 0, 0);
                ngx_http_waf_fetch_failed(r, ctx);
                return;
            }

            /* the machine settles the request when the answer is complete */
            if (ngx_http_waf_fetch_feed(r, ctx, 0)) {
                return;
            }

            continue;
        }

        if (n == 0) {
            if (ctx->fetch.anubis) {
                ngx_http_waf_fetch_note_error(
                    ctx, NGX_HTTP_WAF_FETCH_ERROR_RESPONSE, 0, 0);
                ngx_http_waf_fetch_failed(r, ctx);
                return;
            }
            /*
             * The provider is done (the request asked to close): the machine
             * settles the request, an answer it cannot read included.  A step
             * that still waits for bytes is a failed attempt, not a hang.
             */
            if (!ngx_http_waf_fetch_feed(r, ctx, 1)) {
                ngx_http_waf_fetch_failed(r, ctx);
            }
            return;
        }

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_http_waf_fetch_note_error(
                    ctx,
                    ngx_http_waf_fetch_io_error(
                        ngx_socket_errno, NGX_HTTP_WAF_FETCH_ERROR_RECEIVE),
                    ngx_socket_errno, 0);
                ngx_http_waf_fetch_failed(r, ctx);
            }
            return;
        }

        ngx_http_waf_fetch_note_error(
            ctx,
            ngx_http_waf_fetch_io_error(
                ngx_socket_errno, NGX_HTTP_WAF_FETCH_ERROR_RECEIVE),
            ngx_socket_errno, 0);
        ngx_http_waf_fetch_failed(r, ctx);
        return;
    }
}


static void ngx_http_waf_fetch_write(ngx_event_t* wev) {
    ngx_connection_t* c = wev->data;
    ngx_http_request_t* r = c->data;
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_buf_t* b;
    ssize_t n;
    ngx_int_t rc;

    if (ctx == NULL || ctx->step == NULL || ctx->fetch.request == NULL || ctx->fetch.finished) {
        return;
    }

    if (wev->timedout) {
        ngx_http_waf_fetch_note_timeout(ctx);
        ngx_http_waf_fetch_failed(r, ctx);
        return;
    }

    if (ngx_http_waf_fetch_connect_test(ctx, c) != NGX_OK) {
        ngx_http_waf_fetch_failed(r, ctx);
        return;
    }

    if (ctx->fetch.use_ssl && !ctx->fetch.handshake_done) {
        ctx->fetch.phase = NGX_HTTP_WAF_FETCH_PHASE_HANDSHAKE;
        rc = ngx_ssl_handshake(c);

        if (rc == NGX_AGAIN) {
            ngx_add_timer(c->write, NGX_HTTP_WAF_FETCH_TIMEOUT);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK
                || ngx_handle_write_event(c->write, 0) != NGX_OK)
            {
                ngx_http_waf_fetch_note_error(
                    ctx, NGX_HTTP_WAF_FETCH_ERROR_TLS_HANDSHAKE,
                    ngx_socket_errno, 0);
                ngx_http_waf_fetch_failed(r, ctx);
            }
            return;
        }

        if (rc != NGX_OK) {
            ngx_http_waf_fetch_note_error(
                ctx, NGX_HTTP_WAF_FETCH_ERROR_TLS_HANDSHAKE,
                ngx_socket_errno, 0);
            ngx_http_waf_fetch_failed(r, ctx);
            return;
        }

        ctx->fetch.handshake_done = 1;
    }

    ctx->fetch.phase = NGX_HTTP_WAF_FETCH_PHASE_SEND;
    b = ctx->fetch.request;

    while (b->pos < b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n > 0) {
            b->pos += n;
            continue;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(c->write, NGX_HTTP_WAF_FETCH_TIMEOUT);

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_http_waf_fetch_note_error(
                    ctx,
                    ngx_http_waf_fetch_io_error(
                        ngx_socket_errno, NGX_HTTP_WAF_FETCH_ERROR_SEND),
                    ngx_socket_errno, 0);
                ngx_http_waf_fetch_failed(r, ctx);
            }
            return;
        }

        ngx_http_waf_fetch_note_error(
            ctx,
            ngx_http_waf_fetch_io_error(
                ngx_socket_errno, NGX_HTTP_WAF_FETCH_ERROR_SEND),
            ngx_socket_errno, 0);
        ngx_http_waf_fetch_failed(r, ctx);
        return;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    /* stop writing, wait for the answer */
    c->write->handler = ngx_http_waf_fetch_noop;
    ctx->fetch.phase = NGX_HTTP_WAF_FETCH_PHASE_RECEIVE;
    ngx_add_timer(c->read, NGX_HTTP_WAF_FETCH_TIMEOUT);

    ngx_http_waf_fetch_read(c->read);
}


/**
 * Move the provider request to the address the endpoint already has: the one
 * `api=` resolved while the configuration was read, or the one the resolver of
 * the enclosing context answered with earlier in this request.  `NGX_AGAIN`
 * says the host of the endpoint still has to be looked up.
 */
static ngx_int_t ngx_http_waf_start_http_peer(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx,
    ngx_http_waf_loc_conf_t* conf)
{
    (void) conf;

    if (ctx->fetch.resolved_valid) {
        struct sockaddr* resolved = ctx->fetch.resolved_sockaddr;
        socklen_t resolved_len = ctx->fetch.resolved_socklen;

        ctx->fetch.resolved_valid = 0;

        return ngx_http_waf_fetch_connect(r, ctx, resolved, resolved_len);
    }

    if (ctx->fetch.resolved_failed) {
        ctx->fetch.resolved_failed = 0;

        ngx_http_waf_fetch_failed(r, ctx);
        ctx->fetch.in_drive = 0;

        return NGX_OK;
    }

    if (ctx->fetch.api->resolved) {
        return ngx_http_waf_fetch_connect(r, ctx, ctx->fetch.api->sockaddr,
                                          ctx->fetch.api->socklen);
    }

    return NGX_AGAIN;
}


ngx_str_t ngx_http_waf_original_host(ngx_http_request_t* r)
{
    if (r->headers_in.host != NULL) {
        return r->headers_in.host->value;
    }
    return r->headers_in.server;
}


ngx_uint_t ngx_http_waf_forward_header(ngx_table_elt_t* header)
{
    ngx_str_t name = header->key;
    static const char* skipped[] = {
        "host",
        "connection",
        "keep-alive",
        "proxy-connection",
        "content-length",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "expect",
        "proxy-authenticate",
        "proxy-authorization",
        "forwarded",
        NULL
    };
    ngx_uint_t i;

    for (i = 0; skipped[i] != NULL; i++) {
        size_t len = ngx_strlen(skipped[i]);
        if (name.len == len
            && ngx_strncasecmp(name.data, (u_char*) skipped[i], len) == 0)
        {
            return 0;
        }
    }

    if (name.len == 9 && ngx_strncasecmp(name.data, (u_char*) "x-real-ip", 9) == 0) {
        return 0;
    }
    if (name.len == 15 && ngx_strncasecmp(name.data, (u_char*) "x-forwarded-for", 15) == 0) {
        return 0;
    }
    if (name.len == 14 && ngx_strncasecmp(name.data, (u_char*) "x-original-uri", 14) == 0) {
        return 0;
    }
    if (name.len >= 12 && ngx_strncasecmp(name.data, (u_char*) "x-forwarded-", 12) == 0) {
        return 0;
    }
    if (name.len >= 9 && ngx_strncasecmp(name.data, (u_char*) "x-anubis-", 9) == 0) {
        return 0;
    }

    return 1;
}


size_t ngx_http_waf_forwarded_header_size(ngx_http_request_t* r)
{
    ngx_list_part_t* part = &r->headers_in.headers.part;
    ngx_table_elt_t* header = part->elts;
    ngx_uint_t i;
    size_t len = 0;

    for ( ;; ) {
        for (i = 0; i < part->nelts; i++) {
            if (header[i].hash && ngx_http_waf_forward_header(&header[i])) {
                len += header[i].key.len + header[i].value.len + 4;
            }
        }
        if (part->next == NULL) {
            break;
        }
        part = part->next;
        header = part->elts;
    }

    return len;
}


u_char* ngx_http_waf_copy_forwarded_headers(ngx_http_request_t* r, u_char* p)
{
    ngx_list_part_t* part = &r->headers_in.headers.part;
    ngx_table_elt_t* header = part->elts;
    ngx_uint_t i;

    for ( ;; ) {
        for (i = 0; i < part->nelts; i++) {
            if (!header[i].hash || !ngx_http_waf_forward_header(&header[i])) {
                continue;
            }
            p = ngx_cpymem(p, header[i].key.data, header[i].key.len);
            *p++ = ':'; *p++ = ' ';
            p = ngx_cpymem(p, header[i].value.data, header[i].value.len);
            *p++ = CR; *p++ = LF;
        }
        if (part->next == NULL) {
            break;
        }
        part = part->next;
        header = part->elts;
    }

    return p;
}


/**
 * Park the request and start the provider request.
 */
ngx_int_t ngx_http_waf_start_http(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx) {
    ngx_http_waf_loc_conf_t* conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_http_core_loc_conf_t* clcf;
    const ngx_waf_step_t* step = ctx->step;
    ngx_resolver_ctx_t* rc;
    ngx_buf_t* b;
    ngx_int_t peer;
    u_char* p;
    size_t len;

    ctx->fetch.in_drive = 1;

    if (conf == NULL) {
        /*
         * `waf_captcha` prepares the endpoint while the configuration is read,
         * so this only happens when a request reaches the provider without a
         * captcha configuration at all.
         */
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_ENDPOINT, 0, 0);
        ngx_http_waf_fetch_failed(r, ctx);
        ctx->fetch.in_drive = 0;
        return NGX_OK;
    }

    /*
     * The request (POST <uri> HTTP/1.0 with the form body) and the answer
     * buffer are built once per provider request: this function runs again
     * when the resolver of the enclosing context answered from its cache.
     */
    if (ctx->fetch.request == NULL) {
        ctx->fetch.failure = NGX_HTTP_WAF_FETCH_ERROR_NONE;
        ctx->fetch.phase = NGX_HTTP_WAF_FETCH_PHASE_IDLE;
        ctx->fetch.failure_errno = 0;
        ctx->fetch.failure_detail = 0;
        ctx->fetch.failure_logged = 0;

        if (step->pending.request_kind == NGX_WAF_HTTP_REQUEST_KIND_ANUBIS) {
            /*
             * Anubis only emits its risk headers in reverse-proxy mode.  A
             * client-supplied value must never reach the backend, whether the
             * auth check passes, fails, or is allowed through on error.
             */
            ngx_http_waf_remove_client_risk_headers(r);
            if (!conf->anubis_api.configured) {
                ctx->fetch.anubis = 1;
                ngx_http_waf_fetch_note_error(
                    ctx, NGX_HTTP_WAF_FETCH_ERROR_ENDPOINT, 0, 0);
                ngx_http_waf_fetch_failed(r, ctx);
                ctx->fetch.in_drive = 0;
                return NGX_OK;
            }
            ctx->fetch.api = &conf->anubis_api;
            ctx->fetch.anubis = 1;
        } else {
            if (!conf->captcha_api.configured) {
                ctx->fetch.anubis = 0;
                ngx_http_waf_fetch_note_error(
                    ctx, NGX_HTTP_WAF_FETCH_ERROR_ENDPOINT, 0, 0);
                ngx_http_waf_fetch_failed(r, ctx);
                ctx->fetch.in_drive = 0;
                return NGX_OK;
            }
            ctx->fetch.api = &conf->captcha_api;
            ctx->fetch.anubis = 0;
        }

        if (ctx->fetch.anubis) {
            ngx_str_t host = ngx_http_waf_original_host(r);
            len = ctx->fetch.api->uri.len + host.len
                + ngx_http_waf_forwarded_header_size(r)
                + r->connection->addr_text.len
                + r->unparsed_uri.len * 2
                + sizeof(NGX_HTTP_WAF_ANUBIS_CHECK_PATH) + 1024;
        } else {
            len = ctx->fetch.api->uri.len + ctx->fetch.api->host.len
                + step->pending.body.len + 512;
        }
        b = ngx_create_temp_buf(r->pool, len);
        if (b == NULL) {
            ngx_http_waf_fetch_note_error(
                ctx, NGX_HTTP_WAF_FETCH_ERROR_INTERNAL, 0, 0);
            ngx_http_waf_fetch_failed(r, ctx);
            ctx->fetch.in_drive = 0;
            return NGX_OK;
        }

        p = b->last;
        if (ctx->fetch.anubis) {
            ngx_str_t host = ngx_http_waf_original_host(r);
            ngx_str_t proto = r->connection->ssl != NULL
                ? (ngx_str_t) ngx_string("https")
                : (ngx_str_t) ngx_string("http");

            p = ngx_cpymem(p, "GET ", sizeof("GET ") - 1);
            if (ctx->fetch.api->uri.len > 1) {
                size_t base_len = ctx->fetch.api->uri.len;
                if (ctx->fetch.api->uri.data[base_len - 1] == '/') {
                    base_len--;
                }
                p = ngx_cpymem(p, ctx->fetch.api->uri.data, base_len);
            }
            p = ngx_cpymem(p, NGX_HTTP_WAF_ANUBIS_CHECK_PATH,
                           sizeof(NGX_HTTP_WAF_ANUBIS_CHECK_PATH) - 1);
            p = ngx_cpymem(p, " HTTP/1.0" CRLF, sizeof(" HTTP/1.0" CRLF) - 1);
            p = ngx_sprintf(p, "Host: %V" CRLF, &host);
            p = ngx_http_waf_copy_forwarded_headers(r, p);
            p = ngx_sprintf(p, "X-Real-IP: %V" CRLF,
                            &r->connection->addr_text);
            p = ngx_sprintf(p, "X-Forwarded-For: %V" CRLF,
                            &r->connection->addr_text);
            p = ngx_sprintf(p, "X-Forwarded-Host: %V" CRLF, &host);
            p = ngx_sprintf(p, "X-Forwarded-Proto: %V" CRLF, &proto);
            p = ngx_sprintf(p, "X-Forwarded-Uri: %V" CRLF, &r->unparsed_uri);
            p = ngx_sprintf(p, "X-Original-Uri: %V" CRLF, &r->unparsed_uri);
            p = ngx_cpymem(p, "Connection: close" CRLF CRLF,
                           sizeof("Connection: close" CRLF CRLF) - 1);
        } else {
            p = ngx_sprintf(p, "POST %V HTTP/1.0" CRLF, &ctx->fetch.api->uri);
            p = ngx_sprintf(p, "Host: %V" CRLF, &ctx->fetch.api->host);
            p = ngx_sprintf(p, "Content-Type: application/x-www-form-urlencoded" CRLF);
            p = ngx_sprintf(p, "Content-Length: %uz" CRLF, step->pending.body.len);
            p = ngx_sprintf(p, "Connection: close" CRLF CRLF);
            if (step->pending.body.len != 0) {
                p = ngx_cpymem(p, step->pending.body.data, step->pending.body.len);
            }
        }
        b->last = p;

        ctx->fetch.request = b;
        ctx->fetch.use_ssl = ctx->fetch.api->use_ssl;
        ctx->fetch.host = ctx->fetch.api->host;
    }

    if (ctx->fetch.response == NULL) {
        ctx->fetch.response = ngx_create_temp_buf(r->pool,
            ctx->fetch.anubis ? 16 * 1024 : NGX_HTTP_WAF_FETCH_BUFFER);
        if (ctx->fetch.response == NULL) {
            ngx_http_waf_fetch_note_error(
                ctx, NGX_HTTP_WAF_FETCH_ERROR_INTERNAL, 0, 0);
            ngx_http_waf_fetch_failed(r, ctx);
            ctx->fetch.in_drive = 0;
            return NGX_OK;
        }
    }

    peer = ngx_http_waf_start_http_peer(r, ctx, conf);
    if (peer != NGX_AGAIN) {
        return peer;
    }

    /* the host was not resolvable while the configuration was read */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->resolver == NULL) {
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_RESOLVER_CONFIG, 0, 0);
        ngx_http_waf_fetch_failed(r, ctx);
        ctx->fetch.in_drive = 0;
        return NGX_OK;
    }

    rc = ngx_resolve_start(clcf->resolver, NULL);

    if (rc == NULL || rc == NGX_NO_RESOLVER) {
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_RESOLVER, 0, 0);
        ngx_http_waf_fetch_failed(r, ctx);
        ctx->fetch.in_drive = 0;
        return NGX_OK;
    }

    rc->name = ctx->fetch.api->host;
    rc->handler = ngx_http_waf_fetch_resolved;
    rc->data = r;
    rc->timeout = clcf->resolver_timeout;

    ctx->resolver_inline = 0;

    if (ngx_resolve_name(rc) != NGX_OK) {
        /*
         * `ngx_resolve_name()` released the context on this path (it is what
         * `ngx_http_upstream.c` relies on as well), calling
         * `ngx_resolve_name_done()` here would read and free it a second
         * time.
         */
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_RESOLVER, ngx_socket_errno, 0);
        ngx_http_waf_fetch_failed(r, ctx);
        ctx->fetch.in_drive = 0;
        return NGX_OK;
    }

    if (ctx->resolver_inline) {
        /*
         * The lookup answered from the cache of the resolver while it was
         * started: the handler stored the answer, take it like the first
         * visit does.  The drive loop is still on the stack.
         */
        ctx->resolver_inline = 0;

        return ngx_http_waf_start_http_peer(r, ctx, conf);
    }

    /* the request stays alive until the lookup and the provider answered */
    r->main->count++;
    ctx->fetch.in_drive = 0;

    return NGX_DONE;
}


static void ngx_http_waf_fetch_resolved(ngx_resolver_ctx_t* rc) {
    ngx_http_request_t* r = rc->data;
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_loc_conf_t* conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_uint_t inline_answer = (rc->async == 0);

    if (ctx == NULL || conf == NULL) {
        ngx_resolve_name_done(rc);
        return;
    }

    if (rc->state == NGX_OK && rc->naddrs != 0) {
        struct sockaddr* sockaddr = rc->addrs[0].sockaddr;
        socklen_t socklen = rc->addrs[0].socklen;

        /*
         * The address belongs to the resolver context, which is released
         * before the drive loop continues: copy it into the request pool.
         */
        ctx->fetch.resolved_sockaddr = ngx_palloc(r->pool, socklen);
        if (ctx->fetch.resolved_sockaddr != NULL) {
            ngx_memcpy(ctx->fetch.resolved_sockaddr, sockaddr, socklen);

            /*
             * The resolver hands its addresses over with the port of the
             * query, which is zero here (`ngx_resolver_calloc()`), so the
             * port of the endpoint has to be written into the copy.
             */
            switch (ctx->fetch.resolved_sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
            case AF_INET6:
                ((struct sockaddr_in6*) ctx->fetch.resolved_sockaddr)->sin6_port =
                    htons(ctx->fetch.api->port);
                break;
#endif
            default:
                ((struct sockaddr_in*) ctx->fetch.resolved_sockaddr)->sin_port =
                    htons(ctx->fetch.api->port);
            }

            ctx->fetch.resolved_socklen = socklen;
            ctx->fetch.resolved_valid = 1;

        } else {
            ngx_http_waf_fetch_note_error(
                ctx, NGX_HTTP_WAF_FETCH_ERROR_INTERNAL, 0, 0);
            ctx->fetch.resolved_failed = 1;
        }

    } else {
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_RESOLVER, 0,
            rc->state == NGX_OK ? 0 : (ngx_uint_t) rc->state);
        ctx->fetch.resolved_failed = 1;
    }

    ngx_resolve_name_done(rc);

    if (inline_answer) {
        /*
         * The lookup was answered from the cache of the resolver, inside the
         * call that started it: the drive loop is on the stack and picks the
         * answer up when that call returns.
         */
        ctx->resolver_inline = 1;
        return;
    }

    /*
     * Release the reference the park on the lookup took and re-enter the
     * phases: the access handler resumes the drive loop, which connects to
     * the address stored above.
     */
    ngx_http_finalize_request(r, NGX_DONE);
    ngx_http_core_run_phases(r);
}


static ngx_int_t ngx_http_waf_fetch_connect(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx,
    struct sockaddr* sockaddr, socklen_t socklen)
{
    ngx_peer_connection_t peer;
    ngx_connection_t* c;
    ngx_pool_cleanup_t* cln;
    ngx_int_t rc;

    ctx->fetch.sockaddr = sockaddr;
    ctx->fetch.socklen = socklen;
    ctx->fetch.phase = NGX_HTTP_WAF_FETCH_PHASE_CONNECT;

    ngx_memzero(&peer, sizeof(ngx_peer_connection_t));
    peer.get = ngx_http_waf_get_peer;
    peer.data = ctx;
    peer.log = r->connection->log;
    peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED
        || peer.connection == NULL || peer.connection->fd == -1)
    {
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_CONNECT, ngx_socket_errno, 0);
        ngx_http_waf_fetch_failed(r, ctx);
        return NGX_OK;
    }

    c = peer.connection;
    ctx->fetch.connection = c;

    /* the connection comes from the free list, give it the request's pool and
     * log like the upstream module does */
    c->pool = r->pool;
    c->log = r->connection->log;
    c->read->log = c->log;
    c->write->log = c->log;

    c->data = r;
    c->read->handler = ngx_http_waf_fetch_read;
    c->write->handler = ngx_http_waf_fetch_write;

    /*
     * The cleanup gets the context, not the connection: the connection is back
     * in the free list of the worker once the fetch settled and the pointer in
     * the context is what tells whether it is still ours.
     */
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        ngx_http_waf_fetch_note_error(
            ctx, NGX_HTTP_WAF_FETCH_ERROR_INTERNAL, 0, 0);
        ngx_http_waf_fetch_failed(r, ctx);
        return NGX_OK;
    }
    cln->handler = ngx_http_waf_fetch_cleanup;
    cln->data = ctx;

    if (ctx->fetch.use_ssl) {
        if (ngx_ssl_create_connection(&ctx->fetch.api->ssl, c,
                                      NGX_SSL_BUFFER|NGX_SSL_CLIENT) != NGX_OK)
        {
            ngx_http_waf_fetch_note_error(
                ctx, NGX_HTTP_WAF_FETCH_ERROR_TLS_HANDSHAKE, 0, 0);
            ctx->fetch.connection = c;
            ngx_http_waf_fetch_failed(r, ctx);
            return NGX_OK;
        }
        c->sendfile = 0;
        if (SSL_set_tlsext_host_name(c->ssl->connection, (char*) ctx->fetch.api->host.data)
            == 0)
        {
            ngx_http_waf_fetch_note_error(
                ctx, NGX_HTTP_WAF_FETCH_ERROR_TLS_HOST, 0, 0);
            ngx_http_waf_fetch_failed(r, ctx);
            return NGX_OK;
        }

        c->ssl->handler = ngx_http_waf_fetch_ssl_done;

        ctx->fetch.phase = NGX_HTTP_WAF_FETCH_PHASE_HANDSHAKE;
        rc = ngx_ssl_handshake(c);

        if (rc == NGX_AGAIN) {
            if (!c->read->timer_set) {
                ngx_add_timer(c->read, NGX_HTTP_WAF_FETCH_TIMEOUT);
            }

            r->main->count++;
            ctx->fetch.in_drive = 0;

            return NGX_DONE;
        }

        /*
         * `ngx_ssl_handshake()` does not call the handler when it is done (or
         * when it failed) in this call, the upstream module calls it for every
         * other return value as well.  It checks `handshaked` and fails the
         * fetch when the handshake did not complete.
         */
        ngx_http_waf_fetch_ssl_done(c);

        if (ctx->fetch.finished) {
            /* the whole request finished within the handshake */
            ctx->fetch.in_drive = 0;
            return NGX_OK;
        }

        r->main->count++;
        ctx->fetch.in_drive = 0;

        return NGX_DONE;
    }

    if (rc == NGX_OK || c->write->ready) {
        /* the first send may already carry the whole request */
        ctx->fetch.phase = NGX_HTTP_WAF_FETCH_PHASE_SEND;
        ngx_http_waf_fetch_write(c->write);
        ctx->fetch.in_drive = 0;

        if (ctx->fetch.finished) {
            /* the provider answered before we parked, the drive loop applies */
            return NGX_OK;
        }

        r->main->count++;

        return NGX_DONE;
    }

    ngx_add_timer(c->write, NGX_HTTP_WAF_FETCH_TIMEOUT);
    ctx->fetch.in_drive = 0;
    r->main->count++;

    return NGX_DONE;
}
