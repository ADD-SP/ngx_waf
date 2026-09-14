/**
 * @file ngx_http_waf_module.c
 * @brief The nginx glue of ngx_waf.
 *
 * This file only registers the module and its directives, forwards the raw
 * configuration arguments to the Rust core, packs the request data, drives the
 * nginx asynchronous machinery and applies the decision the core returns.
 * Every rule, action and configuration semantic lives in `rust/`.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdio.h>

#include <ngx_http_waf_ffi.h>


/**
 * @brief The shared memory zones declared with `waf_zone`.
 *
 * The order is the order of the directives, which is also the order the Rust
 * core stores them in, so the index of a zone is the same on both sides.
 */
typedef struct {
    ngx_str_t      name;
    size_t         size;
    ngx_shm_zone_t *zone;
    void           *handle;
} ngx_http_waf_zone_t;


/**
 * The captcha provider endpoint, parsed at configuration time so that a request
 * never has to resolve anything.
 */
typedef struct {
    ngx_str_t                  host;
    ngx_str_t                  uri;
    struct sockaddr           *sockaddr;
    socklen_t                  socklen;
    in_port_t                  port;
    ngx_ssl_t                  ssl;
    unsigned                   use_ssl:1;
    unsigned                   configured:1;
    /** Set when the host was resolved while the configuration was read. */
    unsigned                   resolved:1;
} ngx_http_waf_captcha_api_t;


/**
 * One provider request in flight.
 */
typedef struct {
    ngx_connection_t          *connection;
    ngx_buf_t                 *request;
    ngx_buf_t                 *response;
    struct sockaddr           *sockaddr;
    socklen_t                  socklen;
    ngx_str_t                  host;
    unsigned                   use_ssl:1;
    unsigned                   handshake_done:1;
    /** Set once the machine was given the answer. */
    unsigned                   finished:1;
    /** Set while `start_http` runs, i.e. inside the drive loop. */
    unsigned                   in_drive:1;
} ngx_http_waf_fetch_t;


typedef struct {
    void                      *core;
    ngx_http_complex_value_t  *modsecurity_transaction_id;
    ngx_http_waf_captcha_api_t captcha_api;
} ngx_http_waf_loc_conf_t;


typedef struct {
    void         *core;
    ngx_array_t  *zones;
} ngx_http_waf_main_conf_t;


typedef struct {
    ngx_waf_step_t  *step;
    /** The provider request in flight, when the machine parked on one. */
    ngx_http_waf_fetch_t fetch;
    ngx_uint_t       applied:1;
    ngx_uint_t       waiting_more_body:1;
    ngx_uint_t       read_body_done:1;
} ngx_http_waf_ctx_t;


/* compile time guarantees for the values shared with the Rust core */
typedef char ngx_http_waf_method_bits_must_match[
    (NGX_HTTP_GET == 0x0002
     && NGX_HTTP_HEAD == 0x0004
     && NGX_HTTP_POST == 0x0008
     && NGX_HTTP_PUT == 0x0010
     && NGX_HTTP_DELETE == 0x0020
     && NGX_HTTP_MKCOL == 0x0040
     && NGX_HTTP_COPY == 0x0080
     && NGX_HTTP_MOVE == 0x0100
     && NGX_HTTP_OPTIONS == 0x0200
     && NGX_HTTP_PROPFIND == 0x0400
     && NGX_HTTP_PROPPATCH == 0x0800
     && NGX_HTTP_LOCK == 0x1000
     && NGX_HTTP_UNLOCK == 0x2000
     && NGX_HTTP_PATCH == 0x4000
     && NGX_HTTP_TRACE == 0x8000) ? 1 : -1];


static ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r);


static ngx_int_t ngx_http_waf_handler_precontent_phase(ngx_http_request_t* r);


static ngx_int_t ngx_http_waf_handler_log_phase(ngx_http_request_t* r);


static char *ngx_http_waf_zone_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static char *ngx_http_waf_directive_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static char *ngx_http_waf_modsecurity_transaction_id_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static void *ngx_http_waf_create_main_conf(ngx_conf_t* cf);


static void *ngx_http_waf_create_loc_conf(ngx_conf_t* cf);


static char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);


static ngx_int_t ngx_http_waf_postconfiguration(ngx_conf_t* cf);


static ngx_int_t ngx_http_waf_install_variables(ngx_conf_t* cf);


static char *ngx_http_waf_report(ngx_conf_t* cf, char* message);


static void ngx_http_waf_cleanup(void* data);


static void ngx_http_waf_conf_cleanup(void* data);


static void ngx_http_waf_request_cleanup(void* data);


static ngx_int_t ngx_http_waf_shm_zone_init(ngx_shm_zone_t* zone, void* data);


static void ngx_http_waf_shm_lock(void* ctx);


static void ngx_http_waf_shm_unlock(void* ctx);


static void *ngx_http_waf_shm_alloc(void* ctx, size_t size);


static void *ngx_http_waf_shm_alloc_locked(void* ctx, size_t size);


static ngx_int_t ngx_http_waf_run(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);



/**
 * Resolve the zone a configuration refers to into the handle of this worker.
 */
static void *ngx_http_waf_zone_handle(ngx_http_waf_main_conf_t* mcf, void* core,
    int64_t (*index_of)(void* core));


static ngx_int_t ngx_http_waf_drive(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);


static ngx_int_t ngx_http_waf_apply(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);


static ngx_int_t ngx_http_waf_start_resolve(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);


static void ngx_http_waf_resolve_handler(ngx_resolver_ctx_t* rc);


static void ngx_http_waf_resume(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx, ngx_waf_event_t* event);


static ngx_int_t ngx_http_waf_start_http(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);


static ngx_int_t ngx_http_waf_fetch_connect(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx,
    struct sockaddr* sockaddr, socklen_t socklen);


static void ngx_http_waf_fetch_resolved(ngx_resolver_ctx_t* rc);


static void ngx_http_waf_fetch_write(ngx_event_t* wev);


static void ngx_http_waf_fetch_ssl_done(ngx_connection_t* c);


static void ngx_http_waf_fetch_read(ngx_event_t* rev);


static ngx_uint_t ngx_http_waf_fetch_settle(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx,
    ngx_uint_t status, u_char* body, size_t len, ngx_uint_t failed);


static void ngx_http_waf_fetch_finish(ngx_http_request_t* r, ngx_uint_t status, u_char* body,
    size_t len, ngx_uint_t failed);


static void ngx_http_waf_fetch_cleanup(void* data);


static ngx_int_t ngx_http_waf_fetch_connect_test(ngx_connection_t* c);


static ngx_int_t ngx_http_waf_get_peer(ngx_peer_connection_t* pc, void* data);


static void ngx_http_waf_fetch_noop(ngx_event_t* ev);


static ngx_int_t ngx_http_waf_captcha_api(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf,
    ngx_str_t value);


static ngx_int_t ngx_http_waf_read_body(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);


static void ngx_http_waf_read_body_handler(ngx_http_request_t* r);


static ngx_int_t ngx_http_waf_gen_response(ngx_http_request_t* r, uint8_t* body, size_t body_len,
    uint32_t content_type, uint32_t status);


static void ngx_http_waf_add_no_cache_header(ngx_http_request_t* r);


static void ngx_http_waf_add_retry_after_header(ngx_http_request_t* r, int64_t seconds);


static void ngx_http_waf_add_set_cookies(ngx_http_request_t* r, ngx_waf_step_t* step);


static ngx_int_t ngx_http_waf_var_log(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


static ngx_int_t ngx_http_waf_var_blocking_log(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


static ngx_int_t ngx_http_waf_var_blocked(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


static ngx_int_t ngx_http_waf_var_rule_type(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


static ngx_int_t ngx_http_waf_var_rule_details(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


static ngx_int_t ngx_http_waf_var_spend(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


static ngx_int_t ngx_http_waf_var_rate(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * Write the `Set-Cookie` headers a decision minted (the captcha flow).
 */
static void ngx_http_waf_add_set_cookies(ngx_http_request_t* r, ngx_waf_step_t* step) {
    size_t i;

    for (i = 0; i < step->set_cookie_count; i++) {
        ngx_table_elt_t* header = ngx_list_push(&r->headers_out.headers);
        const ngx_waf_str_t* cookie = &step->set_cookies[i];

        if (header == NULL) {
            return;
        }

        header->hash = 1;
        header->lowcase_key = (u_char*)"set-cookie";
        ngx_str_set(&header->key, "Set-Cookie");
        header->value.data = ngx_pnalloc(r->pool, cookie->len);
        if (header->value.data == NULL) {
            header->hash = 0;
            return;
        }
        ngx_memcpy(header->value.data, cookie->data, cookie->len);
        header->value.len = cookie->len;
    }
}


static ngx_http_waf_ctx_t *ngx_http_waf_get_ctx(ngx_http_request_t* r);


static void ngx_http_waf_free_step(void* data);


static ngx_command_t ngx_http_waf_commands[] = {

    { ngx_string("waf_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_waf_zone_conf,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_rule_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_mode"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_cc_deny"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_cache"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_under_attack"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_captcha"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234|NGX_CONF_TAKE5|NGX_CONF_TAKE6|NGX_CONF_TAKE7,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_verify_bot"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234|NGX_CONF_TAKE5|NGX_CONF_TAKE6|NGX_CONF_TAKE7,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_priority"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_action"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234|NGX_CONF_TAKE5|NGX_CONF_TAKE6|NGX_CONF_TAKE7,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_block_page"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_modsecurity"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_waf_directive_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("waf_modsecurity_transaction_id"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_waf_modsecurity_transaction_id_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_waf_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_waf_postconfiguration,         /* postconfiguration */

    ngx_http_waf_create_main_conf,          /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_waf_create_loc_conf,           /* create location configuration */
    ngx_http_waf_merge_loc_conf             /* merge location configuration */
};


ngx_module_t ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,               /* module context */
    ngx_http_waf_commands,                  /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_waf_variables[] = {

    { ngx_string("waf_log"), NULL, ngx_http_waf_var_log, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_blocking_log"), NULL, ngx_http_waf_var_blocking_log, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_blocked"), NULL, ngx_http_waf_var_blocked, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_rule_type"), NULL, ngx_http_waf_var_rule_type, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_rule_details"), NULL, ngx_http_waf_var_rule_details, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_spend"), NULL, ngx_http_waf_var_spend, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("waf_rate"), NULL, ngx_http_waf_var_rate, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


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


static ngx_int_t ngx_http_waf_fetch_connect_test(ngx_connection_t* c) {
    int       err;
    socklen_t len = sizeof(int);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void*) &err, &len) == -1) {
        err = ngx_socket_errno;
    }

    if (err) {
        ngx_log_error(NGX_LOG_ERR, c->log, err, "ngx_waf: connect() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


/**
 * Close the provider connection; it is also registered as a pool cleanup so a
 * client that gives up does not leak it.
 */
static void ngx_http_waf_fetch_cleanup(void* data) {
    ngx_connection_t* c = data;

    if (c->fd != -1) {
        ngx_close_connection(c);
    }
}


/**
 * Hand the answer to the machine.  Returns 1 when this happened synchronously,
 * i.e. while the drive loop is still on the stack: in that case the caller must
 * not finalize the request, the decision is applied by the phase handler that
 * is already running.
 */
static ngx_uint_t ngx_http_waf_fetch_settle(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx,
    ngx_uint_t status, u_char* body, size_t len, ngx_uint_t failed)
{
    ngx_connection_t* c = NULL;
    ngx_waf_event_t event;

    ngx_memzero(&event, sizeof(ngx_waf_event_t));

    if (ctx->fetch.connection != NULL) {
        c = ctx->fetch.connection;
        ctx->fetch.connection = NULL;
        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }
        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
    }

    if (failed) {
        event.kind = NGX_WAF_EVENT_HTTP_FAILED;

    } else {
        event.kind = NGX_WAF_EVENT_HTTP_RESPONSE;
        event.status = status;
        event.body.data = body;
        event.body.len = len;
    }

    ngx_http_waf_resume(r, ctx, &event);
    ctx->fetch.finished = 1;

    if (c != NULL) {
        ngx_close_connection(c);
    }

    return ctx->fetch.in_drive;
}


/**
 * Wake the parked request up from an event: the machine is resumed and, when
 * this is an asynchronous wake up, the phases are re-entered so that the phase
 * handler applies the new decision.
 */
static void ngx_http_waf_fetch_finish(ngx_http_request_t* r, ngx_uint_t status, u_char* body,
    size_t len, ngx_uint_t failed)
{
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    if (ctx == NULL) {
        return;
    }

    if (ngx_http_waf_fetch_settle(r, ctx, status, body, len, failed)) {
        /* the drive loop is still running, it will apply the decision */
        return;
    }

    ngx_http_finalize_request(r, NGX_DONE);
    ngx_http_core_run_phases(r);
}


/**
 * The TLS handshake of a provider request is finished: send the request.
 * nginx calls this through `c->ssl->handler`.
 */
static void ngx_http_waf_fetch_ssl_done(ngx_connection_t* c) {
    ngx_http_request_t* r = c->data;
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    if (ctx == NULL || ctx->fetch.request == NULL || ctx->fetch.finished) {
        return;
    }

    ctx->fetch.handshake_done = 1;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    c->read->handler = ngx_http_waf_fetch_read;
    c->write->handler = ngx_http_waf_fetch_write;

    ngx_http_waf_fetch_write(c->write);
}


static void ngx_http_waf_fetch_read(ngx_event_t* rev) {
    ngx_connection_t* c = rev->data;
    ngx_http_request_t* r = c->data;
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_buf_t* b;
    ssize_t n;

    if (ctx == NULL || ctx->step == NULL || ctx->fetch.response == NULL || ctx->fetch.finished) {
        return;
    }

    if (rev->timedout) {
        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
        return;
    }

    b = ctx->fetch.response;

    for ( ;; ) {
        n = c->recv(c, b->last, b->end - b->last);

        if (n > 0) {
            b->last += n;

            if (b->last == b->end) {
                /* a provider answer bigger than the buffer is not one we can use */
                ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
                return;
            }

            continue;
        }

        if (n == 0) {
            /* the provider is done (the request asked to close) */
            u_char* p;
            u_char* last = b->last;
            ngx_uint_t status = 0;

            p = ngx_strlchr(b->pos, last, ' ');
            if (p != NULL) {
                status = ngx_atoi(p + 1, 3);
            }

            if (p == NULL || (ngx_int_t) status == NGX_ERROR) {
                ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
                return;
            }

            p = ngx_strlcasestrn(b->pos, last, (u_char*) CRLF CRLF, 4 - 1);
            if (p == NULL) {
                ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
                return;
            }
            p += 4;

            ngx_http_waf_fetch_finish(r, status, p, last - p, 0);
            return;
        }

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
            }
            return;
        }

        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
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
        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
        return;
    }

    if (ngx_http_waf_fetch_connect_test(c) != NGX_OK) {
        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
        return;
    }

    if (ctx->fetch.use_ssl && !ctx->fetch.handshake_done) {
        rc = ngx_ssl_handshake(c);

        if (rc == NGX_AGAIN) {
            ngx_add_timer(c->write, NGX_HTTP_WAF_FETCH_TIMEOUT);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK
                || ngx_handle_write_event(c->write, 0) != NGX_OK)
            {
                ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
            }
            return;
        }

        if (rc != NGX_OK) {
            ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
            return;
        }

        ctx->fetch.handshake_done = 1;
    }

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
                ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
            }
            return;
        }

        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
        return;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    /* stop writing, wait for the answer */
    c->write->handler = ngx_http_waf_fetch_noop;
    ngx_add_timer(c->read, NGX_HTTP_WAF_FETCH_TIMEOUT);

    ngx_http_waf_fetch_read(c->read);
}


/**
 * Park the request and start the provider request.
 */
static ngx_int_t ngx_http_waf_start_http(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx) {
    ngx_http_waf_loc_conf_t* conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_http_core_loc_conf_t* clcf;
    ngx_waf_step_t* step = ctx->step;
    ngx_resolver_ctx_t* rc;
    ngx_buf_t* b;
    u_char* p;
    size_t len;

    ctx->fetch.in_drive = 1;

    if (conf == NULL || !conf->captcha_api.configured) {
        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
        ctx->fetch.in_drive = 0;
        return NGX_OK;
    }

    /* the request: POST <uri> HTTP/1.0 with the form body */
    len = conf->captcha_api.uri.len + conf->captcha_api.host.len + step->http_body.len + 512;
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
        ctx->fetch.in_drive = 0;
        return NGX_OK;
    }

    p = b->last;
    p = ngx_sprintf(p, "POST %V HTTP/1.0" CRLF, &conf->captcha_api.uri);
    p = ngx_sprintf(p, "Host: %V" CRLF, &conf->captcha_api.host);
    p = ngx_sprintf(p, "Content-Type: application/x-www-form-urlencoded" CRLF);
    p = ngx_sprintf(p, "Content-Length: %uz" CRLF, step->http_body.len);
    p = ngx_sprintf(p, "Connection: close" CRLF CRLF);
    if (step->http_body.len != 0) {
        p = ngx_cpymem(p, step->http_body.data, step->http_body.len);
    }
    b->last = p;

    ctx->fetch.request = b;
    ctx->fetch.use_ssl = conf->captcha_api.use_ssl;
    ctx->fetch.host = conf->captcha_api.host;

    ctx->fetch.response = ngx_create_temp_buf(r->pool, NGX_HTTP_WAF_FETCH_BUFFER);
    if (ctx->fetch.response == NULL) {
        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
        ctx->fetch.in_drive = 0;
        return NGX_OK;
    }

    if (conf->captcha_api.resolved) {
        return ngx_http_waf_fetch_connect(r, ctx, conf->captcha_api.sockaddr,
                                          conf->captcha_api.socklen);
    }

    /* the host was not resolvable while the configuration was read */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->resolver == NULL) {
        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
        ctx->fetch.in_drive = 0;
        return NGX_OK;
    }

    rc = ngx_resolve_start(clcf->resolver, NULL);

    if (rc == NULL || rc == NGX_NO_RESOLVER) {
        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
        ctx->fetch.in_drive = 0;
        return NGX_OK;
    }

    rc->name = conf->captcha_api.host;
    rc->handler = ngx_http_waf_fetch_resolved;
    rc->data = r;
    rc->timeout = clcf->resolver_timeout;

    if (ngx_resolve_name(rc) != NGX_OK) {
        ngx_resolve_name_done(rc);
        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
        ctx->fetch.in_drive = 0;
        return NGX_OK;
    }

    /* the resolver may have answered already */
    if (ctx->fetch.finished) {
        ctx->fetch.in_drive = 0;
        return NGX_OK;
    }

    /* the request stays alive until the provider answered */
    r->main->count++;
    ctx->fetch.in_drive = 0;

    return NGX_DONE;
}


static void ngx_http_waf_fetch_resolved(ngx_resolver_ctx_t* rc) {
    ngx_http_request_t* r = rc->data;
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    if (ctx == NULL) {
        ngx_resolve_name_done(rc);
        return;
    }

    if (rc->state == NGX_OK && rc->naddrs != 0) {
        struct sockaddr* sockaddr = rc->addrs[0].sockaddr;
        socklen_t socklen = rc->addrs[0].socklen;

        ngx_resolve_name_done(rc);
        ngx_http_waf_fetch_connect(r, ctx, sockaddr, socklen);
        return;
    }

    ngx_resolve_name_done(rc);
    ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
}


static ngx_int_t ngx_http_waf_fetch_connect(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx,
    struct sockaddr* sockaddr, socklen_t socklen)
{
    ngx_http_waf_loc_conf_t* conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_peer_connection_t peer;
    ngx_connection_t* c;
    ngx_pool_cleanup_t* cln;
    ngx_int_t rc;

    ctx->fetch.sockaddr = sockaddr;
    ctx->fetch.socklen = socklen;

    ngx_memzero(&peer, sizeof(ngx_peer_connection_t));
    peer.get = ngx_http_waf_get_peer;
    peer.data = ctx;
    peer.log = r->connection->log;
    peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED
        || peer.connection == NULL || peer.connection->fd == -1)
    {
        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
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

    if (ctx->fetch.use_ssl) {
        if (ngx_ssl_create_connection(&conf->captcha_api.ssl, c,
                                      NGX_SSL_BUFFER|NGX_SSL_CLIENT) != NGX_OK)
        {
            ctx->fetch.connection = c;
            ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
            return NGX_OK;
        }
        c->sendfile = 0;
        if (SSL_set_tlsext_host_name(c->ssl->connection, (char*) conf->captcha_api.host.data)
            == 0)
        {
            ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
            return NGX_OK;
        }

        c->ssl->handler = ngx_http_waf_fetch_ssl_done;

        rc = ngx_ssl_handshake(c);

        if (rc == NGX_ERROR) {
            ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
            return NGX_OK;
        }

        if (ctx->fetch.finished) {
            /* the whole request finished within the handshake */
            ctx->fetch.in_drive = 0;
            return NGX_OK;
        }

        if (!c->read->timer_set) {
            ngx_add_timer(c->read, NGX_HTTP_WAF_FETCH_TIMEOUT);
        }

        r->main->count++;
        ctx->fetch.in_drive = 0;

        return NGX_DONE;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
        return NGX_OK;
    }
    cln->handler = ngx_http_waf_fetch_cleanup;
    cln->data = c;

    if (rc == NGX_OK || c->write->ready) {
        /* the first send may already carry the whole request */
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


/**
 * Parse `api=<url>` of the `waf_captcha` directive.  The host is resolved once,
 * here, so that a request never has to block on DNS.
 */
static ngx_int_t ngx_http_waf_captcha_api(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf,
    ngx_str_t value)
{
    ngx_url_t url;
    ngx_str_t rest = value;
    ngx_str_t ciphers;
    ngx_uint_t ssl = 0;

    if (rest.len >= 8 && ngx_strncasecmp(rest.data, (u_char*) "https://", 8) == 0) {
        ssl = 1;
        rest.data += 8;
        rest.len -= 8;

    } else if (rest.len >= 7 && ngx_strncasecmp(rest.data, (u_char*) "http://", 7) == 0) {
        rest.data += 7;
        rest.len -= 7;
    }

    ngx_memzero(&url, sizeof(ngx_url_t));
    url.url = rest;
    url.no_resolve = 1;
    url.uri_part = 1;
    url.default_port = ssl ? 443 : 80;

    if (ngx_parse_url(cf->pool, &url) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_waf: invalid value [%V]", &value);
        return NGX_ERROR;
    }

    /*
     * Resolve the host here when possible; a host that cannot be resolved now
     * (no DNS at configuration time) is resolved per request with the resolver
     * of the enclosing context, like the C implementation left it to curl.
     */
    if (!url.naddrs) {
        (void) ngx_inet_resolve_host(cf->pool, &url);
    }

    if (ssl) {
        ngx_memzero(&conf->captcha_api.ssl, sizeof(ngx_ssl_t));
        conf->captcha_api.ssl.log = cf->log;
        if (ngx_ssl_create(&conf->captcha_api.ssl, NGX_SSL_TLSv1_2, NULL) != NGX_OK) {
            return NGX_ERROR;
        }
        ciphers.data = (u_char*) "HIGH:!aNULL:!MD5";
        ciphers.len = sizeof("HIGH:!aNULL:!MD5") - 1;
        if (ngx_ssl_ciphers(cf, &conf->captcha_api.ssl, &ciphers, 0) != NGX_OK) {
            return NGX_ERROR;
        }
        /* the provider certificate cannot be verified without a CA bundle */
        SSL_CTX_set_verify(conf->captcha_api.ssl.ctx, SSL_VERIFY_NONE, NULL);
    }

    conf->captcha_api.use_ssl = ssl;
    conf->captcha_api.port = url.port != 0 ? url.port : (in_port_t) (ssl ? 443 : 80);
    conf->captcha_api.host = url.host;
    conf->captcha_api.uri = url.uri.len != 0 ? url.uri : (ngx_str_t) ngx_string("/");

    if (url.naddrs) {
        conf->captcha_api.sockaddr = url.addrs[0].sockaddr;
        conf->captcha_api.socklen = url.addrs[0].socklen;
        conf->captcha_api.resolved = 1;
    }

    conf->captcha_api.configured = 1;

    return NGX_OK;
}



static char *ngx_http_waf_report(ngx_conf_t* cf, char* message) {

    if (message == NULL) {
        message = "ngx_waf: unexpected error";
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", message);
        ngx_waf_string_free(message);
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", message);

    return NGX_CONF_ERROR;
}


static char *ngx_http_waf_zone_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_main_conf_t* mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);
    ngx_str_t* elts = cf->args->elts;
    const uint8_t* name_data = NULL;
    size_t name_len = 0;
    size_t size = 0;
    ngx_http_waf_zone_t* zone = NULL;

    char* error = ngx_waf_zone_directive(
        mcf->core,
        (const ngx_waf_str_t*)(elts + 1),
        cf->args->nelts - 1,
        &name_data,
        &name_len,
        &size);

    if (error != NULL) {
        return ngx_http_waf_report(cf, error);
    }

    zone = ngx_array_push(mcf->zones);
    if (zone == NULL) {
        return ngx_http_waf_report(cf, NULL);
    }

    zone->name.data = ngx_pnalloc(cf->pool, name_len);
    if (zone->name.data == NULL) {
        return ngx_http_waf_report(cf, NULL);
    }
    ngx_memcpy(zone->name.data, name_data, name_len);
    zone->name.len = name_len;
    zone->size = size;
    zone->handle = NULL;
    zone->zone = NULL;

    zone->zone = ngx_shared_memory_add(cf, &zone->name, size, &ngx_http_waf_module);
    if (zone->zone == NULL) {
        return ngx_http_waf_report(cf, NULL);
    }

    zone->zone->init = ngx_http_waf_shm_zone_init;
    zone->zone->data = zone;

    return NGX_CONF_OK;
}


static char *ngx_http_waf_directive_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_main_conf_t* mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* elts = cf->args->elts;
    ngx_str_t expanded;
    const ngx_waf_str_t* args = (const ngx_waf_str_t*)(elts + 1);
    ngx_uint_t nargs = cf->args->nelts - 1;

    /*
     * A relative `waf_rule_path` is resolved against the nginx prefix, like
     * every other file path of a nginx configuration.
     */
    if (ngx_strcmp(cmd->name.data, "waf_rule_path") == 0 && elts[1].len != 0
        && elts[1].data[0] != '/')
    {
        expanded = elts[1];
        if (ngx_conf_full_name(cf->cycle, &expanded, 0) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        args = (const ngx_waf_str_t*) &expanded;
    }

    char* error = ngx_waf_directive(
        mcf->core,
        loc_conf->core,
        *(const ngx_waf_str_t*)(elts),
        args,
        nargs);

    if (error != NULL) {
        return ngx_http_waf_report(cf, error);
    }

    if (ngx_strcmp(cmd->name.data, "waf_captcha") == 0) {
        ngx_uint_t i;
        for (i = 1; i < cf->args->nelts; i++) {
            if (elts[i].len > 4 && ngx_strncmp(elts[i].data, "api=", 4) == 0) {
                ngx_str_t api;
                api.data = elts[i].data + 4;
                api.len = elts[i].len - 4;
                if (ngx_http_waf_captcha_api(cf, loc_conf, api) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
            }
        }
    }

    if (ngx_strcmp(cmd->name.data, "waf_under_attack") == 0
        || ngx_strcmp(cmd->name.data, "waf_modsecurity") == 0)
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "ngx_waf: the directive [%V] is accepted but its feature is not "
            "available in this build; the inspection is disabled",
            &cmd->name);
    }

    return NGX_CONF_OK;
}


static char *ngx_http_waf_modsecurity_transaction_id_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_http_compile_complex_value_t ccv;
    ngx_str_t* value = cf->args->elts;

    loc_conf->modsecurity_transaction_id = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (loc_conf->modsecurity_transaction_id == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = loc_conf->modsecurity_transaction_id;
    ccv.zero = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *ngx_http_waf_create_main_conf(ngx_conf_t* cf) {
    ngx_http_waf_main_conf_t* mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_main_conf_t));

    if (mcf == NULL) {
        return NULL;
    }

    mcf->core = ngx_waf_main_create();
    if (mcf->core == NULL) {
        return NULL;
    }

    mcf->zones = ngx_array_create(cf->pool, 4, sizeof(ngx_http_waf_zone_t));
    if (mcf->zones == NULL) {
        return NULL;
    }

    ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }
    cln->handler = ngx_http_waf_cleanup;
    cln->data = mcf->core;

    return mcf;
}


static void *ngx_http_waf_create_loc_conf(ngx_conf_t* cf) {
    ngx_http_waf_loc_conf_t* conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_loc_conf_t));

    if (conf == NULL) {
        return NULL;
    }

    conf->core = ngx_waf_conf_create();
    if (conf->core == NULL) {
        return NULL;
    }

    /* freed by the pool cleanup registered in create_main_conf */
    ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }
    cln->handler = ngx_http_waf_conf_cleanup;
    cln->data = conf->core;

    conf->modsecurity_transaction_id = NULL;

    return conf;
}


static char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf) {
    ngx_http_waf_loc_conf_t* parent = prev;
    ngx_http_waf_loc_conf_t* child = conf;

    if (parent == NULL || child == NULL || parent->core == NULL || child->core == NULL) {
        return NGX_CONF_OK;
    }

    char* error = ngx_waf_conf_merge(child->core, parent->core);
    if (error != NULL) {
        return ngx_http_waf_report(cf, error);
    }

    if (child->modsecurity_transaction_id == NULL) {
        child->modsecurity_transaction_id = parent->modsecurity_transaction_id;
    }

    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_waf_postconfiguration(ngx_conf_t* cf) {
    ngx_http_handler_pt* h;
    ngx_http_core_main_conf_t* cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_waf_handler_access_phase;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_waf_handler_log_phase;

    return ngx_http_waf_install_variables(cf);
}


static ngx_int_t ngx_http_waf_install_variables(ngx_conf_t* cf) {
    ngx_http_variable_t* v;

    for (v = ngx_http_waf_variables; v->name.len; v++) {
        ngx_http_variable_t* var = ngx_http_add_variable(cf, &v->name,
            NGX_HTTP_VAR_NOCACHEABLE);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void ngx_http_waf_cleanup(void* data) {
    ngx_waf_main_free(data);
}


static void ngx_http_waf_conf_cleanup(void* data) {
    ngx_waf_conf_free(data);
}


static void ngx_http_waf_shm_lock(void* ctx) {
    ngx_shmtx_lock(&((ngx_slab_pool_t *) ctx)->mutex);
}


static void ngx_http_waf_shm_unlock(void* ctx) {
    ngx_shmtx_unlock(&((ngx_slab_pool_t *) ctx)->mutex);
}


static void *ngx_http_waf_shm_alloc(void* ctx, size_t size) {
    ngx_slab_pool_t* pool = ctx;
    void* p;

    ngx_shmtx_lock(&pool->mutex);
    p = ngx_slab_alloc_locked(pool, size);
    ngx_shmtx_unlock(&pool->mutex);

    return p;
}


static void *ngx_http_waf_shm_alloc_locked(void* ctx, size_t size) {
    /* the caller already holds the zone lock */
    return ngx_slab_alloc_locked((ngx_slab_pool_t *) ctx, size);
}


static ngx_int_t ngx_http_waf_shm_zone_init(ngx_shm_zone_t* zone, void* data) {
    ngx_http_waf_zone_t* z = zone->data;
    ngx_http_waf_zone_t* old = data;
    ngx_slab_pool_t* pool = (ngx_slab_pool_t *) zone->shm.addr;
    ngx_waf_shm_ops_t ops;

    ops.lock = ngx_http_waf_shm_lock;
    ops.unlock = ngx_http_waf_shm_unlock;
    ops.alloc = ngx_http_waf_shm_alloc;
    ops.alloc_locked = ngx_http_waf_shm_alloc_locked;
    ops.ctx = pool;

    z->handle = ngx_waf_shm_zone_init(
        zone->shm.addr,
        zone->shm.size,
        old != NULL ? old->handle : NULL,
        &ops);

    if (z->handle == NULL) {
        ngx_log_error(NGX_LOG_EMERG, zone->shm.log, 0,
            "ngx_waf: failed to initialize the shared memory zone \"%V\"",
            &z->name);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void *ngx_http_waf_zone_handle(ngx_http_waf_main_conf_t* mcf, void* core,
    int64_t (*index_of)(void* core))
{
    int64_t index = index_of(core);

    if (mcf == NULL || mcf->zones == NULL || index < 0
        || (ngx_uint_t) index >= mcf->zones->nelts)
    {
        return NULL;
    }

    return ((ngx_http_waf_zone_t *) mcf->zones->elts)[index].handle;
}


static ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r) {
    ngx_http_waf_loc_conf_t* conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_http_waf_ctx_t* ctx;
    ngx_int_t rc;

    if (conf == NULL || conf->core == NULL) {
        return NGX_DECLINED;
    }

    int64_t waf = ngx_waf_conf_waf(conf->core);
    if (waf == -1 || waf == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL) {
        ngx_http_cleanup_t* cln;

        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cln = ngx_pcalloc(r->pool, sizeof(ngx_http_cleanup_t));
        if (cln == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        cln->handler = ngx_http_waf_request_cleanup;
        cln->data = ctx;
        cln->next = NULL;

        /*
         * The request cleanup chain (not the pool one) so the context can be
         * found again after an `error_page` internal redirect, like the C
         * implementation does.
         */
        if (r->cleanup == NULL) {
            r->cleanup = cln;
        } else {
            ngx_http_cleanup_t* item;
            for (item = r->cleanup; item != NULL; item = item->next) {
                if (item->next == NULL) {
                    item->next = cln;
                    break;
                }
            }
        }

        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);

        ngx_pool_cleanup_t* pool_cln = ngx_pool_cleanup_add(r->pool, 0);
        if (pool_cln == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        pool_cln->handler = ngx_http_waf_free_step;
        pool_cln->data = ctx;
    }

    /*
     * `error_page` internally redirects the request and nginx drops every
     * module context on the way; be sure the context is reachable again for
     * the rest of this request.
     */
    ngx_http_set_ctx(r, ctx, ngx_http_waf_module);

    if (ctx->step != NULL) {
        /* Already inspected: apply the stored decision (a parked request stays
         * parked until its asynchronous operation answers). */
        return ngx_http_waf_drive(r, ctx);
    }

    if (ctx->waiting_more_body) {
        return NGX_DONE;
    }

    if (!ctx->read_body_done) {
        rc = ngx_http_waf_read_body(r, ctx);
        if (rc == NGX_DONE) {
            return NGX_DONE;
        }
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE || rc == NGX_ERROR) {
            return rc;
        }
    }

    return ngx_http_waf_run(r, ctx);
}


static ngx_int_t ngx_http_waf_read_body(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx) {
    ngx_int_t rc;

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    rc = ngx_http_read_client_request_body(r, ngx_http_waf_read_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    if (rc == NGX_AGAIN) {
        ctx->waiting_more_body = 1;
        return NGX_DONE;
    }

    ctx->read_body_done = 1;

    return NGX_OK;
}


static void ngx_http_waf_read_body_handler(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    ctx->read_body_done = 1;
    ngx_http_finalize_request(r, NGX_DONE);

    if (ctx->waiting_more_body) {
        ctx->waiting_more_body = 0;
        ngx_http_core_run_phases(r);
    }
}


/*
 * A no-op handler: it only marks the context in the request cleanup chain so
 * that `ngx_http_waf_get_ctx()` can still find it after an internal redirect.
 * nginx runs this chain *before* the log phase, so the decision must stay
 * readable until then; the step is released by the pool cleanup below.
 */
static void ngx_http_waf_request_cleanup(void* data) {
    (void) data;
}


static void ngx_http_waf_free_step(void* data) {
    ngx_http_waf_ctx_t* ctx = data;

    if (ctx->step != NULL) {
        ngx_waf_step_free(ctx->step);
        ctx->step = NULL;
    }
}


static ngx_int_t ngx_http_waf_make_body(ngx_http_request_t* r, ngx_waf_str_t* body) {
    ngx_chain_t* bufs;
    size_t len = 0;
    u_char* data;
    size_t offset = 0;

    body->data = NULL;
    body->len = 0;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NGX_OK;
    }

    for (bufs = r->request_body->bufs; bufs != NULL; bufs = bufs->next) {
        len += bufs->buf->last - bufs->buf->pos;
    }

    if (len == 0) {
        return NGX_OK;
    }

    data = ngx_pnalloc(r->pool, len);
    if (data == NULL) {
        return NGX_ERROR;
    }

    for (bufs = r->request_body->bufs; bufs != NULL; bufs = bufs->next) {
        size_t size = bufs->buf->last - bufs->buf->pos;
        ngx_memcpy(data + offset, bufs->buf->pos, size);
        offset += size;
    }

    body->data = data;
    body->len = len;

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_make_cookies(ngx_http_request_t* r, ngx_array_t** cookies) {
    ngx_table_elt_t* p;

    *cookies = ngx_array_create(r->pool, 4, sizeof(ngx_waf_str_t));
    if (*cookies == NULL) {
        return NGX_ERROR;
    }

    if (r->headers_in.cookie == NULL) {
        return NGX_OK;
    }

#if (nginx_version >= 1023000)
    for (p = r->headers_in.cookie; p != NULL; p = p->next) {
        size_t len = p->key.len + p->value.len + 1;
        u_char* buf = ngx_pnalloc(r->pool, len);
        ngx_waf_str_t* item;

        if (buf == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(buf, p->key.data, p->key.len);
        buf[p->key.len] = '=';
        ngx_memcpy(buf + p->key.len + 1, p->value.data, p->value.len);

        item = ngx_array_push(*cookies);
        if (item == NULL) {
            return NGX_ERROR;
        }
        item->data = buf;
        item->len = len;
    }
#else
    if (r->headers_in.cookies.nelts == 0) {
        return NGX_OK;
    }

    {
        ngx_table_elt_t** pp = r->headers_in.cookies.elts;
        ngx_uint_t i;

        for (i = 0; i < r->headers_in.cookies.nelts; i++, pp++) {
            ngx_waf_str_t* item = ngx_array_push(*cookies);
            if (item == NULL) {
                return NGX_ERROR;
            }
            item->data = (*pp)->value.data;
            item->len = (*pp)->value.len;
        }
    }
#endif

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_run(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx) {
    ngx_http_waf_loc_conf_t* conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_http_waf_main_conf_t* mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    ngx_waf_req_t req;
    ngx_waf_step_t* step;
    ngx_array_t* cookies = NULL;
    ngx_waf_str_t body;
    void* cc_zone = NULL;
    int64_t cc_index;

    ngx_memzero(&req, sizeof(ngx_waf_req_t));

    if (ngx_http_waf_make_body(r, &body) != NGX_OK) {
        body.data = NULL;
        body.len = 0;
    }
    if (ngx_http_waf_make_cookies(r, &cookies) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    req.ip = (const uint8_t *) &((struct sockaddr_in *) r->connection->sockaddr)->sin_addr;
    req.ip_len = 4;

#if (NGX_HAVE_INET6)
    if (r->connection->sockaddr->sa_family == AF_INET6) {
        req.ip = (const uint8_t *) &((struct sockaddr_in6 *) r->connection->sockaddr)->sin6_addr;
        req.ip_len = 16;
    }
#endif

    req.method = r->method;
    req.uri.data = r->uri.data;
    req.uri.len = r->uri.len;
    req.args.data = r->args.data;
    req.args.len = r->args.len;

    if (r->headers_in.user_agent != NULL) {
        req.user_agent.data = r->headers_in.user_agent->value.data;
        req.user_agent.len = r->headers_in.user_agent->value.len;
    }
    if (r->headers_in.referer != NULL) {
        req.referer.data = r->headers_in.referer->value.data;
        req.referer.len = r->headers_in.referer->value.len;
    }

    req.cookies = (const ngx_waf_str_t *) cookies->elts;
    req.cookie_count = cookies->nelts;
    req.body = body;
    req.has_body = body.data != NULL ? 1 : 0;
    req.internal = r->internal ? 1 : 0;
    req.now = ngx_time();

    cc_index = ngx_waf_conf_cc_zone(conf->core);
    if (cc_index >= 0 && mcf != NULL && mcf->zones != NULL
        && (ngx_uint_t) cc_index < mcf->zones->nelts)
    {
        ngx_http_waf_zone_t* zones = mcf->zones->elts;
        cc_zone = zones[cc_index].handle;
    }

    step = ngx_waf_check_begin(
        conf->core,
        &req,
        cc_zone,
        ngx_http_waf_zone_handle(mcf, conf->core, ngx_waf_conf_action_zone),
        ngx_http_waf_zone_handle(mcf, conf->core, ngx_waf_conf_captcha_zone),
        /* The captcha provider request is performed by this module. */
        1);
    if (step == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->step = step;
    ctx->applied = 0;

    return ngx_http_waf_drive(r, ctx);
}


/**
 * Run the machine as far as the current step allows: apply a decision, or start
 * the asynchronous operation the step asks for and park the request.
 */
static ngx_int_t ngx_http_waf_drive(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx) {
    for ( ;; ) {
        ngx_waf_step_t* step = ctx->step;

        if (step == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        switch (step->kind) {
        case NGX_WAF_STEP_RESOLVE_ADDR:
            return ngx_http_waf_start_resolve(r, ctx);

        case NGX_WAF_STEP_HTTP_REQUEST: {
            ngx_int_t rc = ngx_http_waf_start_http(r, ctx);

            if (rc == NGX_DONE) {
                return rc;
            }

            /* the provider request failed at once, the machine decided */
            continue;
        }

        case NGX_WAF_STEP_ALLOW:
        case NGX_WAF_STEP_RESPONSE:
        case NGX_WAF_STEP_INTERNAL_ERROR:
            return ngx_http_waf_apply(r, ctx);

        default:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
}


/**
 * Turn the decision the core made into the nginx response.  It may run twice
 * for the same request (the phases are re-entered after an asynchronous step),
 * so the headers are only written once.
 */
static ngx_int_t ngx_http_waf_apply(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx) {
    ngx_waf_step_t* step = ctx->step;

    if (step == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!ctx->applied) {
        if (step->retry_after >= 0 && step->status != NGX_HTTP_CLOSE) {
            ngx_http_waf_add_retry_after_header(r, step->retry_after);
        }
        ngx_http_waf_add_set_cookies(r, step);
        ctx->applied = 1;
    }

    if (step->register_content_handler) {
        r->content_handler = ngx_http_waf_handler_precontent_phase;
        return NGX_DECLINED;
    }

    switch (step->kind) {
    case NGX_WAF_STEP_ALLOW:
        return NGX_DECLINED;

    case NGX_WAF_STEP_RESPONSE:
        return (ngx_int_t) step->status;

    default:
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}


/**
 * Reverse resolve the client address for the friendly crawler check.
 */
static ngx_int_t ngx_http_waf_start_resolve(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx) {
    ngx_http_core_loc_conf_t* clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ngx_resolver_ctx_t* rc;
    ngx_waf_event_t event;

    if (clcf->resolver == NULL || ctx->step->ip == NULL || ctx->step->ip_len == 0) {
        /* No resolver: the crawler cannot be verified, which is reported as a
         * failed lookup. */
        ngx_memzero(&event, sizeof(ngx_waf_event_t));
        event.kind = NGX_WAF_EVENT_RESOLVE_FAILED;
        ngx_http_waf_resume(r, ctx, &event);
        return ngx_http_waf_drive(r, ctx);
    }

    rc = ngx_resolve_start(clcf->resolver, NULL);
    if (rc == NULL || rc == NGX_NO_RESOLVER) {
        ngx_memzero(&event, sizeof(ngx_waf_event_t));
        event.kind = NGX_WAF_EVENT_RESOLVE_FAILED;
        ngx_http_waf_resume(r, ctx, &event);
        return ngx_http_waf_drive(r, ctx);
    }

    rc->addr.sockaddr = r->connection->sockaddr;
    rc->addr.socklen = r->connection->socklen;
    rc->handler = ngx_http_waf_resolve_handler;
    rc->data = r;
    rc->timeout = clcf->resolver_timeout;

    if (ngx_resolve_addr(rc) != NGX_OK) {
        ngx_resolve_addr_done(rc);
        ngx_memzero(&event, sizeof(ngx_waf_event_t));
        event.kind = NGX_WAF_EVENT_RESOLVE_FAILED;
        ngx_http_waf_resume(r, ctx, &event);
        return ngx_http_waf_drive(r, ctx);
    }

    /* The request must survive until the resolver answers. */
    r->main->count++;

    return NGX_DONE;
}


static void ngx_http_waf_resolve_handler(ngx_resolver_ctx_t* rc) {
    ngx_http_request_t* r = rc->data;
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);
    ngx_waf_event_t event;

    ngx_memzero(&event, sizeof(ngx_waf_event_t));

    if (ctx == NULL || ctx->step == NULL) {
        ngx_resolve_addr_done(rc);
        return;
    }

    if (rc->state == NGX_OK && rc->name.len != 0) {
        event.kind = NGX_WAF_EVENT_RESOLVED_NAME;
        event.name.data = rc->name.data;
        event.name.len = rc->name.len;
    } else {
        event.kind = NGX_WAF_EVENT_RESOLVE_FAILED;
    }

    ngx_resolve_addr_done(rc);

    ngx_http_waf_resume(r, ctx, &event);

    ngx_http_finalize_request(r, NGX_DONE);
    ngx_http_core_run_phases(r);
}


/**
 * Hand the result of an asynchronous operation back to the core and let it
 * advance to the next decision or request.
 */
static void ngx_http_waf_resume(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx, ngx_waf_event_t* event) {
    if (ctx->step == NULL) {
        return;
    }
    if (ngx_waf_check_resume(ctx->step, event) != 0) {
        ctx->step->kind = NGX_WAF_STEP_INTERNAL_ERROR;
        ctx->step->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx->applied = 0;
}


static ngx_int_t ngx_http_waf_handler_precontent_phase(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_waf_step_t* step;

    if (ctx == NULL || ctx->step == NULL) {
        return NGX_DECLINED;
    }

    step = ctx->step;

    if (step->kind != NGX_WAF_STEP_RESPONSE) {
        return NGX_DECLINED;
    }

    if (step->body == NULL || step->body_len == 0) {
        return ngx_http_waf_gen_response(r, NULL, 0, step->content_type, step->status);
    }

    return ngx_http_waf_gen_response(r, step->body, step->body_len, step->content_type, step->status);
}


static ngx_int_t ngx_http_waf_gen_response(ngx_http_request_t* r, uint8_t* body, size_t body_len,
    uint32_t content_type, uint32_t status)
{
    ngx_int_t rc;
    ngx_buf_t* buf;
    ngx_chain_t* out;
    ngx_str_t type;

    if (content_type == NGX_WAF_CT_TEXT) {
        ngx_str_set(&type, "text/plain");
    } else {
        ngx_str_set(&type, "text/html");
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.content_type.data = ngx_pstrdup(r->pool, &type);
    if (r->headers_out.content_type.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->headers_out.content_type.len = type.len;
    r->headers_out.status = status;
    r->headers_out.content_length_n = body_len;

    ngx_http_waf_add_no_cache_header(r);

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    if (r->header_only) {
        return rc;
    }

    buf = ngx_calloc_buf(r->pool);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (body_len != 0) {
        buf->pos = ngx_pnalloc(r->pool, body_len);
        if (buf->pos == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(buf->pos, body, body_len);
    }
    buf->last = buf->pos + body_len;
    buf->memory = 1;
    buf->last_buf = (r == r->main) ? 1 : 0;
    buf->last_in_chain = 1;

    out = ngx_alloc_chain_link(r->pool);
    if (out == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    out->buf = buf;
    out->next = NULL;

    return ngx_http_output_filter(r, out);
}


static void ngx_http_waf_add_no_cache_header(ngx_http_request_t* r) {
    ngx_table_elt_t* header = ngx_list_push(&r->headers_out.headers);

    if (header == NULL) {
        return;
    }

    header->hash = 1;
    header->lowcase_key = (u_char*)"cache-control";
    ngx_str_set(&header->key, "Cache-control");
    ngx_str_set(&header->value, "no-store");
}


static void ngx_http_waf_add_retry_after_header(ngx_http_request_t* r, int64_t seconds) {
    ngx_table_elt_t* header = ngx_list_push(&r->headers_out.headers);

    if (header == NULL) {
        return;
    }

    header->hash = 1;
    header->lowcase_key = (u_char*)"retry-after";
    ngx_str_set(&header->key, "Retry-After");
    header->value.data = ngx_pnalloc(r->pool, NGX_INT64_LEN + 1);
    if (header->value.data == NULL) {
        header->hash = 0;
        return;
    }
    header->value.len = ngx_sprintf(header->value.data, "%L", seconds) - header->value.data;
}


static ngx_int_t ngx_http_waf_handler_log_phase(ngx_http_request_t* r) {
    ngx_http_waf_loc_conf_t* conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_http_waf_main_conf_t* mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_core_conf_t* ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);

    if (conf == NULL || conf->core == NULL) {
        return NGX_DECLINED;
    }

    int64_t waf = ngx_waf_conf_waf(conf->core);
    if (waf == -1 || waf == 0) {
        return NGX_DECLINED;
    }

    if (ngx_waf_should_gc(ccf != NULL ? (int64_t) ccf->worker_processes : 1)) {
        ngx_waf_gc(conf->core);

        if (mcf != NULL && mcf->zones != NULL) {
            ngx_http_waf_zone_t* zones = mcf->zones->elts;
            ngx_uint_t i;

            for (i = 0; i < mcf->zones->nelts; i++) {
                if (zones[i].handle != NULL) {
                    ngx_waf_shm_zone_gc(zones[i].handle);
                }
            }
        }
    }

    if (ctx == NULL || ctx->step == NULL) {
        return NGX_OK;
    }

    if (ctx->step->general_log && ctx->step->log != NULL) {
        ngx_str_t message;
        message.data = ctx->step->log;
        message.len = ctx->step->log_len;
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "%V", &message);
        /* an internal redirect must not log the same decision twice */
        ctx->step->general_log = 0;
    }

    return NGX_OK;
}


static ngx_http_waf_ctx_t *ngx_http_waf_get_ctx(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    if (ctx != NULL) {
        return ctx;
    }

    /*
     * The context of the original request is kept in the cleanup chain of the
     * pool, which survives an internal redirect (`ngx_http_internal_redirect()`
     * clears `r->ctx`), so `$waf_*` keep reporting the original decision.
     */
    for (ngx_http_cleanup_t* cln = r->cleanup; cln != NULL; cln = cln->next) {
        if (cln->handler == ngx_http_waf_request_cleanup) {
            ngx_http_set_ctx(r, cln->data, ngx_http_waf_module);
            return cln->data;
        }
    }

    return NULL;
}


static ngx_int_t ngx_http_waf_var_log(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL || ctx->step == NULL || !ctx->step->checked) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = 4;
    v->data = (u_char*)"true";
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_var_blocking_log(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL || ctx->step == NULL || !ctx->step->blocked) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = (u_char*)"true";
    v->len = 4;
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_var_blocked(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL || ctx->step == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ctx->step->blocked) {
        v->data = (u_char*)"true";
        v->len = 4;
    } else {
        v->data = (u_char*)"false";
        v->len = 5;
    }

    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_var_rule_type(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL || ctx->step == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->step->rule_type != NULL ? ctx->step->rule_type : (u_char*)"";
    v->len = ctx->step->rule_type_len;
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_var_rule_details(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL || ctx->step == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->step->rule_details != NULL ? ctx->step->rule_details : (u_char*)"";
    v->len = ctx->step->rule_details_len;
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_var_spend(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);
    u_char text[64];

    if (ctx == NULL || ctx->step == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = snprintf((char*) text, sizeof(text), "%.5lf", ctx->step->spend);
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(v->data, text, v->len);
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_var_rate(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);

    if (ctx == NULL || ctx->step == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN + 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }
    v->len = ngx_sprintf(v->data, "%L", ctx->step->rate) - v->data;
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 1;

    return NGX_OK;
}
