/*
 * The private header of the nginx glue: the state the translation units of
 * the module share and the entry points they call in each other.  It is not
 * installed; the C ABI of the Rust core is `include/ngx_http_waf_ffi.h`.
 */

#ifndef _NGX_HTTP_WAF_MODULE_H_INCLUDED_
#define _NGX_HTTP_WAF_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdio.h>
#include <stddef.h>

#include <ngx_http_waf_ffi.h>


/*
 * The captcha provider client is an SSL client of nginx itself and the
 * configuration holds an `ngx_ssl_t`, so an nginx without SSL support cannot
 * compile the module.  The `config` script refuses such a tree as well; this is
 * the message a build system that does not run the script (a hand written
 * compile line, for instance) sees.
 */
#if !(NGX_OPENSSL)
#error "ngx_waf needs an nginx built with SSL support, e.g. --with-http_ssl_module"
#endif


/**
 * @brief The shared memory zones declared with `waf_zone`.
 *
 * A zone is identified by its name, the only identity the configuration and
 * the core share.  The array only holds pointers: a `waf_zone` may reallocate
 * it after the shared memory zone was handed the entry, and a stale copy would
 * lose the handle the init callback writes.
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
    /** The URL the endpoint was parsed from, empty until it is configured. */
    ngx_str_t                  url;
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
    /**
     * Set once the pool cleanup that releases `ssl` was registered: a repeated
     * `waf_captcha` of one context replaces the endpoint but keeps the one
     * cleanup that owns the context built in its place.
     */
    unsigned                   ssl_cleanup_registered:1;
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
    /**
     * The address the resolver of the enclosing context answered with while
     * the request was parked on the lookup.  The memory of the resolver
     * context is released before the drive loop continues, so the address is
     * copied into the request pool.  `resolved_failed` is the lookup that did
     * not answer, either.
     */
    struct sockaddr           *resolved_sockaddr;
    socklen_t                  resolved_socklen;
    unsigned                   use_ssl:1;
    unsigned                   handshake_done:1;
    /** Set once the machine was given the answer. */
    unsigned                   finished:1;
    /** Set while `start_http` runs, i.e. inside the drive loop. */
    unsigned                   in_drive:1;
    unsigned                   resolved_valid:1;
    unsigned                   resolved_failed:1;
} ngx_http_waf_fetch_t;


typedef struct {
    ngx_waf_conf_t            *core;
    ngx_http_complex_value_t  *modsecurity_transaction_id;
    ngx_http_waf_captcha_api_t captcha_api;
} ngx_http_waf_loc_conf_t;


typedef struct {
    ngx_waf_main_t *core;
    ngx_array_t  *zones;
} ngx_http_waf_main_conf_t;


typedef struct {
    /** The inspection of this request, owned by the core. */
    ngx_waf_check_t       *check;
    /** The step last published by the core, read-only for this module. */
    const ngx_waf_step_t  *step;
    /** The provider request in flight, when the machine parked on one. */
    ngx_http_waf_fetch_t fetch;
    /**
     * Set by a resolver handler that runs while its lookup is started, i.e.
     * while the drive loop is on the stack: the answer came from the cache of
     * the resolver, the lookup parked nothing and the drive loop has to pick
     * the answer up.
     */
    ngx_uint_t       resolver_inline:1;
    ngx_uint_t       applied:1;
    /** The audit line of the decision was written once already. */
    ngx_uint_t       general_logged:1;
    ngx_uint_t       waiting_more_body:1;
    ngx_uint_t       read_body_done:1;
} ngx_http_waf_ctx_t;


/*
 * The glue hands nginx strings to the core with a cast (`ngx_str_t *` to
 * `ngx_waf_str_t *`), the two types have to stay layout compatible.
 */
typedef char ngx_http_waf_str_layout_must_match[
    (sizeof(ngx_str_t) == sizeof(ngx_waf_str_t)
     && offsetof(ngx_str_t, len) == offsetof(ngx_waf_str_t, len)
     && offsetof(ngx_str_t, data) == offsetof(ngx_waf_str_t, data)) ? 1 : -1];


/** The module itself, defined once in `ngx_http_waf_module.c`. */
extern ngx_module_t ngx_http_waf_module;


/*
 * The configuration callbacks of the module.
 */
char *ngx_http_waf_zone_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


char *ngx_http_waf_directive_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


char *ngx_http_waf_modsecurity_transaction_id_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


void *ngx_http_waf_create_main_conf(ngx_conf_t* cf);


void *ngx_http_waf_create_loc_conf(ngx_conf_t* cf);


char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);


/*
 * The shared memory zone of a `waf_zone`, used while the configuration is read
 * and while a request looks its handle up.
 */
ngx_int_t ngx_http_waf_shm_zone_init(ngx_shm_zone_t* zone, void* data);


/**
 * Resolve the zone a configuration refers to into the handle of this worker.
 */
void *ngx_http_waf_zone_handle(ngx_http_waf_main_conf_t* mcf, ngx_waf_str_t name);


/*
 * The request phases installed by the module, and the request context shared
 * with the asynchronous parts.
 */
ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r);


ngx_int_t ngx_http_waf_handler_log_phase(ngx_http_request_t* r);


ngx_http_waf_ctx_t *ngx_http_waf_get_ctx(ngx_http_request_t* r);


/*
 * The provider request of the captcha flow, started by the request path and
 * resumed by its own event handlers.
 */
ngx_int_t ngx_http_waf_start_http(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);


void ngx_http_waf_resume(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx, ngx_waf_event_t* event);


/**
 * Hand the bytes of `ctx->fetch.response` to the core, `eof` when the provider
 * closed the connection.  Returns 1 when the core left the HTTP step (the
 * request was settled), 0 when it still waits for the rest of the same answer.
 */
ngx_uint_t ngx_http_waf_fetch_feed(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx,
    ngx_uint_t eof);


/**
 * The provider request failed before an answer could be read: the core
 * settles it as a failed attempt.
 */
void ngx_http_waf_fetch_failed(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);


/*
 * The `$waf_*` variables.
 */
ngx_int_t ngx_http_waf_var_log(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


ngx_int_t ngx_http_waf_var_blocking_log(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


ngx_int_t ngx_http_waf_var_blocked(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


ngx_int_t ngx_http_waf_var_rule_type(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


ngx_int_t ngx_http_waf_var_rule_details(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


ngx_int_t ngx_http_waf_var_spend(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


ngx_int_t ngx_http_waf_var_rate(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


#endif /* _NGX_HTTP_WAF_MODULE_H_INCLUDED_ */
