#ifndef NGX_HTTP_WAF_FFI_H
#define NGX_HTTP_WAF_FFI_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * The result of normalizing the `redir` query of an Anubis challenge proxy
 * request.
 */
typedef enum ngx_waf_anubis_redirect_status {
    /**
     * The request has no `redir` parameter and must be proxied unchanged.
     */
    NGX_WAF_ANUBIS_REDIRECT_STATUS_NO_REDIRECT = 0,
    /**
     * The output buffer holds the normalized views.
     */
    NGX_WAF_ANUBIS_REDIRECT_STATUS_NORMALIZED = 1,
    /**
     * The request has ambiguous or unsafe redirect parameters.
     */
    NGX_WAF_ANUBIS_REDIRECT_STATUS_REJECTED = 2,
    /**
     * The output buffer is too small; `required` is the needed size.
     */
    NGX_WAF_ANUBIS_REDIRECT_STATUS_BUFFER_TOO_SMALL = 3,
    /**
     * The Rust side could not complete the operation.
     */
    NGX_WAF_ANUBIS_REDIRECT_STATUS_INTERNAL_ERROR = 4,
} ngx_waf_anubis_redirect_status;

/**
 * The method of one request.  The glue owns the mapping from the bits of
 * nginx (`NGX_HTTP_*`) onto this enum, so the core never spells an nginx
 * value.
 */
typedef enum ngx_waf_http_method {
    NGX_WAF_HTTP_METHOD_UNKNOWN = 0,
    NGX_WAF_HTTP_METHOD_GET = 1,
    NGX_WAF_HTTP_METHOD_HEAD = 2,
    NGX_WAF_HTTP_METHOD_POST = 3,
    NGX_WAF_HTTP_METHOD_PUT = 4,
    NGX_WAF_HTTP_METHOD_DELETE = 5,
    NGX_WAF_HTTP_METHOD_MKCOL = 6,
    NGX_WAF_HTTP_METHOD_COPY = 7,
    NGX_WAF_HTTP_METHOD_MOVE = 8,
    NGX_WAF_HTTP_METHOD_OPTIONS = 9,
    NGX_WAF_HTTP_METHOD_PROPFIND = 10,
    NGX_WAF_HTTP_METHOD_PROPPATCH = 11,
    NGX_WAF_HTTP_METHOD_LOCK = 12,
    NGX_WAF_HTTP_METHOD_UNLOCK = 13,
    NGX_WAF_HTTP_METHOD_PATCH = 14,
    NGX_WAF_HTTP_METHOD_TRACE = 15,
} ngx_waf_http_method;

/**
 * The protocol version of one request, rendered for libmodsecurity.
 */
typedef enum ngx_waf_http_version {
    NGX_WAF_HTTP_VERSION_HTTP09 = 0,
    NGX_WAF_HTTP_VERSION_HTTP10 = 1,
    NGX_WAF_HTTP_VERSION_HTTP11 = 2,
    NGX_WAF_HTTP_VERSION_HTTP20 = 3,
    NGX_WAF_HTTP_VERSION_UNKNOWN = 4,
} ngx_waf_http_version;

/**
 * What the core asks the glue to do for one request.
 */
typedef enum ngx_waf_step_kind {
    /**
     * The request goes on to the next phase.
     */
    NGX_WAF_STEP_KIND_ALLOW = 0,
    /**
     * The glue answers with the decision of the step.
     */
    NGX_WAF_STEP_KIND_RESPONSE = 1,
    /**
     * The inspection could not run; the glue answers 500.
     */
    NGX_WAF_STEP_KIND_INTERNAL_ERROR = 2,
    /**
     * The glue reverse resolves the address of `pending.ip` and resumes.
     */
    NGX_WAF_STEP_KIND_RESOLVE_ADDR = 3,
    /**
     * The glue performs the request of `pending` and resumes.
     */
    NGX_WAF_STEP_KIND_HTTP_REQUEST = 4,
} ngx_waf_step_kind;

/**
 * How the glue writes the body of a response.
 */
typedef enum ngx_waf_content_type {
    NGX_WAF_CONTENT_TYPE_HTML = 0,
    NGX_WAF_CONTENT_TYPE_TEXT = 1,
} ngx_waf_content_type;

/**
 * The HTTP request a parked inspection asks the glue to perform.
 */
typedef enum NgxWafHttpRequestKind {
    NGX_WAF_HTTP_REQUEST_KIND_CAPTCHA = 0,
    NGX_WAF_HTTP_REQUEST_KIND_ANUBIS = 1,
} NgxWafHttpRequestKind;

/**
 * The events that wake a parked machine up.
 */
typedef enum ngx_waf_event_kind {
    /**
     * The PTR lookup succeeded.
     */
    NGX_WAF_EVENT_KIND_RESOLVED_NAME = 0,
    /**
     * No name, no resolver, timeout or lookup error.
     */
    NGX_WAF_EVENT_KIND_RESOLVE_FAILED = 1,
    /**
     * Bytes of the answer of the captcha provider.
     */
    NGX_WAF_EVENT_KIND_HTTP_DATA = 2,
    /**
     * The captcha provider could not be reached.
     */
    NGX_WAF_EVENT_KIND_HTTP_FAILED = 3,
    /**
     * The status line of an Anubis auth check was read.
     */
    NGX_WAF_EVENT_KIND_HTTP_STATUS = 4,
} ngx_waf_event_kind;

/**
 * The friendly crawler each `BotId` stands for, in the order the C
 * implementation walks them.
 */
typedef struct BotId BotId;

/**
 * The inspection identifiers that `waf_priority` can reorder.
 */
typedef struct CheckKind CheckKind;

/**
 * One request inspection, owned by the glue, opaque to it.
 */
typedef struct ngx_waf_inspection_handle_t ngx_waf_inspection_handle_t;

/**
 * The location configuration of one request, opaque to the glue.
 */
typedef struct ngx_waf_location_configuration_t ngx_waf_location_configuration_t;

/**
 * The main configuration (`http` level) of one nginx cycle, opaque to the
 * glue.
 */
typedef struct ngx_waf_main_configuration_t ngx_waf_main_configuration_t;

/**
 * The three sources that can be configured with `waf_action`.
 */
typedef struct TriggerKind TriggerKind;

/**
 * `ngx_str_t` compatible string view: nginx declares the length first, so the
 * field order matters (see the layout assertion in the C glue).  The data is
 * binary, not NUL terminated.
 */
typedef struct ngx_waf_string_view_t {
    size_t len;
    const uint8_t *data;
} ngx_waf_string_view_t;

/**
 * The request data Anubis redirect normalization needs.
 */
typedef struct ngx_waf_anubis_redirect_input_t {
    /**
     * The original `Host` header.
     */
    struct ngx_waf_string_view_t host;
    /**
     * The configured Anubis base prefix, such as `/base`.
     */
    struct ngx_waf_string_view_t base_prefix;
    /**
     * The request target received by nginx, including its query string.
     */
    struct ngx_waf_string_view_t unparsed_uri;
} ngx_waf_anubis_redirect_input_t;

/**
 * Views into the output buffer and the size the normalized result needs.
 */
typedef struct ngx_waf_anubis_redirect_output_t {
    /**
     * Bytes needed for both views, even when the supplied buffer is too small.
     */
    size_t required;
    /**
     * The protected request target for `X-Original-Uri`.
     */
    struct ngx_waf_string_view_t original_uri;
    /**
     * The rewritten request target sent to Anubis.
     */
    struct ngx_waf_string_view_t request_uri;
} ngx_waf_anubis_redirect_output_t;

/**
 * The shared memory zone of every use of the configuration, by name.  An
 * empty view means the configuration does not use that zone.
 */
typedef struct ngx_waf_zone_references_t {
    struct ngx_waf_string_view_t cc;
    struct ngx_waf_string_view_t captcha;
    struct ngx_waf_string_view_t action;
} ngx_waf_zone_references_t;

/**
 * One request header, the `ngx_table_elt_t` list of nginx.
 */
typedef struct ngx_waf_header_view_t {
    struct ngx_waf_string_view_t key;
    struct ngx_waf_string_view_t value;
} ngx_waf_header_view_t;

/**
 * Everything libmodsecurity reads beyond the common request view.
 */
typedef struct ngx_waf_modsecurity_request_view_t {
    const struct ngx_waf_header_view_t *headers;
    size_t header_count;
    /**
     * Whether `waf_modsecurity_transaction_id` is configured; a configured
     * empty value is still a value.
     */
    bool has_trans_id;
    struct ngx_waf_string_view_t trans_id;
    struct ngx_waf_string_view_t unparsed_uri;
    struct ngx_waf_string_view_t method_name;
    enum ngx_waf_http_version http_version;
    struct ngx_waf_string_view_t client_addr;
    uint32_t client_port;
    struct ngx_waf_string_view_t server_addr;
    uint32_t server_port;
} ngx_waf_modsecurity_request_view_t;

/**
 * The request view the C glue fills in.
 */
typedef struct ngx_waf_request_view_t {
    /**
     * Network order address, 4 or 16 bytes; empty for a connection without
     * one.
     */
    struct ngx_waf_string_view_t ip;
    enum ngx_waf_http_method method;
    struct ngx_waf_string_view_t uri;
    /**
     * The request target as received, including the query string.
     */
    struct ngx_waf_string_view_t unparsed_uri;
    struct ngx_waf_string_view_t user_agent;
    /**
     * One view per `Cookie` header, the raw header values.
     */
    const struct ngx_waf_string_view_t *cookies;
    size_t cookie_count;
    /**
     * The body of the request, empty when there is none.
     */
    struct ngx_waf_string_view_t body;
    /**
     * Wall clock seconds.
     */
    int64_t now;
    /**
     * The fields only `waf_modsecurity` reads, NULL when the inspection
     * cannot run.  The core copies the view while `ngx_waf_inspection_begin()`
     * runs; the views inside it stay valid for the whole request.
     */
    const struct ngx_waf_modsecurity_request_view_t *modsecurity;
    /**
     * `r->connection->log`: the data of the ModSecurity log callback, and
     * where a panic caught at this boundary is reported.
     */
    void *log;
} ngx_waf_request_view_t;

/**
 * The zone handles of one request, NULL when the configuration does not use
 * the zone.
 */
typedef struct ngx_waf_zone_handles_t {
    void *cc;
    void *captcha;
    void *action;
} ngx_waf_zone_handles_t;

/**
 * A decision: everything the glue needs for the response and the `$waf_*`
 * variables.
 */
typedef struct ngx_waf_decision_t {
    uint32_t status;
    enum ngx_waf_content_type content_type;
    bool has_retry_after;
    int64_t retry_after;
    struct ngx_waf_string_view_t body;
    /**
     * The audit line, when `general_log` is set.
     */
    struct ngx_waf_string_view_t log;
    struct ngx_waf_string_view_t rule_type;
    struct ngx_waf_string_view_t rule_details;
    /**
     * The `Location` header of the decision, empty when there is none.
     */
    struct ngx_waf_string_view_t location;
    /**
     * `Set-Cookie` values the decision mints (captcha).
     */
    const struct ngx_waf_string_view_t *set_cookies;
    size_t set_cookie_count;
    bool blocked;
    bool checked;
    bool general_log;
    bool register_content_handler;
    int64_t rate;
    double spend;
} ngx_waf_decision_t;

/**
 * The asynchronous operation a parked step asks for.
 */
typedef struct ngx_waf_pending_t {
    /**
     * `RESOLVE_ADDR`: the address to reverse resolve.
     */
    struct ngx_waf_string_view_t ip;
    /**
     * `HTTP_REQUEST`: the request the glue has to perform.
     */
    enum NgxWafHttpRequestKind request_kind;
    struct ngx_waf_string_view_t url;
    struct ngx_waf_string_view_t body;
} ngx_waf_pending_t;

/**
 * The result of one inspection, read-only for the glue.  The payload fields
 * belong to `kind`: `decision` for a decision, `pending` for a park.
 */
typedef struct ngx_waf_step_t {
    enum ngx_waf_step_kind kind;
    struct ngx_waf_decision_t decision;
    struct ngx_waf_pending_t pending;
} ngx_waf_step_t;

/**
 * The event that wakes a parked inspection up.
 */
typedef struct ngx_waf_event_t {
    enum ngx_waf_event_kind kind;
    /**
     * `RESOLVED_NAME`: the host name the address resolves to.
     */
    struct ngx_waf_string_view_t name;
    /**
     * `HTTP_DATA`: the bytes of the answer the glue read, from its start.
     */
    struct ngx_waf_string_view_t data;
    /**
     * `HTTP_DATA`: whether the provider closed the connection.  The core
     * settles the request when the answer is complete or unreadable; an
     * answer that is merely incomplete leaves the step on `HTTP_REQUEST`,
     * and the glue reads on and feeds the bytes again.
     */
    bool eof;
    /**
     * `HTTP_STATUS`: the status code of an Anubis auth check.
     */
    uint16_t status;
} ngx_waf_event_t;

/**
 * Callbacks the C glue provides for one shared memory zone.
 */
typedef struct ngx_waf_shared_memory_callbacks_t {
    void (*lock)(void*);
    void (*unlock)(void*);
    /**
     * Allocates from the zone: the caller holds the zone lock (the guard of
     * this module), so the callback must not take it again.
     */
    void *(*alloc_locked)(void*, size_t);
    /**
     * Opaque C pointer handed to every callback (the `ngx_slab_pool_t`).
     */
    void *ctx;
} ngx_waf_shared_memory_callbacks_t;

const char *ngx_waf_version(void);

void ngx_waf_string_free(char *text);

/**
 * Normalize the `redir` parameter of an Anubis challenge request.
 *
 * Call once with a NULL/empty output buffer to obtain the required length,
 * then again with caller-owned storage.  The returned views point into that
 * storage and remain valid for as long as the caller keeps it alive.
 *
 * # Safety
 * `input` and `output` must be valid for this call.  Every view in `input`
 * must point to readable memory.  When `capacity` is non-zero, `buffer` must
 * point to that many writable bytes.
 */
enum ngx_waf_anubis_redirect_status ngx_waf_anubis_redirect_normalize(const struct ngx_waf_anubis_redirect_input_t *input,
                                                                      uint8_t *buffer,
                                                                      size_t capacity,
                                                                      struct ngx_waf_anubis_redirect_output_t *output);

struct ngx_waf_main_configuration_t *ngx_waf_main_configuration_create(void);

void ngx_waf_main_configuration_free(struct ngx_waf_main_configuration_t *main);

struct ngx_waf_location_configuration_t *ngx_waf_location_configuration_create(void);

void ngx_waf_location_configuration_free(struct ngx_waf_location_configuration_t *conf);

/**
 * Whether the inspection of a request runs with this configuration:
 * `waf on` or `waf bypass`.  The C side skips the access and log phases of
 * `waf off` and of a context that never set the directive.
 */
bool ngx_waf_location_configuration_enabled(const struct ngx_waf_location_configuration_t *conf);

/**
 * Whether the `waf_modsecurity` inspection can run; the C side only packs the
 * `ngx_waf_modsecurity_request_view_t` view when it does.
 */
bool ngx_waf_location_configuration_modsecurity_enabled(const struct ngx_waf_location_configuration_t *conf);

/**
 * The shared memory zone of every use of this configuration, by name; an
 * empty view means the configuration does not use that zone.  The C side owns
 * the zones and looks the handles up.
 */
struct ngx_waf_zone_references_t ngx_waf_location_configuration_zone_references(const struct ngx_waf_location_configuration_t *conf);

/**
 * The endpoint the captcha provider of this configuration is asked on: the
 * `api=` of `waf_captcha`, or the default of the provider it named.  This is
 * the very URL the core puts into a `STEP_HTTP_REQUEST`, so the C glue parses
 * what it will actually use instead of looking for `api=` itself (a location
 * that inherits the directive has no `api=` of its own).
 *
 * The returned view points into the configuration, which outlives every
 * request; it is empty when no `waf_captcha` was configured.
 */
struct ngx_waf_string_view_t ngx_waf_location_configuration_captcha_api(const struct ngx_waf_location_configuration_t *conf);

/**
 * The configured `waf_anubis` URL, empty when Anubis is off or unset.
 */
struct ngx_waf_string_view_t ngx_waf_location_configuration_anubis_url(const struct ngx_waf_location_configuration_t *conf);

/**
 * Apply one directive, returns NULL on success or an error message.
 */
char *ngx_waf_directive_apply(struct ngx_waf_main_configuration_t *main,
                              struct ngx_waf_location_configuration_t *conf,
                              struct ngx_waf_string_view_t name,
                              const struct ngx_waf_string_view_t *args,
                              size_t nargs);

/**
 * Parse and validate `waf_zone`.  On success the returned name pointer stays
 * valid as long as the main configuration does.
 */
char *ngx_waf_zone_directive_apply(struct ngx_waf_main_configuration_t *main,
                                   const struct ngx_waf_string_view_t *args,
                                   size_t nargs,
                                   const uint8_t **out_name,
                                   size_t *out_name_len,
                                   size_t *out_size);

/**
 * Merge a child configuration into its parent.
 */
char *ngx_waf_location_configuration_merge(struct ngx_waf_location_configuration_t *child,
                                           struct ngx_waf_location_configuration_t *parent);

/**
 * Start the inspection of one request.  The returned handle is owned by the C
 * side and must be freed with `ngx_waf_inspection_free()` once the request is done,
 * which is also what keeps the machine of a parked request alive.
 */
struct ngx_waf_inspection_handle_t *ngx_waf_inspection_begin(struct ngx_waf_location_configuration_t *conf,
                                                             const struct ngx_waf_request_view_t *req,
                                                             struct ngx_waf_zone_handles_t zones,
                                                             bool http_transport);

/**
 * The step of one inspection, read-only for the C side.  The pointer stays
 * valid until the next `ngx_waf_inspection_resume()` or `ngx_waf_inspection_free()`.
 */
const struct ngx_waf_step_t *ngx_waf_inspection_step(const struct ngx_waf_inspection_handle_t *check);

/**
 * Feed the result of an asynchronous operation back into the machine and
 * publish the next step in the same handle.  A panic is reported to the error
 * log and published as the internal error step, so the C side never has to
 * write to the memory this crate owns.
 *
 * `HTTP_DATA` may be fed more than once for the same provider request: the
 * step stays on `HTTP_REQUEST` until the bytes hold a whole answer (or one
 * the core cannot read, which is a failed attempt).
 */
void ngx_waf_inspection_resume(struct ngx_waf_inspection_handle_t *check,
                               const struct ngx_waf_event_t *event);

/**
 * Run the log phase of one request: the audit log of the ModSecurity
 * transaction, when the inspection created one.  nginx runs the log phase
 * before the request pool (and with it the machine) is released.
 */
void ngx_waf_inspection_log(struct ngx_waf_inspection_handle_t *check);

void ngx_waf_inspection_free(struct ngx_waf_inspection_handle_t *check);

/**
 * Initialise (or reuse after a reload) the Rust side state of a shared memory
 * zone.
 */
void *ngx_waf_shared_memory_zone_initialize(void *addr,
                                            size_t size,
                                            void *old,
                                            const struct ngx_waf_shared_memory_callbacks_t *ops);

/**
 * Release a zone handle.  The shared memory itself belongs to nginx.
 */
void ngx_waf_shared_memory_zone_free(void *handle);

/**
 * Sweep the expired counters of one zone.
 */
void ngx_waf_shared_memory_zone_collect_garbage(void *handle);

/**
 * The probability check the glue uses to gate the GC of every zone of this
 * worker.
 */
bool ngx_waf_should_collect_garbage(uint32_t worker_processes);

#endif  /* NGX_HTTP_WAF_FFI_H */
