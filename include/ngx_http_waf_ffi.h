/* The `kind` values of `ngx_waf_step_t`, mirrored from rust/src/types.rs. */
#define NGX_WAF_STEP_ALLOW          0
#define NGX_WAF_STEP_RESPONSE       1
#define NGX_WAF_STEP_INTERNAL_ERROR 2
#define NGX_WAF_STEP_RESOLVE_ADDR   3
#define NGX_WAF_STEP_HTTP_REQUEST   4

/* The `kind` values of `ngx_waf_event_t`. */
#define NGX_WAF_EVENT_RESOLVED_NAME  0
#define NGX_WAF_EVENT_RESOLVE_FAILED 1
#define NGX_WAF_EVENT_HTTP_RESPONSE  2
#define NGX_WAF_EVENT_HTTP_FAILED    3

/* The `content_type` values of `ngx_waf_step_t`. */
#define NGX_WAF_CT_HTML 0
#define NGX_WAF_CT_TEXT 1


#ifndef NGX_HTTP_WAF_FFI_H
#define NGX_HTTP_WAF_FFI_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * `waf` values.
 */
#define WAF_UNSET -1

#define WAF_OFF 0

#define WAF_ON 1

#define WAF_BYPASS 2

#define M_INSPECT_GET 2

#define M_INSPECT_HEAD 4

#define M_INSPECT_POST 8

#define M_INSPECT_PUT 16

#define M_INSPECT_DELETE 32

#define M_INSPECT_MKCOL 64

#define M_INSPECT_COPY 128

#define M_INSPECT_MOVE 256

#define M_INSPECT_OPTIONS 512

#define M_INSPECT_PROPFIND 1024

#define M_INSPECT_PROPPATCH 2048

#define M_INSPECT_LOCK 4096

#define M_INSPECT_UNLOCK 8192

#define M_INSPECT_PATCH 16384

#define M_INSPECT_TRACE 32768

#define M_INSPECT_IP (M_INSPECT_TRACE << 1)

#define M_INSPECT_URL (M_INSPECT_IP << 1)

#define M_INSPECT_RB (M_INSPECT_URL << 1)

#define M_INSPECT_ARGS (M_INSPECT_RB << 1)

#define M_INSPECT_UA (M_INSPECT_ARGS << 1)

#define M_INSPECT_COOKIE (M_INSPECT_UA << 1)

#define M_INSPECT_REFERER (M_INSPECT_COOKIE << 1)

#define M_CMN_METH ((M_INSPECT_GET | M_INSPECT_POST) | M_INSPECT_HEAD)

#define M_ALL_METH ((((((((((((((M_INSPECT_GET | M_INSPECT_HEAD) | M_INSPECT_POST) | M_INSPECT_PUT) | M_INSPECT_DELETE) | M_INSPECT_MKCOL) | M_INSPECT_COPY) | M_INSPECT_MOVE) | M_INSPECT_OPTIONS) | M_INSPECT_PROPFIND) | M_INSPECT_PROPPATCH) | M_INSPECT_LOCK) | M_INSPECT_UNLOCK) | M_INSPECT_PATCH) | M_INSPECT_TRACE)

#define M_STD (((((M_INSPECT_IP | M_INSPECT_URL) | M_INSPECT_RB) | M_INSPECT_ARGS) | M_INSPECT_UA) | M_CMN_METH)

#define M_STATIC ((((M_INSPECT_IP | M_INSPECT_URL) | M_INSPECT_UA) | M_INSPECT_GET) | M_INSPECT_HEAD)

#define M_DYNAMIC ((((((M_INSPECT_IP | M_INSPECT_URL) | M_INSPECT_RB) | M_INSPECT_ARGS) | M_INSPECT_UA) | M_INSPECT_COOKIE) | M_CMN_METH)

#define M_FULL UINT64_MAX

/**
 * Action flags, identical to `action_flag_e` of the C implementation.
 */
#define ACTION_FLAG_NONE 0

#define ACTION_FLAG_UNSET 1

#define ACTION_FLAG_DECLINE 2

#define ACTION_FLAG_FOLLOW 4

#define ACTION_FLAG_RETURN 8

#define ACTION_FLAG_REG_CONTENT 16

#define ACTION_FLAG_STR 32

#define ACTION_FLAG_HTML 64

#define ACTION_FLAG_FROM_WHITE_LIST 128

#define ACTION_FLAG_FROM_BLACK_LIST 256

#define ACTION_FLAG_FROM_CC_DENY 512

#define ACTION_FLAG_FROM_MODSECURITY 1024

#define ACTION_FLAG_FROM_CAPTCHA 2048

#define ACTION_FLAG_FROM_UNDER_ATTACK 4096

#define ACTION_FLAG_FROM_VERIFY_BOT 8192

#define ACTION_FLAG_CAPTCHA 16384

#define ACTION_FLAG_UNDER_ATTACK 32768

/**
 * Bot types, identical to `bot_type_e` of the C implementation.
 */
#define BOT_TYPE_NONE 0

#define BOT_TYPE_UNSET 1

#define BOT_TYPE_GOOGLE 2

#define BOT_TYPE_BING 4

#define BOT_TYPE_BAIDU 8

#define BOT_TYPE_SOGOU 16

#define BOT_TYPE_YANDEX 32

/**
 * Steps returned by the check state machine.  A decision uses the `ALLOW` or
 * `RESPONSE` kind, the other two park the request until the C side has run an
 * asynchronous operation for it.
 */
#define STEP_ALLOW 0

#define STEP_RESPONSE 1

#define STEP_INTERNAL_ERROR 2

#define STEP_RESOLVE_ADDR 3

#define STEP_HTTP_REQUEST 4

/**
 * Events that wake a parked machine up.
 */
#define EVENT_RESOLVED_NAME 0

#define EVENT_RESOLVE_FAILED 1

#define EVENT_HTTP_RESPONSE 2

#define EVENT_HTTP_FAILED 3

/**
 * Content types the C side knows how to emit.
 */
#define CT_HTML 0

#define CT_TEXT 1

/**
 * Default status codes used when a directive does not override them.
 */
#define HTTP_OK 200

#define HTTP_FORBIDDEN 403

#define HTTP_NOT_FOUND 404

#define HTTP_TOO_MANY_REQUESTS 429

#define HTTP_INTERNAL_SERVER_ERROR 500

#define HTTP_SERVICE_UNAVAILABLE 503

/**
 * `crypto_hash_sha256_BYTES * 2`
 */
#define SHA256_HEX_LEN 64

/**
 * The friendly crawler each `BotId` stands for, in the order the C
 * implementation walks them.
 */
typedef struct BotId BotId;

/**
 * The inspection identifiers that `waf_priority` can reorder.
 */
typedef struct CheckId CheckId;

/**
 * The four sources that can be configured with `waf_action`.
 */
typedef struct TriggerKind TriggerKind;

/**
 * `ngx_str_t` compatible string view: nginx declares the length first, so the
 * field order matters (see the layout assertion in the C glue).
 */
typedef struct ngx_waf_str_t {
    size_t len;
    const uint8_t *data;
} ngx_waf_str_t;

/**
 * The result of one inspection.
 */
typedef struct ngx_waf_step_t {
    uint32_t kind;
    uint32_t status;
    uint32_t content_type;
    int64_t retry_after;
    uint8_t *body;
    size_t body_len;
    uint8_t *log;
    size_t log_len;
    uint8_t *rule_type;
    size_t rule_type_len;
    uint8_t *rule_details;
    size_t rule_details_len;
    uint8_t blocked;
    uint8_t checked;
    uint8_t general_log;
    uint8_t register_content_handler;
    int64_t rate;
    double spend;
    /**
     * `Set-Cookie` values for a decision that mints them (captcha).
     */
    const struct ngx_waf_str_t *set_cookies;
    size_t set_cookie_count;
    /**
     * The `Location` header of a decision (the redirect of ModSecurity).
     */
    struct ngx_waf_str_t location;
    /**
     * `RESOLVE_ADDR`: the address to reverse resolve.
     */
    const uint8_t *ip;
    size_t ip_len;
    /**
     * `HTTP_REQUEST`: the request the C side has to perform.
     */
    struct ngx_waf_str_t url;
    struct ngx_waf_str_t http_body;
    int64_t timeout_ms;
} ngx_waf_step_t;

/**
 * One request header, the `ngx_table_elt_t` list of nginx.
 */
typedef struct ngx_waf_header_t {
    struct ngx_waf_str_t key;
    struct ngx_waf_str_t value;
} ngx_waf_header_t;

/**
 * The request view the C glue fills in.
 */
typedef struct ngx_waf_req_t {
    const uint8_t *ip;
    size_t ip_len;
    uint64_t method;
    struct ngx_waf_str_t uri;
    struct ngx_waf_str_t args;
    struct ngx_waf_str_t user_agent;
    struct ngx_waf_str_t referer;
    const struct ngx_waf_str_t *cookies;
    size_t cookie_count;
    struct ngx_waf_str_t body;
    uint8_t has_body;
    uint8_t internal;
    int64_t now;
    /**
     * The request headers, only `waf_modsecurity` reads them.
     */
    const struct ngx_waf_header_t *headers;
    size_t header_count;
    /**
     * The evaluated `waf_modsecurity_transaction_id`, its `data` is NULL when
     * the directive is not configured.
     */
    struct ngx_waf_str_t trans_id;
    /**
     * The rest of what ModSecurity reads.
     */
    struct ngx_waf_str_t unparsed_uri;
    struct ngx_waf_str_t method_name;
    struct ngx_waf_str_t http_version;
    struct ngx_waf_str_t client_addr;
    uint32_t client_port;
    struct ngx_waf_str_t server_addr;
    uint32_t server_port;
    /**
     * `r->connection->log`, the data of the ModSecurity log callback.
     */
    void *log;
} ngx_waf_req_t;

/**
 * The event that wakes a parked inspection up.
 */
typedef struct ngx_waf_event_t {
    uint32_t kind;
    /**
     * `RESOLVED_NAME`: the host name the address resolves to.
     */
    struct ngx_waf_str_t name;
    /**
     * `HTTP_RESPONSE`: the status code of the provider.
     */
    uint32_t status;
    /**
     * `HTTP_RESPONSE`: its body.
     */
    struct ngx_waf_str_t body;
} ngx_waf_event_t;

/**
 * Callbacks the C glue provides for one shared memory zone.
 */
typedef struct ngx_waf_shm_ops_t {
    void (*lock)(void*);
    void (*unlock)(void*);
    /**
     * Allocates from the zone, taking the zone lock.
     */
    void *(*alloc)(void*, size_t);
    /**
     * Allocates from the zone, the caller already holds the zone lock.
     */
    void *(*alloc_locked)(void*, size_t);
    /**
     * Opaque C pointer handed to every callback (the `ngx_slab_pool_t`).
     */
    void *ctx;
} ngx_waf_shm_ops_t;







const char *ngx_waf_version(void);

void ngx_waf_string_free(char *text);

void *ngx_waf_main_create(void);

void ngx_waf_main_free(void *main);

void *ngx_waf_conf_create(void);

void ngx_waf_conf_free(void *conf);

/**
 * The zone index the configuration uses for `waf_cc_deny`, or `-1`.
 */
int64_t ngx_waf_conf_cc_zone(void *conf);

/**
 * The zone index of the captcha action table, `-1` when there is none.
 */
int64_t ngx_waf_conf_action_zone(void *conf);

/**
 * The zone index of the captcha fail counters, `-1` when there is none.
 */
int64_t ngx_waf_conf_captcha_zone(void *conf);

/**
 * The `waf` value of the configuration: `-1` unset, 0 off, 1 on, 2 bypass.
 */
int64_t ngx_waf_conf_waf(void *conf);

/**
 * The `waf_modsecurity` value of the configuration: `-1` unset, 0 off, 1 on.
 * The C glue only packs the request headers when the inspection can run.
 */
int64_t ngx_waf_conf_modsecurity(void *conf);

/**
 * Apply one directive, returns NULL on success or an error message.
 */
char *ngx_waf_directive(void *main,
                        void *conf,
                        struct ngx_waf_str_t name,
                        const struct ngx_waf_str_t *args,
                        size_t nargs);

/**
 * Parse and validate `waf_zone`.  On success the returned name pointer stays
 * valid as long as the main configuration does.
 */
char *ngx_waf_zone_directive(void *main,
                             const struct ngx_waf_str_t *args,
                             size_t nargs,
                             const uint8_t **out_name,
                             size_t *out_name_len,
                             size_t *out_size);

/**
 * Merge a child configuration into its parent.
 */
char *ngx_waf_conf_merge(void *child, void *parent);

/**
 * Start the inspection of one request.  The returned handle is owned by the C
 * side and must be freed with `ngx_waf_step_free()` once the request is done,
 * which is also what keeps the machine of a parked request alive.
 */
struct ngx_waf_step_t *ngx_waf_check_begin(void *conf,
                                           const struct ngx_waf_req_t *req,
                                           void *cc_zone,
                                           void *action_zone,
                                           void *captcha_zone,
                                           int32_t http_transport);

/**
 * Feed the result of an asynchronous operation back into the machine, then
 * report the next step in the same handle.  Returns 0 on success.
 */
int32_t ngx_waf_check_resume(struct ngx_waf_step_t *step, const struct ngx_waf_event_t *event);

/**
 * Run the log phase of one request: the audit log of the ModSecurity
 * transaction, when the inspection created one.  nginx runs the log phase
 * before the request pool (and with it the machine) is released.
 */
void ngx_waf_check_log(struct ngx_waf_step_t *step);

void ngx_waf_step_free(struct ngx_waf_step_t *step);

/**
 * Initialise (or reuse after a reload) the Rust side state of a shared memory
 * zone.
 */
void *ngx_waf_shm_zone_init(void *addr,
                            size_t size,
                            void *old,
                            const struct ngx_waf_shm_ops_t *ops);

/**
 * Release a zone handle.  The shared memory itself belongs to nginx.
 */
void ngx_waf_shm_zone_free(void *handle);

/**
 * Sweep the expired counters of one zone.
 */
void ngx_waf_shm_zone_gc(void *handle);

/**
 * The probability check of `_gc()`, exposed so the C glue can gate the GC of
 * every zone of this worker.
 */
int32_t ngx_waf_should_gc(int64_t worker_processes);

/**
 * Garbage collect the per-worker inspection caches.
 */
void ngx_waf_gc(void *conf);

#endif  /* NGX_HTTP_WAF_FFI_H */
