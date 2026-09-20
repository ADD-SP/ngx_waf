/*
 * The configuration side of the module: the directives, the configuration
 * objects they build and the callbacks they hand to nginx.
 */

#include "ngx_http_waf_module.h"

static void ngx_http_waf_cleanup(void* data);


static void ngx_http_waf_conf_cleanup(void* data);


static void ngx_http_waf_zone_cleanup(void* data);


#if !(NGX_PCRE2)
/*
 * nginx and libmodsecurity share the same libpcre when nginx is built with
 * PCRE1, and the library allocates through the global `pcre_malloc`/
 * `pcre_free` while it parses rules.  Those allocations are routed to the
 * nginx pool of the configuration being read; the rule loading happens inside
 * the Rust core, this glue switches the callbacks around the `waf_modsecurity`
 * directive.
 */
extern void *(*pcre_malloc)(size_t);
extern void  (*pcre_free)(void *);

static ngx_pool_t  *ngx_http_waf_modsecurity_pcre_pool;
static void        *ngx_http_waf_modsecurity_pcre_malloc_old;
static void        *ngx_http_waf_modsecurity_pcre_free_old;
#endif

/**
 * Parse `api=<url>` of the `waf_captcha` directive.  The host is resolved once,
 * here, so that a request never has to block on DNS.
 */
static ngx_int_t ngx_http_waf_captcha_api(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf,
    ngx_str_t value)
{
    ngx_pool_cleanup_t* cln;
    ngx_url_t url;
    ngx_str_t rest = value;
    ngx_str_t ciphers;
    ngx_uint_t ssl = 0;

    /* The same directive is handled again only when it is repeated in one
     * context; parsing the same endpoint twice is wasted work. */
    if (conf->captcha_api.configured
        && conf->captcha_api.url.len == value.len
        && ngx_strncmp(conf->captcha_api.url.data, value.data, value.len) == 0)
    {
        return NGX_OK;
    }

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
     * of the enclosing context.
     */
    if (!url.naddrs) {
        (void) ngx_inet_resolve_host(cf->pool, &url);
    }

    if (ssl) {
        /*
         * A repeated `waf_captcha` of this context replaced the endpoint: the
         * SSL context of the previous one is released here, the pool cleanup
         * registered for the struct releases the one that takes its place.
         */
        if (conf->captcha_api.ssl.ctx != NULL) {
            ngx_ssl_cleanup_ctx(&conf->captcha_api.ssl);
        }

        ngx_memzero(&conf->captcha_api.ssl, sizeof(ngx_ssl_t));
        conf->captcha_api.ssl.log = cf->log;
        if (ngx_ssl_create(&conf->captcha_api.ssl, NGX_SSL_TLSv1_2, NULL) != NGX_OK) {
            /*
             * `ngx_ssl_create()` leaves a partially built context behind on
             * some of its failures; the cleanup that may already be
             * registered for this struct has to find none.
             */
            if (conf->captcha_api.ssl.ctx != NULL) {
                ngx_ssl_cleanup_ctx(&conf->captcha_api.ssl);
                ngx_memzero(&conf->captcha_api.ssl, sizeof(ngx_ssl_t));
            }
            return NGX_ERROR;
        }

        /*
         * `ngx_ssl_create()` only builds the context: the caller owns it and
         * hands it to a cleanup of the pool the configuration lives in, the
         * way the nginx modules do.  The cleanup is registered once per
         * context: a second one would `SSL_CTX_free()` the same context when
         * the configuration goes away.  The merge copies the context into the
         * contexts below, which never register a cleanup of their own.
         */
        if (!conf->captcha_api.ssl_cleanup_registered) {
            cln = ngx_pool_cleanup_add(cf->pool, 0);

            if (cln == NULL) {
                ngx_ssl_cleanup_ctx(&conf->captcha_api.ssl);
                ngx_memzero(&conf->captcha_api.ssl, sizeof(ngx_ssl_t));
                return NGX_ERROR;
            }

            cln->handler = ngx_ssl_cleanup_ctx;
            cln->data = &conf->captcha_api.ssl;
            conf->captcha_api.ssl_cleanup_registered = 1;
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

    /*
     * `SSL_set_tlsext_host_name()` is a macro that runs `strlen()` over the
     * name, and the core hands its endpoint over as a view without a
     * terminator: copy the host with one, it is what the ClientHello carries as
     * the server name.
     */
    conf->captcha_api.host.data = ngx_pnalloc(cf->pool, url.host.len + 1);
    if (conf->captcha_api.host.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(conf->captcha_api.host.data, url.host.data, url.host.len);
    conf->captcha_api.host.data[url.host.len] = '\0';
    conf->captcha_api.host.len = url.host.len;

    conf->captcha_api.uri = url.uri.len != 0 ? url.uri : (ngx_str_t) ngx_string("/");

    if (url.naddrs) {
        conf->captcha_api.sockaddr = url.addrs[0].sockaddr;
        conf->captcha_api.socklen = url.addrs[0].socklen;
        conf->captcha_api.resolved = 1;
    }

    conf->captcha_api.configured = 1;
    conf->captcha_api.url.data = ngx_pnalloc(cf->pool, value.len);
    if (conf->captcha_api.url.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(conf->captcha_api.url.data, value.data, value.len);
    conf->captcha_api.url.len = value.len;

    return NGX_OK;
}




#if !(NGX_PCRE2)
static void* ngx_http_waf_modsecurity_pcre_malloc(size_t size) {
    return ngx_palloc(ngx_http_waf_modsecurity_pcre_pool, size);
}


static void ngx_http_waf_modsecurity_pcre_free(void* ptr) {
    ngx_pfree(ngx_http_waf_modsecurity_pcre_pool, ptr);
}


/*
 * Point the allocator globals of libpcre at `pool` and return the pool they
 * were pointed at before, NULL when the callbacks were installed by this call
 * (and therefore have to be restored when the directive is done).
 */
static ngx_pool_t* ngx_http_waf_modsecurity_pcre_acquire(ngx_pool_t* pool) {
    ngx_pool_t* old_pool;

    if (pcre_malloc != ngx_http_waf_modsecurity_pcre_malloc) {
        ngx_http_waf_modsecurity_pcre_pool = pool;

        ngx_http_waf_modsecurity_pcre_malloc_old = (void*) pcre_malloc;
        ngx_http_waf_modsecurity_pcre_free_old = (void*) pcre_free;

        pcre_malloc = ngx_http_waf_modsecurity_pcre_malloc;
        pcre_free = ngx_http_waf_modsecurity_pcre_free;

        return NULL;
    }

    old_pool = ngx_http_waf_modsecurity_pcre_pool;
    ngx_http_waf_modsecurity_pcre_pool = pool;

    return old_pool;
}


static void ngx_http_waf_modsecurity_pcre_release(ngx_pool_t* old_pool) {
    ngx_http_waf_modsecurity_pcre_pool = old_pool;

    if (old_pool == NULL) {
        pcre_malloc = (void* (*)(size_t)) ngx_http_waf_modsecurity_pcre_malloc_old;
        pcre_free = (void (*)(void*)) ngx_http_waf_modsecurity_pcre_free_old;
    }
}
#endif

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


char *ngx_http_waf_zone_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_main_conf_t* mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);
    ngx_str_t* elts = cf->args->elts;
    const uint8_t* name_data = NULL;
    size_t name_len = 0;
    size_t size = 0;
    ngx_http_waf_zone_t* zone = NULL;
    ngx_http_waf_zone_t** slot = NULL;

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

    /*
     * The zone entry lives in the pool and only its pointer goes into the
     * array: the array is grown by a later `waf_zone` (it starts with room for
     * four), and the shared memory zone keeps the entry it was handed, so a
     * reallocated array would leave every reader with a stale copy.
     */
    zone = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_zone_t));
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

    slot = ngx_array_push(mcf->zones);
    if (slot == NULL) {
        return ngx_http_waf_report(cf, NULL);
    }
    *slot = zone;

    zone->zone = ngx_shared_memory_add(cf, &zone->name, size, &ngx_http_waf_module);
    if (zone->zone == NULL) {
        return ngx_http_waf_report(cf, NULL);
    }

    zone->zone->init = ngx_http_waf_shm_zone_init;
    zone->zone->data = zone;

    /* the handle the init callback builds belongs to this cycle */
    ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return ngx_http_waf_report(cf, NULL);
    }
    cln->handler = ngx_http_waf_zone_cleanup;
    cln->data = zone;

    return NGX_CONF_OK;
}


/*
 * The regex engine of the rules.  Every rule of `waf_rule_path` is compiled
 * with `ngx_regex_compile()` and matched with `ngx_regex_exec()`, so a rule
 * file may use the whole PCRE syntax; the core uses these two callbacks for the
 * same engine instead of a regex library of its own.  They are handed to the
 * core with the directive that needs them, and `ctx` is the pool the compiled
 * patterns live in.
 */
static void* ngx_http_waf_regex_compile(void* ctx, const uint8_t* pattern, size_t len) {
    ngx_regex_compile_t  rc;
    u_char               errstr[NGX_MAX_CONF_ERRSTR];
    ngx_pool_t*          pool = ctx;
    u_char*              terminated;

    /*
     * The core hands the pattern over as a slice of a rule file, and the
     * engine of nginx expects a NUL terminated string with PCRE1 (its
     * `ngx_regex_compile()` passes `rc.pattern.data` to `pcre_compile()`,
     * which has no length): without the copy PCRE1 reads whatever follows the
     * pattern in the file, and a rule is refused, or compiled with the bytes
     * behind it.  The copy lives in the configuration pool, which is also the
     * lifetime `ngx_regex_studies` keeps for its name.
     */
    terminated = ngx_pnalloc(pool, len + 1);
    if (terminated == NULL) {
        return NULL;
    }
    ngx_memcpy(terminated, pattern, len);
    terminated[len] = '\0';

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern.data = terminated;
    rc.pattern.len = len;
    rc.pool = pool;
    rc.options = 0;
    rc.err.data = errstr;
    rc.err.len = NGX_MAX_CONF_ERRSTR;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        /* `rc.err` carries the reason of the engine, the core only sees that
         * the pattern was refused. */
        ngx_log_error(NGX_LOG_EMERG, pool->log, 0, "%V", &rc.err);
        return NULL;
    }

    return rc.regex;
}


static ptrdiff_t ngx_http_waf_regex_exec(void* regex, const uint8_t* value, size_t len) {
    ngx_str_t subject;
    ngx_int_t rc;

    subject.data = (u_char*) value;
    subject.len = len;

    rc = ngx_regex_exec((ngx_regex_t*) regex, &subject, NULL, 0);

    if (rc == NGX_REGEX_NO_MATCHED) {
        return 0;
    }

    return rc < 0 ? -1 : 1;
}


/*
 * Call one directive of the core.  With PCRE1 the allocator globals of libpcre
 * point at the pool of the configuration for the call: libmodsecurity parses
 * the rules while a `waf_modsecurity` directive is handled and allocates
 * through them.  Taking the hooks and giving them back inside this one
 * function is what keeps the pair together: a handler that returns early, or
 * throws, cannot leave libpcre with the allocator of a pool the cycle
 * destroys.  PCRE2 has no such globals, the helper is the plain call then.
 */
static char* ngx_http_waf_directive_call(ngx_conf_t* cf, ngx_command_t* cmd,
    ngx_waf_main_t* main, ngx_waf_conf_t* conf, ngx_waf_str_t name,
    const ngx_waf_str_t* args, size_t nargs, ngx_waf_regex_ops_t* regex_ops)
{
#if !(NGX_PCRE2)
    ngx_pool_t* old_pcre_pool = NULL;

    if (ngx_strcmp(cmd->name.data, "waf_modsecurity") == 0) {
        old_pcre_pool = ngx_http_waf_modsecurity_pcre_acquire(cf->pool);
    }

    char* error = ngx_waf_directive(main, conf, name, args, nargs, regex_ops);

    if (ngx_strcmp(cmd->name.data, "waf_modsecurity") == 0) {
        ngx_http_waf_modsecurity_pcre_release(old_pcre_pool);
    }

    return error;
#else
    return ngx_waf_directive(main, conf, name, args, nargs, regex_ops);
#endif
}


char *ngx_http_waf_directive_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_main_conf_t* mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* elts = cf->args->elts;
    ngx_str_t expanded;
    ngx_waf_regex_ops_t regex_ops;
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

    regex_ops.compile = ngx_http_waf_regex_compile;
    regex_ops.exec = ngx_http_waf_regex_exec;
    regex_ops.ctx = cf->pool;

    char* error = ngx_http_waf_directive_call(cf, cmd, mcf->core, loc_conf->core,
        *(const ngx_waf_str_t*)(elts), args, nargs, &regex_ops);

    if (error != NULL) {
        return ngx_http_waf_report(cf, error);
    }

    /*
     * Problems that are only logged, e.g. an address block that is already
     * covered by one read before it: nginx keeps the configuration and the
     * block is dropped.
     */
    for ( ;; ) {
        char* warning = ngx_waf_conf_take_warning(loc_conf->core);

        if (warning == NULL) {
            break;
        }

        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "%s", warning);
        ngx_waf_string_free(warning);
    }

    /*
     * The provider endpoint is the URL the core will ask for: the `api=` of
     * this directive, or the default endpoint of the provider it named.  Ask
     * the core instead of scanning the argument here, a location that inherits
     * `waf_captcha` never saw an `api=` of its own (it inherits this endpoint
     * through the configuration merge).
     */
    if (ngx_strcmp(cmd->name.data, "waf_captcha") == 0) {
        ngx_waf_str_t api = ngx_waf_conf_captcha_api(loc_conf->core);

        if (api.len != 0) {
            ngx_str_t value;

            value.data = (u_char*) api.data;
            value.len = api.len;

            if (ngx_http_waf_captcha_api(cf, loc_conf, value) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    return NGX_CONF_OK;
}


char *ngx_http_waf_modsecurity_transaction_id_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
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


void *ngx_http_waf_create_main_conf(ngx_conf_t* cf) {
    ngx_http_waf_main_conf_t* mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_main_conf_t));

    if (mcf == NULL) {
        return NULL;
    }

    mcf->core = ngx_waf_main_create();
    if (mcf->core == NULL) {
        return NULL;
    }

    /* the array holds pointers, the entries themselves live in the pool */
    mcf->zones = ngx_array_create(cf->pool, 4, sizeof(ngx_http_waf_zone_t *));
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


void *ngx_http_waf_create_loc_conf(ngx_conf_t* cf) {
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


char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf) {
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

    /*
     * A location that does not configure `waf_captcha` itself uses the one of
     * the context above, and with it the endpoint that was parsed there.  The
     * `ngx_ssl_t` inside is shared, the cleanup of the configuration pool
     * releases it at the end of the cycle.
     */
    if (!child->captcha_api.configured && parent->captcha_api.configured) {
        child->captcha_api = parent->captcha_api;
    }

    return NGX_CONF_OK;
}



static void ngx_http_waf_cleanup(void* data) {
    ngx_waf_main_free(data);
}


static void ngx_http_waf_conf_cleanup(void* data) {
    ngx_waf_conf_free(data);
}


/**
 * Release the core side handle of one shared memory zone with the cycle it was
 * built in.  The segment itself belongs to nginx; on a reload the new cycle
 * builds its own handle on top of the same segment.
 */
static void ngx_http_waf_zone_cleanup(void* data) {
    ngx_http_waf_zone_t* zone = data;

    if (zone->handle != NULL) {
        ngx_waf_shm_zone_free(zone->handle);
        zone->handle = NULL;
    }
}
