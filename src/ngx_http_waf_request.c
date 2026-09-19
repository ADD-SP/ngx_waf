/*
 * The request path of the module: the phases, the request data the core
 * reads, the state machine that drives it and the response it produces.
 */

#include "ngx_http_waf_module.h"

static ngx_int_t ngx_http_waf_run(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);


static ngx_int_t ngx_http_waf_drive(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);


static ngx_int_t ngx_http_waf_apply(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);


static ngx_int_t ngx_http_waf_start_resolve(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);


static void ngx_http_waf_resolve_handler(ngx_resolver_ctx_t* rc);


static ngx_int_t ngx_http_waf_handler_precontent_phase(ngx_http_request_t* r);


static ngx_int_t ngx_http_waf_gen_response(ngx_http_request_t* r, uint8_t* body, size_t body_len,
    ngx_waf_content_type content_type, uint32_t status);


static void ngx_http_waf_add_no_cache_header(ngx_http_request_t* r);


static void ngx_http_waf_add_retry_after_header(ngx_http_request_t* r, int64_t seconds);


static ngx_int_t ngx_http_waf_read_body(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx);


static void ngx_http_waf_read_body_handler(ngx_http_request_t* r);


static void ngx_http_waf_request_cleanup(void* data);


static void ngx_http_waf_free_check(void* data);


/*
 * The `Location` header of a ModSecurity redirect.  `hash` stays 0: nginx
 * turns `r->headers_out.location` into the header and the body of a 3xx
 * response itself (see `ngx_http_special_response_handler()`).
 */
static void ngx_http_waf_add_location(ngx_http_request_t* r, const ngx_waf_step_t* step) {
    ngx_table_elt_t* location;

    if (step->decision.location.len == 0 || step->decision.location.data == NULL) {
        return;
    }

    ngx_http_clear_location(r);

    location = ngx_list_push(&r->headers_out.headers);
    if (location == NULL) {
        return;
    }

    r->headers_out.location = location;
    ngx_str_set(&location->key, "Location");
    location->lowcase_key = (u_char*)"location";
    location->value.data = (u_char*) step->decision.location.data;
    location->value.len = step->decision.location.len;
    location->hash = 0;
}


/**
 * Write the `Set-Cookie` headers a decision minted (the captcha flow).
 */
static void ngx_http_waf_add_set_cookies(ngx_http_request_t* r, const ngx_waf_step_t* step) {
    size_t i;

    for (i = 0; i < step->decision.set_cookie_count; i++) {
        ngx_table_elt_t* header = ngx_list_push(&r->headers_out.headers);
        const ngx_waf_str_t* cookie = &step->decision.set_cookies[i];

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


ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r) {
    ngx_http_waf_loc_conf_t* conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_http_waf_ctx_t* ctx;
    ngx_int_t rc;

    if (conf == NULL || conf->core == NULL) {
        return NGX_DECLINED;
    }

    if (!ngx_waf_conf_enabled(conf->core)) {
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
        pool_cln->handler = ngx_http_waf_free_check;
        pool_cln->data = ctx;
    }

    /*
     * `error_page` internally redirects the request and nginx drops every
     * module context on the way; be sure the context is reachable again for
     * the rest of this request.
     */
    ngx_http_set_ctx(r, ctx, ngx_http_waf_module);

    if (ctx->step != NULL) {
        if (ctx->applied) {
            /*
             * The decision was carried out already and the phases are running
             * again: nginx re-enters them for a postponed request (the body of
             * a POST arrived, the provider answered) and after an internal
             * redirect (`error_page`, ...).  Answer nothing a second time - an
             * `error_page` would skip the page it is supposed to produce - but
             * put the content handler of a decision that has a body back in
             * place, `ngx_http_update_location_config()` resets it to the
             * handler of the location at the start of every pass.
             */
            if (ctx->step->decision.register_content_handler) {
                r->content_handler = ngx_http_waf_handler_precontent_phase;
            }

            return NGX_DECLINED;
        }

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


static void ngx_http_waf_free_check(void* data) {
    ngx_http_waf_ctx_t* ctx = data;

    if (ctx->check != NULL) {
        ngx_waf_check_free(ctx->check);
        ctx->check = NULL;
        ctx->step = NULL;
    }
}


/*
 * The request headers libmodsecurity inspects, as the `ngx_table_elt_t` list
 * nginx parsed them.  Only `waf_modsecurity` needs them, the other inspections
 * read the few headers they care about from the request view.
 */
static ngx_int_t ngx_http_waf_make_headers(ngx_http_request_t* r, ngx_array_t** headers) {
    ngx_list_part_t* part;
    ngx_table_elt_t* header;
    ngx_uint_t i;
    ngx_waf_header_t* item;

    *headers = ngx_array_create(r->pool, r->headers_in.headers.nalloc,
        sizeof(ngx_waf_header_t));
    if (*headers == NULL) {
        return NGX_ERROR;
    }

    for (part = &r->headers_in.headers.part; part != NULL; part = part->next) {
        header = part->elts;

        for (i = 0; i < part->nelts; i++) {
            item = ngx_array_push(*headers);
            if (item == NULL) {
                return NGX_ERROR;
            }

            item->key.data = header[i].key.data;
            item->key.len = header[i].key.len;
            item->value.data = header[i].value.data;
            item->value.len = header[i].value.len;
        }
    }

    return NGX_OK;
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

    /*
     * A body above `client_body_buffer_size` is written to a temporary file by
     * nginx: the chain holds one buffer whose bytes are in the file instead of
     * in memory.  Reading it back is what keeps the inspections that look at
     * the body (the POST list, ModSecurity) effective for larger requests; the
     * size is bounded by `client_max_body_size`, which nginx enforces before
     * the access phase runs.
     */
    if (r->request_body->bufs->buf->in_file) {
        ngx_buf_t* b = r->request_body->bufs->buf;
        off_t size = b->file_last - b->file_pos;

        if (size <= 0) {
            return NGX_OK;
        }

        data = ngx_pnalloc(r->pool, size);
        if (data == NULL) {
            return NGX_ERROR;
        }

        if (ngx_read_file(b->file, data, size, b->file_pos) != (ssize_t) size) {
            return NGX_ERROR;
        }

        body->data = data;
        body->len = size;

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


/*
 * One `Cookie` header for the core: the raw header value, one view per header,
 * with the bytes nginx keeps for the whole request.  The core parses the pairs
 * and builds the text the rule list matches.
 */
static ngx_waf_str_t* ngx_http_waf_push_cookie(ngx_array_t* cookies, ngx_str_t* value) {
    ngx_waf_str_t* item = ngx_array_push(cookies);

    if (item == NULL) {
        return NULL;
    }

    item->data = value->data;
    item->len = value->len;

    return item;
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
        if (ngx_http_waf_push_cookie(*cookies, &p->value) == NULL) {
            return NGX_ERROR;
        }
    }
#else
    if (r->headers_in.cookies.nelts == 0) {
        return NGX_OK;
    }

    {
        ngx_table_elt_t** pp = r->headers_in.cookies.elts;
        ngx_uint_t i;

        for (i = 0; i < r->headers_in.cookies.nelts; i++, pp++) {
            if (ngx_http_waf_push_cookie(*cookies, &(*pp)->value) == NULL) {
                return NGX_ERROR;
            }
        }
    }
#endif

    return NGX_OK;
}


/*
 * The method of the request.  nginx spells the known methods as bits, the ABI
 * of the core spells them as an enum; the mapping belongs to the glue.
 */
static ngx_waf_method ngx_http_waf_method(ngx_uint_t method) {
    switch (method) {
    case NGX_HTTP_GET:
        return NGX_WAF_METHOD_GET;
    case NGX_HTTP_HEAD:
        return NGX_WAF_METHOD_HEAD;
    case NGX_HTTP_POST:
        return NGX_WAF_METHOD_POST;
    case NGX_HTTP_PUT:
        return NGX_WAF_METHOD_PUT;
    case NGX_HTTP_DELETE:
        return NGX_WAF_METHOD_DELETE;
    case NGX_HTTP_MKCOL:
        return NGX_WAF_METHOD_MKCOL;
    case NGX_HTTP_COPY:
        return NGX_WAF_METHOD_COPY;
    case NGX_HTTP_MOVE:
        return NGX_WAF_METHOD_MOVE;
    case NGX_HTTP_OPTIONS:
        return NGX_WAF_METHOD_OPTIONS;
    case NGX_HTTP_PROPFIND:
        return NGX_WAF_METHOD_PROPFIND;
    case NGX_HTTP_PROPPATCH:
        return NGX_WAF_METHOD_PROPPATCH;
    case NGX_HTTP_LOCK:
        return NGX_WAF_METHOD_LOCK;
    case NGX_HTTP_UNLOCK:
        return NGX_WAF_METHOD_UNLOCK;
    case NGX_HTTP_PATCH:
        return NGX_WAF_METHOD_PATCH;
    case NGX_HTTP_TRACE:
        return NGX_WAF_METHOD_TRACE;
    default:
        return NGX_WAF_METHOD_UNKNOWN;
    }
}


/*
 * The protocol version of the request, the strings libmodsecurity reads are
 * built by the core.
 */
static ngx_waf_http_version ngx_http_waf_http_version(ngx_uint_t version) {
    switch (version) {
    case NGX_HTTP_VERSION_9:
        return NGX_WAF_HTTP_VERSION_HTTP09;
    case NGX_HTTP_VERSION_10:
        return NGX_WAF_HTTP_VERSION_HTTP10;
#if (defined(nginx_version) && nginx_version >= 1009005)
    case NGX_HTTP_VERSION_11:
        return NGX_WAF_HTTP_VERSION_HTTP11;
#endif
    case NGX_HTTP_VERSION_20:
        return NGX_WAF_HTTP_VERSION_HTTP20;
    default:
        return NGX_WAF_HTTP_VERSION_UNKNOWN;
    }
}


static ngx_int_t ngx_http_waf_run(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx) {
    ngx_http_waf_loc_conf_t* conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_http_waf_main_conf_t* mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    ngx_waf_req_t req;
    ngx_waf_modsec_req_t modsec;
    ngx_waf_zone_refs_t zone_refs;
    ngx_waf_zone_handles_t zone_handles;
    ngx_waf_check_t* check;
    ngx_array_t* cookies = NULL;
    ngx_array_t* headers = NULL;
    ngx_waf_str_t body;

    ngx_memzero(&req, sizeof(ngx_waf_req_t));

    /* A body this module cannot read (or could not allocate) is not a body it
     * may skip: the POST list and ModSecurity have to see it, so the request
     * is refused instead of being served uninspected. */
    if (ngx_http_waf_make_body(r, &body) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (ngx_http_waf_make_cookies(r, &cookies) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

#if (NGX_HAVE_INET6)
    if (r->connection->sockaddr->sa_family == AF_INET6) {
        req.ip.data =
            (const uint8_t *) &((struct sockaddr_in6 *) r->connection->sockaddr)->sin6_addr;
        req.ip.len = 16;
    } else
#endif
    if (r->connection->sockaddr->sa_family == AF_INET) {
        req.ip.data =
            (const uint8_t *) &((struct sockaddr_in *) r->connection->sockaddr)->sin_addr;
        req.ip.len = 4;
    } else {
        /*
         * A unix domain connection has no address: the IP lists, the CC
         * counters and the captcha tables see nothing to match on (the C
         * implementation read whatever the memory of another family held).
         */
        req.ip.data = NULL;
        req.ip.len = 0;
    }

    req.method = ngx_http_waf_method(r->method);
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
    req.now = ngx_time();
    /* where the core reports an internal error, and where ModSecurity logs */
    req.log = r->connection->log;

    /*
     * Everything libmodsecurity reads beyond the common request view.  It is
     * packed only when the inspection can run, a configuration without
     * `waf_modsecurity` must not pay for it.
     */
    if (ngx_waf_conf_modsecurity_enabled(conf->core)) {
        ngx_memzero(&modsec, sizeof(ngx_waf_modsec_req_t));

        if (ngx_http_waf_make_headers(r, &headers) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        modsec.headers = (const ngx_waf_header_t*) headers->elts;
        modsec.header_count = headers->nelts;

        if (conf->modsecurity_transaction_id != NULL) {
            ngx_str_t transaction_id;

            ngx_str_null(&transaction_id);
            if (ngx_http_complex_value(r, conf->modsecurity_transaction_id,
                                       &transaction_id) != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            modsec.has_trans_id = 1;
            modsec.trans_id.data = transaction_id.data;
            modsec.trans_id.len = transaction_id.len;
        }

        modsec.unparsed_uri.data = r->unparsed_uri.data;
        modsec.unparsed_uri.len = r->unparsed_uri.len;
        modsec.method_name.data = r->method_name.data;
        modsec.method_name.len = r->method_name.len;
        modsec.http_version = ngx_http_waf_http_version(r->http_version);
        modsec.client_addr.data = r->connection->addr_text.data;
        modsec.client_addr.len = r->connection->addr_text.len;
        modsec.client_port = ngx_inet_get_port(r->connection->sockaddr);

        {
            /*
             * The address the local end of the connection was bound to.  The
             * buffer belongs to the request pool: the Rust side may read it
             * again after an asynchronous step.
             */
            u_char* server_addr = ngx_pnalloc(r->pool, NGX_SOCKADDR_STRLEN);
            ngx_str_t server_addr_str;

            if (server_addr == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            server_addr_str.len = NGX_SOCKADDR_STRLEN;
            server_addr_str.data = server_addr;
            if (ngx_connection_local_sockaddr(r->connection, &server_addr_str, 0)
                != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            modsec.server_addr.data = server_addr_str.data;
            modsec.server_addr.len = server_addr_str.len;
            modsec.server_port = ngx_inet_get_port(r->connection->local_sockaddr);
        }

        req.modsec = &modsec;
    }

    zone_refs = ngx_waf_conf_zone_refs(conf->core);
    zone_handles.cc = ngx_http_waf_zone_handle(mcf, zone_refs.cc);
    zone_handles.captcha = ngx_http_waf_zone_handle(mcf, zone_refs.captcha);
    zone_handles.action = ngx_http_waf_zone_handle(mcf, zone_refs.action);

    check = ngx_waf_check_begin(
        conf->core,
        &req,
        zone_handles,
        /* The captcha provider request is performed by this module. */
        1);
    if (check == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->check = check;
    ctx->step = ngx_waf_check_step(check);
    ctx->applied = 0;
    ctx->general_logged = 0;

    return ngx_http_waf_drive(r, ctx);
}


/**
 * Run the machine as far as the current step allows: apply a decision, or start
 * the asynchronous operation the step asks for and park the request.
 */
static ngx_int_t ngx_http_waf_drive(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx) {
    for ( ;; ) {
        const ngx_waf_step_t* step = ctx->step;

        if (step == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        switch (step->kind) {
        case NGX_WAF_STEP_KIND_RESOLVE_ADDR: {
            ngx_int_t rc = ngx_http_waf_start_resolve(r, ctx);

            if (rc == NGX_DONE) {
                return rc;
            }

            /* the resolver answered from its cache, keep driving */
            continue;
        }

        case NGX_WAF_STEP_KIND_HTTP_REQUEST: {
            ngx_int_t rc = ngx_http_waf_start_http(r, ctx);

            if (rc == NGX_DONE) {
                return rc;
            }

            /* the provider request failed at once, the machine decided */
            continue;
        }

        case NGX_WAF_STEP_KIND_ALLOW:
        case NGX_WAF_STEP_KIND_RESPONSE:
        case NGX_WAF_STEP_KIND_INTERNAL_ERROR:
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
    const ngx_waf_step_t* step = ctx->step;

    if (step == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!ctx->applied) {
        if (step->decision.has_retry_after && step->decision.status != NGX_HTTP_CLOSE) {
            ngx_http_waf_add_retry_after_header(r, step->decision.retry_after);
        }
        ngx_http_waf_add_set_cookies(r, step);
        ngx_http_waf_add_location(r, step);
        ctx->applied = 1;
    }

    if (step->decision.register_content_handler) {
        r->content_handler = ngx_http_waf_handler_precontent_phase;
        return NGX_DECLINED;
    }

    switch (step->kind) {
    case NGX_WAF_STEP_KIND_ALLOW:
        return NGX_DECLINED;

    case NGX_WAF_STEP_KIND_RESPONSE:
        return (ngx_int_t) step->decision.status;

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

    if (clcf->resolver == NULL || ctx->step->pending.ip.data == NULL
        || ctx->step->pending.ip.len == 0)
    {
        /* No resolver: the crawler cannot be verified, which is reported as a
         * failed lookup. */
        ngx_memzero(&event, sizeof(ngx_waf_event_t));
        event.kind = NGX_WAF_EVENT_KIND_RESOLVE_FAILED;
        ngx_http_waf_resume(r, ctx, &event);
        return ngx_http_waf_drive(r, ctx);
    }

    rc = ngx_resolve_start(clcf->resolver, NULL);
    if (rc == NULL || rc == NGX_NO_RESOLVER) {
        ngx_memzero(&event, sizeof(ngx_waf_event_t));
        event.kind = NGX_WAF_EVENT_KIND_RESOLVE_FAILED;
        ngx_http_waf_resume(r, ctx, &event);
        return ngx_http_waf_drive(r, ctx);
    }

    rc->addr.sockaddr = r->connection->sockaddr;
    rc->addr.socklen = r->connection->socklen;
    rc->handler = ngx_http_waf_resolve_handler;
    rc->data = r;
    rc->timeout = clcf->resolver_timeout;

    ctx->resolver_inline = 0;

    if (ngx_resolve_addr(rc) != NGX_OK) {
        ngx_resolve_addr_done(rc);
        ngx_memzero(&event, sizeof(ngx_waf_event_t));
        event.kind = NGX_WAF_EVENT_KIND_RESOLVE_FAILED;
        ngx_http_waf_resume(r, ctx, &event);
        return ngx_http_waf_drive(r, ctx);
    }

    if (ctx->resolver_inline) {
        /*
         * The lookup was answered from the cache of the resolver, inside the
         * call that started it: the handler resumed the machine already, the
         * drive loop keeps going in the caller.
         */
        ctx->resolver_inline = 0;
        return NGX_OK;
    }

    /* The request must survive until the resolver answers. */
    r->main->count++;

    return NGX_DONE;
}


static void ngx_http_waf_resolve_handler(ngx_resolver_ctx_t* rc) {
    ngx_http_request_t* r = rc->data;
    ngx_http_waf_ctx_t* ctx = ngx_http_waf_get_ctx(r);
    ngx_waf_event_t event;
    ngx_uint_t inline_answer = (rc->async == 0);

    ngx_memzero(&event, sizeof(ngx_waf_event_t));

    if (ctx == NULL || ctx->step == NULL) {
        ngx_resolve_addr_done(rc);
        return;
    }

    if (rc->state == NGX_OK && rc->name.len != 0) {
        event.kind = NGX_WAF_EVENT_KIND_RESOLVED_NAME;
        event.name.data = rc->name.data;
        event.name.len = rc->name.len;
    } else {
        event.kind = NGX_WAF_EVENT_KIND_RESOLVE_FAILED;
    }

    ngx_resolve_addr_done(rc);

    ngx_http_waf_resume(r, ctx, &event);

    if (inline_answer) {
        /*
         * The machine advanced while the drive loop is on the stack; that
         * loop, and not this handler, carries on.
         */
        ctx->resolver_inline = 1;
        return;
    }

    ngx_http_finalize_request(r, NGX_DONE);
    ngx_http_core_run_phases(r);
}


/**
 * Hand the result of an asynchronous operation back to the core and let it
 * advance to the next decision or request.
 */
void ngx_http_waf_resume(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx, ngx_waf_event_t* event) {
    if (ctx->check == NULL) {
        return;
    }
    ngx_waf_check_resume(ctx->check, event);
    ctx->step = ngx_waf_check_step(ctx->check);
    ctx->applied = 0;
}


static ngx_int_t ngx_http_waf_handler_precontent_phase(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    const ngx_waf_step_t* step;

    if (ctx == NULL || ctx->step == NULL) {
        return NGX_DECLINED;
    }

    step = ctx->step;

    if (step->kind != NGX_WAF_STEP_KIND_RESPONSE) {
        return NGX_DECLINED;
    }

    return ngx_http_waf_gen_response(r, (uint8_t*) step->decision.body.data,
        step->decision.body.len, step->decision.content_type, step->decision.status);
}


static ngx_int_t ngx_http_waf_gen_response(ngx_http_request_t* r, uint8_t* body, size_t body_len,
    ngx_waf_content_type content_type, uint32_t status)
{
    ngx_int_t rc;
    ngx_buf_t* buf;
    ngx_chain_t* out;
    ngx_str_t type;

    if (content_type == NGX_WAF_CONTENT_TYPE_TEXT) {
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


ngx_int_t ngx_http_waf_handler_log_phase(ngx_http_request_t* r) {
    ngx_http_waf_loc_conf_t* conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_http_waf_main_conf_t* mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_core_conf_t* ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);

    if (conf == NULL || conf->core == NULL) {
        return NGX_DECLINED;
    }

    if (!ngx_waf_conf_enabled(conf->core)) {
        return NGX_DECLINED;
    }

    if (ngx_waf_should_gc(ccf != NULL ? (uint32_t) ccf->worker_processes : 1)) {
        ngx_waf_gc(conf->core);

        if (mcf != NULL && mcf->zones != NULL) {
            ngx_http_waf_zone_t** zones = mcf->zones->elts;
            ngx_uint_t i;

            for (i = 0; i < mcf->zones->nelts; i++) {
                if (zones[i]->handle != NULL) {
                    ngx_waf_shm_zone_gc(zones[i]->handle);
                }
            }
        }
    }

    if (ctx == NULL || ctx->step == NULL) {
        return NGX_OK;
    }

    /* The audit log of the ModSecurity transaction, when the inspection ran. */
    ngx_waf_check_log(ctx->check);

    if (!ctx->general_logged && ctx->step->decision.general_log
        && ctx->step->decision.log.data != NULL)
    {
        ngx_str_t message;
        message.data = (u_char*) ctx->step->decision.log.data;
        message.len = ctx->step->decision.log.len;
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "%V", &message);
        /* an internal redirect must not log the same decision twice */
        ctx->general_logged = 1;
    }

    return NGX_OK;
}


ngx_http_waf_ctx_t *ngx_http_waf_get_ctx(ngx_http_request_t* r) {
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

