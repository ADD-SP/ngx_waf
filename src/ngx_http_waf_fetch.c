/*
 * The client that reaches the captcha provider: a non blocking request
 * built on the event loop and the TLS machinery of nginx.
 */

#include "ngx_http_waf_module.h"

static void ngx_http_waf_fetch_read(ngx_event_t* rev);


static void ngx_http_waf_fetch_write(ngx_event_t* wev);


static void ngx_http_waf_fetch_resolved(ngx_resolver_ctx_t* rc);


static ngx_int_t ngx_http_waf_fetch_connect(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx,
    struct sockaddr* sockaddr, socklen_t socklen);


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

    ngx_memzero(&event, sizeof(ngx_waf_event_t));
    event.kind = NGX_WAF_EVENT_KIND_HTTP_FAILED;

    ngx_http_waf_resume(r, ctx, &event);

    ngx_http_waf_fetch_settle(ctx);
    ngx_http_waf_fetch_wake(r, ctx);
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

    /*
     * nginx calls this handler when the handshake timed out or failed as well,
     * and then `c->send` is still the raw socket: sending the request would put
     * the token and the secret on the wire in clear text, and the TLS bytes the
     * peer sends back would be parsed as an answer.
     */
    if (c->ssl == NULL || !c->ssl->handshaked || c->timedout || c->error) {
        ngx_http_waf_fetch_failed(r, ctx);
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
        ngx_http_waf_fetch_failed(r, ctx);
        return;
    }

    b = ctx->fetch.response;

    for ( ;; ) {
        n = c->recv(c, b->last, b->end - b->last);

        if (n > 0) {
            b->last += n;

            if (b->last == b->end) {
                /* a provider answer bigger than the buffer is not one we can use */
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
                ngx_http_waf_fetch_failed(r, ctx);
            }
            return;
        }

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
        ngx_http_waf_fetch_failed(r, ctx);
        return;
    }

    if (ngx_http_waf_fetch_connect_test(c) != NGX_OK) {
        ngx_http_waf_fetch_failed(r, ctx);
        return;
    }

    if (ctx->fetch.use_ssl && !ctx->fetch.handshake_done) {
        rc = ngx_ssl_handshake(c);

        if (rc == NGX_AGAIN) {
            ngx_add_timer(c->write, NGX_HTTP_WAF_FETCH_TIMEOUT);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK
                || ngx_handle_write_event(c->write, 0) != NGX_OK)
            {
                ngx_http_waf_fetch_failed(r, ctx);
            }
            return;
        }

        if (rc != NGX_OK) {
            ngx_http_waf_fetch_failed(r, ctx);
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
                ngx_http_waf_fetch_failed(r, ctx);
            }
            return;
        }

        ngx_http_waf_fetch_failed(r, ctx);
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
 * Move the provider request to the address the endpoint already has: the one
 * `api=` resolved while the configuration was read, or the one the resolver of
 * the enclosing context answered with earlier in this request.  `NGX_AGAIN`
 * says the host of the endpoint still has to be looked up.
 */
static ngx_int_t ngx_http_waf_start_http_peer(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx,
    ngx_http_waf_loc_conf_t* conf)
{
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

    if (conf->captcha_api.resolved) {
        return ngx_http_waf_fetch_connect(r, ctx, conf->captcha_api.sockaddr,
                                          conf->captcha_api.socklen);
    }

    return NGX_AGAIN;
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

    if (conf == NULL || !conf->captcha_api.configured) {
        /*
         * `waf_captcha` prepares the endpoint while the configuration is read,
         * so this only happens when a request reaches the provider without a
         * captcha configuration at all.
         */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_waf: the captcha provider endpoint is not configured");
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
        len = conf->captcha_api.uri.len + conf->captcha_api.host.len
            + step->pending.body.len + 512;
        b = ngx_create_temp_buf(r->pool, len);
        if (b == NULL) {
            ngx_http_waf_fetch_failed(r, ctx);
            ctx->fetch.in_drive = 0;
            return NGX_OK;
        }

        p = b->last;
        p = ngx_sprintf(p, "POST %V HTTP/1.0" CRLF, &conf->captcha_api.uri);
        p = ngx_sprintf(p, "Host: %V" CRLF, &conf->captcha_api.host);
        p = ngx_sprintf(p, "Content-Type: application/x-www-form-urlencoded" CRLF);
        p = ngx_sprintf(p, "Content-Length: %uz" CRLF, step->pending.body.len);
        p = ngx_sprintf(p, "Connection: close" CRLF CRLF);
        if (step->pending.body.len != 0) {
            p = ngx_cpymem(p, step->pending.body.data, step->pending.body.len);
        }
        b->last = p;

        ctx->fetch.request = b;
        ctx->fetch.use_ssl = conf->captcha_api.use_ssl;
        ctx->fetch.host = conf->captcha_api.host;
    }

    if (ctx->fetch.response == NULL) {
        ctx->fetch.response = ngx_create_temp_buf(r->pool, NGX_HTTP_WAF_FETCH_BUFFER);
        if (ctx->fetch.response == NULL) {
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
        ngx_http_waf_fetch_failed(r, ctx);
        ctx->fetch.in_drive = 0;
        return NGX_OK;
    }

    rc = ngx_resolve_start(clcf->resolver, NULL);

    if (rc == NULL || rc == NGX_NO_RESOLVER) {
        ngx_http_waf_fetch_failed(r, ctx);
        ctx->fetch.in_drive = 0;
        return NGX_OK;
    }

    rc->name = conf->captcha_api.host;
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
                    htons(conf->captcha_api.port);
                break;
#endif
            default:
                ((struct sockaddr_in*) ctx->fetch.resolved_sockaddr)->sin_port =
                    htons(conf->captcha_api.port);
            }

            ctx->fetch.resolved_socklen = socklen;
            ctx->fetch.resolved_valid = 1;

        } else {
            ctx->fetch.resolved_failed = 1;
        }

    } else {
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
        ngx_http_waf_fetch_failed(r, ctx);
        return NGX_OK;
    }
    cln->handler = ngx_http_waf_fetch_cleanup;
    cln->data = ctx;

    if (ctx->fetch.use_ssl) {
        if (ngx_ssl_create_connection(&conf->captcha_api.ssl, c,
                                      NGX_SSL_BUFFER|NGX_SSL_CLIENT) != NGX_OK)
        {
            ctx->fetch.connection = c;
            ngx_http_waf_fetch_failed(r, ctx);
            return NGX_OK;
        }
        c->sendfile = 0;
        if (SSL_set_tlsext_host_name(c->ssl->connection, (char*) conf->captcha_api.host.data)
            == 0)
        {
            ngx_http_waf_fetch_failed(r, ctx);
            return NGX_OK;
        }

        c->ssl->handler = ngx_http_waf_fetch_ssl_done;

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
