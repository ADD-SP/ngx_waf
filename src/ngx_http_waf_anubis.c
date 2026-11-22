/*
 * The same-origin half of waf_anubis: the challenge page and its assets are
 * forwarded to Anubis with nginx's upstream machinery.  The auth check itself
 * lives in ngx_http_waf_fetch.c.
 */

#include "ngx_http_waf_module.h"
#include <ngx_http_upstream.h>


typedef struct {
    ngx_http_request_t* request;
    ngx_http_chunked_t  chunked;
    off_t               body_length;
    ngx_str_t           original_uri;
    ngx_str_t           request_uri;
} ngx_http_waf_anubis_ctx_t;


static void ngx_http_waf_anubis_body_handler(ngx_http_request_t* r);


static ngx_int_t ngx_http_waf_anubis_upstream(ngx_http_request_t* r);


static ngx_int_t ngx_http_waf_anubis_create_request(ngx_http_request_t* r);


static ngx_int_t ngx_http_waf_anubis_reinit_request(ngx_http_request_t* r);


static ngx_int_t ngx_http_waf_anubis_process_header(ngx_http_request_t* r);


static ngx_int_t ngx_http_waf_anubis_filter_init(void* data);


static ngx_int_t ngx_http_waf_anubis_chunked_filter(void* data, ssize_t bytes);


static void ngx_http_waf_anubis_abort(ngx_http_request_t* r);


static void ngx_http_waf_anubis_finalize(ngx_http_request_t* r, ngx_int_t rc);


static ngx_int_t ngx_http_waf_anubis_add_header(ngx_http_request_t* r,
    ngx_str_t* key, ngx_str_t* value, ngx_table_elt_t** result);


static ngx_int_t ngx_http_waf_anubis_prepare(ngx_http_request_t* r,
    ngx_http_waf_loc_conf_t* conf, ngx_http_waf_anubis_ctx_t* anubis);


static void ngx_http_waf_anubis_rewrite_cookie_path(ngx_http_request_t* r,
    ngx_str_t* value);


ngx_uint_t ngx_http_waf_is_anubis_path(ngx_http_request_t* r,
    ngx_http_waf_loc_conf_t* conf)
{
    ngx_str_t prefix;
    size_t base_len;
    size_t reserved_len;

    if (!conf->anubis_api.configured || r->uri.len == 0) {
        return 0;
    }

    reserved_len = sizeof(NGX_HTTP_WAF_ANUBIS_RESERVED_PATH) - 1;
    prefix.data = conf->anubis_api.uri.data;
    prefix.len = conf->anubis_api.uri.len;
    base_len = prefix.len;
    if (base_len == 1 && prefix.data[0] == '/') {
        base_len = 0;
    } else {
        while (base_len > 0 && prefix.data[base_len - 1] == '/') {
            base_len--;
        }
    }

    if (r->uri.len < base_len + reserved_len
        || ngx_strncmp(r->uri.data, prefix.data, base_len) != 0
        || ngx_strncmp(r->uri.data + base_len, NGX_HTTP_WAF_ANUBIS_RESERVED_PATH,
                       reserved_len) != 0)
    {
        return 0;
    }

    if (r->uri.len == base_len + reserved_len) {
        return 1;
    }

    return r->uri.data[base_len + reserved_len] == '/';
}


ngx_int_t ngx_http_waf_anubis_proxy_handler(ngx_http_request_t* r)
{
    ngx_http_waf_loc_conf_t* conf;
    ngx_http_waf_ctx_t* ctx;
    ngx_http_waf_anubis_ctx_t* anubis;
    ngx_int_t rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    if (conf == NULL || !conf->anubis_api.configured) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_http_waf_get_ctx(r);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    anubis = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_anubis_ctx_t));
    if (anubis == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    anubis->request = r;
    ctx->anubis_proxy = anubis;

    rc = ngx_http_waf_anubis_prepare(r, conf, anubis);
    if (rc != NGX_OK) {
        return rc;
    }

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    rc = ngx_http_read_client_request_body(r, ngx_http_waf_anubis_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void ngx_http_waf_anubis_body_handler(ngx_http_request_t* r)
{
    ngx_int_t rc;

    if (ngx_http_waf_anubis_upstream(r) != NGX_OK) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    } else {
        return;
    }

    ngx_http_finalize_request(r, rc);
}


static ngx_int_t ngx_http_waf_anubis_upstream(ngx_http_request_t* r)
{
    ngx_http_waf_loc_conf_t* conf =
        ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_http_waf_ctx_t* ctx =
        ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_anubis_ctx_t* anubis;
    ngx_http_upstream_t* u;
    ngx_http_upstream_conf_t* ucf;

    if (conf == NULL || ctx == NULL || ctx->anubis_proxy == NULL
        || !conf->anubis_api.configured)
    {
        return NGX_ERROR;
    }

    anubis = ctx->anubis_proxy;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_ERROR;
    }

    u = r->upstream;
    ucf = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_conf_t));
    if (ucf == NULL) {
        return NGX_ERROR;
    }

    ucf->connect_timeout = 5000;
    ucf->send_timeout = 5000;
    ucf->read_timeout = 5000;
    ucf->buffer_size = 16 * 1024;
    ucf->busy_buffers_size = 64 * 1024;
    ucf->max_temp_file_size = 0;
    ucf->temp_file_write_size = 0;
    ucf->bufs.num = 8;
    ucf->bufs.size = 8 * 1024;
    ucf->buffering = 0;
    ucf->request_buffering = 1;
    ucf->pass_request_headers = 0;
    ucf->pass_request_body = 0;
    ucf->pass_trailers = 0;
    ucf->intercept_errors = 1;

#if (NGX_HTTP_SSL)
    if (conf->anubis_api.use_ssl) {
        ucf->ssl = &conf->anubis_api.ssl;
        ucf->ssl_session_reuse = 0;
        ucf->ssl_verify = 1;
        ucf->ssl_server_name = 1;
        u->ssl = 1;
        ngx_str_set(&u->schema, "https://");
    } else
#endif
    {
        ngx_str_set(&u->schema, "http://");
    }

    u->conf = ucf;
    u->output.tag = (ngx_buf_tag_t) &ngx_http_waf_module;
    u->create_request = ngx_http_waf_anubis_create_request;
    u->reinit_request = ngx_http_waf_anubis_reinit_request;
    u->process_header = ngx_http_waf_anubis_process_header;
    u->abort_request = ngx_http_waf_anubis_abort;
    u->finalize_request = ngx_http_waf_anubis_finalize;
    u->input_filter_init = ngx_http_waf_anubis_filter_init;
    u->input_filter_ctx = anubis;
    u->buffering = 0;

    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    u->resolved->host = conf->anubis_api.host;
    u->resolved->port = conf->anubis_api.port;
    u->resolved->no_port = 0;
    if (conf->anubis_api.resolved) {
        u->resolved->sockaddr = conf->anubis_api.sockaddr;
        u->resolved->socklen = conf->anubis_api.socklen;
        u->resolved->naddrs = 1;
    }

    ngx_http_upstream_init(r);
    return NGX_OK;
}


static off_t ngx_http_waf_anubis_body_length(ngx_chain_t* chain)
{
    off_t length = 0;
    ngx_buf_t* b;

    for (; chain != NULL; chain = chain->next) {
        b = chain->buf;
        if (b->in_file) {
            length += b->file_last - b->file_pos;
        } else {
            length += b->last - b->pos;
        }
    }

    return length;
}


static ngx_int_t ngx_http_waf_anubis_prepare(ngx_http_request_t* r,
    ngx_http_waf_loc_conf_t* conf, ngx_http_waf_anubis_ctx_t* anubis)
{
    ngx_waf_anubis_redirect_input_t input;
    ngx_waf_anubis_redirect_output_t output;
    ngx_waf_anubis_redirect_status status;
    ngx_str_t host;

    host = ngx_http_waf_original_host(r);
    input = (ngx_waf_anubis_redirect_input_t) {
        .host = {
            .len = host.len,
            .data = host.data,
        },
        .base_prefix = {
            .len = conf->anubis_api.uri.len,
            .data = conf->anubis_api.uri.data,
        },
        .unparsed_uri = {
            .len = r->unparsed_uri.len,
            .data = r->unparsed_uri.data,
        },
    };

    ngx_memzero(&output, sizeof(output));
    status = ngx_waf_anubis_redirect_normalize(&input, NULL, 0, &output);

    if (status == NGX_WAF_ANUBIS_REDIRECT_STATUS_NO_REDIRECT) {
        anubis->original_uri = r->unparsed_uri;
        anubis->request_uri = r->unparsed_uri;
        return NGX_OK;
    }
    if (status == NGX_WAF_ANUBIS_REDIRECT_STATUS_REJECTED) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (status != NGX_WAF_ANUBIS_REDIRECT_STATUS_BUFFER_TOO_SMALL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    anubis->request_uri.data = ngx_pnalloc(r->pool, output.required);
    if (anubis->request_uri.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    anubis->request_uri.len = output.required;

    status = ngx_waf_anubis_redirect_normalize(
        &input, anubis->request_uri.data, anubis->request_uri.len, &output);
    if (status == NGX_WAF_ANUBIS_REDIRECT_STATUS_REJECTED) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (status != NGX_WAF_ANUBIS_REDIRECT_STATUS_NORMALIZED) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    anubis->original_uri.data = (u_char*) output.original_uri.data;
    anubis->original_uri.len = output.original_uri.len;
    anubis->request_uri.data = (u_char*) output.request_uri.data;
    anubis->request_uri.len = output.request_uri.len;
    return NGX_OK;
}


static ngx_int_t ngx_http_waf_anubis_create_request(ngx_http_request_t* r)
{
    ngx_http_waf_loc_conf_t* conf =
        ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_http_waf_ctx_t* ctx =
        ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_anubis_ctx_t* anubis;
    ngx_http_upstream_t* u = r->upstream;
    ngx_chain_t* body = NULL;
    ngx_chain_t* cl;
    ngx_buf_t* b;
    ngx_str_t host;
    ngx_str_t proto;
    u_char* p;
    size_t len;

    if (conf == NULL || ctx == NULL || ctx->anubis_proxy == NULL) {
        return NGX_ERROR;
    }

    anubis = ctx->anubis_proxy;
    host = ngx_http_waf_original_host(r);
    proto = r->connection->ssl != NULL
        ? (ngx_str_t) ngx_string("https")
        : (ngx_str_t) ngx_string("http");

    if (r->request_body != NULL) {
        body = r->request_body->bufs;
        anubis->body_length = ngx_http_waf_anubis_body_length(body);
    } else {
        anubis->body_length = 0;
    }

    len = r->method_name.len + anubis->request_uri.len + host.len
        + ngx_http_waf_forwarded_header_size(r)
        + r->connection->addr_text.len * 2
        + anubis->original_uri.len * 2
        + 1024;
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    p = b->last;
    p = ngx_cpymem(p, r->method_name.data, r->method_name.len);
    *p++ = ' ';
    p = ngx_cpymem(p, anubis->request_uri.data, anubis->request_uri.len);
    p = ngx_cpymem(p, " HTTP/1.0" CRLF, sizeof(" HTTP/1.0" CRLF) - 1);
    p = ngx_sprintf(p, "Host: %V" CRLF, &host);
    p = ngx_http_waf_copy_forwarded_headers(r, p);
    p = ngx_sprintf(p, "X-Real-IP: %V" CRLF, &r->connection->addr_text);
    p = ngx_sprintf(p, "X-Forwarded-For: %V" CRLF, &r->connection->addr_text);
    p = ngx_sprintf(p, "X-Forwarded-Host: %V" CRLF, &host);
    p = ngx_sprintf(p, "X-Forwarded-Proto: %V" CRLF, &proto);
    p = ngx_sprintf(p, "X-Forwarded-Uri: %V" CRLF, &anubis->original_uri);
    p = ngx_sprintf(p, "X-Original-Uri: %V" CRLF, &anubis->original_uri);
    if (anubis->body_length != 0) {
        p = ngx_sprintf(p, "Content-Length: %O" CRLF, anubis->body_length);
    }
    p = ngx_cpymem(p, "Connection: close" CRLF CRLF,
                   sizeof("Connection: close" CRLF CRLF) - 1);
    b->last = p;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }
    cl->buf = b;
    cl->next = body;
    if (body == NULL) {
        b->last_buf = 1;
    }

    u->request_bufs = cl;
    return NGX_OK;
}


static ngx_int_t ngx_http_waf_anubis_reinit_request(ngx_http_request_t* r)
{
    (void) r;
    return NGX_OK;
}


static ngx_uint_t ngx_http_waf_anubis_hop_header(ngx_str_t* key)
{
    static const char* skipped[] = {
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        NULL
    };
    ngx_uint_t i;

    for (i = 0; skipped[i] != NULL; i++) {
        size_t len = ngx_strlen(skipped[i]);
        if (key->len == len && ngx_strncasecmp(key->data, (u_char*) skipped[i], len) == 0) {
            return 1;
        }
    }
    return 0;
}


/*
 * Anubis scopes its auth cookie to BASE_PREFIX because it assumes that all
 * protected requests also carry that prefix.  This module uses Anubis as a
 * subrequest sidecar, so the protected application may live above the
 * challenge prefix.  Restore the cookie to the site root or browsers will not
 * send it on those requests.
 */
static void ngx_http_waf_anubis_rewrite_cookie_path(ngx_http_request_t* r,
    ngx_str_t* value)
{
    ngx_http_waf_loc_conf_t* conf =
        ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_str_t base;
    u_char* p;
    u_char* end;
    u_char* next;
    u_char* path;
    u_char* path_end;
    size_t base_len;

    if (conf == NULL || !conf->anubis_api.configured) {
        return;
    }

    base = conf->anubis_api.uri;
    base_len = base.len;
    while (base_len > 1 && base.data[base_len - 1] == '/') {
        base_len--;
    }
    if (base_len == 0 || (base_len == 1 && base.data[0] == '/')) {
        return;
    }

    p = value->data;
    end = value->data + value->len;

    for ( ;; ) {
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }
        if ((size_t) (end - p) >= sizeof("Path=") - 1
            && ngx_strncasecmp(p, (u_char*) "Path=", sizeof("Path=") - 1) == 0)
        {
            path = p + sizeof("Path=") - 1;
            while (path < end && (*path == ' ' || *path == '\t')) {
                path++;
            }

            path_end = ngx_strlchr(path, end, ';');
            if (path_end == NULL) {
                path_end = end;
            }
            while (path_end > path
                   && (path_end[-1] == ' ' || path_end[-1] == '\t'))
            {
                path_end--;
            }

            if ((size_t) (path_end - path) == base_len + 1
                && ngx_strncmp(path, base.data, base_len) == 0
                && path[base_len] == '/')
            {
                ngx_memmove(path + 1, path_end, end - path_end);
                path[0] = '/';
                value->len -= base_len;
                return;
            }
        }

        next = ngx_strlchr(p, end, ';');
        if (next == NULL) {
            return;
        }
        p = next + 1;
    }
}


static ngx_int_t ngx_http_waf_anubis_add_header(ngx_http_request_t* r,
    ngx_str_t* key, ngx_str_t* value, ngx_table_elt_t** result)
{
    ngx_table_elt_t* header;
    size_t i;

    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(header, sizeof(ngx_table_elt_t));
    header->key.data = ngx_pnalloc(r->pool, key->len + 1);
    if (header->key.data == NULL) {
        header->hash = 0;
        return NGX_ERROR;
    }
    ngx_memcpy(header->key.data, key->data, key->len);
    header->key.data[key->len] = '\0';
    header->key.len = key->len;

    header->value.data = ngx_pnalloc(r->pool, value->len + 1);
    if (header->value.data == NULL) {
        header->hash = 0;
        return NGX_ERROR;
    }
    ngx_memcpy(header->value.data, value->data, value->len);
    header->value.data[value->len] = '\0';
    header->value.len = value->len;
    header->lowcase_key = ngx_pnalloc(r->pool, key->len + 1);
    if (header->lowcase_key == NULL) {
        return NGX_ERROR;
    }
    for (i = 0; i < key->len; i++) {
        header->lowcase_key[i] = ngx_tolower(key->data[i]);
    }
    header->lowcase_key[key->len] = '\0';
    header->hash = ngx_hash_key_lc(header->lowcase_key, key->len);
    *result = header;

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_anubis_process_header(ngx_http_request_t* r)
{
    ngx_http_upstream_t* u = r->upstream;
    ngx_buf_t probe = u->buffer;
    ngx_http_status_t status;
    u_char* start;
    u_char* end = NULL;
    u_char* p;
    u_char* line_end;
    u_char* next_line;
    u_char* colon;
    ngx_str_t key;
    ngx_str_t value;
    ngx_table_elt_t* header;
    off_t content_length = -1;
    ngx_flag_t chunked = 0;
    ngx_int_t rc;

    for (p = probe.pos; p + 3 < probe.last; p++) {
        if (p[0] == CR && p[1] == LF && p[2] == CR && p[3] == LF) {
            end = p + 4;
            break;
        }
    }
    if (end == NULL) {
        return NGX_AGAIN;
    }

    probe.last = end;
    ngx_memzero(&status, sizeof(ngx_http_status_t));
    if (ngx_http_parse_status_line(r, &probe, &status) != NGX_OK
        || status.code < 200 || status.code > 599)
    {
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    u->headers_in.status_n = status.code;
    u->headers_in.status_line.data = status.start;
    u->headers_in.status_line.len = status.end - status.start;
    u->headers_in.content_length_n = -1;

    start = probe.pos;

    while (start < end) {
        next_line = ngx_strlchr(start, end, LF);
        if (next_line == NULL) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }
        line_end = next_line++;
        while (line_end > start && line_end[-1] == CR) {
            line_end--;
        }
        if (line_end == start) {
            break;
        }

        colon = ngx_strlchr(start, line_end, ':');
        if (colon == NULL) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        key.data = start;
        key.len = colon - start;
        while (key.len != 0 && (key.data[key.len - 1] == ' '
                                || key.data[key.len - 1] == '\t'))
        {
            key.len--;
        }
        value.data = colon + 1;
        while (value.data < line_end && (*value.data == ' ' || *value.data == '\t')) {
            value.data++;
        }
        value.len = line_end - value.data;
        while (value.len != 0 && (value.data[value.len - 1] == ' '
                                  || value.data[value.len - 1] == '\t'))
        {
            value.len--;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ngx_waf Anubis response header: \"%V: %V\"", &key, &value);

        if (key.len == sizeof("Content-Length") - 1
            && ngx_strncasecmp(key.data, (u_char*) "Content-Length", key.len) == 0)
        {
            content_length = ngx_atoof(value.data, value.len);
            if (content_length == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }
        } else if (key.len == sizeof("Transfer-Encoding") - 1
                   && ngx_strncasecmp(key.data, (u_char*) "Transfer-Encoding", key.len) == 0)
        {
            if (ngx_strlcasestrn(value.data, value.data + value.len,
                                 (u_char*) "chunked", sizeof("chunked") - 1)
                != NULL)
            {
                chunked = 1;
            }
        } else if (key.len == sizeof("Connection") - 1
                   && ngx_strncasecmp(key.data, (u_char*) "Connection", key.len) == 0)
        {
            if (ngx_strlcasestrn(value.data, value.data + value.len,
                                 (u_char*) "close", sizeof("close") - 1)
                != NULL)
            {
                u->headers_in.connection_close = 1;
            }
        } else if (!ngx_http_waf_anubis_hop_header(&key)) {
            if (key.len == sizeof("Set-Cookie") - 1
                && ngx_strncasecmp(key.data, (u_char*) "Set-Cookie", key.len) == 0)
            {
                ngx_http_waf_anubis_rewrite_cookie_path(r, &value);
            }

            rc = ngx_http_waf_anubis_add_header(r, &key, &value, &header);
            if (rc != NGX_OK) {
                return rc;
            }

            if (key.len == sizeof("Content-Type") - 1
                && ngx_strncasecmp(key.data, (u_char*) "Content-Type", key.len) == 0)
            {
                r->headers_out.content_type = header->value;
                r->headers_out.content_type_len = header->value.len;
                r->headers_out.content_type_lowcase = NULL;
                header->hash = 0;
            } else if (key.len == sizeof("Set-Cookie") - 1
                       && ngx_strncasecmp(key.data, (u_char*) "Set-Cookie", key.len) == 0)
            {
                /* The generic header list entry is enough; duplicates are valid. */
            } else if (key.len == sizeof("Cache-Control") - 1
                       && ngx_strncasecmp(key.data, (u_char*) "Cache-Control", key.len) == 0)
            {
                /* A regular header; the header filter sends the list entry. */
            } else if (key.len == sizeof("Location") - 1
                       && ngx_strncasecmp(key.data, (u_char*) "Location", key.len) == 0)
            {
                r->headers_out.location = header;
                /* Keep a relative Location when `absolute_redirect` is off. */
                header->hash = 1;
            } else if (key.len == sizeof("Date") - 1
                       && ngx_strncasecmp(key.data, (u_char*) "Date", key.len) == 0)
            {
                r->headers_out.date = header;
            } else if (key.len == sizeof("Server") - 1
                       && ngx_strncasecmp(key.data, (u_char*) "Server", key.len) == 0)
            {
                r->headers_out.server = header;
            }
        }

        start = next_line;
    }

    if (chunked) {
        content_length = -1;
    }
    u->headers_in.chunked = chunked;
    u->headers_in.content_length_n = content_length;
    u->buffer.pos = end;

    if (content_length == 0 || status.code == NGX_HTTP_NO_CONTENT
        || status.code == NGX_HTTP_NOT_MODIFIED || r->header_only)
    {
        u->keepalive = 0;
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_anubis_filter_init(void* data)
{
    ngx_http_waf_anubis_ctx_t* anubis = data;
    ngx_http_request_t* r = anubis->request;
    ngx_http_upstream_t* u = r->upstream;

    if (r->header_only || u->headers_in.status_n == NGX_HTTP_NO_CONTENT
        || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED)
    {
        u->length = 0;
        u->input_filter = ngx_http_upstream_non_buffered_filter;
        return NGX_OK;
    }

    if (u->headers_in.chunked) {
        ngx_memzero(&anubis->chunked, sizeof(ngx_http_chunked_t));
        u->length = 1;
        u->input_filter = ngx_http_waf_anubis_chunked_filter;
        return NGX_OK;
    }

    u->input_filter = ngx_http_upstream_non_buffered_filter;
    u->length = u->headers_in.content_length_n;
    return NGX_OK;
}


static ngx_int_t ngx_http_waf_anubis_chunked_filter(void* data, ssize_t bytes)
{
    ngx_http_waf_anubis_ctx_t* anubis = data;
    ngx_http_request_t* r = anubis->request;
    ngx_http_upstream_t* u = r->upstream;
    ngx_buf_t* buf = &u->buffer;
    ngx_chain_t* cl;
    ngx_chain_t** last;
    ngx_buf_t* b;
    ngx_int_t rc;

    if (u->length == 0) {
        return NGX_OK;
    }

    buf->pos = buf->last;
    buf->last += bytes;

    for (cl = u->out_bufs, last = &u->out_bufs; cl != NULL; cl = cl->next) {
        last = &cl->next;
    }

    for ( ;; ) {
        rc = ngx_http_parse_chunked(r, buf, &anubis->chunked, 0);
        if (rc == NGX_OK) {
            cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
            if (cl == NULL) {
                return NGX_ERROR;
            }
            *last = cl;
            last = &cl->next;
            b = cl->buf;
            b->flush = 1;
            b->memory = 1;
            b->pos = buf->pos;
            b->tag = u->output.tag;

            if (buf->last - buf->pos >= anubis->chunked.size) {
                buf->pos += (size_t) anubis->chunked.size;
                b->last = buf->pos;
                anubis->chunked.size = 0;
            } else {
                anubis->chunked.size -= buf->last - buf->pos;
                buf->pos = buf->last;
                b->last = buf->last;
            }
            continue;
        }

        if (rc == NGX_DONE) {
            u->length = 0;
            u->keepalive = 0;
            if (buf->pos != buf->last) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "ngx_waf: Anubis sent data after the final chunk");
            }
            break;
        }

        if (rc == NGX_AGAIN) {
            break;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_waf: Anubis sent an invalid chunked response");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void ngx_http_waf_anubis_abort(ngx_http_request_t* r)
{
    (void) r;
}


static void ngx_http_waf_anubis_finalize(ngx_http_request_t* r, ngx_int_t rc)
{
    (void) r;
    (void) rc;
}
