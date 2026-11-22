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


static ngx_int_t ngx_http_waf_anubis_original_uri(ngx_http_request_t* r,
    ngx_str_t* uri, ngx_uint_t* have_target);


static ngx_int_t ngx_http_waf_anubis_rewrite_request_uri(ngx_http_request_t* r,
    ngx_str_t* target, ngx_str_t* uri);


static ngx_int_t ngx_http_waf_anubis_decode_form(ngx_http_request_t* r,
    ngx_str_t* encoded, ngx_str_t* decoded);


static ngx_int_t ngx_http_waf_anubis_normalize_absolute(ngx_http_request_t* r,
    ngx_http_waf_loc_conf_t* conf, ngx_str_t* absolute, ngx_str_t* uri);


static ngx_int_t ngx_http_waf_anubis_query_arg(ngx_str_t* args, u_char* name,
    size_t name_len, ngx_str_t* value);


static ngx_uint_t ngx_http_waf_anubis_is_origin_form(ngx_str_t* uri);


static ngx_uint_t ngx_http_waf_anubis_is_challenge_path(ngx_str_t* path,
    ngx_http_waf_loc_conf_t* conf);


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
    ngx_http_waf_ctx_t* ctx;
    ngx_http_waf_anubis_ctx_t* anubis;
    ngx_int_t rc;

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


static ngx_int_t ngx_http_waf_anubis_decode_form(ngx_http_request_t* r,
    ngx_str_t* encoded, ngx_str_t* decoded)
{
    u_char ch;
    u_char value;
    u_char hi;
    u_char lo;
    u_char* dst;
    u_char* last;
    u_char* src;

    dst = ngx_pnalloc(r->pool, encoded->len + 1);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    decoded->data = dst;
    src = encoded->data;
    last = encoded->data + encoded->len;

    while (src < last) {
        ch = *src++;

        if (ch == '+') {
            *dst++ = ' ';
            continue;
        }

        if (ch != '%') {
            *dst++ = ch;
            continue;
        }

        if (last - src < 2) {
            break;
        }

        hi = src[0];
        lo = src[1];
        if (hi >= '0' && hi <= '9') {
            value = (u_char) (hi - '0');
        } else if ((hi | 0x20) >= 'a' && (hi | 0x20) <= 'f') {
            value = (u_char) ((hi | 0x20) - 'a' + 10);
        } else {
            break;
        }
        value <<= 4;
        if (lo >= '0' && lo <= '9') {
            value += (u_char) (lo - '0');
        } else if ((lo | 0x20) >= 'a' && (lo | 0x20) <= 'f') {
            value += (u_char) ((lo | 0x20) - 'a' + 10);
        } else {
            break;
        }

        *dst++ = value;
        src += 2;
    }

    if (src != last) {
        return NGX_DECLINED;
    }
    decoded->len = dst - decoded->data;

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_anubis_query_arg(ngx_str_t* args, u_char* name,
    size_t name_len, ngx_str_t* value)
{
    u_char* end;
    u_char* equal;
    u_char* p;
    u_char* last;

    p = args->data;
    last = args->data + args->len;

    while (p < last) {
        end = ngx_strlchr(p, last, '&');
        if (end == NULL) {
            end = last;
        }

        equal = ngx_strlchr(p, end, '=');
        if (equal != NULL && (size_t) (equal - p) == name_len
            && ngx_strncmp(p, name, name_len) == 0)
        {
            value->data = equal + 1;
            value->len = end - value->data;
            return NGX_OK;
        }

        if (end == last) {
            break;
        }
        p = end + 1;
    }

    return NGX_DECLINED;
}


static ngx_uint_t ngx_http_waf_anubis_is_origin_form(ngx_str_t* uri)
{
    size_t i;

    if (uri->len == 0 || uri->data[0] != '/'
        || (uri->len > 1 && uri->data[1] == '/'))
    {
        return 0;
    }

    for (i = 0; i < uri->len; i++) {
        if (uri->data[i] < 0x20 || uri->data[i] == 0x7f
            || uri->data[i] == '\\')
        {
            return 0;
        }
    }

    return 1;
}


static ngx_uint_t ngx_http_waf_anubis_is_challenge_path(ngx_str_t* path,
    ngx_http_waf_loc_conf_t* conf)
{
    ngx_str_t base;
    size_t base_len;
    size_t reserved_len;

    base = conf->anubis_api.uri;
    base_len = base.len;
    if (base_len == 1 && base.data[0] == '/') {
        base_len = 0;
    } else {
        while (base_len > 0 && base.data[base_len - 1] == '/') {
            base_len--;
        }
    }
    reserved_len = sizeof(NGX_HTTP_WAF_ANUBIS_RESERVED_PATH) - 1;

    if (path->len < base_len + reserved_len
        || ngx_strncmp(path->data, base.data, base_len) != 0
        || ngx_strncmp(path->data + base_len,
                       NGX_HTTP_WAF_ANUBIS_RESERVED_PATH, reserved_len) != 0)
    {
        return 0;
    }

    return path->len == base_len + reserved_len
           || path->data[base_len + reserved_len] == '/';
}


static ngx_int_t ngx_http_waf_anubis_normalize_absolute(ngx_http_request_t* r,
    ngx_http_waf_loc_conf_t* conf, ngx_str_t* absolute, ngx_str_t* uri)
{
    ngx_str_t args;
    ngx_str_t host;
    ngx_str_t nested;
    ngx_str_t path;
    ngx_str_t redir;
    u_char* authority;
    u_char* end;
    u_char* last;
    u_char* query;
    u_char* slash;
    ngx_int_t rc;

    authority = absolute->data;
    if (absolute->len > sizeof("https://") - 1
        && ngx_strncasecmp(authority, (u_char*) "https://",
                           sizeof("https://") - 1) == 0)
    {
        authority += sizeof("https://") - 1;

    } else if (absolute->len > sizeof("http://") - 1
               && ngx_strncasecmp(authority, (u_char*) "http://",
                                  sizeof("http://") - 1) == 0)
    {
        authority += sizeof("http://") - 1;

    } else {
        return NGX_DECLINED;
    }

    last = absolute->data + absolute->len;
    slash = ngx_strlchr(authority, last, '/');
    if (slash == NULL) {
        return NGX_DECLINED;
    }

    host = ngx_http_waf_original_host(r);
    if ((size_t) (slash - authority) != host.len
        || ngx_strncasecmp(authority, host.data, host.len) != 0)
    {
        return NGX_DECLINED;
    }

    end = ngx_strlchr(slash, last, '#');
    if (end == NULL) {
        end = last;
    }
    query = ngx_strlchr(slash, end, '?');
    path.data = slash;
    path.len = (query != NULL ? query : end) - slash;

    if (!ngx_http_waf_anubis_is_challenge_path(&path, conf)) {
        uri->data = slash;
        uri->len = end - slash;
        return ngx_http_waf_anubis_is_origin_form(uri)
               ? NGX_OK : NGX_DECLINED;
    }

    if (query == NULL) {
        return NGX_DECLINED;
    }

    args.data = query + 1;
    args.len = end - args.data;
    if (ngx_http_waf_anubis_query_arg(&args, (u_char*) "redir",
                                      sizeof("redir") - 1, &redir)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    rc = ngx_http_waf_anubis_decode_form(r, &redir, &nested);
    if (rc != NGX_OK) {
        return rc;
    }
    if (!ngx_http_waf_anubis_is_origin_form(&nested)) {
        return NGX_DECLINED;
    }

    *uri = nested;
    return NGX_OK;
}


/*
 * The challenge page and pass-challenge endpoint carry the protected request
 * target in `redir`.  Anubis checks path rules against X-Original-Uri while it
 * issues a challenge and again while it validates the solution.
 *
 * Anubis emits a relative target through ngx_waf, but with PUBLIC_URL unset its
 * browser code can submit the absolute challenge URL itself.  Unwrap that URL
 * so the protected path, not the challenge endpoint, is checked both times.
 */
static ngx_int_t ngx_http_waf_anubis_original_uri(ngx_http_request_t* r,
    ngx_str_t* uri, ngx_uint_t* have_target)
{
    ngx_http_waf_loc_conf_t* conf =
        ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_str_t decoded;
    ngx_str_t redir;
    ngx_int_t rc;

    if (conf == NULL
        || ngx_http_arg(r, (u_char*) "redir", sizeof("redir") - 1, &redir)
           != NGX_OK
        || redir.len == 0)
    {
        *uri = r->unparsed_uri;
        *have_target = 0;
        return NGX_OK;
    }

    rc = ngx_http_waf_anubis_decode_form(r, &redir, &decoded);
    if (rc != NGX_OK) {
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }
        *uri = r->unparsed_uri;
        *have_target = 0;
        return NGX_OK;
    }

    if (ngx_http_waf_anubis_is_origin_form(&decoded)) {
        *uri = decoded;
        *have_target = 1;
        return NGX_OK;
    }

    rc = ngx_http_waf_anubis_normalize_absolute(r, conf, &decoded, uri);
    if (rc == NGX_OK) {
        *have_target = 1;
        return NGX_OK;
    }
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    *uri = r->unparsed_uri;
    *have_target = 0;
    return NGX_OK;
}


/*
 * pass-challenge's Location comes directly from the `redir` form value.
 * Replace that value with the normalized target so Anubis redirects to the
 * protected page instead of the self-referential challenge URL.
 */
static ngx_int_t ngx_http_waf_anubis_rewrite_request_uri(ngx_http_request_t* r,
    ngx_str_t* target, ngx_str_t* uri)
{
    u_char ch;
    u_char* args;
    u_char* dst;
    u_char* end;
    u_char* equal;
    u_char* last;
    u_char* path_end;
    u_char* segment;
    static u_char hex[] = "0123456789ABCDEF";

    if (r->args.len == 0) {
        args = NULL;
        last = NULL;
    } else {
        args = r->args.data;
        last = r->args.data + r->args.len;
    }
    path_end = ngx_strlchr(r->unparsed_uri.data,
                           r->unparsed_uri.data + r->unparsed_uri.len, '?');
    if (path_end == NULL) {
        path_end = r->unparsed_uri.data + r->unparsed_uri.len;
    }

    dst = ngx_pnalloc(r->pool,
                      r->unparsed_uri.len + target->len * 3
                      + sizeof("redir=&") + 1);
    if (dst == NULL) {
        return NGX_ERROR;
    }
    uri->data = dst;

    dst = ngx_cpymem(dst, r->unparsed_uri.data,
                     path_end - r->unparsed_uri.data);
    *dst++ = '?';

    while (args != NULL && args < last) {
        end = ngx_strlchr(args, last, '&');
        if (end == NULL) {
            end = last;
        }

        equal = ngx_strlchr(args, end, '=');
        if (equal == NULL || (size_t) (equal - args) != sizeof("redir") - 1
            || ngx_strncasecmp(args, (u_char*) "redir",
                               sizeof("redir") - 1) != 0)
        {
            dst = ngx_cpymem(dst, args, end - args);
            *dst++ = '&';
        }

        if (end == last) {
            break;
        }
        args = end + 1;
    }

    dst = ngx_cpymem(dst, "redir=", sizeof("redir=") - 1);
    for (segment = target->data; segment < target->data + target->len;
         segment++)
    {
        ch = *segment;
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
            || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.'
            || ch == '_' || ch == '~')
        {
            *dst++ = ch;
        } else {
            *dst++ = '%';
            *dst++ = hex[ch >> 4];
            *dst++ = hex[ch & 0x0f];
        }
    }

    uri->len = dst - uri->data;
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
    ngx_str_t original_uri;
    ngx_str_t proto;
    ngx_str_t request_uri;
    ngx_uint_t have_target;
    u_char* p;
    size_t len;

    if (conf == NULL || ctx == NULL || ctx->anubis_proxy == NULL) {
        return NGX_ERROR;
    }

    anubis = ctx->anubis_proxy;
    host = ngx_http_waf_original_host(r);
    if (ngx_http_waf_anubis_original_uri(r, &original_uri, &have_target)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (have_target) {
        if (ngx_http_waf_anubis_rewrite_request_uri(r, &original_uri,
                                                    &request_uri)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    } else {
        request_uri = r->unparsed_uri;
    }
    proto = r->connection->ssl != NULL
        ? (ngx_str_t) ngx_string("https")
        : (ngx_str_t) ngx_string("http");

    if (r->request_body != NULL) {
        body = r->request_body->bufs;
        anubis->body_length = ngx_http_waf_anubis_body_length(body);
    } else {
        anubis->body_length = 0;
    }

    len = r->method_name.len + request_uri.len + host.len
        + ngx_http_waf_forwarded_header_size(r)
        + r->connection->addr_text.len * 2
        + original_uri.len * 2
        + 1024;
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    p = b->last;
    p = ngx_cpymem(p, r->method_name.data, r->method_name.len);
    *p++ = ' ';
    p = ngx_cpymem(p, request_uri.data, request_uri.len);
    p = ngx_cpymem(p, " HTTP/1.0" CRLF, sizeof(" HTTP/1.0" CRLF) - 1);
    p = ngx_sprintf(p, "Host: %V" CRLF, &host);
    p = ngx_http_waf_copy_forwarded_headers(r, p);
    p = ngx_sprintf(p, "X-Real-IP: %V" CRLF, &r->connection->addr_text);
    p = ngx_sprintf(p, "X-Forwarded-For: %V" CRLF, &r->connection->addr_text);
    p = ngx_sprintf(p, "X-Forwarded-Host: %V" CRLF, &host);
    p = ngx_sprintf(p, "X-Forwarded-Proto: %V" CRLF, &proto);
    p = ngx_sprintf(p, "X-Forwarded-Uri: %V" CRLF, &original_uri);
    p = ngx_sprintf(p, "X-Original-Uri: %V" CRLF, &original_uri);
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
