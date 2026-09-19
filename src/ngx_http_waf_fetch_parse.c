/*
 * The HTTP framing of the captcha provider answer: the status line, the
 * headers, the chunked and the fixed length bodies.
 */

#include "ngx_http_waf_module.h"

/**
 * Whether the headers of the answer announce a chunked body.  The request is
 * HTTP/1.0, so a compliant provider does not use it, but a provider in front
 * of a HTTP/1.1 back end may still send it.
 */
ngx_uint_t ngx_http_waf_fetch_is_chunked(u_char* headers, u_char* end) {
    u_char* p;

    for (p = headers; p + 17 <= end; p++) {
        if (p != headers && p[-1] != '\n') {
            continue;
        }

        if (ngx_strncasecmp(p, (u_char*) "transfer-encoding", 17) != 0) {
            continue;
        }

        p += 17;

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        if (p >= end || *p != ':') {
            continue;
        }
        p++;

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        if (p + 7 <= end && ngx_strncasecmp(p, (u_char*) "chunked", 7) == 0) {
            return 1;
        }
    }

    return 0;
}


/**
 * Walk the chunked framing of `body` .. `end`: the size line (its extensions
 * included), the CRLF that ends every chunk, and the last chunk with its
 * trailers.  `write` is where the bytes of the chunks are copied, `NULL` for a
 * pass that only checks the framing.  Returns 1 when the terminal chunk was
 * reached (the length of the body is in `out_len`), 0 when the framing is
 * incomplete or cannot be read at all.
 */
static ngx_uint_t ngx_http_waf_fetch_dechunk_parse(u_char* body, u_char* end, u_char* write,
    size_t* out_len)
{
    u_char* read = body;
    u_char* out = write;
    size_t decoded = 0;

    for ( ;; ) {
        size_t size = 0;
        ngx_uint_t digits = 0;

        while (read < end && *read != '\r' && *read != '\n' && *read != ';') {
            size_t digit;

            if (*read >= '0' && *read <= '9') {
                digit = *read - '0';

            } else if (*read >= 'a' && *read <= 'f') {
                digit = *read - 'a' + 10;

            } else if (*read >= 'A' && *read <= 'F') {
                digit = *read - 'A' + 10;

            } else {
                return 0;
            }

            if (size > (NGX_MAX_SIZE_T_VALUE >> 4)) {
                return 0;
            }

            size = (size << 4) + digit;
            digits++;
            read++;
        }

        if (digits == 0) {
            return 0;
        }

        /* skip the rest of the size line and its CRLF */
        while (read < end && *read != '\n') {
            read++;
        }

        if (read >= end) {
            return 0;
        }
        read++;

        if (size == 0) {
            *out_len = decoded;
            return 1;
        }

        if ((size_t) (end - read) < size + 2) {
            return 0;
        }

        if (write != NULL) {
            if (out != read) {
                ngx_memmove(out, read, size);
            }
            out += size;
        }
        decoded += size;
        read += size;

        if (read[0] != '\r' || read[1] != '\n') {
            return 0;
        }
        read += 2;
    }
}


/**
 * Remove the chunked framing of `body` in place: the size line (its extensions
 * included), the CRLF that ends every chunk, and the last chunk with its
 * trailers.  Returns 0 when the framing is not one we can read, the caller
 * answers the failure of the provider request then.
 *
 * The answer of a provider may arrive in several reads, so the buffer has to
 * stay readable as the framing of the whole answer until the framing is
 * complete: a pass that only checks the framing runs first, and a call that has
 * to wait for more bytes (that is, one that returns 0) leaves the buffer alone.
 * Compacting as it went made the next call read the decoded bytes as a size
 * line, which turned a valid answer split in front of its last chunk into a
 * failed attempt.
 */
ngx_uint_t ngx_http_waf_fetch_dechunk(u_char* body, u_char* end, size_t* out_len) {
    if (!ngx_http_waf_fetch_dechunk_parse(body, end, NULL, out_len)) {
        return 0;
    }

    return ngx_http_waf_fetch_dechunk_parse(body, end, body, out_len);
}


/**
 * The `Content-Length` of the answer, when the headers carry one.  Only a field
 * that starts a line counts: a header whose name merely ends with the same text
 * (`x-content-length`) is not one.
 */
ngx_uint_t ngx_http_waf_fetch_length(u_char* headers, u_char* end, size_t* out_len) {
    u_char* p;

    for (p = headers; p + 14 <= end; p++) {
        size_t value = 0;
        ngx_uint_t digits = 0;

        if (p != headers && p[-1] != '\n') {
            continue;
        }

        if (ngx_strncasecmp(p, (u_char*) "content-length", 14) != 0) {
            continue;
        }

        p += 14;

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        if (p >= end || *p != ':') {
            continue;
        }
        p++;

        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        while (p < end && *p >= '0' && *p <= '9') {
            if (value > (NGX_MAX_SIZE_T_VALUE / 10)) {
                return 0;
            }

            value = value * 10 + (*p - '0');
            digits++;
            p++;
        }

        if (digits == 0) {
            return 0;
        }

        *out_len = value;
        return 1;
    }

    return 0;
}


/**
 * Settle the provider request once the answer in the buffer is complete: the
 * body of a `Content-Length` that arrived, the framing of a chunked answer, or
 * the bytes the provider sent before it closed the connection.  `eof` says the
 * provider closed, so an answer without a length is complete then, and an
 * answer that is still incomplete becomes the failure of the request.
 *
 * Returns 1 when the request was settled (the caller returns), 0 when more
 * bytes are needed.
 */
ngx_uint_t ngx_http_waf_fetch_answer(ngx_http_request_t* r, ngx_http_waf_ctx_t* ctx,
    u_char* data, u_char* last, ngx_uint_t eof)
{
    u_char* p;
    u_char* body;
    size_t length = 0;
    size_t have;
    size_t decoded;
    ngx_uint_t status = 0;
    ngx_uint_t has_length;

    p = ngx_strlchr(data, last, ' ');
    if (p != NULL) {
        status = ngx_atoi(p + 1, 3);
    }

    if (p == NULL || (ngx_int_t) status == NGX_ERROR) {
        if (!eof) {
            /* the status line is not complete yet */
            return 0;
        }

        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
        return 1;
    }

    p = ngx_strlcasestrn(data, last, (u_char*) CRLF CRLF, 4 - 1);
    if (p == NULL) {
        if (!eof) {
            /* the headers are not complete yet */
            return 0;
        }

        ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
        return 1;
    }

    body = p + 4;
    have = (size_t) (last - body);
    has_length = ngx_http_waf_fetch_length(data, p, &length);

    if (ngx_http_waf_fetch_is_chunked(data, p)) {
        if (!ngx_http_waf_fetch_dechunk(body, last, &decoded)) {
            /*
             * An incomplete framing cannot be told from a broken one, so the
             * connection has to end before the answer is judged.
             */
            if (!eof) {
                return 0;
            }

            ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
            return 1;
        }

        ngx_http_waf_fetch_finish(r, status, body, decoded, 0);
        return 1;
    }

    if (has_length) {
        if (have < length) {
            if (!eof) {
                return 0;
            }

            /* the provider closed before the length it announced */
            ngx_http_waf_fetch_finish(r, 0, NULL, 0, 1);
            return 1;
        }

        ngx_http_waf_fetch_finish(r, status, body, length, 0);
        return 1;
    }

    if (!eof) {
        /* without a length the body ends with the connection */
        return 0;
    }

    ngx_http_waf_fetch_finish(r, status, body, have, 0);
    return 1;
}
