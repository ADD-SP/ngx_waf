#include <ngx_http_waf_module_under_attack.h>


ngx_int_t ngx_http_waf_check_under_attack(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Enter the Under-Attack processing flow.");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (loc_conf->waf_under_attack == 0 || loc_conf->waf_under_attack == NGX_CONF_UNSET) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Processing is complete.");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    if (ngx_strncmp(r->uri.data, 
                    loc_conf->waf_under_attack_uri.data, 
                    ngx_max(r->uri.len, loc_conf->waf_under_attack_uri.len)) == 0) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Processing is complete.");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Begin the processing flow.");

    ngx_str_t __waf_under_attack_time = { 0, NULL };
    ngx_str_t __waf_under_attack_uid = { 0, NULL };
    ngx_str_t __waf_under_attack_verification = { 0, NULL };

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Start parsing cookies.");

#if (nginx_version >= 1023000)
    if (r->headers_in.cookie != NULL) {
        ngx_table_elt_t* cookies = r->headers_in.cookie;
#else
    if (r->headers_in.cookies.nelts > 0) {
        ngx_array_t* cookies = &(r->headers_in.cookies);
#endif
        ngx_str_t key, value;


        ngx_str_set(&key, "__waf_under_attack_time");
        ngx_str_null(&value);

#if (nginx_version >= 1023000)
        if (ngx_http_parse_multi_header_lines(r, cookies, &key, &value) != NULL) {
#else
        if (ngx_http_parse_multi_header_lines(cookies, &key, &value) != NGX_DECLINED) {
#endif
            __waf_under_attack_time.data = ngx_pcalloc(r->pool, value.len + 1);
            __waf_under_attack_time.len = value.len;
            ngx_memcpy(__waf_under_attack_time.data, value.data, value.len);

        }

        ngx_str_set(&key, "__waf_under_attack_uid");
        ngx_str_null(&value);

#if (nginx_version >= 1023000)
        if (ngx_http_parse_multi_header_lines(r, cookies, &key, &value) != NULL) {
#else
        if (ngx_http_parse_multi_header_lines(cookies, &key, &value) != NGX_DECLINED) {
#endif
            __waf_under_attack_uid.data = ngx_pcalloc(r->pool, value.len + 1);
            __waf_under_attack_uid.len = value.len;
            ngx_memcpy(__waf_under_attack_uid.data, value.data, value.len);

        }

        ngx_str_set(&key, "__waf_under_attack_verification");
        ngx_str_null(&value);

#if (nginx_version >= 1023000)
        if (ngx_http_parse_multi_header_lines(r, cookies, &key, &value) != NULL) {
#else
        if (ngx_http_parse_multi_header_lines(cookies, &key, &value) != NGX_DECLINED) {
#endif
            __waf_under_attack_verification.data = ngx_pcalloc(r->pool, value.len + 1);
            __waf_under_attack_verification.len = value.len;
            ngx_memcpy(__waf_under_attack_verification.data, value.data, value.len);

        }
    }


    /* 如果 cookie 不完整 */
    if (__waf_under_attack_time.data == NULL || __waf_under_attack_uid.data == NULL || __waf_under_attack_verification.data == NULL) {
        ngx_http_waf_gen_cookie(r);
        *out_http_status = 303;
        ngx_http_waf_gen_ctx_and_header_location(r);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Failed to parse cookies");
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Processing is complete.");
        return NGX_HTTP_WAF_MATCHED;
    }


    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Successfully parsed all cookies.");


    /* 验证 token 是否正确 */
    u_char cur_verification[NGX_HTTP_WAF_SHA256_HEX_LEN + 1];
    ngx_memzero(cur_verification, sizeof(u_char) * (NGX_HTTP_WAF_SHA256_HEX_LEN + 1));
    ngx_http_waf_gen_verification(r,
                                  __waf_under_attack_uid.data,
                                  NGX_HTTP_WAF_UNDER_ATTACH_UID_LEN,
                                  cur_verification,
                                  NGX_HTTP_WAF_SHA256_HEX_LEN,
                                  __waf_under_attack_time.data,
                                  NGX_HTTP_WAF_UNDER_ATTACH_TIME_LEN);
    if (ngx_memcmp(__waf_under_attack_verification.data, cur_verification, sizeof(u_char) * NGX_HTTP_WAF_SHA256_HEX_LEN) != 0) {
        ngx_http_waf_gen_cookie(r);
        *out_http_status = 303;
        ngx_http_waf_gen_ctx_and_header_location(r);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Wrong __waf_under_attack_verification.");
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Processing is complete.");
        return NGX_HTTP_WAF_MATCHED;
    }


    /* 验证时间是否超过 5 秒 */
    time_t client_time = ngx_atoi(__waf_under_attack_time.data, __waf_under_attack_time.len);
    /* 如果 Cookie 不合法 或 已经超过 30 分钟 */
    if (client_time == NGX_ERROR || difftime(time(NULL), client_time) > 60 * 30) {
        ngx_http_waf_gen_cookie(r);
        *out_http_status = 303;
        ngx_http_waf_gen_ctx_and_header_location(r);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Wrong __waf_under_attack_verification.");
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Processing is complete.");
        return NGX_HTTP_WAF_MATCHED;
    } else if (difftime(time(NULL), client_time) < 5) {
        *out_http_status = 303;
        ngx_http_waf_gen_ctx_and_header_location(r);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Not five seconds have passed.");
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Processing is complete.");
        return NGX_HTTP_WAF_MATCHED;
    }

    return NGX_HTTP_WAF_NOT_MATCHED;
}


ngx_int_t ngx_http_waf_gen_cookie(ngx_http_request_t *r) {
    static size_t s_header_key_len = sizeof("Set-Cookie");

    ngx_table_elt_t *__waf_under_attack_time = NULL;
    ngx_table_elt_t *__waf_under_attack_uid = NULL;
    ngx_table_elt_t *__waf_under_attack_verification = NULL;
    int write_len = 0;
    long long int now = (long long int)time(NULL);
    u_char now_str[NGX_HTTP_WAF_UNDER_ATTACH_TIME_LEN + 1];
    ngx_memzero(now_str, sizeof(u_char) * (NGX_HTTP_WAF_UNDER_ATTACH_TIME_LEN + 1));
    sprintf((char*)now_str, "%lld", now);

    __waf_under_attack_time = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    __waf_under_attack_time->hash = 1;
    __waf_under_attack_time->key.data = (u_char *)ngx_pnalloc(r->pool, sizeof(u_char) * (s_header_key_len + 1));
    ngx_memzero(__waf_under_attack_time->key.data, sizeof(u_char) * (s_header_key_len + 1));
    __waf_under_attack_time->key.len = s_header_key_len - 1;
    strcpy((char *)(__waf_under_attack_time->key.data), "Set-Cookie");

    __waf_under_attack_time->value.data = (u_char *)ngx_pnalloc(r->pool, sizeof(u_char) * (NGX_HTTP_WAF_UNDER_ATTACH_TIME_LEN * 4));
    ngx_memzero(__waf_under_attack_time->value.data, sizeof(u_char) * (NGX_HTTP_WAF_UNDER_ATTACH_TIME_LEN + 1));
    write_len = sprintf((char *)(__waf_under_attack_time->value.data), "__waf_under_attack_time=%s; Path=/", (char*)now_str);
    __waf_under_attack_time->value.len = (size_t)write_len;


    __waf_under_attack_uid = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    __waf_under_attack_uid->hash = 1;
    __waf_under_attack_uid->key.data = (u_char *)ngx_pnalloc(r->pool, sizeof(u_char) * s_header_key_len);
    ngx_memzero(__waf_under_attack_uid->key.data, sizeof(u_char) * (s_header_key_len + 1));
    __waf_under_attack_uid->key.len = s_header_key_len - 1;
    strcpy((char *)(__waf_under_attack_uid->key.data), "Set-Cookie");

    __waf_under_attack_uid->value.data = (u_char *)ngx_pnalloc(r->pool, sizeof(u_char) * NGX_HTTP_WAF_UNDER_ATTACH_UID_LEN * 2);
    ngx_memzero(__waf_under_attack_uid->value.data, sizeof(u_char) * NGX_HTTP_WAF_UNDER_ATTACH_UID_LEN * 2);
    u_char* uid = ngx_pnalloc(r->pool, sizeof(u_char) * (NGX_HTTP_WAF_UNDER_ATTACH_UID_LEN + 1));
    ngx_http_waf_rand_str(uid, NGX_HTTP_WAF_UNDER_ATTACH_UID_LEN);
    write_len = sprintf((char *)(__waf_under_attack_uid->value.data)
                        , "__waf_under_attack_uid=%s; Path=/",
                        (char *)uid);
    
    __waf_under_attack_uid->value.len = (size_t)write_len;


    __waf_under_attack_verification = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    __waf_under_attack_verification->hash = 1;
    __waf_under_attack_verification->key.data = (u_char *)ngx_pnalloc(r->pool, sizeof(u_char) * s_header_key_len);
    ngx_memzero(__waf_under_attack_verification->key.data, sizeof(u_char) * (s_header_key_len + 1));
    __waf_under_attack_verification->key.len = s_header_key_len - 1;
    strcpy((char *)(__waf_under_attack_verification->key.data), "Set-Cookie");


    __waf_under_attack_verification->value.data = (u_char *)ngx_pnalloc(r->pool, sizeof(u_char) * NGX_HTTP_WAF_SHA256_HEX_LEN * 2);
    u_char* verification = ngx_pnalloc(r->pool, sizeof(u_char) * (NGX_HTTP_WAF_SHA256_HEX_LEN + 1));
    ngx_memzero(__waf_under_attack_verification->value.data, sizeof(u_char) * NGX_HTTP_WAF_SHA256_HEX_LEN * 2);
    ngx_memzero(verification, sizeof(u_char) * (NGX_HTTP_WAF_SHA256_HEX_LEN + 1));
    ngx_http_waf_gen_verification(r,
                                  uid,
                                  NGX_HTTP_WAF_UNDER_ATTACH_UID_LEN,
                                  verification,
                                  NGX_HTTP_WAF_SHA256_HEX_LEN,
                                  now_str,
                                  NGX_HTTP_WAF_UNDER_ATTACH_TIME_LEN);
    write_len = sprintf((char *)(__waf_under_attack_verification->value.data),
                        "__waf_under_attack_verification=%s; Path=/", (char*)verification);
    
    ngx_pfree(r->pool, verification);
    ngx_pfree(r->pool, uid);
    __waf_under_attack_verification->value.len = (size_t)write_len;

    return NGX_HTTP_WAF_TRUE;
}


ngx_int_t ngx_http_waf_gen_verification(ngx_http_request_t *r, 
                                                u_char* uid, 
                                                size_t uid_len, 
                                                u_char* dst, 
                                                size_t dst_len, 
                                                u_char* now,
                                                size_t now_len) {
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);
    size_t buf_len = sizeof(loc_conf->random_str) + sizeof(inx_addr_t) + uid_len + now_len;
    u_char *buf = (u_char *)ngx_pnalloc(r->pool, buf_len);
    ngx_memzero(buf, sizeof(u_char) * buf_len);
    inx_addr_t inx_addr;
    ngx_memzero(&inx_addr, sizeof(inx_addr));

    if (r->connection->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)r->connection->sockaddr;
        ngx_memcpy(&(inx_addr.ipv4), &(sin->sin_addr), sizeof(struct in_addr));

    } 
#if (NGX_HAVE_INET6)
    else if (r->connection->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)r->connection->sockaddr;
        ngx_memcpy(&(inx_addr.ipv6), &(sin6->sin6_addr), sizeof(struct in6_addr));
    }
#endif

    
    size_t offset = 0;

    /* 写入随机字符串 */
    ngx_memcpy(buf+ offset, loc_conf->random_str, sizeof(loc_conf->random_str));
    offset += sizeof(loc_conf->random_str);

    /* 写入时间戳 */
    ngx_memcpy(buf + offset, now, sizeof(u_char) * now_len);
    offset += now_len;

    /* 写入 uid */
    ngx_memcpy(buf + offset, uid, sizeof(u_char) * uid_len);
    offset += uid_len;

    /* 写入 IP 地址 */
    ngx_memcpy(buf + offset, &inx_addr, sizeof(inx_addr_t));
    offset += sizeof(inx_addr_t);

    ngx_int_t ret = ngx_http_waf_sha256(dst, dst_len + 1, buf, buf_len);
    ngx_pfree(r->pool, buf);

    return ret;
}


void ngx_http_waf_gen_ctx_and_header_location(ngx_http_request_t *r) {
    size_t s_header_location_key_len = sizeof("Location");
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    
    ngx_table_elt_t* header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    header->hash = 1;
    header->key.data = ngx_pnalloc(r->pool, sizeof(u_char) * (s_header_location_key_len + 1));
    ngx_memzero(header->key.data, sizeof(u_char) * (s_header_location_key_len + 1));
    ngx_memcpy(header->key.data, "Location", s_header_location_key_len - 1);
    header->key.len = s_header_location_key_len - 1;

    header->value.data = ngx_pnalloc(r->pool, sizeof(u_char) * (loc_conf->waf_under_attack_uri.len + r->uri.len + 32));
    ngx_memzero(header->value.data, sizeof(u_char) * (loc_conf->waf_under_attack_uri.len + r->uri.len + 1));
    u_char* uri = ngx_pnalloc(r->pool, sizeof(u_char) * (r->uri.len + 1));
    ngx_memzero(uri, sizeof(u_char) * (r->uri.len + 1));
    ngx_memcpy(uri, r->uri.data, sizeof(u_char) * r->uri.len);
    header->value.len = sprintf((char*)header->value.data, "%s?target=%s",
            (char*)loc_conf->waf_under_attack_uri.data,
            (char*)uri);
    ngx_pfree(r->pool, uri);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);
    ctx->blocked = NGX_HTTP_WAF_TRUE;
    strcpy((char*)ctx->rule_type, "UNDER-ATTACK");
    ctx->rule_deatils[0] = '\0';
}