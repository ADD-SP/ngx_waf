#include <ngx_http_waf_module_under_attack.h>

typedef struct {
    u_char time[NGX_TIME_T_LEN + 1];
    u_char uid[NGX_HTTP_WAF_UID_LEN + 1];
    u_char hmac[crypto_hash_sha256_BYTES * 2 + 1];
} _info_t;

static ngx_int_t _gen_under_attack_info(ngx_http_request_t* r, _info_t* under_attack);

/**
 * @brief 生成用于验证五秒盾的三个 Cookie
*/
static ngx_int_t _gen_cookie(ngx_http_request_t *r, _info_t* under_attack);


/**
 * @brief 生成 Cookie 完整性校验码
*/
static ngx_int_t _gen_verification(ngx_http_request_t *r, _info_t* under_attack);


ngx_int_t ngx_http_waf_handler_under_attack(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_under_attack)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    _info_t* under_attack_client = ngx_pcalloc(r->pool, sizeof(_info_t));
    _info_t* under_attack_expect = ngx_pcalloc(r->pool, sizeof(_info_t));

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
        ngx_http_waf_dpf(r, "searching cookie %V", &key);

#if (nginx_version >= 1023000)
        if (ngx_http_parse_multi_header_lines(r, cookies, &key, &value) != NULL) {
#else
        if (ngx_http_parse_multi_header_lines(cookies, &key, &value) != NGX_DECLINED) {
#endif
            ngx_http_waf_dpf(r, "found cookie %V", &key);
            ngx_memcpy(under_attack_client->time, value.data, value.len);

        } else {
            ngx_http_waf_dpf(r, "not found cookie %V", &key);
        }

        ngx_str_set(&key, "__waf_under_attack_uid");
        ngx_str_null(&value);
        ngx_http_waf_dpf(r, "searching cookie %V", &key);

#if (nginx_version >= 1023000)
        if (ngx_http_parse_multi_header_lines(r, cookies, &key, &value) != NULL) {
#else
        if (ngx_http_parse_multi_header_lines(cookies, &key, &value) != NGX_DECLINED) {
#endif
            ngx_http_waf_dpf(r, "found cookie %V", &key);
            ngx_memcpy(under_attack_client->uid, value.data, value.len);

        } else {
            ngx_http_waf_dpf(r, "not found cookie %V", &key);
        }

        ngx_str_set(&key, "__waf_under_attack_hmac");
        ngx_str_null(&value);
        ngx_http_waf_dpf(r, "searching cookie %V", &key);

#if (nginx_version >= 1023000)
        if (ngx_http_parse_multi_header_lines(r, cookies, &key, &value) != NULL) {
#else
        if (ngx_http_parse_multi_header_lines(cookies, &key, &value) != NGX_DECLINED) {
#endif
            ngx_http_waf_dpf(r, "found cookie %V", &key);
            ngx_memcpy(under_attack_client->hmac, value.data, value.len);

        } else {
            ngx_http_waf_dpf(r, "not found cookie %V", &key);
        }
    }

    ngx_memcpy(under_attack_expect, under_attack_client, sizeof(_info_t));

    ngx_http_waf_dp(r, "generating expected message")
    if (_gen_verification(r, under_attack_expect) != NGX_HTTP_WAF_SUCCESS) {
        ngx_http_waf_dp(r, "failed ... return");
        ngx_http_waf_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_UNDER_ATTACK);
        return NGX_HTTP_WAF_MATCHED;
    }
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dpf(r, "client.time=%s, client.uid=%s, client.hmac=%s", 
        under_attack_client->time, under_attack_client->uid, under_attack_client->hmac);

    ngx_http_waf_dpf(r, "expect.time=%s, expect.uid=%s, expect.hmac=%s", 
        under_attack_expect->time, under_attack_expect->uid, under_attack_expect->hmac);

    /* 验证 token 是否正确 */
    ngx_http_waf_dp(r, "verifying info");
    if (ngx_memcmp(under_attack_client, under_attack_expect, sizeof(_info_t)) != 0) {
        ngx_http_waf_dp(r, "failed");

        ngx_http_waf_dp(r, "generating new info");
        if (_gen_under_attack_info(r, under_attack_expect) != NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dp(r, "failed ... return");
            ngx_http_waf_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_UNDER_ATTACK);
            return NGX_HTTP_WAF_MATCHED;
        }
        ngx_http_waf_dp(r, "success");

        ngx_http_waf_dp(r, "generating new cookies");
        if (_gen_cookie(r, under_attack_expect) != NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dp(r, "failed ... return");
            ngx_http_waf_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_UNDER_ATTACK);
            return NGX_HTTP_WAF_MATCHED;
        }
        ngx_http_waf_dp(r, "success ... return");
        
        ngx_http_waf_append_action_under_attack(r, ACTION_FLAG_FROM_UNDER_ATTACK);   
        ngx_http_waf_set_rule_info(r, "UNDER-ATTACK", "", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);

        return NGX_HTTP_WAF_MATCHED;
    }


    /* 验证时间是否超过 5 秒 */
    ngx_http_waf_dp(r, "is expired?");
    time_t client_time = ngx_atoi(under_attack_client->time, ngx_strlen(under_attack_client->time));
    /* 如果 Cookie 不合法 或 已经超过 30 分钟 */
    if (client_time == NGX_ERROR || difftime(time(NULL), client_time) > 60 * 30) {
        ngx_http_waf_dp(r, "expired info");

        ngx_http_waf_dp(r, "generating new info");
        if (_gen_under_attack_info(r, under_attack_expect) != NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dp(r, "failed ... return");
            ngx_http_waf_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_UNDER_ATTACK);
            return NGX_HTTP_WAF_MATCHED;
        }
        ngx_http_waf_dp(r, "success");

        ngx_http_waf_dp(r, "generating new cookies");
        if (_gen_cookie(r, under_attack_expect) != NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dp(r, "failed ... return");
            ngx_http_waf_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_UNDER_ATTACK);
            return NGX_HTTP_WAF_MATCHED;
        }
        ngx_http_waf_dp(r, "success ... return");

        ngx_http_waf_append_action_under_attack(r, ACTION_FLAG_FROM_UNDER_ATTACK);
        ngx_http_waf_set_rule_info(r, "UNDER-ATTACK", "", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
        return NGX_HTTP_WAF_MATCHED;

    } else if (difftime(time(NULL), client_time) <= 5) {
        ngx_http_waf_dp(r, "on delay ... return");
        ngx_http_waf_append_action_under_attack(r, ACTION_FLAG_FROM_UNDER_ATTACK);
        ngx_http_waf_set_rule_info(r, "UNDER-ATTACK", "", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
        return NGX_HTTP_WAF_MATCHED;
    }

    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_NOT_MATCHED;
}


static ngx_int_t _gen_under_attack_info(ngx_http_request_t* r, _info_t* under_attack) {
    ngx_http_waf_dp_func_start(r);

    time_t now = time(NULL);

    #if (NGX_TIME_T_SIZE == 4)
        sprintf((char*)under_attack->time, "%d", (int)now);
    #elif (NGX_TIME_T_SIZE == 8)
        sprintf((char*)under_attack->time, "%lld", (long long)now);
    #else
        #error The size of time_t is unexpected.
    #endif

    ngx_http_waf_dp(r, "generating random string");
    if (ngx_http_waf_rand_str(under_attack->uid, sizeof(under_attack->uid) - 1) != NGX_HTTP_WAF_SUCCESS) {
        ngx_http_waf_dp(r, "failed ... return");
        return NGX_HTTP_WAF_FAIL;
    }
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dp_func_end(r);
    return _gen_verification(r, under_attack);
}


static ngx_int_t _gen_cookie(ngx_http_request_t *r, _info_t* under_attack) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    ngx_table_elt_t *header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");
    header->value.data = ngx_pnalloc(r->pool, sizeof(under_attack->time) + 64);
    header->value.len = sprintf((char*)header->value.data, "__waf_under_attack_time=%s; Path=/", under_attack->time);
    ngx_http_waf_dpf(r, "Header %V: %V", &header->key, &header->value);

    header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");
    header->value.data = ngx_pnalloc(r->pool, sizeof(under_attack->uid) + 64);
    header->value.len = sprintf((char*)header->value.data, "__waf_under_attack_uid=%s; Path=/", under_attack->uid);
    ngx_http_waf_dpf(r, "Header %V: %V", &header->key, &header->value);

    header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");
    header->value.data = ngx_pnalloc(r->pool, sizeof(under_attack->hmac) + 64);
    header->value.len = sprintf((char*)header->value.data, "__waf_under_attack_hmac=%s; Path=/", under_attack->hmac);
    ngx_http_waf_dpf(r, "Header %V: %V", &header->key, &header->value);

    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t _gen_verification(ngx_http_request_t *r, _info_t* under_attack) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    struct {
        inx_addr_t inx_addr;
        u_char time[NGX_TIME_T_LEN + 1];
        u_char uid[NGX_HTTP_WAF_UID_LEN + 1];
        u_char salt[129];
    } buf;
    ngx_memzero(&buf, sizeof(buf));
    ngx_memcpy(buf.time, under_attack->time, sizeof(buf.time));
    ngx_memcpy(buf.uid, under_attack->uid, sizeof(buf.uid));
    ngx_memcpy(buf.salt, loc_conf->random_str, sizeof(buf.salt));

    ngx_http_waf_dpf(r, "time=%s, uid=%s, salt=%s", buf.time, buf.uid, buf.salt);

    if (r->connection->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)r->connection->sockaddr;
        ngx_memcpy(&(buf.inx_addr.ipv4), &(sin->sin_addr), sizeof(struct in_addr));

    } 
#if (NGX_HAVE_INET6)
    else if (r->connection->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)r->connection->sockaddr;
        ngx_memcpy(&(buf.inx_addr.ipv6), &(sin6->sin6_addr), sizeof(struct in6_addr));
    }
#endif

    ngx_memzero(under_attack->hmac, sizeof(under_attack->hmac));

    ngx_http_waf_dp_func_end(r);
    return ngx_http_waf_sha256(under_attack->hmac, sizeof(under_attack->hmac), &buf, sizeof(buf));
}