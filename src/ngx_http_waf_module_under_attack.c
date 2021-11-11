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


static void _gen_ctx(ngx_http_request_t *r);


ngx_int_t ngx_http_waf_handler_under_attack(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_dp(r, "ngx_http_waf_handler_under_attack() ... start");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_under_attack)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }


    ngx_table_elt_t **ppcookie = (ngx_table_elt_t **)(r->headers_in.cookies.elts);
    _info_t under_attack_client, under_attack_expect;
    ngx_memzero(&under_attack_client, sizeof(_info_t));
    ngx_memzero(&under_attack_expect, sizeof(_info_t));


    for (size_t i = 0; i < r->headers_in.cookies.nelts; i++, ppcookie++) {
        ngx_table_elt_t *native_cookie = *ppcookie;
        UT_array* cookies = NULL;

        ngx_http_waf_dpf(r, "parsing cookie %V", &native_cookie->value);
        if (ngx_http_waf_parse_cookie(&(native_cookie->value), &cookies) != NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dp(r, "failed ... continuse");
            continue;
        }
        ngx_http_waf_dp(r, "success");

        ngx_str_t* key = NULL;
        ngx_str_t* value = NULL;
        ngx_str_t* p = NULL;

        do {
            if (key = (ngx_str_t*)utarray_next(cookies, p), p = key, key == NULL) {
                break;
            }

            if (value = (ngx_str_t*)utarray_next(cookies, p), p = value, value == NULL) {
                break;
            }

            ngx_http_waf_dpf(r, "%V: %V", key, value);

            if (ngx_strcmp(key->data, "__waf_under_attack_time") == 0) {
                ngx_memcpy(under_attack_client.time, value->data, ngx_min(sizeof(under_attack_client.time) - 1, value->len));
            }
            else if (ngx_strcmp(key->data, "__waf_under_attack_uid") == 0) {
                ngx_memcpy(under_attack_client.uid, value->data, ngx_min(sizeof(under_attack_client.uid) - 1, value->len));
            }
            else if (ngx_strcmp(key->data, "__waf_under_attack_hmac") == 0) {
                ngx_memcpy(under_attack_client.hmac, value->data, ngx_min(sizeof(under_attack_client.hmac) - 1, value->len));
            }

        } while (p != NULL);
        utarray_free(cookies);
    }

    ngx_memcpy(&under_attack_expect, &under_attack_client, sizeof(_info_t));

    ngx_http_waf_dp(r, "generating expected message")
    if (_gen_verification(r, &under_attack_expect) != NGX_HTTP_WAF_SUCCESS) {
        ngx_http_waf_dp(r, "failed ... return");
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dpf(r, "client.time=%s, client.uid=%s, client.hmac=%s", 
        under_attack_client.time, under_attack_client.uid, under_attack_client.hmac);

    ngx_http_waf_dpf(r, "expect.time=%s, expect.uid=%s, expect.hmac=%s", 
        under_attack_expect.time, under_attack_expect.uid, under_attack_expect.hmac);

    /* 验证 token 是否正确 */
    ngx_http_waf_dp(r, "verifying info");
    if (ngx_memcmp(&under_attack_client, &under_attack_expect, sizeof(_info_t)) != 0) {
        ngx_http_waf_dp(r, "failed");

        _gen_ctx(r);

        ngx_http_waf_dp(r, "generating new info");
        if (_gen_under_attack_info(r, &under_attack_expect) != NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dp(r, "failed ... return");
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }
        ngx_http_waf_dp(r, "success");

        ngx_http_waf_dp(r, "generating new cookies");
        if (_gen_cookie(r, &under_attack_expect) != NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dp(r, "failed ... return");
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }
        ngx_http_waf_dp(r, "success ... return");
        
        *out_http_status = NGX_DECLINED;
        return NGX_HTTP_WAF_MATCHED;
    }


    /* 验证时间是否超过 5 秒 */
    ngx_http_waf_dp(r, "is expired?");
    time_t client_time = ngx_atoi(under_attack_client.time, ngx_strlen(under_attack_client.time));
    /* 如果 Cookie 不合法 或 已经超过 30 分钟 */
    if (client_time == NGX_ERROR || difftime(time(NULL), client_time) > 60 * 30) {
        ngx_http_waf_dp(r, "expired info");

        _gen_ctx(r);

        ngx_http_waf_dp(r, "generating new info");
        if (_gen_under_attack_info(r, &under_attack_expect) != NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dp(r, "failed ... return");
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }
        ngx_http_waf_dp(r, "success");

        ngx_http_waf_dp(r, "generating new cookies");
        if (_gen_cookie(r, &under_attack_expect) != NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dp(r, "failed ... return");
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        }
        ngx_http_waf_dp(r, "success ... return");

        *out_http_status = NGX_DECLINED;
        return NGX_HTTP_WAF_MATCHED;
    } else if (difftime(time(NULL), client_time) <= 5) {
        ngx_http_waf_dp(r, "on delay ... return");
        *out_http_status = NGX_DECLINED;
        _gen_ctx(r);
        return NGX_HTTP_WAF_MATCHED;
    }

    ngx_http_waf_dp(r, "ngx_http_waf_handler_under_attack() ... end");
    return NGX_HTTP_WAF_NOT_MATCHED;
}


static ngx_int_t _gen_under_attack_info(ngx_http_request_t* r, _info_t* under_attack) {
    ngx_http_waf_dp(r, "_gen_under_attack_info() ... start");

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

    ngx_http_waf_dp(r, "_gen_under_attack_info() ... end");
    return _gen_verification(r, under_attack);
}


static ngx_int_t _gen_cookie(ngx_http_request_t *r, _info_t* under_attack) {
    ngx_http_waf_dp(r, "_gen_cookie() ... start");

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

    ngx_http_waf_dp(r, "_gen_cookie() ... end");
    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t _gen_verification(ngx_http_request_t *r, _info_t* under_attack) {
    ngx_http_waf_dp(r, "_gen_verification() ... start");

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

    ngx_http_waf_dp(r, "_gen_verification() ... end");
    return ngx_http_waf_sha256(under_attack->hmac, sizeof(under_attack->hmac), &buf, sizeof(buf));
}


static void _gen_ctx(ngx_http_request_t *r) {
    ngx_http_waf_dp(r, "_gen_ctx() ... start");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    ngx_http_waf_register_content_handler(r);
    
    ctx->gernal_logged = 1;
    ctx->blocked = 1;
    ctx->under_attack = 1;
    ngx_http_waf_set_rule_info(r, "UNDER-ATTACK", "");

    ngx_http_waf_dp(r, "_gen_ctx() ... end");
}