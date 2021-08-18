#include <ngx_http_waf_module_under_attack.h>

static ngx_int_t _gen_under_attack_info(ngx_http_request_t* r, under_attack_info_t* under_attack);

/**
 * @brief 生成用于验证五秒盾的三个 Cookie
*/
static ngx_int_t _gen_cookie(ngx_http_request_t *r, under_attack_info_t* under_attack);

/**
 * @brief 生成 Cookie 完整性校验码
*/
static ngx_int_t _gen_verification(ngx_http_request_t *r, under_attack_info_t* under_attack);

static void _gen_ctx(ngx_http_request_t *r);


ngx_int_t ngx_http_waf_handler_under_attack(ngx_http_request_t* r, ngx_int_t* out_http_status) {
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

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Begin the processing flow.");

    ngx_table_elt_t **ppcookie = (ngx_table_elt_t **)(r->headers_in.cookies.elts);
    under_attack_info_t under_attack_client, under_attack_expect;
    ngx_memzero(&under_attack_client, sizeof(under_attack_info_t));
    ngx_memzero(&under_attack_expect, sizeof(under_attack_info_t));

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Start parsing cookies.");

    for (size_t i = 0; i < r->headers_in.cookies.nelts; i++, ppcookie++) {
        ngx_table_elt_t *native_cookie = *ppcookie;
        UT_array* cookies = NULL;
        if (ngx_http_waf_parse_cookie(&(native_cookie->value), &cookies) != NGX_HTTP_WAF_SUCCESS) {
            continue;
        }

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

            if (ngx_strcmp(key->data, "__waf_under_attack_time") == 0) {
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: Being parsed __waf_under_attack_time.");
                ngx_memcpy(under_attack_client.time, value->data, ngx_min(sizeof(under_attack_client.time) - 1, value->len));
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: Successfully get __waf_under_attack_time.");
            }
            else if (ngx_strcmp(key->data, "__waf_under_attack_uid") == 0) {
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: Being parsed __waf_under_attack_uid.");
                ngx_memcpy(under_attack_client.uid, value->data, ngx_min(sizeof(under_attack_client.uid) - 1, value->len));
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: Successfully get __waf_under_attack_uid.");
            }
            else if (ngx_strcmp(key->data, "__waf_under_attack_hmac") == 0) {
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: Being parsed __waf_under_attack_hmac.");
                ngx_memcpy(under_attack_client.hmac, value->data, ngx_min(sizeof(under_attack_client.hmac) - 1, value->len));
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: Successfully get __waf_under_attack_hmac.");
            }

        } while (p != NULL);


        utarray_free(cookies);
    }


    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Successfully parsed all cookies.");

    ngx_memcpy(&under_attack_expect, &under_attack_client, sizeof(under_attack_info_t));


    if (_gen_verification(r, &under_attack_expect) != NGX_HTTP_WAF_SUCCESS) {
        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_MATCHED;
    }

    /* 验证 token 是否正确 */
    if (ngx_memcmp(&under_attack_client, &under_attack_expect, sizeof(under_attack_info_t)) != 0) {
        _gen_under_attack_info(r, &under_attack_expect);
        _gen_cookie(r, &under_attack_expect);
        *out_http_status = NGX_DECLINED;
        _gen_ctx(r);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Wrong __waf_under_attack_verification.");
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Processing is complete.");
        return NGX_HTTP_WAF_MATCHED;
    }


    /* 验证时间是否超过 5 秒 */
    time_t client_time = ngx_atoi(under_attack_client.time, ngx_strlen(under_attack_client.time));
    /* 如果 Cookie 不合法 或 已经超过 30 分钟 */
    if (client_time == NGX_ERROR || difftime(time(NULL), client_time) > 60 * 30) {
        _gen_under_attack_info(r, &under_attack_expect);
        _gen_cookie(r, &under_attack_expect);
        *out_http_status = NGX_DECLINED;
        _gen_ctx(r);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Wrong __waf_under_attack_verification.");
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Processing is complete.");
        return NGX_HTTP_WAF_MATCHED;
    } else if (difftime(time(NULL), client_time) <= 5) {
        *out_http_status = NGX_DECLINED;
        _gen_ctx(r);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Not five seconds have passed.");
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Processing is complete.");
        return NGX_HTTP_WAF_MATCHED;
    }

    return NGX_HTTP_WAF_NOT_MATCHED;
}


static ngx_int_t _gen_under_attack_info(ngx_http_request_t* r, under_attack_info_t* under_attack) {
    time_t now = time(NULL);

    #if (NGX_TIME_T_SIZE == 4)
        sprintf((char*)under_attack->time, "%d", (int)now);
    #elif (NGX_TIME_T_SIZE == 8)
        sprintf((char*)under_attack->time, "%lld", (long long)now);
    #else
        #error The size of time_t is unexpected.
    #endif

    if (ngx_http_waf_rand_str(under_attack->uid, sizeof(under_attack->uid) - 1) != NGX_HTTP_WAF_SUCCESS) {
        return NGX_HTTP_WAF_FAIL;
    }

    return _gen_verification(r, under_attack);
}


static ngx_int_t _gen_cookie(ngx_http_request_t *r, under_attack_info_t* under_attack) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);
    if (ctx->under_attack == NGX_HTTP_WAF_TRUE) {
        return NGX_HTTP_WAF_SUCCESS;
    }

    ngx_table_elt_t *header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");
    header->value.data = ngx_pnalloc(r->pool, sizeof(under_attack->time) + 64);
    header->value.len = sprintf((char*)header->value.data, "__waf_under_attack_time=%s; Path=/", under_attack->time);

    header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");
    header->value.data = ngx_pnalloc(r->pool, sizeof(under_attack->uid) + 64);
    header->value.len = sprintf((char*)header->value.data, "__waf_under_attack_uid=%s; Path=/", under_attack->uid);

    header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");
    header->value.data = ngx_pnalloc(r->pool, sizeof(under_attack->hmac) + 64);
    header->value.len = sprintf((char*)header->value.data, "__waf_under_attack_hmac=%s; Path=/", under_attack->hmac);


    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t _gen_verification(ngx_http_request_t *r, under_attack_info_t* under_attack) {
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
    return ngx_http_waf_sha256(under_attack->hmac, sizeof(under_attack->hmac), &buf, sizeof(buf));
}


static void _gen_ctx(ngx_http_request_t *r) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);
    
    ctx->blocked = NGX_HTTP_WAF_TRUE;
    ctx->under_attack = NGX_HTTP_WAF_TRUE;
    strcpy((char*)ctx->rule_type, "UNDER-ATTACK");
    ctx->rule_deatils[0] = '\0';
}