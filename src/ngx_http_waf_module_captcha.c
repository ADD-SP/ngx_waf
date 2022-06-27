#include <ngx_http_waf_module_captcha.h>

typedef struct {
    u_char time[NGX_TIME_T_LEN + 1];
    u_char uid[NGX_HTTP_WAF_UID_LEN + 1];
    u_char hmac[crypto_hash_sha256_BYTES * 2 + 1];
} _info_t;


typedef struct _cache_info_s {
    ngx_int_t count;
} _cache_info_t;


static ngx_int_t _gen_info(ngx_http_request_t* r, _info_t* info);

static ngx_int_t _gen_verify_cookie(ngx_http_request_t *r, _info_t* info);

static ngx_int_t _gen_hmac(ngx_http_request_t* r, _info_t* info);

static ngx_int_t _verify_cookies(ngx_http_request_t* r);

static ngx_int_t _verify_captcha_dispatcher(ngx_http_request_t* r);

static ngx_int_t _verify_hCaptcha(ngx_http_request_t* r);

static ngx_int_t _verify_reCAPTCHAv2(ngx_http_request_t* r);

static ngx_int_t _verify_reCAPTCHAv3(ngx_http_request_t* r);

static ngx_int_t _verfiy_reCAPTCHA_compatible(ngx_http_request_t* r, 
    ngx_str_t response_key, 
    ngx_str_t secret,
    ngx_str_t url,
    ngx_int_t is_reCAPTCHA_v3,
    ngx_int_t score);


ngx_int_t ngx_http_waf_handler_captcha(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_captcha)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ngx_http_waf_dp(r, "verifying cookie");    
    switch (_verify_cookies(r)) {
        case NGX_HTTP_WAF_FAULT:
            ngx_http_waf_dp(r, "bad ... return");
            ngx_http_waf_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_CAPTCHA);
            return NGX_HTTP_WAF_MATCHED;
        case NGX_HTTP_WAF_SUCCESS:
            ngx_http_waf_dp(r, "success");

            ngx_http_waf_dpf(r, "checking if request_uri(%V) equals verify_url(%V)", 
                &r->uri, &loc_conf->waf_captcha_verify_url);
            
            if (r->uri.len == loc_conf->waf_captcha_verify_url.len
            && ngx_memcmp(r->uri.data, loc_conf->waf_captcha_verify_url.data, r->uri.len) == 0) {
                ngx_http_waf_dp(r, "equal");
                ngx_str_t* res_str = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
                ngx_str_set(res_str, "good");
                ngx_http_waf_append_action_str(r, res_str, NGX_HTTP_OK, ACTION_FLAG_FROM_CAPTCHA);
                return NGX_HTTP_WAF_MATCHED;
            }

            ngx_http_waf_dp(r, "not equal");
            break;

        case NGX_HTTP_WAF_FAIL:
            ngx_http_waf_dp(r, "failed");
            ngx_http_waf_dp(r, "verifying captcha");

            switch (_verify_captcha_dispatcher(r)) {
                case NGX_HTTP_WAF_FAULT:
                    ngx_http_waf_dp(r, "bad ... return");
                    ngx_http_waf_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_CAPTCHA);
                    return NGX_HTTP_WAF_MATCHED;

                case NGX_HTTP_WAF_CAPTCHA_CHALLENGE:
                    ngx_http_waf_dp(r, "challenging ... return");

                    if (ngx_http_waf_captcha_inc_fails(r) == NGX_HTTP_WAF_MATCHED) {
                        ngx_http_waf_set_rule_info(r, "CAPTCHA", "TO MANY FAILS", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
                        
                        if (ngx_is_null_str(&loc_conf->waf_block_page)) {
                            ngx_http_waf_append_action_return(r, NGX_HTTP_TOO_MANY_REQUESTS, ACTION_FLAG_FROM_CAPTCHA);

                        } else {
                            ngx_http_waf_append_action_html(r,
                                &loc_conf->waf_block_page,
                                NGX_HTTP_TOO_MANY_REQUESTS,
                                ACTION_FLAG_FROM_CAPTCHA);
                        }

                    } else {
                        ngx_http_waf_set_rule_info(r, "CAPTCHA", "CHALLENGE", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
                        ngx_http_waf_append_action_captcha(r, ACTION_FLAG_FROM_CAPTCHA);
                        
                    }
                    
                    return NGX_HTTP_WAF_MATCHED;

                case NGX_HTTP_WAF_CAPTCHA_BAD:
                    ngx_http_waf_dp(r, "captcha bad ... return");

                    if (ngx_http_waf_captcha_inc_fails(r) == NGX_HTTP_WAF_MATCHED) {
                        ngx_http_waf_set_rule_info(r, "CAPTCHA", "TO MANY FAILS", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
                        
                        if (ngx_is_null_str(&loc_conf->waf_block_page)) {
                            ngx_http_waf_append_action_return(r, NGX_HTTP_TOO_MANY_REQUESTS, ACTION_FLAG_FROM_CAPTCHA);

                        } else {
                            ngx_http_waf_append_action_html(r,
                                &loc_conf->waf_block_page,
                                NGX_HTTP_TOO_MANY_REQUESTS,
                                ACTION_FLAG_FROM_CAPTCHA);
                        }

                    } else {
                        ngx_http_waf_set_rule_info(r, "CAPTCHA", "bad", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
                        ngx_str_t* res_str = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
                        ngx_str_set(res_str, "bad");
                        ngx_http_waf_append_action_str(r, res_str, NGX_HTTP_OK, ACTION_FLAG_FROM_CAPTCHA);
                        
                    }
                    
                    return NGX_HTTP_WAF_MATCHED;

                case NGX_HTTP_WAF_CAPTCHA_PASS:
                {
                    ngx_http_waf_dp(r, "pass");
                    ngx_http_waf_dp(r, "generating releated info");
                    _info_t* info = ngx_pcalloc(r->pool, sizeof(_info_t));

                    if (info != NULL
                    &&  _gen_info(r, info) == NGX_HTTP_WAF_SUCCESS
                    &&  _gen_verify_cookie(r, info) == NGX_HTTP_WAF_SUCCESS) {
                        ngx_http_waf_dp(r, "success ... return");
                        ngx_http_waf_set_rule_info(r, "CAPTCHA", "PASS", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
                        ngx_str_t* res_str = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
                        ngx_str_set(res_str, "good");
                        ngx_http_waf_append_action_str(r, res_str, NGX_HTTP_OK, ACTION_FLAG_FROM_CAPTCHA);

                    } else {
                        ngx_http_waf_dp(r, "failed ... return");
                        ngx_http_waf_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_CAPTCHA);
                    }

                    return NGX_HTTP_WAF_MATCHED;
                }
                case NGX_HTTP_WAF_FAIL:
                    ngx_http_waf_dp(r, "failed ... return");
                    
                    if (ngx_http_waf_captcha_inc_fails(r) == NGX_HTTP_WAF_MATCHED) {
                        ngx_http_waf_set_rule_info(r, "CAPTCHA", "TO MANY FAILS", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
                        
                        if (ngx_is_null_str(&loc_conf->waf_block_page)) {
                            ngx_http_waf_append_action_return(r, NGX_HTTP_TOO_MANY_REQUESTS, ACTION_FLAG_FROM_CAPTCHA);

                        } else {
                            ngx_http_waf_append_action_html(r,
                                &loc_conf->waf_block_page,
                                NGX_HTTP_TOO_MANY_REQUESTS,
                                ACTION_FLAG_FROM_CAPTCHA);
                        }

                    } else {
                        ngx_http_waf_set_rule_info(r, "CAPTCHA", "CHALLENGE", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
                        ngx_http_waf_append_action_captcha(r, ACTION_FLAG_FROM_CAPTCHA);
                        
                    }

                    return NGX_HTTP_WAF_MATCHED;
                default:
                    ngx_http_waf_dp(r, "default ... return");
                    ngx_http_waf_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_CAPTCHA);
                    return NGX_HTTP_WAF_MATCHED;
            }
            break;
        default:
            ngx_http_waf_dp(r, "default ... return");
            ngx_http_waf_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_CAPTCHA);
            return NGX_HTTP_WAF_MATCHED;
    }

    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_NOT_MATCHED;
}


ngx_int_t ngx_http_waf_captcha_test(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_http_waf_dp(r, "verifying captcha");
    switch (_verify_captcha_dispatcher(r)) {
        case NGX_HTTP_WAF_FAULT:
            ngx_http_waf_dp(r, "bad ... return");
            return NGX_HTTP_WAF_FAULT;
        case NGX_HTTP_WAF_CAPTCHA_CHALLENGE:
            ngx_http_waf_dp(r, "challenging ... return");
            return NGX_HTTP_WAF_CAPTCHA_CHALLENGE;
        case NGX_HTTP_WAF_CAPTCHA_BAD:
            ngx_http_waf_dp(r, "bad captcha ... return");
            return NGX_HTTP_WAF_CAPTCHA_BAD;
        case NGX_HTTP_WAF_CAPTCHA_PASS:
            ngx_http_waf_dp(r, "captcha pass ... return");
            return NGX_HTTP_WAF_CAPTCHA_PASS;
        case NGX_HTTP_WAF_FAIL:
            ngx_http_waf_dp(r, "failed ... return");
            return NGX_HTTP_WAF_CAPTCHA_CHALLENGE;
        default:
            ngx_http_waf_dp(r, "default ... return");
            return NGX_HTTP_WAF_FAULT;
    }

    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_FAULT;
}


ngx_int_t ngx_http_waf_captcha_inc_fails(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_captcha_max_fails)
        || ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_captcha_duration)) {

        ngx_http_waf_dp(r, "unset or disable conf ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    if (!ngx_http_waf_is_valid_ptr_value(loc_conf->waf_captcha_cache)) {
        ngx_http_waf_dp(r, "cache is null ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    inx_addr_t inx_addr;
    ngx_http_waf_make_inx_addr(r, &inx_addr);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    lru_cache_t* cache = loc_conf->waf_captcha_cache;
    ngx_slab_pool_t* shpool = (ngx_slab_pool_t*)loc_conf->waf_captcha_shm_zone->shm.addr;

    ngx_http_waf_dp(r, "locking shared memory");
    ngx_shmtx_lock(&shpool->mutex);
    ngx_http_waf_dp(r, "success");

    /** 过期时间为 [15, 60] 分钟 */
    time_t expire = (time_t)randombytes_uniform(60 * 15) + 60 * 45;
    lru_cache_find_result_t result = lru_cache_add(cache, &inx_addr, sizeof(inx_addr), expire);

    if (result.status == NGX_HTTP_WAF_SUCCESS) {
        _cache_info_t* tmp = lru_cache_calloc(cache, sizeof(_cache_info_t));

        if (tmp == NULL) {
            ngx_http_waf_dp(r, "no memory ... return");

        } else {
            *result.data = tmp;
            tmp->count = 1;
        }
    } else if (result.status == NGX_HTTP_WAF_KEY_EXISTS) {
        _cache_info_t* tmp = *result.data;

        if (tmp->count != NGX_MAX_INT_T_VALUE) {
            tmp->count++;
        }

        if (tmp->count > ngx_max(loc_conf->waf_captcha_max_fails, 20)) {
            if (tmp->count -1 <= ngx_max(loc_conf->waf_captcha_max_fails, 20)) {
                lru_cache_set_expire(cache, &inx_addr, sizeof(inx_addr_t), 
                    loc_conf->waf_captcha_duration);
            }

            ret_value = NGX_HTTP_WAF_MATCHED;
        }
    }

    ngx_http_waf_dp(r, "unlocking shared memory")
    ngx_shmtx_unlock(&shpool->mutex);
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


static ngx_int_t _gen_info(ngx_http_request_t* r, _info_t* info) {
    ngx_http_waf_dp_func_start(r);

    time_t now = time(NULL);

    #if (NGX_TIME_T_SIZE == 4)
        sprintf((char*)info->time, "%d", (int)now);
    #elif (NGX_TIME_T_SIZE == 8)
        sprintf((char*)info->time, "%lld", (long long)now);
    #else
        #error The size of time_t is unexpected.
    #endif

    ngx_http_waf_dp(r, "generating random string");
    if (ngx_http_waf_rand_str(info->uid, sizeof(info->uid) - 1) != NGX_HTTP_WAF_SUCCESS) {
        ngx_http_waf_dp(r, "failed ... return");
        return NGX_HTTP_WAF_FAIL;
    }
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dp_func_end(r);
    return _gen_hmac(r, info);
}


static ngx_int_t _gen_verify_cookie(ngx_http_request_t *r, _info_t* info) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    ngx_http_waf_dpf(r, "generating cookie %s", "__waf_captcha_time");
    ngx_table_elt_t *header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        ngx_http_waf_dp(r, "failed ... return");
        return NGX_HTTP_WAF_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");
    header->value.data = ngx_pnalloc(r->pool, sizeof(info->time) + 64);
    header->value.len = sprintf((char*)header->value.data, "__waf_captcha_time=%s; Path=/", info->time);
    ngx_http_waf_dpf(r, "success %V", &header->value);

    ngx_http_waf_dpf(r, "generating cookie %s", "__waf_captcha_uid");
    header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        ngx_http_waf_dp(r, "failed ... return");
        return NGX_HTTP_WAF_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");
    header->value.data = ngx_pnalloc(r->pool, sizeof(info->uid) + 64);
    header->value.len = sprintf((char*)header->value.data, "__waf_captcha_uid=%s; Path=/", info->uid);
    ngx_http_waf_dpf(r, "success %V", &header->value);

    ngx_http_waf_dpf(r, "generating cookie %s", "__waf_captcha_hmac");
    header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        ngx_http_waf_dp(r, "failed ... return");
        return NGX_HTTP_WAF_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");
    header->value.data = ngx_pnalloc(r->pool, sizeof(info->hmac) + 64);
    header->value.len = sprintf((char*)header->value.data, "__waf_captcha_hmac=%s; Path=/", info->hmac);
    ngx_http_waf_dpf(r, "success %V", &header->value);

    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t _gen_hmac(ngx_http_request_t *r, _info_t* info) {
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
    ngx_memcpy(buf.time, info->time, sizeof(buf.time));
    ngx_memcpy(buf.uid, info->uid, sizeof(buf.uid));
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

    ngx_memzero(info->hmac, sizeof(info->hmac));

    ngx_http_waf_dp(r, "getting hmac");
    ngx_int_t ret = ngx_http_waf_sha256(info->hmac, sizeof(info->hmac), &buf, sizeof(buf));
    if (ret == NGX_HTTP_WAF_SUCCESS) {
        ngx_http_waf_dpf(r, "success(%s)", info->hmac);
    } else {
        ngx_http_waf_dp(r, "failed");
    }

    ngx_http_waf_dp_func_end(r);
    return ret;
}


static ngx_int_t _verify_cookies(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    _info_t* under_attack_client = ngx_pcalloc(r->pool, sizeof(_info_t));
    _info_t* under_attack_expect = ngx_pcalloc(r->pool, sizeof(_info_t));

    if (under_attack_client == NULL || under_attack_expect == NULL) {
        ngx_http_waf_dp(r, "no memcoy ... return");
        return NGX_HTTP_WAF_FAULT;
    }

    ngx_memzero(under_attack_client, sizeof(_info_t));
    ngx_memzero(under_attack_expect, sizeof(_info_t));

#if (nginx_version >= 1023000)
    if (r->headers_in.cookie != NULL) {
        ngx_table_elt_t* cookies = r->headers_in.cookie;
#else
    if (r->headers_in.cookies.nelts > 0) {
        ngx_array_t* cookies = &(r->headers_in.cookies);
#endif
        ngx_str_t key, value;

        ngx_str_set(&key, "__waf_captcha_uid");
        ngx_str_null(&value);
        ngx_http_waf_dpf(r, "searching cookie %V", &key);

#if (nginx_version >= 1023000)
        if (ngx_http_parse_multi_header_lines(r, cookies, &key, &value) != NULL) {
#else
        if (ngx_http_parse_multi_header_lines(cookies, &key, &value) != NGX_DECLINED) {
#endif
            ngx_http_waf_dpf(r, "found cookie %V", &value);
            ngx_memcpy(under_attack_client->uid, value.data, value.len);

        } else {
            ngx_http_waf_dpf(r, "not found cookie %V", &key);
        }

        ngx_str_set(&key, "__waf_captcha_hmac");
        ngx_str_null(&value);
        ngx_http_waf_dpf(r, "searching cookie %V", &key);

#if (nginx_version >= 1023000)
        if (ngx_http_parse_multi_header_lines(r, cookies, &key, &value) != NULL) {
#else
        if (ngx_http_parse_multi_header_lines(cookies, &key, &value) != NGX_DECLINED) {
#endif
            ngx_http_waf_dpf(r, "found cookie %V", &value);
            ngx_memcpy(under_attack_client->hmac, value.data, value.len);

        } else {
            ngx_http_waf_dpf(r, "not found cookie %V", &key);
        }

        ngx_str_set(&key, "__waf_captcha_time");
        ngx_str_null(&value);
        ngx_http_waf_dpf(r, "searching cookie %V", &key);

#if (nginx_version >= 1023000)
        if (ngx_http_parse_multi_header_lines(r, cookies, &key, &value) != NULL) {
#else
        if (ngx_http_parse_multi_header_lines(cookies, &key, &value) != NGX_DECLINED) {
#endif
            ngx_http_waf_dpf(r, "found cookie %V", &value);
            ngx_memcpy(under_attack_client->time, value.data, value.len);

        } else {
            ngx_http_waf_dpf(r, "not found cookie %V", &key);
        }
    }

    ngx_memcpy(under_attack_expect, under_attack_client, sizeof(_info_t));

    /* 计算正确的 HMAC */
    ngx_http_waf_dp(r, "generating hmac");
    if (_gen_hmac(r, under_attack_expect) != NGX_HTTP_WAF_SUCCESS) {
        ngx_http_waf_dp(r, "failed ... return");
        return NGX_HTTP_WAF_FAULT;
    }
    ngx_http_waf_dpf(r, "success(%s)", under_attack_expect->hmac);

    ngx_http_waf_dpf(r, "client.time=%s, client.uid=%s, client.hmac=%s", 
        under_attack_client->time, under_attack_client->uid, under_attack_client->hmac);

    ngx_http_waf_dpf(r, "expect.time=%s, expect.uid=%s, expect.hmac=%s", 
        under_attack_expect->time, under_attack_expect->uid, under_attack_expect->hmac);

    /* 验证 HMAC 是否正确 */
    ngx_http_waf_dp(r, "verifying hmac");
    if (ngx_memcmp(under_attack_client, under_attack_expect, sizeof(_info_t)) != 0) {
        ngx_http_waf_dp(r, "failed ... return");
        return NGX_HTTP_WAF_FAIL;
    }
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dpf(r, "expired(%s)?", under_attack_client->time);
    time_t client_time = ngx_atoi(under_attack_client->time, ngx_strlen(under_attack_client->time));
    if (difftime(time(NULL), client_time) > loc_conf->waf_captcha_expire) {
        ngx_http_waf_dp(r, "yes");
        return NGX_HTTP_WAF_FAIL;
    }
    ngx_http_waf_dp(r, "no");

    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t _verify_captcha_dispatcher(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_end(r);

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    ngx_http_waf_dp(r, "allocating memory to store uri");
    ngx_str_t uri = ngx_null_string;
    uri.data = ngx_pnalloc(r->pool, r->uri.len + 1);
    if (uri.data == NULL) {
        ngx_http_waf_dp(r, "no memory ... return");
        return NGX_HTTP_WAF_FAULT;
    }
    ngx_memcpy(uri.data, r->uri.data, r->uri.len);
    uri.data[r->uri.len] = '\0';
    uri.len = r->uri.len;
    ngx_http_waf_dpf(r, "success(%V)", &uri);


    if (ngx_strcmp(uri.data, loc_conf->waf_captcha_verify_url.data) == 0 
    &&  ngx_http_waf_check_flag(r->method, NGX_HTTP_POST)) {
        ngx_int_t is_valid = NGX_HTTP_WAF_FALSE;
        switch (loc_conf->waf_captcha_type) {
            case NGX_HTTP_WAF_HCAPTCHA:
                ngx_http_waf_dp(r, "verifying hCaptcha");
                is_valid = _verify_hCaptcha(r);
                break;
            case NGX_HTTP_WAF_RECAPTCHA_V2_CHECKBOX:
            case NGX_HTTP_WAF_RECAPTCHA_V2_INVISIBLE:
                ngx_http_waf_dp(r, "verifying reCAPTCHAv2");
                is_valid = _verify_reCAPTCHAv2(r);
                break;
            case NGX_HTTP_WAF_RECAPTCHA_V3:
                ngx_http_waf_dp(r, "verifying reCAPTCHAv3");
                is_valid = _verify_reCAPTCHAv3(r);
                break;
            default:
                return NGX_HTTP_WAF_FAULT;
        }
        if (is_valid == NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dp(r, "pass");
            return NGX_HTTP_WAF_CAPTCHA_PASS;
        } else {
            ngx_http_waf_dp(r, "bad");
            return NGX_HTTP_WAF_CAPTCHA_BAD;
        }
    }

    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_FAIL;
}


static ngx_int_t _verify_hCaptcha(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_str_t response_key = ngx_string("h-captcha-response");
    ngx_int_t ret = _verfiy_reCAPTCHA_compatible(r,
                                                 response_key,
                                                 loc_conf->waf_captcha_hCaptcha_secret,
                                                 loc_conf->waf_captcha_api,
                                                 NGX_HTTP_WAF_FALSE,
                                                 INT_MIN);
    
    ngx_http_waf_dp_func_end(r);
    return ret;
}


static ngx_int_t _verify_reCAPTCHAv2(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_str_t response_key = ngx_string("g-recaptcha-response");
    ngx_int_t ret = _verfiy_reCAPTCHA_compatible(r,
                                                 response_key,
                                                 loc_conf->waf_captcha_reCAPTCHAv2_secret,
                                                 loc_conf->waf_captcha_api,
                                                 NGX_HTTP_WAF_FALSE,
                                                 INT_MIN);
    
    ngx_http_waf_dp_func_end(r);
    return ret;
}


static ngx_int_t _verify_reCAPTCHAv3(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_str_t response_key = ngx_string("g-recaptcha-response");
    ngx_int_t ret = _verfiy_reCAPTCHA_compatible(r,
                                                 response_key,
                                                 loc_conf->waf_captcha_reCAPTCHAv3_secret,
                                                 loc_conf->waf_captcha_api,
                                                 NGX_HTTP_WAF_TRUE,
                                                 loc_conf->waf_captcha_reCAPTCHAv3_score);
    
    ngx_http_waf_dp_func_end(r);
    return ret;
}


static ngx_int_t _verfiy_reCAPTCHA_compatible(ngx_http_request_t* r, 
    ngx_str_t response_key, 
    ngx_str_t secret,
    ngx_str_t url,
    ngx_int_t is_reCAPTCHA_v3,
    ngx_int_t score) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_str_t body = { ctx->req_body.last - ctx->req_body.pos, ctx->req_body.pos };
    key_value_t* kvs = NULL;
    ngx_http_waf_dpf(r, "parsing form %V", &body);
    ngx_int_t ret = ngx_http_waf_parse_form_string(&body, &kvs);
    if (ret != NGX_HTTP_WAF_SUCCESS) {
        goto hash_map_free;
    }
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dpf(r, "getting %V", &response_key);
    key_value_t* captcha_response = NULL;
    HASH_FIND(hh, kvs, response_key.data, response_key.len, captcha_response);
    if (captcha_response == NULL) {
        ngx_http_waf_dp(r, "failed ... releasing resources");
        ret = NGX_HTTP_WAF_FAIL;
        goto hash_map_free;
    }
    ngx_http_waf_dpf(r, "success(%V)", &captcha_response->value);

    char* json_str = NULL;
    ngx_http_waf_dpf(r, "using serect %V", &secret);

    ngx_http_waf_dp(r, "gererating request body for verification");
    char* in = ngx_pnalloc(r->pool, captcha_response->value.len + secret.len + 64);
    if (in == NULL) {
        ngx_http_waf_dp(r, "no memory ... releasing resources");
        goto hash_map_free;
    }
    sprintf(in, "response=%s&secret=%s", (char*)(captcha_response->value.data), (char*)(secret.data));
    ngx_http_waf_dpf(r, "success(%s)", in);

    ngx_http_waf_dpf(r, "sending a request to %V", &url);
    if (ngx_http_waf_http_post(r, (char*)url.data, in, &json_str) != NGX_HTTP_WAF_SUCCESS) {
        if (json_str != NULL) {
            ngx_http_waf_dpf(r, "failed(%s)", json_str);
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: %s", json_str);
            free(json_str);
        } else {
            ngx_http_waf_dp(r, "failed");
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: ngx_http_waf_http_post failed");
        }

        ngx_http_waf_dp(r, "releasing resources");
        goto hash_map_free;
    }
    ngx_http_waf_dpf(r, "success(%s)", json_str);

    ngx_http_waf_dpf(r, "parsing json_string(%s)", json_str);
    cJSON* json_obj = cJSON_Parse(json_str);
    free(json_str);
    if (json_obj == NULL) {
        ngx_http_waf_dp(r, "failed ... releasing resources");
        ret = NGX_HTTP_WAF_FAIL;
        goto hash_map_free;
    }
    ngx_http_waf_dp(r, "success");

    cJSON* json = json_obj->child;
    ngx_int_t flag = 0;
    while(json != NULL) {
        switch (json->type) {
            case cJSON_NULL:
                ngx_http_waf_dpf(r, "%s: null", json->string);
                break;
            case cJSON_True:
                ngx_http_waf_dpf(r, "%s: true", json->string);
                break;
            case cJSON_False:
                ngx_http_waf_dpf(r, "%s: false", json->string);
                break;
            case cJSON_Number:
                ngx_http_waf_dpf(r, "%s: %f", json->string, json->valuedouble);
                break;
            case cJSON_String:
                ngx_http_waf_dpf(r, "%s: %s", json->string, json->valuestring);
                break;
            default:
                break;
        }
        if (strcmp(json->string, "success") == 0 && json->type == cJSON_True) {
            ++flag;
        } else if (is_reCAPTCHA_v3 == NGX_HTTP_WAF_TRUE
               &&  strcmp(json->string, "score") == 0 
               &&  json->type == cJSON_Number
               &&  json->valuedouble >= score) {
            ++flag;
        }
        json = json->next;
    }

    if (flag == 2
    || (flag == 1 && is_reCAPTCHA_v3 == NGX_HTTP_WAF_FALSE)) {
        ret = NGX_HTTP_WAF_SUCCESS;
    } else {
        ret = NGX_HTTP_WAF_FAIL;
    }

    // json_free:
    cJSON_Delete(json_obj);

    hash_map_free:
    {
        key_value_t *temp0 = NULL, *temp1 = NULL;
        HASH_ITER(hh, kvs, temp0, temp1) {
            HASH_DEL(kvs, temp0);
            free(temp0->key.data);
            free(temp0->value.data);
            free(temp0);
        }
    }
    
    ngx_http_waf_dp_func_end(r);
    return ret;
}