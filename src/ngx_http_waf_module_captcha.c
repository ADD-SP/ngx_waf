#include <ngx_http_waf_module_captcha.h>

static ngx_int_t _gen_nocache_header(ngx_http_request_t* r);

static ngx_int_t _gen_pass_ctx(ngx_http_request_t* r);

static ngx_int_t _gen_show_html_ctx(ngx_http_request_t* r);

static ngx_int_t _gen_info(ngx_http_request_t* r, under_attack_info_t* info);

static ngx_int_t _gen_verify_cookie(ngx_http_request_t *r, under_attack_info_t* info);

static ngx_int_t _gen_hmac(ngx_http_request_t* r, under_attack_info_t* info);

static ngx_int_t _verify_cookies(ngx_http_request_t* r);

static ngx_int_t _verify_captcha_dispatcher(ngx_http_request_t* r);

static ngx_int_t _verify_hCaptcha(ngx_http_request_t* r);

static ngx_int_t _verify_reCAPTCHAv2(ngx_http_request_t* r);

static ngx_int_t _verify_reCAPTCHAv3(ngx_http_request_t* r);


ngx_int_t ngx_http_waf_handler_captcha(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Enter the CAPTCHA processing flow.");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (loc_conf->waf_captcha == 0 || loc_conf->waf_captcha == NGX_CONF_UNSET) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Processing is complete.");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Begin the processing flow.");
    
    switch (_verify_cookies(r)) {
        case NGX_HTTP_WAF_BAD:
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
        case NGX_HTTP_WAF_SUCCESS:
            if (r->uri.len == loc_conf->waf_captcha_verify_url.len
            && ngx_memcmp(r->uri.data, loc_conf->waf_captcha_verify_url.data, r->uri.len) == 0) {
                *out_http_status = NGX_HTTP_NO_CONTENT;
                return NGX_HTTP_WAF_MATCHED;
            }
            break;
        case NGX_HTTP_WAF_FAIL:
            switch (_verify_captcha_dispatcher(r)) {
                case NGX_HTTP_WAF_BAD:
                    *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                    return NGX_HTTP_WAF_MATCHED;
                case NGX_HTTP_WAF_CAPTCHA_CHALLENGE:
                case NGX_HTTP_WAF_CAPTCHA_BAD:
                    if (_gen_show_html_ctx(r) != NGX_HTTP_WAF_SUCCESS) {
                        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                        return NGX_HTTP_WAF_BAD;
                    }
                    *out_http_status = NGX_DECLINED;
                    return NGX_HTTP_WAF_MATCHED;
                case NGX_HTTP_WAF_CAPTCHA_PASS:
                {
                    under_attack_info_t* info = ngx_pcalloc(r->pool, sizeof(under_attack_info_t));
                    if (info != NULL
                    &&  _gen_info(r, info) == NGX_HTTP_WAF_SUCCESS
                    &&  _gen_verify_cookie(r, info) == NGX_HTTP_WAF_SUCCESS
                    &&  _gen_pass_ctx(r) == NGX_HTTP_WAF_SUCCESS
                    &&  _gen_nocache_header(r) == NGX_HTTP_WAF_SUCCESS) {
                        *out_http_status = NGX_HTTP_NO_CONTENT;
                    } else {
                        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }
                    return NGX_HTTP_WAF_MATCHED;
                }
                case NGX_HTTP_WAF_FAIL:
                    if (_gen_show_html_ctx(r) != NGX_HTTP_WAF_SUCCESS) {
                        *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                        return NGX_HTTP_WAF_BAD;
                    }
                    *out_http_status = NGX_DECLINED;
                    return NGX_HTTP_WAF_MATCHED;
                default:
                    *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                    return NGX_HTTP_WAF_MATCHED;
            }
            break;
        default:
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_MATCHED;
    }

    return NGX_HTTP_WAF_NOT_MATCHED;
}

ngx_int_t ngx_http_waf_captcha_test(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    switch (_verify_captcha_dispatcher(r)) {
        case NGX_HTTP_WAF_BAD:
            *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_HTTP_WAF_BAD;
        case NGX_HTTP_WAF_CAPTCHA_CHALLENGE:
            if (_gen_show_html_ctx(r) != NGX_HTTP_WAF_SUCCESS) {
                *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return NGX_HTTP_WAF_BAD;
            }
            return NGX_HTTP_WAF_CAPTCHA_CHALLENGE;
        case NGX_HTTP_WAF_CAPTCHA_BAD:
            if (_gen_show_html_ctx(r) != NGX_HTTP_WAF_SUCCESS) {
                *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return NGX_HTTP_WAF_BAD;
            }
            return NGX_HTTP_WAF_CAPTCHA_BAD;
        case NGX_HTTP_WAF_CAPTCHA_PASS:
            if (_gen_pass_ctx(r) != NGX_HTTP_WAF_SUCCESS || _gen_nocache_header(r) != NGX_HTTP_WAF_SUCCESS) {
                *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return NGX_HTTP_WAF_BAD;
            }
            return NGX_HTTP_WAF_CAPTCHA_PASS;
        case NGX_HTTP_WAF_FAIL:
            if (_gen_show_html_ctx(r) != NGX_HTTP_WAF_SUCCESS) {
                *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return NGX_HTTP_WAF_BAD;
            }
            return NGX_HTTP_WAF_CAPTCHA_CHALLENGE;
        default:
            return NGX_HTTP_WAF_BAD;
    }
}


static ngx_int_t _gen_nocache_header(ngx_http_request_t* r) {
    ngx_table_elt_t* header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
            return NGX_HTTP_WAF_FAIL; 
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"cache-control";
    ngx_str_set(&header->key, "Cache-control");
    ngx_str_set(&header->value, "no-store");

    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t _gen_pass_ctx(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);
    
    ctx->blocked = NGX_HTTP_WAF_FALSE;
    ctx->captcha = NGX_HTTP_WAF_FALSE;
    strcpy((char*)ctx->rule_type, "CAPTCHA");
    strcpy((char*)ctx->rule_deatils, "PASS");

    return NGX_HTTP_WAF_TRUE;
}


static ngx_int_t _gen_show_html_ctx(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);
    
    ctx->blocked = NGX_HTTP_WAF_TRUE;
    ctx->captcha = NGX_HTTP_WAF_TRUE;
    strcpy((char*)ctx->rule_type, "CAPTCHA");
    strcpy((char*)ctx->rule_deatils, "CHALLENGE");

    return NGX_HTTP_WAF_TRUE;
}


static ngx_int_t _gen_info(ngx_http_request_t* r, under_attack_info_t* info) {
    time_t now = time(NULL);

    #if (NGX_TIME_T_SIZE == 4)
        sprintf((char*)info->time, "%d", (int)now);
    #elif (NGX_TIME_T_SIZE == 8)
        sprintf((char*)info->time, "%lld", (long long)now);
    #else
        #error The size of time_t is unexpected.
    #endif

    if (ngx_http_waf_rand_str(info->uid, sizeof(info->uid) - 1) != NGX_HTTP_WAF_SUCCESS) {
        return NGX_HTTP_WAF_FAIL;
    }

    return _gen_hmac(r, info);
}


static ngx_int_t _gen_verify_cookie(ngx_http_request_t *r, under_attack_info_t* info) {
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
    header->value.data = ngx_pnalloc(r->pool, sizeof(info->time) + 64);
    header->value.len = sprintf((char*)header->value.data, "__waf_captcha_time=%s; Path=/", info->time);

    header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");
    header->value.data = ngx_pnalloc(r->pool, sizeof(info->uid) + 64);
    header->value.len = sprintf((char*)header->value.data, "__waf_captcha_uid=%s; Path=/", info->uid);

    header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"set-cookie";
    ngx_str_set(&header->key, "Set-Cookie");
    header->value.data = ngx_pnalloc(r->pool, sizeof(info->hmac) + 64);
    header->value.len = sprintf((char*)header->value.data, "__waf_captcha_hmac=%s; Path=/", info->hmac);


    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t _gen_hmac(ngx_http_request_t *r, under_attack_info_t* info) {
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
    return ngx_http_waf_sha256(info->hmac, sizeof(info->hmac), &buf, sizeof(buf));
}


static ngx_int_t _verify_cookies(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_table_elt_t **ppcookie = (ngx_table_elt_t **)(r->headers_in.cookies.elts);
    under_attack_info_t* under_attack_client = ngx_pcalloc(r->pool, sizeof(under_attack_info_t));
    under_attack_info_t* under_attack_expect = ngx_pcalloc(r->pool, sizeof(under_attack_info_t));

    if (under_attack_client == NULL || under_attack_expect == NULL) {
        return NGX_HTTP_WAF_BAD;
    }

    ngx_int_t cookie_count = 0;
    ngx_memzero(under_attack_client, sizeof(under_attack_info_t));
    ngx_memzero(under_attack_expect, sizeof(under_attack_info_t));

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

            if (ngx_strcmp(key->data, "__waf_captcha_time") == 0) {
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: Being parsed __waf_captcha_time.");
                ngx_memcpy(under_attack_client->time, value->data, ngx_min(sizeof(under_attack_client->time) - 1, value->len));
                ++cookie_count;
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: Successfully get __waf_captcha_time.");
            }
            else if (ngx_strcmp(key->data, "__waf_captcha_uid") == 0) {
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: Being parsed __waf_captcha_uid.");
                ngx_memcpy(under_attack_client->uid, value->data, ngx_min(sizeof(under_attack_client->uid) - 1, value->len));
                ++cookie_count;
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: Successfully get __waf_captcha_uid.");
            }
            else if (ngx_strcmp(key->data, "__waf_captcha_hmac") == 0) {
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: Being parsed __waf_captcha_hmac.");
                ngx_memcpy(under_attack_client->hmac, value->data, ngx_min(sizeof(under_attack_client->hmac) - 1, value->len));
                ++cookie_count;
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: Successfully get __waf_captcha_hmac.");
            }

        } while (p != NULL);

        utarray_free(cookies);
    }


    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Successfully parsed all cookies.");

    ngx_memcpy(under_attack_expect, under_attack_client, sizeof(under_attack_info_t));

    /* 计算正确的 HMAC */
    if (_gen_hmac(r, under_attack_expect) != NGX_HTTP_WAF_SUCCESS) {
        // *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_HTTP_WAF_BAD;
    }

    /* 验证 HMAC 是否正确 */
    if (ngx_memcmp(under_attack_client, under_attack_expect, sizeof(under_attack_info_t)) != 0) {
        // *out_http_status = NGX_DECLINED;
        // _gen_challenge_cookie(r);
        // _gen_show_html_ctx(r);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Bad __waf_captcha_hmac");
        return NGX_HTTP_WAF_FAIL;
    }

    time_t client_time = ngx_atoi(under_attack_client->time, ngx_strlen(under_attack_client->time));
    if (difftime(time(NULL), client_time) > loc_conf->waf_captcha_expire) {
        // *out_http_status = NGX_DECLINED;
        // _gen_challenge_cookie(r);
        // _gen_show_html_ctx(r);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Bad __waf_captcha_time");
        return NGX_HTTP_WAF_FAIL;
    }

    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t _verify_captcha_dispatcher(ngx_http_request_t* r) {
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    ngx_str_t uri = ngx_null_string;
    uri.data = ngx_pnalloc(r->pool, r->uri.len + 1);
    if (uri.data == NULL) {
        return NGX_HTTP_WAF_BAD;
    }
    ngx_memcpy(uri.data, r->uri.data, r->uri.len);
    uri.data[r->uri.len] = '\0';
    uri.len = r->uri.len;


    if (ngx_strcmp(uri.data, loc_conf->waf_captcha_verify_url.data) == 0 
    &&  ngx_http_waf_check_flag(r->method, NGX_HTTP_POST) == NGX_HTTP_WAF_TRUE) {
        ngx_int_t is_valid = NGX_HTTP_WAF_FALSE;
        switch (loc_conf->waf_captcha_type) {
            case NGX_HTTP_WAF_HCAPTCHA:
                is_valid = _verify_hCaptcha(r);
                break;
            case NGX_HTTP_WAF_RECAPTCHA_V2:
                is_valid = _verify_reCAPTCHAv2(r);
                break;
            case NGX_HTTP_WAF_RECAPTCHA_V3:
                is_valid = _verify_reCAPTCHAv3(r);
                break;
            default:
                return NGX_HTTP_WAF_BAD;
        }
        if (is_valid == NGX_HTTP_WAF_SUCCESS) {
            return NGX_HTTP_WAF_CAPTCHA_PASS;
        } else {
            return NGX_HTTP_WAF_CAPTCHA_BAD;
        }
    }

    return NGX_HTTP_WAF_FAIL;
}


static ngx_int_t _verify_hCaptcha(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_str_t body = { ctx->req_body.last - ctx->req_body.pos, ctx->req_body.pos };
    key_value_t* kvs = NULL;
    ngx_int_t ret = ngx_http_waf_parse_form_string(&body, &kvs);
    if (ret != NGX_HTTP_WAF_SUCCESS) {
        goto hash_map_free;
    }

    key_value_t* h_captcha_response = NULL;
    HASH_FIND(hh, kvs, "h-captcha-response", sizeof("h-captcha-response") - 1, h_captcha_response);
    if (h_captcha_response == NULL) {
        ret = NGX_HTTP_WAF_FAIL;
        goto hash_map_free;
    }

    char* json_str = NULL;
    ngx_str_t* secret = &loc_conf->waf_captcha_hCaptcha_secret;
    char* in = ngx_pnalloc(r->pool, h_captcha_response->value.len + secret->len + 64);

    if (in == NULL) {
        goto hash_map_free;
    }

    sprintf(in, "response=%s&secret=%s", (char*)(h_captcha_response->value.data), (char*)(secret->data));

    if (ngx_http_waf_http_post((char*)loc_conf->waf_captcha_api.data, in, &json_str) != NGX_HTTP_WAF_SUCCESS) {
        if (json_str != NULL) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: %s", json_str);
            free(json_str);
        } else {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: ngx_http_waf_http_post failed");
        }

        goto hash_map_free;
    }

    cJSON* json_obj = cJSON_Parse(json_str);
    free(json_str);
    if (json_obj == NULL) {
        ret = NGX_HTTP_WAF_FAIL;
        goto hash_map_free;
    }

    cJSON* json = json_obj->child;
    while(json != NULL) {
        if (strcmp(json->string, "success") == 0) {
            if (json->type == cJSON_True) {
                ret = NGX_HTTP_WAF_SUCCESS;
            } else {
                ret = NGX_HTTP_WAF_FAIL;
            }
            break;
        }
        json = json->next;
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
    
    return ret;
}


static ngx_int_t _verify_reCAPTCHAv2(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_str_t body = { ctx->req_body.last - ctx->req_body.pos, ctx->req_body.pos };
    key_value_t* kvs = NULL;
    ngx_int_t ret = ngx_http_waf_parse_form_string(&body, &kvs);
    if (ret != NGX_HTTP_WAF_SUCCESS) {
        goto hash_map_free;
    }

    key_value_t* g_captcha_response = NULL;
    HASH_FIND(hh, kvs, "g-recaptcha-response", sizeof("g-recaptcha-response") - 1, g_captcha_response);
    if (g_captcha_response == NULL) {
        ret = NGX_HTTP_WAF_FAIL;
        goto hash_map_free;
    }

    char* json_str = NULL;
    ngx_str_t* secret = &loc_conf->waf_captcha_reCAPTCHAv2_secret;
    char* in = ngx_pnalloc(r->pool, g_captcha_response->value.len + secret->len + 64);

    if (in == NULL) {
        goto hash_map_free;
    }

    sprintf(in, "response=%s&secret=%s", (char*)(g_captcha_response->value.data), (char*)(secret->data));

    if (ngx_http_waf_http_post((char*)loc_conf->waf_captcha_api.data, in, &json_str) != NGX_HTTP_WAF_SUCCESS) {
        if (json_str != NULL) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: %s", json_str);
            free(json_str);
        } else {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: ngx_http_waf_http_post failed");
        }

        goto hash_map_free;
    }

    cJSON* json_obj = cJSON_Parse(json_str);
    free(json_str);
    if (json_obj == NULL) {
        ret = NGX_HTTP_WAF_FAIL;
        goto hash_map_free;
    }

    cJSON* json = json_obj->child;
    while(json != NULL) {
        if (strcmp(json->string, "success") == 0) {
            if (json->type == cJSON_True) {
                ret = NGX_HTTP_WAF_SUCCESS;
            } else {
                ret = NGX_HTTP_WAF_FAIL;
            }
            break;
        }
        json = json->next;
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
    
    return ret;
}


static ngx_int_t _verify_reCAPTCHAv3(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_str_t body = { ctx->req_body.last - ctx->req_body.pos, ctx->req_body.pos };
    key_value_t* kvs = NULL;
    ngx_int_t ret = ngx_http_waf_parse_form_string(&body, &kvs);
    if (ret != NGX_HTTP_WAF_SUCCESS) {
        goto hash_map_free;
    }

    key_value_t* g_captcha_response = NULL;
    HASH_FIND(hh, kvs, "g-recaptcha-response", sizeof("g-recaptcha-response") - 1, g_captcha_response);
    if (g_captcha_response == NULL) {
        ret = NGX_HTTP_WAF_FAIL;
        goto hash_map_free;
    }

    char* json_str = NULL;
    ngx_str_t* secret = &loc_conf->waf_captcha_reCAPTCHAv2_secret;
    char* in = ngx_pnalloc(r->pool, g_captcha_response->value.len + secret->len + 64);

    if (in == NULL) {
        goto hash_map_free;
    }

    sprintf(in, "response=%s&secret=%s", (char*)(g_captcha_response->value.data), (char*)(secret->data));

    if (ngx_http_waf_http_post((char*)loc_conf->waf_captcha_api.data, in, &json_str) != NGX_HTTP_WAF_SUCCESS) {
        if (json_str != NULL) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: %s", json_str);
            free(json_str);
        } else {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: ngx_http_waf_http_post failed");
        }

        goto hash_map_free;
    }

    cJSON* json_obj = cJSON_Parse(json_str);
    free(json_str);
    if (json_obj == NULL) {
        ret = NGX_HTTP_WAF_FAIL;
        goto hash_map_free;
    }

    cJSON* json = json_obj->child;
    ngx_int_t flag = 0;
    while(json != NULL) {
        if (strcmp(json->string, "success") == 0 && json->type == cJSON_True) {
            ++flag;
        } else if (strcmp(json->string, "score") == 0 
                && json->type == cJSON_Number
                && json->valuedouble >= loc_conf->waf_captcha_reCAPTCHAv3_score) {
            ++flag;
        }
        json = json->next;
    }

    if (flag == 2) {
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
    
    return ret;
}