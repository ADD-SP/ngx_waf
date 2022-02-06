#include <ngx_http_waf_module_action.h>


typedef struct _captcha_cache_s {
    action_flag_e flag;
    ngx_uint_t skip_sysguard:1;      /**< 1: 验证码通过，0: 验证码未通过 */
    ngx_uint_t invoke_captcha:1;    /**< 1: 需要调用 CAPTCHA，0: 不需要调用 CAPTCHA */
    ngx_uint_t error_page:1;        /**< 1: 返回 403, 0: CAPTCHA */
} _captcha_cache_t;


static ngx_int_t _perform_action_return(ngx_http_request_t* r, action_t* action);


static ngx_int_t _perform_action_decline(ngx_http_request_t* r, action_t* action);


static ngx_int_t _perform_action_done(ngx_http_request_t* r, action_t* action);


static ngx_int_t _perform_action_internal_redirect(ngx_http_request_t* r, action_t* action);


static void _perform_action_reg_content(ngx_http_request_t* r, action_t* action);


static ngx_int_t _perform_action_html(ngx_http_request_t* r, action_t* action);


static ngx_int_t _perform_action_str(ngx_http_request_t* r, action_t* action);


static ngx_int_t _gen_response(ngx_http_request_t* r, ngx_str_t data, ngx_str_t content_type, ngx_uint_t http_status);


ngx_int_t ngx_http_waf_perform_action_at_access_start(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (loc_conf->waf == 2) {
        ngx_http_waf_dp(r, "bypass mode ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    lru_cache_t* cache = loc_conf->action_cache_captcha;

    if (!ngx_http_waf_is_valid_ptr_value(cache)) {
        ngx_http_waf_dp(r, "cache is null ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    inx_addr_t inx_addr;
    ngx_http_waf_make_inx_addr(r, &inx_addr);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    action_flag_e action_flag = ACTION_FLAG_NONE;
    ngx_uint_t invoke_captcha = 0;
    ngx_uint_t skip_sysguard = 0;
    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)loc_conf->action_zone_captcha->shm.addr;

    ngx_http_waf_dp(r, "locking shared memory");
    ngx_shmtx_lock(&shpool->mutex);
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dp(r, "searching cache");
    lru_cache_find_result_t result = lru_cache_find(cache, &inx_addr, sizeof(inx_addr));

    if (result.status == NGX_HTTP_WAF_KEY_EXISTS) {
        ngx_http_waf_dp(r, "cache found");
        _captcha_cache_t* cache_data = *((_captcha_cache_t**)(result.data));
        cache_data->invoke_captcha = 1;
        action_flag = cache_data->flag;

        if (ngx_http_waf_is_action_from_sysguard(action_flag)) {
            cache_data->skip_sysguard = 1;
        }

        invoke_captcha = cache_data->invoke_captcha;
        skip_sysguard = cache_data->skip_sysguard;
    }

    ngx_http_waf_dp(r, "unlocking shared memory")
    ngx_shmtx_unlock(&shpool->mutex);
    ngx_http_waf_dp(r, "success");

    ctx->invoke_captcha = invoke_captcha;
    ctx->skip_sysguard = skip_sysguard;

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


ngx_int_t ngx_http_waf_perform_action_at_access_end(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (loc_conf->waf == 2) {
        ngx_http_waf_dp(r, "bypass mode ... return");
        return NGX_DECLINED;
    }

    ngx_int_t ret_value = NGX_DECLINED;
    action_t *elt = NULL, *tmp = NULL;

    ngx_http_waf_dp(r, "looking action chain");

    DL_FOREACH_SAFE(ctx->action_chain, elt, tmp) {
        if (ngx_http_waf_check_flag(elt->flag, ACTION_FLAG_DECLINE)) {
            ngx_http_waf_dp(r, "action is decline");
            DL_DELETE(ctx->action_chain, elt);
            ret_value = _perform_action_decline(r, elt);
            break;
            
        } else if (ngx_http_waf_check_flag(elt->flag, ACTION_FLAG_RETURN)) {
            ngx_http_waf_dp(r, "action is return");
            DL_DELETE(ctx->action_chain, elt);
            ret_value = _perform_action_return(r, elt);
            break;

        } else if (ngx_http_waf_check_flag(elt->flag, ACTION_FLAG_DONE)) {
            ngx_http_waf_dp(r, "action is done");
            DL_DELETE(ctx->action_chain, elt);
            ret_value = _perform_action_done(r, elt);
            break;

        } else if (ngx_http_waf_check_flag(elt->flag, ACTION_FLAG_REG_CONTENT)) {
            ngx_http_waf_dp(r, "action is reg content");
            DL_DELETE(ctx->action_chain, elt);
            _perform_action_reg_content(r, elt);

        } else if (ngx_http_waf_check_flag(elt->flag, ACTION_FLAG_INTERNAL_REDIRECT)) {
            ngx_http_waf_dp(r, "action is internal redirect");
            DL_DELETE(ctx->action_chain, elt);
            _perform_action_internal_redirect(r, elt);

        } else {
            abort();
        }
    }

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


ngx_int_t ngx_http_waf_perform_action_at_content(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    // ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    ngx_int_t ret_value = NGX_DECLINED;
    action_t *elt = NULL, *tmp = NULL;

    ngx_http_waf_dp(r, "looking action chain");

    DL_FOREACH_SAFE(ctx->action_chain, elt, tmp) {
        if (ngx_http_waf_check_flag(elt->flag, ACTION_FLAG_STR)) {
            ngx_http_waf_dp(r, "action is str");
            DL_DELETE(ctx->action_chain, elt);
            ret_value = _perform_action_str(r, elt);
            break;
            
        } else if (ngx_http_waf_check_flag(elt->flag, ACTION_FLAG_HTML)) {
            ngx_http_waf_dp(r, "action is html");
            DL_DELETE(ctx->action_chain, elt);
            ret_value = _perform_action_html(r, elt);
            break;

        } else {
            abort();
        }
    }

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


static ngx_int_t _perform_action_return(ngx_http_request_t* r, action_t* action) {
    ngx_http_waf_dp_func_start(r);
    ngx_int_t ret = action->extra.http_status;
    ngx_http_waf_dpf(r, "return %i", ret);
    ngx_http_waf_dp_func_end(r);
    return ret;
}


static ngx_int_t _perform_action_decline(ngx_http_request_t* r, action_t* action) {
    ngx_http_waf_dp_func_start(r);
    ngx_http_waf_dp(r, "return NGX_DECLINED");
    ngx_http_waf_dp_func_end(r);
    return NGX_DECLINED;
    
}


static ngx_int_t _perform_action_done(ngx_http_request_t* r, action_t* action) {
    ngx_http_waf_dp_func_start(r);
    ngx_http_waf_dp(r, "return NGX_DONE");
    ngx_http_waf_dp_func_end(r);
    return NGX_DONE;
}


static ngx_int_t _perform_action_internal_redirect(ngx_http_request_t* r, action_t* action) {
    ngx_http_waf_dp_func_start(r);
    ngx_http_waf_dpf(r, "internal redirect to %V?%V", 
        action->extra.extra_internal_redirect.uri,
        action->extra.extra_internal_redirect.args);
    ngx_http_waf_dp_func_end(r);
    return ngx_http_internal_redirect(r, action->extra.extra_internal_redirect.uri,
        action->extra.extra_internal_redirect.args);
}


static void _perform_action_reg_content(ngx_http_request_t* r, action_t* action) {
    ngx_http_waf_dp_func_start(r);
    ngx_http_waf_register_content_handler(r);
    ngx_http_waf_dp_func_end(r);
}


static ngx_int_t _perform_action_html(ngx_http_request_t* r, action_t* action) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    ngx_str_t content_type = ngx_string("text/html");

    inx_addr_t inx_addr;
    ngx_uint_t error_page = 0;
    ngx_http_waf_make_inx_addr(r, &inx_addr);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;

    if (ngx_http_waf_check_flag(action->flag, ACTION_FLAG_CAPTCHA)) {
        if (!ngx_http_waf_check_flag(action->flag, ACTION_FLAG_FROM_CAPTCHA)) {
            ngx_http_waf_dp(r, "action not from CPATCHA");

            lru_cache_t* cache = loc_conf->action_cache_captcha;

            if (!ngx_http_waf_is_valid_ptr_value(cache)) {
                ngx_http_waf_dp(r, "cache is null ... return");
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_HTTP_WAF_NOT_MATCHED;
            }

            ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)loc_conf->action_zone_captcha->shm.addr;

            ngx_http_waf_dp(r, "locking shared memory");
            ngx_shmtx_lock(&shpool->mutex);
            ngx_http_waf_dp(r, "success");

            ngx_http_waf_dp(r, "adding cache");

            /** 过期时间为 [15, 60] 分钟 */
            time_t expire = (time_t)randombytes_uniform(60 * 15) + 60 * 45;
            lru_cache_add_result_t result = lru_cache_add(cache, &inx_addr, sizeof(inx_addr), expire);

            if (result.status == NGX_HTTP_WAF_SUCCESS) {
                ngx_http_waf_dp(r, "success");

                _captcha_cache_t* tmp = lru_cache_calloc(cache, sizeof(_captcha_cache_t));

                if (tmp == NULL) {
                    ngx_http_waf_dp(r, "no memory ... return");
                    ret_value = NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                *result.data = tmp;
                tmp->flag = action->flag;
                tmp->skip_sysguard = 0;
                tmp->invoke_captcha = 0;

                if (!ngx_http_waf_check_flag(action->flag, ACTION_FLAG_FROM_CC_DENY)) {
                    tmp->error_page = 1;
                    error_page = tmp->error_page;
                }

            } else if (result.status == NGX_HTTP_WAF_KEY_EXISTS) {
                _captcha_cache_t* tmp = *result.data;
                
                if (!ngx_http_waf_check_flag(action->flag, ACTION_FLAG_FROM_CC_DENY)) {
                    tmp->skip_sysguard = 0;
                    tmp->error_page = 0;
                    tmp->invoke_captcha = 0;
                    error_page = tmp->error_page;
                }
                
            } else {
                ngx_http_waf_dp(r, "error");
                ret_value = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            
            ngx_http_waf_dp(r, "unlocking shared memory");
            ngx_shmtx_unlock(&shpool->mutex);
            ngx_http_waf_dp(r, "success");
        }

        if (ngx_http_waf_check_flag(action->flag, ACTION_FLAG_FROM_CC_DENY)) {
            ngx_http_waf_dp(r, "action from CC_DENY");

            lru_cache_t* cache = loc_conf->ip_access_statistics;

            if (!ngx_http_waf_is_valid_ptr_value(cache)) {
                ngx_http_waf_dp(r, "cache is null ... return");
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_HTTP_WAF_NOT_MATCHED;
            }

            ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)loc_conf->shm_zone_cc_deny->shm.addr;

            ngx_http_waf_dp(r, "locking shared memory");
            ngx_shmtx_lock(&shpool->mutex);
            ngx_http_waf_dp(r, "success");

            ngx_http_waf_dp(r, "searching cache");
            lru_cache_find_result_t result = lru_cache_find(cache, &inx_addr, sizeof(inx_addr));

            if (result.status == NGX_HTTP_WAF_KEY_NOT_EXISTS) {
                ngx_http_waf_dp(r, "not found");
                ret_value = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_http_waf_dp(r, "found");

            ip_statis_t* ip_statis = *(result.data);
            ip_statis->count = 0;
            ip_statis->is_blocked = NGX_HTTP_WAF_FALSE;
            ip_statis->record_time = time(NULL);
            ip_statis->block_time = 0;


            ngx_http_waf_dp(r, "unlocking shared memory");
            ngx_shmtx_unlock(&shpool->mutex);
            ngx_http_waf_dp(r, "success");
        }
    }
    

    if (ret_value != NGX_HTTP_WAF_NOT_MATCHED) {
        ngx_http_finalize_request(r, ret_value);
        return ret_value;
    }

    
    if (error_page) {
        ngx_http_waf_dp(r, "error page 403");
        if (ngx_is_null_str(&loc_conf->waf_block_page)) {
            ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);

        } else {
            ret_value = _gen_response(r, loc_conf->waf_block_page, content_type, NGX_HTTP_FORBIDDEN);
        }

    } else {
        ngx_http_waf_dp(r, "gen response");
        ret_value = _gen_response(r, *action->extra.extra_html.html, content_type, action->extra.extra_html.http_status);
    }

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


static ngx_int_t _perform_action_str(ngx_http_request_t* r, action_t* action) {
    ngx_http_waf_dp_func_start(r);
    ngx_str_t content_type = ngx_string("text/plain");
    ngx_http_waf_dp_func_end(r);
    return _gen_response(r, *action->extra.extra_str.str, content_type, action->extra.extra_str.http_status);
}


static ngx_int_t _gen_response(ngx_http_request_t* r, ngx_str_t data, ngx_str_t content_type, ngx_uint_t http_status) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_dp(r, "discard_request_body");
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        ngx_http_waf_dpf(r, "failed(%i) ... return", rc);
        return rc;
    }
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dp(r, "getting response str");
    ngx_str_t res = data;
    ngx_http_waf_dpf(r, "success(%V)", &res);

    ngx_http_waf_dp(r, "generating response headers");
    r->headers_out.content_type.data = ngx_pstrdup(r->pool, &content_type);
    r->headers_out.content_type.len = content_type.len;
    ngx_http_waf_dpf(r, "success(Content-Type=%V)", &content_type);

    ngx_http_waf_dp(r, "setting resposne status code");
    r->headers_out.status = http_status;
    ngx_http_waf_dpf(r, "success(%ui)", r->headers_out.status);

    r->headers_out.content_length_n = res.len;

    if (ngx_http_waf_gen_no_cache_header(r) != NGX_HTTP_WAF_SUCCESS) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }

    ngx_http_waf_dp(r, "sending headers");

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_http_waf_dpf(r, "failed(%i) ... return", rc);
        return rc;
    }

    if (r->header_only) {
        ngx_http_waf_dp(r, "success ... return");
        return rc;
    }

    ngx_http_waf_dp(r, "success");
    

    ngx_http_waf_dp(r, "allocating buffer object");
    ngx_buf_t* buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (buf == NULL) {
        ngx_http_waf_dp(r, "failed ... return");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dp(r, "allocating buffer space");
    buf->pos = ngx_pcalloc(r->pool, res.len);
    if (buf->pos == NULL) {
        ngx_http_waf_dp(r, "failed ... return");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dp(r, "copying str to buffer");
    ngx_memcpy(buf->pos, res.data, res.len);
    buf->last = buf->pos + res.len;
    buf->memory = 1;
    buf->last_buf = (r == r->main) ? 1 : 0;
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dp(r, "allocating out chain");
    ngx_chain_t* out = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (out == NULL) {
        ngx_http_waf_dp(r, "failed ... return");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }
    out->buf = buf;
    out->next = NULL;
    ngx_http_waf_dp(r, "success");

    rc = ngx_http_output_filter(r, out);
    ngx_http_waf_dp_func_end(r);
    return rc;
}
