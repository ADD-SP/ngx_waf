#include <ngx_http_waf_module_action.h>


typedef struct _captcha_cache_s {
    ngx_int_t count;
    ngx_uint_t error_page:1;    /**< 1: 返回 403, 0: CAPTCHA */
} _captcha_cache_t;


static ngx_int_t _perform_action_return(ngx_http_request_t* r, action_t* action);


static ngx_int_t _perform_action_decline(ngx_http_request_t* r, action_t* action);


static void _perform_action_reg_content(ngx_http_request_t* r, action_t* action);


static ngx_int_t _perform_action_html(ngx_http_request_t* r, action_t* action);


static ngx_int_t _perform_action_str(ngx_http_request_t* r, action_t* action);


static ngx_int_t _gen_response(ngx_http_request_t* r, ngx_str_t data, ngx_str_t content_type, ngx_uint_t http_status);


ngx_int_t ngx_http_waf_perform_action_at_access_start(ngx_http_request_t* r) {

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (loc_conf->waf == 2) {
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    lru_cache_t* cache = loc_conf->action_cache_captcha;

    if (!ngx_http_waf_is_valid_ptr_value(cache)) {
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    inx_addr_t inx_addr;
    ngx_http_waf_make_inx_addr(r, &inx_addr);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)loc_conf->action_zone_captcha->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    lru_cache_find_result_t result = lru_cache_find(cache, &inx_addr, sizeof(inx_addr));

    ngx_shmtx_unlock(&shpool->mutex);

    ngx_int_t need_delete = 0;

    if (result.status == NGX_HTTP_WAF_KEY_EXISTS) {

        switch (ngx_http_waf_captcha_test(r)) {
            case NGX_HTTP_WAF_FAULT:
                ngx_http_waf_append_action_return(r, NGX_HTTP_SERVICE_UNAVAILABLE, ACTION_FLAG_NONE);
                ret_value = NGX_HTTP_WAF_MATCHED;
                break;

            case NGX_HTTP_WAF_CAPTCHA_CHALLENGE:
                
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

                ret_value = NGX_HTTP_WAF_MATCHED;
                break;

            case NGX_HTTP_WAF_CAPTCHA_BAD:

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
                    ngx_http_waf_append_action_str(r, res_str, NGX_HTTP_OK, ACTION_FLAG_NONE);
                }

                ret_value = NGX_HTTP_WAF_MATCHED;
                break;

            case NGX_HTTP_WAF_CAPTCHA_PASS:
                need_delete = 1;
                ngx_str_t* res_str = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
                ngx_str_set(res_str, "good");
                ngx_http_waf_append_action_str(r, res_str, NGX_HTTP_OK, ACTION_FLAG_NONE);
                ret_value = NGX_HTTP_WAF_MATCHED;
                break;

            case NGX_HTTP_WAF_FAIL:

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
                
                ret_value = NGX_HTTP_WAF_MATCHED;
                break;
        }

    } else {
    }

    if (need_delete) {
        ngx_shmtx_lock(&shpool->mutex);

        lru_cache_delete(cache, &inx_addr, sizeof(inx_addr));

        ngx_shmtx_unlock(&shpool->mutex);
    }

    return ret_value;
}


ngx_int_t ngx_http_waf_perform_action_at_access_end(ngx_http_request_t* r) {

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (loc_conf->waf == 2) {
        return NGX_DECLINED;
    }

    ngx_int_t ret_value = NGX_DECLINED;
    action_t *elt = NULL, *tmp = NULL;


    DL_FOREACH_SAFE(ctx->action_chain, elt, tmp) {
        if (ngx_http_waf_check_flag(elt->flag, ACTION_FLAG_DECLINE)) {
            DL_DELETE(ctx->action_chain, elt);
            ret_value = _perform_action_decline(r, elt);
            break;
            
        } else if (ngx_http_waf_check_flag(elt->flag, ACTION_FLAG_RETURN)) {
            DL_DELETE(ctx->action_chain, elt);
            ret_value = _perform_action_return(r, elt);
            break;

        } else if (ngx_http_waf_check_flag(elt->flag, ACTION_FLAG_REG_CONTENT)) {
            DL_DELETE(ctx->action_chain, elt);
            _perform_action_reg_content(r, elt);

        } else {
            abort();
        }
    }

    return ret_value;
}


ngx_int_t ngx_http_waf_perform_action_at_content(ngx_http_request_t* r) {

    ngx_http_waf_ctx_t* ctx = NULL;
    // ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    ngx_int_t ret_value = NGX_DECLINED;
    action_t *elt = NULL, *tmp = NULL;


    DL_FOREACH_SAFE(ctx->action_chain, elt, tmp) {
        if (ngx_http_waf_check_flag(elt->flag, ACTION_FLAG_STR)) {
            DL_DELETE(ctx->action_chain, elt);
            ret_value = _perform_action_str(r, elt);
            break;
            
        } else if (ngx_http_waf_check_flag(elt->flag, ACTION_FLAG_HTML)) {
            DL_DELETE(ctx->action_chain, elt);
            ret_value = _perform_action_html(r, elt);
            break;

        } else {
            abort();
        }
    }

    return ret_value;
}


static ngx_int_t _perform_action_return(ngx_http_request_t* r, action_t* action) {
    ngx_int_t ret = action->extra.http_status;
    return ret;
}


static ngx_int_t _perform_action_decline(ngx_http_request_t* r, action_t* action) {
    return NGX_DECLINED;
    
}


static void _perform_action_reg_content(ngx_http_request_t* r, action_t* action) {
    ngx_http_waf_register_content_handler(r);
}


static ngx_int_t _perform_action_html(ngx_http_request_t* r, action_t* action) {

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    ngx_str_t content_type = ngx_string("text/html");

    inx_addr_t inx_addr;
    ngx_uint_t error_page = 0;
    ngx_http_waf_make_inx_addr(r, &inx_addr);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;

    if (ngx_http_waf_check_flag(action->flag, ACTION_FLAG_CAPTCHA)) {
        if (!ngx_http_waf_check_flag(action->flag, ACTION_FLAG_FROM_CAPTCHA)) {

            lru_cache_t* cache = loc_conf->action_cache_captcha;

            if (!ngx_http_waf_is_valid_ptr_value(cache)) {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_HTTP_WAF_NOT_MATCHED;
            }

            ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)loc_conf->action_zone_captcha->shm.addr;

            ngx_shmtx_lock(&shpool->mutex);


            /** 过期时间为 [15, 60] 分钟 */
            time_t expire = (time_t)randombytes_uniform(60 * 15) + 60 * 45;
            lru_cache_add_result_t result = lru_cache_add(cache, &inx_addr, sizeof(inx_addr), expire);

            if (result.status == NGX_HTTP_WAF_SUCCESS) {

                _captcha_cache_t* tmp = lru_cache_calloc(cache, sizeof(_captcha_cache_t));

                if (tmp == NULL) {
                    ret_value = NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                *result.data = tmp;
                tmp->count = 0;

                if (!ngx_http_waf_check_flag(action->flag, ACTION_FLAG_FROM_CC_DENY)) {
                    tmp->error_page = 1;
                    error_page = tmp->error_page;
                }

            } else if (result.status == NGX_HTTP_WAF_KEY_EXISTS) {
                _captcha_cache_t* tmp = *result.data;
                
                if (!ngx_http_waf_check_flag(action->flag, ACTION_FLAG_FROM_CC_DENY)) {
                    tmp->error_page = 0;
                    error_page = tmp->error_page;
                }
                
            } else {
                ret_value = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            
            ngx_shmtx_unlock(&shpool->mutex);
        }

        if (ngx_http_waf_check_flag(action->flag, ACTION_FLAG_FROM_CC_DENY)) {

            lru_cache_t* cache = loc_conf->ip_access_statistics;

            if (!ngx_http_waf_is_valid_ptr_value(cache)) {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_HTTP_WAF_NOT_MATCHED;
            }

            ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)loc_conf->shm_zone_cc_deny->shm.addr;

            ngx_shmtx_lock(&shpool->mutex);

            lru_cache_find_result_t result = lru_cache_find(cache, &inx_addr, sizeof(inx_addr));

            if (result.status == NGX_HTTP_WAF_KEY_NOT_EXISTS) {
                ret_value = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }


            ip_statis_t* ip_statis = *(result.data);
            ip_statis->count = 0;
            ip_statis->is_blocked = NGX_HTTP_WAF_FALSE;
            ip_statis->record_time = time(NULL);
            ip_statis->block_time = 0;


            ngx_shmtx_unlock(&shpool->mutex);
        }
    }
    

    if (ret_value != NGX_HTTP_WAF_NOT_MATCHED) {
        ngx_http_finalize_request(r, ret_value);
        return ret_value;
    }

    
    if (error_page) {
        if (ngx_is_null_str(&loc_conf->waf_block_page)) {
            ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);

        } else {
            ret_value = _gen_response(r, loc_conf->waf_block_page, content_type, NGX_HTTP_FORBIDDEN);
        }

    } else {
        ret_value = _gen_response(r, *action->extra.extra_html.html, content_type, action->extra.extra_html.http_status);
    }

    return ret_value;
}


static ngx_int_t _perform_action_str(ngx_http_request_t* r, action_t* action) {
    ngx_str_t content_type = ngx_string("text/plain");
    return _gen_response(r, *action->extra.extra_str.str, content_type, action->extra.extra_str.http_status);
}


static ngx_int_t _gen_response(ngx_http_request_t* r, ngx_str_t data, ngx_str_t content_type, ngx_uint_t http_status) {

    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_t res = data;

    r->headers_out.content_type.data = ngx_pstrdup(r->pool, &content_type);
    r->headers_out.content_type.len = content_type.len;

    r->headers_out.status = http_status;

    r->headers_out.content_length_n = res.len;

    if (ngx_http_waf_gen_no_cache_header(r) != NGX_HTTP_WAF_SUCCESS) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }


    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    if (r->header_only) {
        return rc;
    }

    

    ngx_buf_t* buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (buf == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }

    buf->pos = ngx_pcalloc(r->pool, res.len);
    if (buf->pos == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }

    ngx_memcpy(buf->pos, res.data, res.len);
    buf->last = buf->pos + res.len;
    buf->memory = 1;
    buf->last_buf = (r == r->main) ? 1 : 0;

    ngx_chain_t* out = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (out == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }
    out->buf = buf;
    out->next = NULL;

    rc = ngx_http_output_filter(r, out);
    return rc;
}
