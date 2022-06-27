#include <ngx_http_waf_module_check.h>

extern ngx_module_t ngx_http_waf_module; /**< 模块详情 */


ngx_int_t ngx_http_waf_handler_check_white_ip(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    action_t* action = ngx_pcalloc(r->pool, sizeof(action_t));
    
    ngx_http_waf_set_action_decline(action, ACTION_FLAG_FROM_WHITE_LIST);

    if (!ngx_http_waf_check_flag(loc_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_IP)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ip_trie_node_t* ip_trie_node = NULL;
    inx_addr_t inx_addr;
    ngx_http_waf_make_inx_addr(r, &inx_addr);

    if (r->connection->sockaddr->sa_family == AF_INET) {
        ngx_http_waf_dp(r, "matching ipv4");
        if (ip_trie_find(loc_conf->white_ipv4, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dpf(r, "matched(%s)", ip_trie_node->data);
            ctx->gernal_logged = 1;
            ctx->blocked = 0;
            ngx_http_waf_set_rule_info(r, "WHITE-IPV4", ip_trie_node->data,
                NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_FALSE);
            ngx_http_waf_append_action(r, action);
            ret_value = NGX_HTTP_WAF_MATCHED;
        } else {
            ngx_http_waf_dp(r, "not matched");
        }
    }
#if (NGX_HAVE_INET6)
    else if (r->connection->sockaddr->sa_family == AF_INET6) {
        ngx_http_waf_dp(r, "matching ipv6");
        if (ip_trie_find(loc_conf->white_ipv6, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dpf(r, "matched(%s)", ip_trie_node->data);
            ctx->gernal_logged = 1;
            ctx->blocked = 0;
            ngx_http_waf_set_rule_info(r, "WHITE-IPV6", ip_trie_node->data,
                NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_FALSE);
            ngx_http_waf_append_action(r, action);
            ret_value = NGX_HTTP_WAF_MATCHED;
        } else {
            ngx_http_waf_dp(r, "not matched");
        }
    }
#endif

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


ngx_int_t ngx_http_waf_handler_check_black_ip(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);
    
    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    action_t* action = NULL;

    ngx_http_waf_copy_action_chain(r->pool, action, loc_conf->action_chain_blacklist);

    if (!ngx_http_waf_check_flag(loc_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_IP)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ip_trie_node_t *ip_trie_node = NULL;
    inx_addr_t inx_addr;
    ngx_http_waf_make_inx_addr(r, &inx_addr);

    if (r->connection->sockaddr->sa_family == AF_INET) {
        ngx_http_waf_dp(r, "matching ipv4");
        if (ip_trie_find(loc_conf->black_ipv4, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dpf(r, "matched(%s)", ip_trie_node->data);
            ctx->gernal_logged = 1;
            ctx->blocked = 1;
            ngx_http_waf_set_rule_info(r, "BLACK-IPV4", ip_trie_node->data,
                NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
            ngx_http_waf_append_action_chain(r, action);
            ret_value = NGX_HTTP_WAF_MATCHED;
        } else {
            ngx_http_waf_dp(r, "not matched");
        }
    } 
#if (NGX_HAVE_INET6)
    else if (r->connection->sockaddr->sa_family == AF_INET6) {
        ngx_http_waf_dp(r, "matching ipv6");
        if (ip_trie_find(loc_conf->black_ipv6, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dpf(r, "matched(%s)", ip_trie_node->data);
            ctx->gernal_logged = 1;
            ctx->blocked = 1;
            ngx_http_waf_set_rule_info(r, "BLACK-IPV6", ip_trie_node->data,
                NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
            ngx_http_waf_append_action_chain(r, action);
            ret_value = NGX_HTTP_WAF_MATCHED;
        } else {
            ngx_http_waf_dp(r, "not matched");
        }
    }
#endif

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


ngx_int_t ngx_http_waf_handler_check_cc(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);
    
    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    time_t now = time(NULL);
    action_t* action = NULL;

    ngx_http_waf_copy_action_chain(r->pool, action, loc_conf->action_chain_cc_deny);
    
    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_cc_deny)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    } 
    
    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_cc_deny_duration)
        || ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_cc_deny_limit)
        || ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_cc_deny_cycle)
        || !ngx_http_waf_is_valid_ptr_value(loc_conf->shm_zone_cc_deny)
        || !ngx_http_waf_is_valid_ptr_value(loc_conf->ip_access_statistics)) {
        ngx_http_waf_dp(r, "invalid configuratiion ... return");
        ngx_http_waf_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_CC_DENY);
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ngx_http_waf_dp(r, "generating inx_addr_t");
    inx_addr_t inx_addr;
    ngx_http_waf_make_inx_addr(r, &inx_addr);
    ngx_http_waf_dp(r, "success");

    ngx_int_t limit  = loc_conf->waf_cc_deny_limit;
    ngx_int_t duration = loc_conf->waf_cc_deny_duration;
    ip_statis_t* statis = NULL;
    ngx_http_waf_dpf(r, "limit: %i, duration: %i", limit, duration);

    
    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)loc_conf->shm_zone_cc_deny->shm.addr;
    ngx_http_waf_dp(r, "locking shared memory");
    ngx_shmtx_lock(&shpool->mutex);
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dp(r, "getting cache");
    lru_cache_find_result_t tmp0 = lru_cache_find(loc_conf->ip_access_statistics, &inx_addr, sizeof(inx_addr_t));
    if (tmp0.status == NGX_HTTP_WAF_KEY_EXISTS) {
        ngx_http_waf_dp(r, "found");
        statis = *(tmp0).data;
    } else {
        ngx_http_waf_dp(r, "not found");

        ngx_http_waf_dp(r, "adding cache");
        lru_cache_add_result_t tmp1 = lru_cache_add(
            loc_conf->ip_access_statistics, 
            &inx_addr, 
            sizeof(inx_addr_t), 
            loc_conf->waf_cc_deny_cycle);

        if (tmp1.status == NGX_HTTP_WAF_SUCCESS) {
            statis = mem_pool_calloc(loc_conf->ip_access_statistics->pool, sizeof(ip_statis_t));
            if (statis == NULL) {
                ngx_http_waf_dp(r, "no memroy ... exception");
                goto exception;
            }
            statis->count = 0;
            statis->is_blocked = NGX_HTTP_WAF_FALSE;
            statis->record_time = now;
            statis->block_time = 0;
            ctx->rate = 0;
            *(tmp1.data) = statis;
            ngx_http_waf_dp(r, "success");

        } else {
            goto exception;
        }
    }

    // double diff_second_record = difftime(now, statis->record_time);
    // double diff_second_block = difftime(now, statis->block_time);

    if (statis->count != NGX_MAX_INT_T_VALUE) {
        statis->count++;
    }

    ctx->rate = statis->count;

    if (statis->count > loc_conf->waf_cc_deny_limit) {
        if (statis->count -1 <= loc_conf->waf_cc_deny_limit) {
            lru_cache_set_expire(loc_conf->ip_access_statistics, &inx_addr, sizeof(inx_addr_t), 
                loc_conf->waf_cc_deny_duration);
        }

        goto matched;
    }

    // /* 如果已经被拦截 */
    // if (statis->is_blocked == NGX_HTTP_WAF_TRUE) {
    //     /* 如果还在拦截时间内 */
    //     if (diff_second_block < duration) {
    //         ngx_http_waf_dp(r, "still blocked");
    //         goto matched;
    //     } else {
    //         ngx_http_waf_dp(r, "reset record");
    //         statis->count = 1;
    //         statis->is_blocked = NGX_HTTP_WAF_FALSE;
    //         statis->record_time = now;
    //         statis->block_time = 0;
    //         ctx->rate = 1;
    //     }
    // }
    // /* 如果还在一个统计周期内 */ 
    // else if (diff_second_record <= loc_conf->waf_cc_deny_cycle) {
    //     /* 如果访问频率超出限制 */
    //     if (statis->count > limit) {
    //         ngx_http_waf_dp(r, "start blocking");
    //         goto matched;
    //     }
    // } else {
    //     ngx_http_waf_dp(r, "expired cache");
    //     statis->count = 1;
    //     statis->is_blocked = NGX_HTTP_WAF_FALSE;
    //     statis->record_time = now;
    //     statis->block_time = 0;
    //     ctx->rate = 1;
    // }


    goto unlock;

    matched: 
    {
        ngx_http_waf_dp(r, "flow: matched");
        goto block;
    }

    block: 
    {
        ngx_http_waf_dp(r, "flow: block");

        ctx->gernal_logged = 1;
        ctx->blocked = 1;
        ngx_http_waf_set_rule_info(r, "CC-DENY", "", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
        ngx_http_waf_append_action_chain(r, action);
        ret_value = NGX_HTTP_WAF_MATCHED;
        time_t remain = duration - (now - statis->block_time);

        /* 如果不是 444 状态码则生成响应头 Retry-After。*/
        if (ngx_http_waf_check_flag(action->flag, ACTION_FLAG_RETURN) && action->extra.http_status != NGX_HTTP_CLOSE) {
            ngx_http_waf_dp(r, "generating reponse header: Retry-After ");
            ngx_table_elt_t* header = (ngx_table_elt_t*)ngx_list_push(&(r->headers_out.headers));
            if (header == NULL) {
                ngx_http_waf_dp(r, "failed ... unlock");
                goto unlock;
            }

            /* 如果 hash 字段为 0 则会在遍历 HTTP 头的时候被忽略 */
            header->hash = 1;
            header->lowcase_key = (u_char*)"Retry-After";
            ngx_str_set(&header->key, "Retry-After");
            header->value.data = ngx_palloc(r->pool, NGX_TIME_T_LEN + 1);
            if (header->value.data == NULL) {
                ngx_http_waf_dp(r, "no memory ... unlock");
                goto unlock;
            }

            #if (NGX_TIME_T_SIZE == 4)
                header->value.len = sprintf((char*)header->value.data, "%d", (int)remain);
            #elif (NGX_TIME_T_SIZE == 8)
                header->value.len = sprintf((char*)header->value.data, "%lld", (long long)remain);
            #else
                #error The size of time_t is unexpected.
            #endif
            ngx_http_waf_dpf(r, "success(%V=%V)", &header->key, &header->value);
        }
        goto unlock;
    }
        
    exception:
    {
        ngx_http_waf_dp(r, "flow expcetion");
        ngx_http_waf_append_action_return(r, NGX_HTTP_SERVICE_UNAVAILABLE, ACTION_FLAG_FROM_CC_DENY);
        ret_value = NGX_HTTP_WAF_MATCHED;
        goto unlock;
    }
    // no_memory:
    // not_matched:
    unlock:
    ngx_http_waf_dp(r, "flow unlock");
    
    ngx_http_waf_dp(r, "unlocking shared memory")
    ngx_shmtx_unlock(&shpool->mutex);
    ngx_http_waf_dp(r, "success");


    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


ngx_int_t ngx_http_waf_handler_check_white_url(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    action_t* action = ngx_pcalloc(r->pool, sizeof(action_t));
    
    ngx_http_waf_set_action_decline(action, ACTION_FLAG_FROM_WHITE_LIST);

    if (!ngx_http_waf_check_flag(loc_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_URL | r->method)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ngx_str_t* p_uri = &r->uri;
    ngx_array_t* regex_array = loc_conf->white_url;
    lru_cache_t* cache = loc_conf->white_url_inspection_cache;

    ngx_http_waf_dpf(r, "matching uri(%V)", p_uri);
    ret_value = ngx_http_waf_regex_exec_arrray(r, p_uri, regex_array, (u_char*)"WHITE-URL", cache);

    if (ret_value == NGX_HTTP_WAF_MATCHED) {
        ngx_http_waf_dp(r, "matched");
        ctx->gernal_logged = 1;
        ctx->blocked = 0;
        ngx_http_waf_append_action(r, action);
    } else {
        ngx_http_waf_dp(r, "not matched");
    }

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


ngx_int_t ngx_http_waf_handler_check_black_url(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    action_t* action = ngx_pcalloc(r->pool, sizeof(action_t));

    ngx_http_waf_copy_action_chain(r->pool, action, loc_conf->action_chain_blacklist);

    if (!ngx_http_waf_check_flag(loc_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_URL | r->method)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ngx_str_t* p_uri = &r->uri;
    ngx_array_t* regex_array = loc_conf->black_url;
    lru_cache_t* cache = loc_conf->black_url_inspection_cache;

    ngx_http_waf_dpf(r, "matching uri(%V)", p_uri);
    ret_value = ngx_http_waf_regex_exec_arrray(r, p_uri, regex_array, (u_char*)"BLACK-URL", cache);

    if (ret_value == NGX_HTTP_WAF_MATCHED) {
        ngx_http_waf_dp(r, "matched");
        ctx->gernal_logged = 1;
        ctx->blocked = 1;
        ngx_http_waf_append_action_chain(r, action);
    } else {
        ngx_http_waf_dp(r, "not matched");
    }

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


ngx_int_t ngx_http_waf_handler_check_black_args(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    action_t* action = NULL;

    ngx_http_waf_copy_action_chain(r->pool, action, loc_conf->action_chain_blacklist);

    if (!ngx_http_waf_check_flag(loc_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_ARGS | r->method)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ngx_str_t* p_args = &r->args;
    ngx_array_t* regex_array = loc_conf->black_args;
    lru_cache_t* cache = loc_conf->black_args_inspection_cache;

    ngx_http_waf_dpf(r, "matching args(%V)", p_args);
    ret_value = ngx_http_waf_regex_exec_arrray(r, p_args, regex_array, (u_char*)"BLACK-ARGS", cache);

    if (ret_value == NGX_HTTP_WAF_MATCHED) {
        ngx_http_waf_dp(r, "matched");
        ctx->gernal_logged = 1;
        ctx->blocked = 1;
        ngx_http_waf_append_action_chain(r, action);
    } else {
        ngx_http_waf_dp(r, "not matched");
    }

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


ngx_int_t ngx_http_waf_handler_check_black_user_agent(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    action_t* action = ngx_pcalloc(r->pool, sizeof(action_t));

    ngx_http_waf_copy_action_chain(r->pool, action, loc_conf->action_chain_blacklist);

    if (!ngx_http_waf_check_flag(loc_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_UA | r->method)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }
    
    if (r->headers_in.user_agent == NULL) {
        ngx_http_waf_dp(r, "empty user-agent ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ngx_str_t* p_ua = &r->headers_in.user_agent->value;
    ngx_array_t* regex_array = loc_conf->black_ua;
    lru_cache_t* cache = loc_conf->black_ua_inspection_cache;

    ngx_http_waf_dpf(r, "matching user-agent(%V)", p_ua);
    ret_value = ngx_http_waf_regex_exec_arrray(r, p_ua, regex_array, (u_char*)"BLACK-UA", cache);

    if (ret_value == NGX_HTTP_WAF_MATCHED) {
        ngx_http_waf_dp(r, "matched");
        ctx->gernal_logged = 1;
        ctx->blocked = 1;
        ngx_http_waf_append_action_chain(r, action);
    } else {
        ngx_http_waf_dp(r, "not matched");
    }

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


ngx_int_t ngx_http_waf_handler_check_white_referer(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    action_t* action = ngx_pcalloc(r->pool, sizeof(action_t));
    
    ngx_http_waf_set_action_decline(action, ACTION_FLAG_FROM_WHITE_LIST);

    if (!ngx_http_waf_check_flag(loc_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_REFERER | r->method)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    } 
    
    if (r->headers_in.referer == NULL) {
        ngx_http_waf_dp(r, "empty referer ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }


    ngx_str_t* p_referer = &r->headers_in.referer->value;
    ngx_array_t* regex_array = loc_conf->white_referer;
    lru_cache_t* cache = loc_conf->white_referer_inspection_cache;

    ngx_http_waf_dpf(r, "matching referer(%V)", p_referer);
    ret_value = ngx_http_waf_regex_exec_arrray(r, p_referer, regex_array, (u_char*)"WHITE-REFERER", cache);

    if (ret_value == NGX_HTTP_WAF_MATCHED) {
        ngx_http_waf_dp(r, "matched");
        ctx->gernal_logged = 1;
        ctx->blocked = 0;
        ngx_http_waf_append_action(r, action);
    } else {
        ngx_http_waf_dp(r, "not matched");
    }

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


ngx_int_t ngx_http_waf_handler_check_black_referer(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    action_t* action = ngx_pcalloc(r->pool, sizeof(action_t));

    ngx_http_waf_copy_action_chain(r->pool, action, loc_conf->action_chain_blacklist);

    if (!ngx_http_waf_check_flag(loc_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_REFERER | r->method)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    } 
    
    if (r->headers_in.referer == NULL) {
        ngx_http_waf_dp(r, "empty referer ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ngx_str_t* p_referer = &r->headers_in.referer->value;
    ngx_array_t* regex_array = loc_conf->black_referer;
    lru_cache_t* cache = loc_conf->black_referer_inspection_cache;

    ngx_http_waf_dpf(r, "matching referer(%V)", p_referer);
    ret_value = ngx_http_waf_regex_exec_arrray(r, p_referer, regex_array, (u_char*)"BLACK-REFERER", cache);

    if (ret_value == NGX_HTTP_WAF_MATCHED) {
        ngx_http_waf_dp(r, "matched");
        ctx->gernal_logged = 1;
        ctx->blocked = 1;
        ngx_http_waf_append_action_chain(r, action);
    } else {
        ngx_http_waf_dp(r, "not matched");
    }

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


ngx_int_t ngx_http_waf_handler_check_black_cookie(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    action_t* action = ngx_pcalloc(r->pool, sizeof(action_t));

    ngx_http_waf_copy_action_chain(r->pool, action, loc_conf->action_chain_blacklist);

    if (!ngx_http_waf_check_flag(loc_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_COOKIE | r->method)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

#if (nginx_version >= 1023000)
    if (r->headers_in.cookie == NULL) {
        ngx_http_waf_dp(r, "empty cookies ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ngx_table_elt_t* p = r->headers_in.cookie;

    for (p = r->headers_in.cookie; p != NULL; p = p->next) {
        size_t len = p->key.len + p->value.len + 1;
        u_char* buf = ngx_pcalloc(r->pool, sizeof(u_char) * (len + 1));

        size_t offset = 0;
        ngx_memcpy(buf + offset, p->key.data, sizeof(u_char) * p->key.len);

        offset += sizeof(u_char) * p->key.len;
        buf[offset] = '=';

        ++offset;
        ngx_memcpy(buf + offset, p->value.data, sizeof(u_char) * p->value.len);

        ngx_str_t cookie;
        cookie.len = len;
        cookie.data = buf;

        ngx_array_t* regex_array = loc_conf->black_cookie;
        lru_cache_t* cache = loc_conf->black_cookie_inspection_cache;
        ret_value = ngx_http_waf_regex_exec_arrray(r, &cookie, regex_array, (u_char*)"BLACK-COOKIE", cache);

        if (ret_value == NGX_HTTP_WAF_MATCHED) {
            ngx_http_waf_dp(r, "matched");
            ctx->gernal_logged = 1;
            ctx->blocked = 1;
            ngx_http_waf_append_action_chain(r, action);

        } else {
            ngx_http_waf_dp(r, "not matched");
        }

        if (ctx->blocked) {
            ngx_http_waf_dp(r, "blocked ... break");
            break;
        }
    }
#else
    if (r->headers_in.cookies.nelts == 0) {
        ngx_http_waf_dp(r, "empty cookies ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ngx_table_elt_t** ppcookie = r->headers_in.cookies.elts;
    size_t i;
    for (i = 0; i < r->headers_in.cookies.nelts; i++, ppcookie++) {
        ngx_str_t* native_cookies = &((**ppcookie).value);

        ngx_http_waf_dpf(r, "matching cookie(%V)", native_cookies);

        ngx_array_t* regex_array = loc_conf->black_cookie;
        lru_cache_t* cache = loc_conf->black_cookie_inspection_cache;
        ret_value = ngx_http_waf_regex_exec_arrray(r, native_cookies, regex_array, (u_char*)"BLACK-COOKIE", cache);

        if (ret_value == NGX_HTTP_WAF_MATCHED) {
            ngx_http_waf_dp(r, "matched");
            ctx->gernal_logged = 1;
            ctx->blocked = 1;
            ngx_http_waf_append_action_chain(r, action);

        } else {
            ngx_http_waf_dp(r, "not matched");
        }

        if (ctx->blocked) {
            ngx_http_waf_dp(r, "blocked ... break");
            break;
        }
    }
#endif

    ngx_http_waf_dp_func_end(r);
    return ret_value;
}


ngx_int_t ngx_http_waf_handler_check_black_post(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    action_t* action = ngx_pcalloc(r->pool, sizeof(action_t));

    ngx_http_waf_copy_action_chain(r->pool, action, loc_conf->action_chain_blacklist);

    if (!ngx_http_waf_check_flag(loc_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_RB)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    if (ctx->has_req_body == NGX_HTTP_WAF_FALSE) {
        ngx_http_waf_dp(r, "empty request body ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    ngx_str_t body_str;
    body_str.data = ctx->req_body.pos;
    body_str.len = ctx->req_body.last - ctx->req_body.pos;

    ngx_http_waf_dpf(r, "matching request body %V", &body_str);
    ngx_int_t rc = ngx_http_waf_regex_exec_arrray(r, &body_str, loc_conf->black_post, (u_char*)"BLACK-POST", NULL);
    if (rc == NGX_HTTP_WAF_MATCHED) {
        ngx_http_waf_dp(r, "matched");
        ctx->gernal_logged = 1;
        ctx->blocked = 1;
        ngx_http_waf_append_action_chain(r, action);
        return NGX_HTTP_WAF_MATCHED;
    } else {
        ngx_http_waf_dp(r, "not matched");
        ngx_http_waf_dp_func_end(r);
        return NGX_HTTP_WAF_NOT_MATCHED;
    }
}


ngx_int_t ngx_http_waf_regex_exec_arrray(ngx_http_request_t* r, 
                                         ngx_str_t* str, 
                                         ngx_array_t* array, 
                                         const u_char* rule_type, 
                                         lru_cache_t* cache) {
    ngx_http_waf_dp_func_start(r);
    
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);
    ngx_int_t cache_hit = NGX_HTTP_WAF_FAIL;
    check_result_t result;
    result.is_matched = NGX_HTTP_WAF_NOT_MATCHED;
    result.detail = NULL;

    if (ngx_http_waf_is_empty_str_value(str) || !ngx_http_waf_is_valid_ptr_value(array)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    if (   loc_conf->waf_cache == 1
        && loc_conf->waf_cache_capacity != NGX_CONF_UNSET
        && cache != NULL) {
        ngx_http_waf_dp(r, "getting cache");
        lru_cache_find_result_t tmp = lru_cache_find(cache, str->data, sizeof(u_char) * str->len);
        if (tmp.status == NGX_HTTP_WAF_KEY_EXISTS) {
            ngx_http_waf_dp(r, "found");
            cache_hit = NGX_HTTP_WAF_SUCCESS;
            ngx_memcpy(&result, *(tmp.data), sizeof(check_result_t));
            
        } else {
            ngx_http_waf_dp(r, "not found");
        }
    }

    if (cache_hit != NGX_HTTP_WAF_SUCCESS) {
        ngx_http_waf_dpf(r, "matching str(%V)", str);
        ngx_regex_elt_t* p = (ngx_regex_elt_t*)(array->elts);
        for (size_t i = 0; i < array->nelts; i++, p++) {
            ngx_http_waf_dpf(r, "testing %s", p->name);
            ngx_int_t rc = ngx_regex_exec(p->regex, str, NULL, 0);
            if (rc >= 0) {
                ngx_http_waf_dp(r, "matched");
                result.is_matched = NGX_HTTP_WAF_MATCHED;
                result.detail = p->name;
                break;
            }
        }
    }

    if (   loc_conf->waf_cache == 1
        && loc_conf->waf_cache_capacity != NGX_CONF_UNSET
        && cache != NULL) {
        ngx_http_waf_dp(r, "adding cache");

        /* 过期时间为 [5, 10] 分钟 */
        time_t expire = (time_t)randombytes_uniform(60 * 5) + 60 * 5;
        lru_cache_add_result_t tmp = lru_cache_add(cache, str->data, str->len * sizeof(u_char), expire);
        if (tmp.status == NGX_HTTP_WAF_SUCCESS) {
            *(tmp.data) = lru_cache_calloc(cache, sizeof(check_result_t));
            if (*(tmp.data) == NULL) {
                ngx_http_waf_dp(r, "no memory");

            } else {
                ngx_memcpy(*(tmp.data), &result, sizeof(check_result_t));
                ngx_http_waf_dp(r, "success");
            }

        } else {
            ngx_http_waf_dp(r, "failed");
        }
    }

    if (result.is_matched == NGX_HTTP_WAF_MATCHED) {
        ngx_http_waf_dp(r, "matched");

        /* 这里不设置 ctx->gernal_logged 和 ctx->blocked，参数只是凑数的。 */
        ngx_http_waf_set_rule_info(r, (char*)rule_type, (char*)result.detail, 0, 0);

    } else {
        ngx_http_waf_dp(r, "not matched");
    }

    ngx_http_waf_dp_func_end(r);
    return result.is_matched;
}
