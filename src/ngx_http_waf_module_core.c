#include <ngx_http_waf_module_core.h>
#include <ngx_http_waf_module_check.h>
#include <ngx_http_waf_module_config.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_lru_cache.h>

static ngx_command_t ngx_http_waf_commands[] = {
   {
        ngx_string("waf_mult_mount"),
        NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
        ngx_http_waf_mult_mount_conf,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf"),
        NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
        ngx_http_waf_conf,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_waf_srv_conf_t, waf),
        NULL
   },
   {
        ngx_string("waf_rule_path"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_waf_rule_path_conf,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_waf_srv_conf_t, waf_rule_path),
        NULL
   },
   {
        ngx_string("waf_mode"),
        NGX_HTTP_SRV_CONF | NGX_CONF_1MORE,
        ngx_http_waf_mode_conf,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
   },
    {
        ngx_string("waf_cc_deny"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE123,
        ngx_http_waf_cc_deny_conf,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_cache"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE123,
        ngx_http_waf_cache_conf,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_priority"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_waf_priority_conf,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
   },
    ngx_null_command
};


static ngx_http_module_t ngx_http_waf_module_ctx = {
    NULL,
    ngx_http_waf_init_after_load_config,
    NULL,
    NULL,
    ngx_http_waf_create_srv_conf,
    NULL,
    NULL,
    NULL
};


ngx_module_t ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,    /* module context */
    ngx_http_waf_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_waf_handler_server_rewrite_phase(ngx_http_request_t* r) {
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (NGX_HTTP_WAF_CHECK_FLAG(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_EXTRA_COMPAT) == NGX_HTTP_WAF_TRUE) {
        ngx_http_waf_trigger_mem_collation_event(r);
        return check_all(r, NGX_HTTP_WAF_TRUE);
    }
    return NGX_DECLINED;
}


static ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r) {
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    if (NGX_HTTP_WAF_CHECK_FLAG(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_EXTRA_COMPAT) == NGX_HTTP_WAF_FALSE) {
        ngx_http_waf_trigger_mem_collation_event(r);
        return check_all(r, NGX_HTTP_WAF_TRUE);
    }
    else if (NGX_HTTP_WAF_CHECK_FLAG(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_EXTRA_COMPAT | NGX_HTTP_WAF_MODE_EXTRA_STRICT) == NGX_HTTP_WAF_TRUE) {
        return check_all(r, NGX_HTTP_WAF_FALSE);
    }
    return NGX_DECLINED;
}


static void ngx_http_waf_trigger_mem_collation_event(ngx_http_request_t* r) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start the memory collection event trigger process.");

    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    time_t now = time(NULL);

    if (srv_conf->waf == 0 || srv_conf->waf == NGX_CONF_UNSET) {
        return;
    }

    if (srv_conf->shm_zone_cc_deny == NULL
        || srv_conf->last_clear_ip_access_statistics == NULL) {
        return;
    }

    
    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)srv_conf->shm_zone_cc_deny->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Shared memory is locked.");
    
    double diff_clear_minute = difftime(now, *(srv_conf->last_clear_ip_access_statistics)) / 60;

    ngx_shmtx_unlock(&shpool->mutex);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Shared memory is unlocked.");
    
    if (diff_clear_minute > ngx_max(60, srv_conf->waf_cc_deny_duration / 60 * 3)) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Start process - clear ip access statistics.");
        ngx_http_waf_clear_ip_access_statistics(r);

    }

    ngx_int_t is_need_eliminate_cache = NGX_HTTP_WAF_FALSE;
    ngx_int_t interval = srv_conf->waf_eliminate_inspection_cache_interval;
    

    if (difftime(now, srv_conf->black_url_inspection_cache.last_eliminate) > interval) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The cache in black_url_inspection_cache will trigger memory collection process.");
        is_need_eliminate_cache = NGX_HTTP_WAF_TRUE;
    } 
    
    else if (difftime(now, srv_conf->black_args_inspection_cache.last_eliminate) > interval) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The cache in black_args_inspection_cache will trigger memory collection process.");
        is_need_eliminate_cache = NGX_HTTP_WAF_TRUE;
    } 
    
    else if (difftime(now, srv_conf->black_ua_inspection_cache.last_eliminate) > interval) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The cache in black_ua_inspection_cache will trigger memory collection process.");
        is_need_eliminate_cache = NGX_HTTP_WAF_TRUE;
    } 
    
    else if (difftime(now, srv_conf->black_referer_inspection_cache.last_eliminate) > interval) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The cache in black_referer_inspection_cache will trigger memory collection process.");
        is_need_eliminate_cache = NGX_HTTP_WAF_TRUE;
    } 
    
    else if (difftime(now, srv_conf->black_cookie_inspection_cache.last_eliminate) > interval) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The cache in black_cookie_inspection_cache will trigger memory collection process.");
        is_need_eliminate_cache = NGX_HTTP_WAF_TRUE;
    } 
    
    else if (difftime(now, srv_conf->white_url_inspection_cache.last_eliminate) > interval) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The cache in white_url_inspection_cache will trigger memory collection process.");
        is_need_eliminate_cache = NGX_HTTP_WAF_TRUE;
    } 
    
    else if (difftime(now, srv_conf->white_referer_inspection_cache.last_eliminate) > interval) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The cache in white_referer_inspection_cache will trigger memory collection process.");
        is_need_eliminate_cache = NGX_HTTP_WAF_TRUE;
    }

    if (is_need_eliminate_cache == NGX_HTTP_WAF_TRUE) {
        srv_conf->black_url_inspection_cache.last_eliminate = now;
        srv_conf->black_args_inspection_cache.last_eliminate = now;
        srv_conf->black_ua_inspection_cache.last_eliminate = now;
        srv_conf->black_referer_inspection_cache.last_eliminate = now;
        srv_conf->black_cookie_inspection_cache.last_eliminate = now;
        srv_conf->white_url_inspection_cache.last_eliminate = now;
        srv_conf->white_referer_inspection_cache.last_eliminate = now;
        ngx_http_waf_eliminate_inspection_cache(r);
    }


    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The memory collection event trigger process is all done.");
}


static void ngx_http_waf_clear_ip_access_statistics(ngx_http_request_t* r) {
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The IP statistics cleanup process has been started.");
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");

    
    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)srv_conf->shm_zone_cc_deny->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Shared memory is locked.");
 
    ip_trie_clear(srv_conf->ipv4_access_statistics);
    ip_trie_clear(srv_conf->ipv6_access_statistics);

    ngx_shmtx_unlock(&shpool->mutex);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Shared memory is unlocked.");

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The IP statistics cleanup process has been fully completed.");
}


static void ngx_http_waf_eliminate_inspection_cache(ngx_http_request_t* r) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The batch cache elimination process has been started.");

    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");
    
    double percent = srv_conf->waf_eliminate_inspection_cache_percent / 100.0;


    if (lru_cache_manager_eliminate_percent(&srv_conf->black_url_inspection_cache, percent) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Unable to clear cache from black_url_inspection_cache.");
    }

    if (lru_cache_manager_eliminate_percent(&srv_conf->black_args_inspection_cache, percent) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Unable to clear cache from black_args_inspection_cache.");
    }

    if (lru_cache_manager_eliminate_percent(&srv_conf->black_ua_inspection_cache, percent) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Unable to clear cache from black_ua_inspection_cache.");
    }

    if (lru_cache_manager_eliminate_percent(&srv_conf->black_referer_inspection_cache, percent) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Unable to clear cache from black_referer_inspection_cache.");
    }

    if (lru_cache_manager_eliminate_percent(&srv_conf->black_cookie_inspection_cache, percent) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Unable to clear cache from black_cookie_inspection_cache.");
    }

    if (lru_cache_manager_eliminate_percent(&srv_conf->white_url_inspection_cache, percent) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Unable to clear cache from white_url_inspection_cache.");
    }

    if (lru_cache_manager_eliminate_percent(&srv_conf->white_referer_inspection_cache, percent) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Unable to clear cache from white_referer_inspection_cache.");
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The batch cache elimination process has been fully completed.");
}


static ngx_int_t check_all(ngx_http_request_t* r, ngx_int_t is_check_cc) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_int_t is_matched = NGX_HTTP_WAF_NOT_MATCHED;
    ngx_int_t http_status = NGX_DECLINED;

    if (ctx == NULL) {
        ctx = ngx_palloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            http_status = NGX_ERROR;
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
                "ngx_waf: The request context could not be created because the memory allocation failed.");
            return http_status;
        }
        else {
            ctx->read_body_done = NGX_HTTP_WAF_FALSE;
            ctx->blocked = NGX_HTTP_WAF_FALSE;
            ctx->rule_type[0] = '\0';
            ctx->rule_deatils[0] = '\0';
            ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
        }
    }

    if (r->internal != 0 || srv_conf->waf == 0 || srv_conf->waf == NGX_CONF_UNSET || ctx->read_body_done == NGX_HTTP_WAF_TRUE) {
        http_status = NGX_DECLINED;
    }
    else {
        ngx_http_waf_check_pt* funcs = NULL;
        if (is_check_cc == NGX_HTTP_WAF_TRUE) {
            funcs = srv_conf->check_proc;
        } else {
            funcs = srv_conf->check_proc_no_cc;
        }
        for (size_t i = 0; funcs[i] != NULL; i++) {
            is_matched = funcs[i](r, &http_status);
            if (is_matched == NGX_HTTP_WAF_MATCHED) {
                break;
            }
        }
        /* 如果请求方法为 POST 且 本模块还未读取过请求体 且 配置中未关闭请求体检查 */
        if ((r->method & NGX_HTTP_POST) != 0
            && ctx->read_body_done == NGX_HTTP_WAF_FALSE
            && is_matched != NGX_HTTP_WAF_MATCHED
            && NGX_HTTP_WAF_CHECK_FLAG(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_RB) == NGX_HTTP_WAF_TRUE) {
            r->request_body_in_persistent_file = 0;
            r->request_body_in_clean_file = 0;
            http_status = ngx_http_read_client_request_body(r, ngx_http_waf_handler_check_black_post);
            if (http_status != NGX_ERROR && http_status < NGX_HTTP_SPECIAL_RESPONSE) {
                http_status = NGX_DONE;
            }
        }
    }

    if (http_status != NGX_DECLINED && http_status != NGX_DONE) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%s][%s]", ctx->rule_type, ctx->rule_deatils);
    }
    return http_status;
}
