#include <ngx_http_waf_module_core.h>
#include <ngx_http_waf_module_check.h>
#include <ngx_http_waf_module_config.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_lru_cache.h>
#include <ngx_http_waf_module_under_attack.h>

static ngx_command_t ngx_http_waf_commands[] = {
    {
        ngx_string("waf_zone"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2,
        ngx_http_waf_zone_conf,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_http_waf_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_rule_path"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_waf_rule_path_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_waf_loc_conf_t, waf_rule_path),
        NULL
   },
   {
        ngx_string("waf_mode"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
        ngx_http_waf_mode_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
    {
        ngx_string("waf_cc_deny"),
        NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,
        ngx_http_waf_cc_deny_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_cache"),
        NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,
        ngx_http_waf_cache_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_under_attack"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
        ngx_http_waf_under_attack_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_captcha"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234 | NGX_CONF_TAKE5 | NGX_CONF_TAKE6 | NGX_CONF_TAKE7,
        ngx_http_waf_captcha_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_verify_bot"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234 | NGX_CONF_TAKE5 | NGX_CONF_TAKE6 | NGX_CONF_TAKE7,
        ngx_http_waf_verify_bot_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_priority"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_waf_priority_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_action"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234 | NGX_CONF_TAKE5 | NGX_CONF_TAKE6 | NGX_CONF_TAKE7,
        ngx_http_waf_action_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_block_page"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_waf_block_page_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_modsecurity"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123,
        ngx_http_waf_modsecurity_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_modsecurity_transaction_id"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123,
        ngx_http_waf_modsecurity_transaction_id_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
    ngx_null_command
};


static ngx_http_module_t ngx_http_waf_module_ctx = {
    ngx_http_waf_preconfiguration,
    ngx_http_waf_postconfiguration,
    ngx_http_waf_create_main_conf, 
    NULL, 
    NULL, 
    NULL,
    ngx_http_waf_create_loc_conf,
    ngx_http_waf_merge_loc_conf
};


ngx_module_t ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,       /* module context */
    ngx_http_waf_commands,          /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    ngx_http_waf_init_process,      /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t _read_request_body(ngx_http_request_t* r);


static void _handler_read_request_body(ngx_http_request_t* r);


static ngx_int_t _gc(ngx_http_request_t* r);


ngx_int_t ngx_http_waf_init_process(ngx_cycle_t *cycle) {
    randombytes_stir();
    curl_global_init(CURL_GLOBAL_DEFAULT);
    return NGX_OK;
}


ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r) {
    return ngx_http_waf_check_all(r, NGX_HTTP_WAF_TRUE);
}

ngx_int_t ngx_http_waf_handler_precontent_phase(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ngx_http_waf_perform_action_at_content(r);
    
    ngx_http_waf_dp_func_end(r);
    return NGX_OK;
}


ngx_int_t ngx_http_waf_handler_log_phase(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (loc_conf->waf == 0 || loc_conf->waf == NGX_CONF_UNSET) {
        ngx_http_waf_dp(r, "do nothing due to not enabled ... return");
        return NGX_DECLINED;
    }

    _gc(r);

    if (ctx == NULL) {
        ngx_http_waf_dp(r, "no ctx ... return");
        return NGX_OK;
    }

    if (ctx->gernal_logged) {
        ctx->gernal_logged = 0;
        ngx_http_waf_dp(r, "logging (gernal)");
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%V][%V]", &ctx->rule_type, &ctx->rule_deatils);
        ngx_http_waf_dp(r, "success ... return");
    }

    if (ctx->modsecurity_transaction != NULL) {
        ngx_http_waf_dp(r, "logging (ModSecurity)");
        int ret = msc_process_logging(ctx->modsecurity_transaction);

        ngx_http_waf_dp(ctx->r, "cleaning transaction");
        msc_transaction_cleanup(ctx->modsecurity_transaction);
        ctx->modsecurity_transaction = NULL;
        ngx_http_waf_dp(ctx->r, "success ... return");

        if (ret != 1) {
            ngx_http_waf_dp(r, "msc_process_logging() failed ... return");
            return NGX_ERROR;
        }
        ngx_http_waf_dp(r, "success ... return");
    }

    ngx_http_waf_dp_func_end(r);
    return NGX_OK;
}


ngx_int_t ngx_http_waf_check_all(ngx_http_request_t* r, ngx_int_t is_check_cc) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);
    ngx_int_t is_matched = NGX_HTTP_WAF_NOT_MATCHED;

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf)) {
        ngx_http_waf_dp(r, "do nothing due to not enabled ... return");
        return NGX_DECLINED;
    }

    if (ctx == NULL) {
        ngx_http_waf_dp(r, "allocating memory to storage ctx");

        ngx_http_cleanup_t* cln = ngx_palloc(r->pool, sizeof(ngx_http_cleanup_t));
        if (cln == NULL) {
            ngx_http_waf_dp(r, "no memory to store cleanup_pt ... return");
            return NGX_ERROR;
        }
        ngx_http_waf_dp(r, "success");

        ctx = ngx_palloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            ngx_http_waf_dp(r, "no memory to store ctx ... return");
            return NGX_ERROR;
        }
        ngx_http_waf_dp(r, "success");

        ngx_http_waf_dp(r, "initializing cleanup_pt");
        cln->handler = ngx_http_waf_handler_cleanup;
        cln->data = ctx;
        cln->next = NULL;
        ngx_http_waf_dp(r, "success");

        ngx_http_waf_dp(r, "initializing ctx");
        ctx->r = r;
        ctx->action_chain = NULL;
        ctx->rate = 0;
        ctx->response_str = NULL;
        ctx->register_content_handler = 0;
        ctx->gernal_logged = 0;
        ctx->read_body_done = 0;
        ctx->has_req_body = 0;
        ctx->waiting_more_body = 0;
        ctx->pre_content_run = 0;
        ctx->handler_index = 0;

#if (NGX_THREADS)
        ctx->async_captcha = 0;
        ctx->async_captcha_pass = 0;
#endif

        ctx->checked = 0;
        ctx->blocked = 0;
        ctx->spend = (double)clock() / CLOCKS_PER_SEC * 1000;
        ngx_str_null(&ctx->rule_type);
        ngx_str_null(&ctx->rule_deatils);
        ctx->req_body.pos = NULL;
        ctx->req_body.last = NULL;
        ctx->req_body.memory = 1;
        ctx->req_body.temporary = 0;
        ctx->req_body.mmap = 0;
        ctx->modsecurity_transaction = NULL;
#if (NGX_THREADS) && (NGX_HTTP_WAF_ASYNC_MODSECURITY)
        ctx->modsecurity_triggered = NGX_HTTP_WAF_FALSE;
        ctx->start_from_thread = NGX_HTTP_WAF_FALSE;
#endif
        ngx_http_waf_dp(r, "success");
        

        ngx_http_waf_dp(r, "installing cleanup_pt");
        if (r->cleanup == NULL) {
            r->cleanup = cln;
        } else {
            for (ngx_http_cleanup_t* i = r->cleanup; i != NULL; i = i->next) {
                if (i->next == NULL) {
                    i->next = cln;
                    break;
                }
            }
        }
        ngx_http_waf_dp(r, "success");

        ngx_http_waf_dp(r, "installing cleanup_pt");
        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
        ngx_http_waf_dp(r, "success");
    }

    if (ngx_http_get_module_ctx(r, ngx_http_waf_module) == NULL) {
        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    
    if (ctx->register_content_handler && loc_conf->waf == 1) {
        ngx_http_waf_dp(r, "registering content handler");
        ngx_http_waf_register_content_handler(r);
        ngx_http_waf_dp(r, "success");
    }

    if (ngx_http_waf_check_flag(!loc_conf->waf_mode, r->method)) {
        ngx_http_waf_dp(r, "do nothing due to waf_mode ... return");
        return NGX_DECLINED;
    }


    if (ctx->waiting_more_body) {
        return NGX_DONE;
    }

    if (!ctx->read_body_done) {
        ngx_http_waf_dp(r, "reading request body");
        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;

        ngx_int_t rc = ngx_http_read_client_request_body(r, _handler_read_request_body);
        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ngx_http_waf_dpf(r, "failed(%i) ... return", rc);
            return rc;
        }
        if (rc == NGX_AGAIN) {
            ngx_http_waf_dpf(r, "continuse(%i) ... return", rc);
            ctx->waiting_more_body = 1;
            return NGX_DONE;
        }
    }

    // if (!r->internal && ctx->checked) {
    //     ngx_http_waf_dp(r, "do nothing due to multiple internal redirects ... return");
    //     return NGX_DECLINED;
    // }

#if (NGX_THREADS) && (NGX_HTTP_WAF_ASYNC_MODSECURITY)
    if (ctx->start_from_thread == NGX_HTTP_WAF_TRUE) {
        if (ctx->modsecurity_triggered == NGX_HTTP_WAF_TRUE) {
            return ctx->modsecurity_status;
        } else {
            return NGX_DECLINED;
        }
    }
#endif

#if (NGX_THREADS)
    if (ctx->checked && !ctx->async_captcha) {
        ngx_http_waf_dp(r, "do nothing due to internal redirect ... return");
        return NGX_DECLINED;
    }
#else
    if (ctx->checked) {
        ngx_http_waf_dp(r, "do nothing due to internal redirect ... return");
        return NGX_DECLINED;
    }
#endif

    ngx_http_waf_dp(r, "reading request body to ctx");
    if (_read_request_body(r) == NGX_HTTP_WAF_FAULT) {
        ngx_http_waf_dp(r, "failed ... return");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_waf_dp(r, "success");

    ctx->checked = 1;

    ngx_http_waf_dp(r, "invoke inspection handler");
    ngx_http_waf_check_pt* funcs = loc_conf->check_proc;
    for ( ; funcs[ctx->handler_index] != NULL; (ctx->handler_index)++) {
        is_matched = funcs[ctx->handler_index](r);
        if (is_matched == NGX_HTTP_WAF_MATCHED) {
            break;
        }
        ctx->action_chain = NULL;
    }

    ctx->spend = ((double)clock() / CLOCKS_PER_SEC * 1000) - ctx->spend;

    ngx_int_t http_status = ngx_http_waf_perform_action_at_access_end(r);
    ngx_http_waf_dpf(r, "return %i", http_status);

    ngx_http_waf_dp_func_end(r);
    return http_status;
}


void ngx_http_waf_handler_cleanup(void *data) {
    return;
}


static ngx_int_t _read_request_body(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);


    if (r->request_body == NULL) {
        ngx_http_waf_dp(r, "no request body ... return");
        return NGX_HTTP_WAF_FAIL;
    }

    if (r->request_body->bufs == NULL) {
        ngx_http_waf_dp(r, "no request body ... return");
        return NGX_HTTP_WAF_FAIL;
    }

    if (r->request_body->temp_file) {
        ngx_http_waf_dp(r, "in temp file ... return");
        return NGX_HTTP_WAF_FAIL;
    }

    if (ctx->has_req_body) {
        ngx_http_waf_dp(r, "already read ... return");
        return NGX_HTTP_WAF_SUCCESS;
    }

    ngx_chain_t* bufs = r->request_body->bufs;
    size_t len = 0;

    ngx_http_waf_dp(r, "getting request body length");
    while (bufs != NULL) {
        len += (bufs->buf->last - bufs->buf->pos) * (sizeof(u_char) / sizeof(uint8_t));
        bufs = bufs->next;
    }
    ngx_http_waf_dpf(r, "request body length is %z", len);

    ngx_http_waf_dp(r, "allocing memory to store request body into ctx");
    u_char* body = ngx_pnalloc(r->pool, len + sizeof(u_char));
    if (body == NULL) {
        ngx_http_waf_dp(r, "no memroy ... return");
        return NGX_HTTP_WAF_FAULT;
    }
    ngx_http_waf_dp(r, "success");

    ctx->has_req_body = 1;
    ctx->req_body.pos = body;
    ctx->req_body.last = (u_char*)((uint8_t*)body + len);

    ngx_http_waf_dp(r, "copying request body into ctx");
    bufs = r->request_body->bufs;
    size_t offset = 0;
    while (bufs != NULL) {
        size_t size = bufs->buf->last - bufs->buf->pos;
        ngx_memcpy((uint8_t*)body + offset, bufs->buf->pos, size);
        offset += size;
        bufs = bufs->next;
    }
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dpf(r, "request body is %*s", len, body);

    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_SUCCESS;
}


static void _handler_read_request_body(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ctx->read_body_done = 1;
    ngx_http_finalize_request(r, NGX_DONE);

    if (ctx->waiting_more_body) {
        ctx->waiting_more_body = 0;
        ngx_http_core_run_phases(r);
    }

    ngx_http_waf_dp_func_end(r);
}


static ngx_int_t _gc(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_main_conf_t* mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    ngx_core_conf_t* ccf = (ngx_core_conf_t *)ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);
    ngx_int_t worker_processes = ccf->worker_processes;

    ngx_http_waf_dpf(r, "%i worker processes", worker_processes);

    /* 如果至少有一个 worker 进程则计算概率 */
    if (worker_processes > 1 && randombytes_uniform(worker_processes) != 0) {
        return NGX_HTTP_WAF_SUCCESS;
    }

    /* 首先释放共享内存 */
    ngx_http_waf_dp(r, "freeing shared memory");
    shm_t* shms = mcf->shms->elts;

    for (size_t i = 0; i < mcf->shms->nelts; i++) {
        shm_t* shm = &shms[i];

        ngx_http_waf_dpf(r, "freeing shared memory %V", &shm->name);

        if (ngx_http_waf_shm_gc(shm) != NGX_HTTP_WAF_SUCCESS) {
            ngx_http_waf_dp(r, "failed ... return");
            return NGX_HTTP_WAF_FAIL;
        }

        ngx_http_waf_dp(r, "success");
    }
    
    /* 最后释放非共享内存 */
    ngx_http_waf_dp(r, "freeing non-shared memory");
    lru_cache_t** caches = mcf->local_caches->elts;
    ngx_uint_t nelts = mcf->local_caches->nelts;

    ngx_http_waf_dpf(r, "%i caches", nelts);

    if (nelts != 0) {
        for (ngx_uint_t i = 0; i < nelts; i++){
            lru_cache_t* cache = caches[i];

            if (cache->no_memory) {
                ngx_http_waf_dp(r, "low memory");
                cache->no_memory = 0;
                lru_cache_eliminate(cache, 5);

            } else {
                ngx_uint_t limit = 10, loop = 0;

                ngx_http_waf_dpf(r, "limit is %ui", limit);

                while (loop < limit && lru_cache_eliminate_expire(cache, 5) >= 3) {
                    ngx_http_waf_dpf(r, "loop %ui", loop);
                    loop++;
                }
            }
        }
    }

    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_SUCCESS;
}