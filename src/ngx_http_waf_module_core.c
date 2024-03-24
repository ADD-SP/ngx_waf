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


static ngx_int_t _handler_content_phase(ngx_http_request_t* r);


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


ngx_int_t ngx_http_waf_handler_log_phase(ngx_http_request_t* r) {

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (loc_conf->waf == 0 || loc_conf->waf == NGX_CONF_UNSET) {
        return NGX_DECLINED;
    }

    _gc(r);

    if (ctx == NULL) {
        return NGX_OK;
    }

    // if (ctx->gernal_logged) {
    //     ctx->gernal_logged = 0;
    //     ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%V][%V]", &ctx->rule_type, &ctx->rule_deatils);
    // }

    if (ctx->modsecurity_transaction != NULL) {
        int ret = msc_process_logging(ctx->modsecurity_transaction);

        msc_transaction_cleanup(ctx->modsecurity_transaction);
        ctx->modsecurity_transaction = NULL;

        if (ret != 1) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t ngx_http_waf_check_all(ngx_http_request_t* r, ngx_int_t is_check_cc) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);
    ngx_int_t is_matched = NGX_HTTP_WAF_NOT_MATCHED;
    ngx_http_waf_check_result_t check_result;
    ngx_http_request_t* sr;
    ngx_http_post_subrequest_t* psr;

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf)) {
        return NGX_DECLINED;
    }

    if (ctx == NULL) {
        ngx_http_cleanup_t* cln = ngx_palloc(r->pool, sizeof(ngx_http_cleanup_t));
        if (cln == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ngx_waf] failed to allocate memory for ngx_http_cleanup_t");
            return NGX_ERROR;
        }

        ctx = ngx_palloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ngx_waf] failed to allocate memory for ctx");
            return NGX_ERROR;
        }

        cln->handler = ngx_http_waf_handler_cleanup;
        cln->data = ctx;
        cln->next = NULL;

        ctx->r = r;
        ctx->modsecurity_transaction = NULL;
        ctx->next_chekcer_index = 0;
        ctx->waiting_subrequest = 0;

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

        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    if (ngx_http_get_module_ctx(r, ngx_http_waf_module) == NULL) {
        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    if (ngx_http_waf_is_internal_request(r)) {
        return NGX_DECLINED;
    }

    if (ctx->next_chekcer_index >= sizeof(loc_conf->check_proc) / sizeof(ngx_http_waf_check_pt*)) {
        return NGX_DECLINED;
    }

    if (ctx->waiting_subrequest) {
        return NGX_AGAIN;
    }

    ngx_http_waf_check_pt* funcs = loc_conf->check_proc;
    for (; ctx->next_chekcer_index < sizeof(loc_conf->check_proc) / sizeof(ngx_http_waf_check_pt*); ctx->next_chekcer_index++) {
        check_result = funcs[ctx->next_chekcer_index](r);

        if (!check_result.need_do_sth) {
            continue;
        }

        if (check_result.need_log) {
            ngx_log_error(check_result.log_level, r->connection->log, 0, "[ngx_waf] %V", &check_result.log_message);
        }

        if (check_result.need_response) {
            ctx->next_chekcer_index = sizeof(loc_conf->check_proc) / sizeof(ngx_http_waf_check_pt*);

            if (ngx_http_waf_is_empty_str_value(&check_result.response_body)) {
                return check_result.http_status;
            }

            ctx->result_for_content_phase = check_result;
            r->content_handler = _handler_content_phase;
        }

        if (check_result.need_subrequest) {
            if ((psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t))) == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ngx_waf] failed to allocate memory for ngx_http_post_subrequest_t");
                return NGX_ERROR;
            }

            psr->data = ctx;
            psr->handler = check_result.subrequest_handler;

            if (ngx_http_subrequest(r, &check_result.subrequest_uri, &check_result.subrequest_args, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ngx_waf] failed to create subrequest");
                return NGX_ERROR;
            }

            return NGX_AGAIN;
        }
    }

    return NGX_DECLINED;
}


void ngx_http_waf_handler_cleanup(void *data) {
    return;
}


static ngx_int_t _handler_content_phase(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);
    ngx_http_waf_check_result_t result = ctx->result_for_content_phase;
    ngx_buf_t* buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    ngx_chain_t* out;
    ngx_int_t rc;
    
    r->headers_out.content_type.data = "text/html";
    r->headers_out.content_type.len = sizeof("text/html") - 1;

    r->headers_out.status = result.http_status;

    r->headers_out.content_length_n = result.response_body.len;

    if (ngx_http_waf_gen_no_cache_header(r) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[ngx_waf] failed to generate response header Cache-control");
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ngx_waf] failed to send response header");
        return rc;
    }

    if (r->header_only) {
        return rc;
    }

    if ((buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ngx_waf] failed to allocate memory for response body");
        return NGX_ERROR; 
    }

    if ((buf->pos = ngx_pcalloc(r->pool, result.response_body.len)) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ngx_waf] failed to allocate memory for response body");
        return NGX_ERROR; 
    }

    ngx_memcpy(buf->pos, result.response_body.data, result.response_body.len);
    buf->last = buf->pos + result.response_body.len;
    buf->memory = 1;
    buf->last_buf = 1;
    buf->start = buf->pos;
    buf->end = buf->last;

    if ((out = ngx_pcalloc(r->pool, sizeof(ngx_chain_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ngx_waf] failed to allocate memory for response body");
        return NGX_ERROR; 
    }

    out->buf = buf;
    out->next = NULL;

    return ngx_http_output_filter(r, out);
}


static ngx_int_t _gc(ngx_http_request_t* r) {

    ngx_http_waf_main_conf_t* mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    ngx_core_conf_t* ccf = (ngx_core_conf_t *)ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);
    ngx_int_t worker_processes = ccf->worker_processes;


    /* 如果至少有一个 worker 进程则计算概率 */
    if (worker_processes > 1 && randombytes_uniform(worker_processes) != 0) {
        return NGX_HTTP_WAF_SUCCESS;
    }

    /* 首先释放共享内存 */
    shm_t* shms = mcf->shms->elts;

    for (size_t i = 0; i < mcf->shms->nelts; i++) {
        shm_t* shm = &shms[i];


        if (ngx_http_waf_shm_gc(shm) != NGX_HTTP_WAF_SUCCESS) {
            return NGX_HTTP_WAF_FAIL;
        }

    }
    
    /* 最后释放非共享内存 */
    lru_cache_t** caches = mcf->local_caches->elts;
    ngx_uint_t nelts = mcf->local_caches->nelts;


    if (nelts != 0) {
        for (ngx_uint_t i = 0; i < nelts; i++){
            lru_cache_t* cache = caches[i];

            if (cache->no_memory) {
                cache->no_memory = 0;
                lru_cache_eliminate(cache, 5);

            } else {
                ngx_uint_t limit = 10, loop = 0;


                while (loop < limit && lru_cache_eliminate_expire(cache, 5) >= 3) {
                    loop++;
                }
            }
        }
    }

    return NGX_HTTP_WAF_SUCCESS;
}