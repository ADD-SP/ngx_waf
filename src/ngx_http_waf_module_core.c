#include <ngx_http_waf_module_core.h>
#include <ngx_http_waf_module_check.h>
#include <ngx_http_waf_module_config.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_lru_cache.h>
#include <ngx_http_waf_module_under_attack.h>

static ngx_command_t ngx_http_waf_commands[] = {
   {
        ngx_string("waf"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_http_waf_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_waf_loc_conf_t, waf),
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
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
        ngx_http_waf_under_attack_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_captcha"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234 | NGX_CONF_TAKE5 | NGX_CONF_TAKE6,
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
        ngx_string("waf_http_status"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
        ngx_http_waf_http_status_conf,
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
    NULL,
    ngx_http_waf_init_after_load_config,
    NULL, 
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


ngx_int_t ngx_http_waf_init_process(ngx_cycle_t *cycle) {
    randombytes_stir();
    curl_global_init(CURL_GLOBAL_DEFAULT);
    return NGX_OK;
}


ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r) {
    return ngx_http_waf_check_all(r, NGX_HTTP_WAF_TRUE);
}

ngx_int_t ngx_http_waf_handler_precontent_phase(ngx_http_request_t* r) {
    ngx_http_waf_dp(r, "ngx_http_waf_handler_precontent_phase() ... start");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf)) {
        ngx_http_waf_dp(r, "do nothing due to not enabled ... return");
        return NGX_DECLINED;
    }

    if (ctx->pre_content == NGX_HTTP_WAF_TRUE) {
        ngx_http_waf_dp(r, "nothing todo  ... return");
        return NGX_DECLINED;
    }

    if (ctx->under_attack != NGX_HTTP_WAF_TRUE && ctx->captcha != NGX_HTTP_WAF_TRUE && ctx->response_str == NULL) {
        ngx_http_waf_dp(r, "nothing todo  ... return");
        return NGX_DECLINED;
    }

    ctx->pre_content = NGX_HTTP_WAF_TRUE;

    ngx_http_waf_dp(r, "discard_request_body");
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        ngx_http_waf_dpf(r, "failed(%i) ... return", rc);
        return rc;
    }
    ngx_http_waf_dp(r, "success");

    u_char* html = NULL;
    size_t html_len = 0;
    ngx_http_waf_dp(r, "getting html");
    if (ctx->under_attack == NGX_HTTP_WAF_TRUE) {
        html = loc_conf->waf_under_attack_html;
        html_len = loc_conf->waf_under_attack_len;
    } else if (ctx->captcha == NGX_HTTP_WAF_TRUE) {
        html = loc_conf->waf_captcha_html;
        html_len = loc_conf->waf_captcha_html_len;
    } else {
        html = (u_char*)ctx->response_str;
        html_len = ngx_strlen(html);
    }
    ngx_http_waf_dpf(r, "success(%s)", html);

    r->headers_out.content_length_n = 0;
    if (ctx->under_attack == NGX_HTTP_WAF_TRUE || ctx->captcha == NGX_HTTP_WAF_TRUE) {
        ngx_str_set(&r->headers_out.content_type, "text/html");
        r->headers_out.status = NGX_HTTP_SERVICE_UNAVAILABLE;
    } else {
        ngx_str_set(&r->headers_out.content_type, "text/plain");
        r->headers_out.status = 200;
    }

    if (ngx_http_waf_gen_no_cache_header(r) != NGX_HTTP_WAF_SUCCESS) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }

    if (r->method == NGX_HTTP_HEAD) {
        ngx_http_waf_dp(r, "sending headers");
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            ngx_http_waf_dpf(r, "failed(%i) ... return", rc);
            return rc;
        }
        ngx_http_waf_dp(r, "success");
    } else {
        ngx_http_waf_dp(r, "allocating buffer object");
        ngx_buf_t* buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        if (buf == NULL) {
            ngx_http_waf_dp(r, "failed ... return");
            return NGX_HTTP_INTERNAL_SERVER_ERROR; 
        }
        ngx_http_waf_dp(r, "success");

        ngx_http_waf_dp(r, "allocating buffer");
        buf->pos = ngx_pcalloc(r->pool, html_len);
        if (buf->pos == NULL) {
            ngx_http_waf_dp(r, "failed ... return");
            return NGX_HTTP_INTERNAL_SERVER_ERROR; 
        }
        ngx_http_waf_dp(r, "success");

        ngx_http_waf_dp(r, "copying html to buffer");
        ngx_memcpy(buf->pos, html, html_len);
        buf->last = buf->pos + html_len;
        buf->memory = 1;
        buf->last_buf = (r == r->main) ? 1 : 0;
        ngx_http_waf_dp(r, "success");

        ngx_http_waf_dp(r, "allocating out buffer");
        ngx_chain_t* out = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
        if (out == NULL) {
            ngx_http_waf_dp(r, "failed ... return");
            return NGX_HTTP_INTERNAL_SERVER_ERROR; 
        }
        out->buf = buf;
        out->next = NULL;
        ngx_http_waf_dp(r, "success");

        ngx_http_waf_dp(r, "sending headers");
        r->headers_out.content_length_n = html_len;
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            ngx_http_waf_dp(r, "failed ... return");
            return rc;
        }
        ngx_http_waf_dp(r, "success");

        ngx_http_waf_dp(r, "next filter ... end");
        rc = ngx_http_output_filter(r, out);
        return rc;
    }

    ngx_http_waf_dp(r, "ngx_http_waf_handler_precontent_phase() ... end");
    return NGX_DECLINED;
}


ngx_int_t ngx_http_waf_handler_log_phase(ngx_http_request_t* r) {
    ngx_http_waf_dp(r, "ngx_http_waf_handler_log_phase() ... start");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (loc_conf->waf == 0 || loc_conf->waf == NGX_CONF_UNSET) {
        ngx_http_waf_dp(r, "do nothing due to not enabled ... return");
        return NGX_DECLINED;
    }

    if (ctx == NULL) {
        ngx_http_waf_dp(r, "no ctx ... return");
        return NGX_OK;
    }

    if (ctx->gernal_logged == NGX_HTTP_WAF_TRUE) {
        ctx->gernal_logged = 0;
        ngx_http_waf_dp(r, "logging (gernal)");
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%s][%s]", ctx->rule_type, ctx->rule_deatils);
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

    ngx_http_waf_dp(r, "ngx_http_waf_handler_log_phase() ... end");
    return NGX_OK;
}


ngx_int_t ngx_http_waf_check_all(ngx_http_request_t* r, ngx_int_t is_check_cc) {
    ngx_http_waf_dp(r, "ngx_http_waf_check_all() ... start");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);
    ngx_int_t is_matched = NGX_HTTP_WAF_NOT_MATCHED;
    ngx_int_t http_status = NGX_DECLINED;

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
        ctx->response_str = NULL;
        ctx->gernal_logged = NGX_HTTP_WAF_FALSE;
        ctx->read_body_done = NGX_HTTP_WAF_FALSE;
        ctx->has_req_body = NGX_HTTP_WAF_FALSE;
        ctx->waiting_more_body = NGX_HTTP_WAF_FALSE;
        ctx->pre_content = NGX_HTTP_WAF_FALSE;
        ctx->checked = NGX_HTTP_WAF_FALSE;
        ctx->blocked = NGX_HTTP_WAF_FALSE;
        ctx->under_attack = NGX_HTTP_WAF_FALSE;
        ctx->captcha = NGX_HTTP_WAF_FALSE;
        ctx->spend = (double)clock() / CLOCKS_PER_SEC * 1000;
        ctx->rule_type[0] = '\0';
        ctx->rule_deatils[0] = '\0';
        ctx->req_body.pos = NULL;
        ctx->req_body.last = NULL;
        ctx->req_body.memory = 1;
        ctx->req_body.temporary = 0;
        ctx->req_body.mmap = 0;
        ctx->modsecurity_transaction = NULL;
        ctx->modsecurity_intervention = NULL;
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

    if (ctx->waiting_more_body == NGX_HTTP_WAF_TRUE) {
        return NGX_DONE;
    }

    if (ctx->read_body_done != NGX_HTTP_WAF_TRUE) {
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
            ctx->waiting_more_body = NGX_HTTP_WAF_TRUE;
            return NGX_DONE;
        }
    }

    if (r->internal != 0 && ctx->checked == NGX_HTTP_WAF_TRUE) {
        ngx_http_waf_dp(r, "do nothing due to multiple internal redirects ... return");
        return NGX_DECLINED;
    }

#if (NGX_THREADS) && (NGX_HTTP_WAF_ASYNC_MODSECURITY)
    if (ctx->start_from_thread == NGX_HTTP_WAF_TRUE) {
        if (ctx->modsecurity_triggered == NGX_HTTP_WAF_TRUE) {
            return ctx->modsecurity_status;
        } else {
            return NGX_DECLINED;
        }
    }
#endif

    if (ctx->checked == NGX_HTTP_WAF_TRUE) {
        ngx_http_waf_dp(r, "do nothing due to internal redirect ... return");
        return NGX_DECLINED;
    }

    ngx_http_waf_dp(r, "reading request body to ctx");
    if (_read_request_body(r) == NGX_HTTP_WAF_BAD) {
        ngx_http_waf_dp(r, "failed ... return");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_waf_dp(r, "success");

    ctx->checked = NGX_HTTP_WAF_TRUE;

    ngx_http_waf_dp(r, "invoke inspection handler");
    ngx_http_waf_check_pt* funcs = loc_conf->check_proc;
    for (size_t i = 0; funcs[i] != NULL; i++) {
        is_matched = funcs[i](r, &http_status);
        if (is_matched == NGX_HTTP_WAF_MATCHED) {
            ngx_http_waf_dpf(r, "matched(%i)", http_status);
            break;
        }
        http_status = NGX_DECLINED;
    }

    if (http_status != NGX_DONE) {
        ctx->spend = ((double)clock() / CLOCKS_PER_SEC * 1000) - ctx->spend;
    }

    ngx_http_waf_dp(r, "ngx_http_waf_check_all() ... end");
    return http_status;
}


static ngx_int_t _read_request_body(ngx_http_request_t* r) {
    ngx_http_waf_dp(r, "_read_request_body() ... start");

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

    if (ctx->has_req_body == NGX_HTTP_WAF_TRUE) {
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
        return NGX_HTTP_WAF_BAD;
    }
    ngx_http_waf_dp(r, "success");

    ctx->has_req_body = NGX_HTTP_WAF_TRUE;
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

    ngx_http_waf_dp(r, "_read_request_body() ... end");
    return NGX_HTTP_WAF_SUCCESS;
}


static void _handler_read_request_body(ngx_http_request_t* r) {
    ngx_http_waf_dp(r, "_handler_read_request_body() ... start");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    ctx->read_body_done = NGX_HTTP_WAF_TRUE;
    ngx_http_finalize_request(r, NGX_DONE);
    // r->main->count--;

    if (ctx->waiting_more_body == NGX_HTTP_WAF_TRUE) {
        ctx->waiting_more_body = NGX_HTTP_WAF_FALSE;
        ngx_http_core_run_phases(r);
    }

    ngx_http_waf_dp(r, "_handler_read_request_body() ... end");
}


void ngx_http_waf_handler_cleanup(void *data) {
    return;
}