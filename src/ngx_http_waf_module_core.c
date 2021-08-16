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
        NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123,
        ngx_http_waf_cc_deny_conf,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_cache"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123,
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


ngx_int_t ngx_http_waf_init_process(ngx_cycle_t *cycle) {
    randombytes_stir();
    return NGX_OK;
}


ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r) {
    return ngx_http_waf_check_all(r, NGX_HTTP_WAF_TRUE);
}

ngx_int_t ngx_http_waf_handler_content_phase(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);

    if (ctx->under_attack == NGX_HTTP_WAF_FALSE) {
        return NGX_DECLINED;
    }

    ngx_int_t rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_set(&r->headers_out.content_type, "text/html");
    r->headers_out.content_length_n = loc_conf->waf_under_attack_len;
    r->headers_out.status = NGX_HTTP_SERVICE_UNAVAILABLE;

    ngx_table_elt_t* header = (ngx_table_elt_t *)ngx_list_push(&(r->headers_out.headers));
    if (header == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR; 
    }
    header->hash = 1;
    header->lowcase_key = (u_char*)"cache-control";
    ngx_str_set(&header->key, "Cache-control");
    ngx_str_set(&header->value, "no-store");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    if (r->method != NGX_HTTP_HEAD) {
        ngx_buf_t* buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        if (buf == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR; 
        }

        buf->pos = ngx_pcalloc(r->pool, loc_conf->waf_under_attack_len);
        if (buf->pos == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR; 
        }
        ngx_memcpy(buf->pos, loc_conf->waf_under_attack_html, loc_conf->waf_under_attack_len);
        buf->last = buf->pos + loc_conf->waf_under_attack_len;
        buf->memory = 1;
        buf->last_buf = 1;

        ngx_chain_t* out = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
        if (out == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR; 
        }

        out->buf = buf;
        out->next = NULL;

        return ngx_http_output_filter(r, out);
    }

    return NGX_OK;
}


ngx_int_t ngx_http_waf_check_all(ngx_http_request_t* r, ngx_int_t is_check_cc) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The scheduler has been started.");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, &ctx);
    ngx_int_t is_matched = NGX_HTTP_WAF_NOT_MATCHED;
    ngx_int_t http_status = NGX_DECLINED;

    if (ctx == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Start allocating memory for storage contexts.");
        ngx_http_cleanup_t* cln = ngx_palloc(r->pool, sizeof(ngx_http_cleanup_t));
        ctx = ngx_palloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL || cln == NULL) {
            http_status = NGX_ERROR;
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
                "ngx_waf: The request context could not be created because the memory allocation failed.");
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                "ngx_waf_debug: The scheduler shutdown abnormally.");
            return http_status;
        }
        else {
            cln->handler = ngx_http_waf_handler_cleanup;
            cln->data = ctx;
            cln->next = NULL;

            ctx->read_body_done = NGX_HTTP_WAF_FALSE;
            ctx->checked = NGX_HTTP_WAF_FALSE;
            ctx->blocked = NGX_HTTP_WAF_FALSE;
            ctx->under_attack = NGX_HTTP_WAF_FALSE;
            ctx->spend = (double)clock() / CLOCKS_PER_SEC * 1000;
            ctx->rule_type[0] = '\0';
            ctx->rule_deatils[0] = '\0';

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
            
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                "ngx_waf_debug: Context initialization is complete.");
        }
    } else if (ngx_http_get_module_ctx(r, ngx_http_waf_module) == NULL) {
        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    if (r->internal != 0 
        || loc_conf->waf == 0 
        || loc_conf->waf == NGX_CONF_UNSET 
        || ctx->read_body_done == NGX_HTTP_WAF_TRUE) {
        http_status = NGX_DECLINED;
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Skip scheduling.");
    }
    else {
        ctx->checked = NGX_HTTP_WAF_TRUE;
        ngx_http_waf_check_pt* funcs = loc_conf->check_proc;
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
            && ngx_http_waf_check_flag(loc_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_RB) == NGX_HTTP_WAF_TRUE) {
            r->request_body_in_persistent_file = 0;
            r->request_body_in_clean_file = 0;
            ctx->spend = ((double)clock() / CLOCKS_PER_SEC * 1000) - ctx->spend;
            http_status = ngx_http_read_client_request_body(r, ngx_http_waf_handler_check_black_post);
            if (http_status != NGX_ERROR && http_status < NGX_HTTP_SPECIAL_RESPONSE) {
                http_status = NGX_DONE;
            }
        }
    }

    if (http_status != NGX_DECLINED && http_status != NGX_DONE && http_status != NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%s][%s]", ctx->rule_type, ctx->rule_deatils);
    }

    if (http_status != NGX_DONE) {
        ctx->spend = ((double)clock() / CLOCKS_PER_SEC * 1000) - ctx->spend;
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The scheduler shutdown normally.");
    return http_status;
}


void ngx_http_waf_handler_cleanup(void *data) {
    return;
}
