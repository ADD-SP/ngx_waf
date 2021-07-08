#include <ngx_http_waf_module_core.h>
#include <ngx_http_waf_module_check.h>
#include <ngx_http_waf_module_config.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_under_attack.h>

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
        ngx_string("waf_redis"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE123,
        ngx_http_waf_redis_conf,
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
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1234,
        ngx_http_waf_cache_conf,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
   },
   {
        ngx_string("waf_under_attack"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE2,
        ngx_http_waf_under_attack_conf,
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
   {
        ngx_string("waf_http_status"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE12,
        ngx_http_waf_http_status_conf,
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


char ngx_http_waf_module_nonce[17];

ngx_module_t ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,       /* module context */
    ngx_http_waf_commands,          /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    ngx_http_waf_init_module,       /* init module */
    ngx_http_waf_init_process,      /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_waf_init_module(ngx_cycle_t *cycle) {
    ngx_memzero(ngx_http_waf_module_nonce, sizeof(ngx_http_waf_module_nonce));
    rand_str((u_char*)ngx_http_waf_module_nonce, sizeof(ngx_http_waf_module_nonce) / sizeof(char) - 1);
    return NGX_OK;
}


static ngx_int_t ngx_http_waf_init_process(ngx_cycle_t *cycle) {
    randombytes_stir();
    return NGX_OK;
}


static ngx_int_t ngx_http_waf_handler_server_rewrite_phase(ngx_http_request_t* r) {
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_EXTRA_COMPAT) == NGX_HTTP_WAF_TRUE) {
        return check_all(r, NGX_HTTP_WAF_TRUE);
    }
    return NGX_DECLINED;
}


static ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r) {
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_EXTRA_COMPAT) == NGX_HTTP_WAF_FALSE) {
        return check_all(r, NGX_HTTP_WAF_TRUE);
    }
    else if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_EXTRA_COMPAT | NGX_HTTP_WAF_MODE_EXTRA_STRICT) == NGX_HTTP_WAF_TRUE) {
        return check_all(r, NGX_HTTP_WAF_FALSE);
    }
    return NGX_DECLINED;
}


static ngx_int_t check_all(ngx_http_request_t* r, ngx_int_t is_check_cc) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The scheduler has been started.");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &srv_conf, &ctx);
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
        || srv_conf->waf == 0 
        || srv_conf->waf == NGX_CONF_UNSET 
        || ctx->read_body_done == NGX_HTTP_WAF_TRUE) {
        http_status = NGX_DECLINED;
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Skip scheduling.");
    }
    else {
        ctx->checked = NGX_HTTP_WAF_TRUE;
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
            && ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_RB) == NGX_HTTP_WAF_TRUE) {
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


static void ngx_http_waf_handler_cleanup(void *data) {
    return;
}
