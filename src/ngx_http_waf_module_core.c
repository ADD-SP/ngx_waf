#include <ngx_http_waf_module_core.h>
#include <ngx_http_waf_module_check.h>
#include <ngx_http_waf_module_config.h>
#include <ngx_http_waf_module_util.h>

static ngx_command_t ngx_http_waf_commands[] = {
   {
        ngx_string("waf_mult_mount"),
        NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
        ngx_http_waf_mult_mount_conf,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_waf_srv_conf_t, waf_mult_mount),
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
        ngx_string("waf_cc_deny_limit"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE2,
        ngx_http_waf_cc_deny_limit_conf,
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


static ngx_int_t ngx_http_waf_handler_url_args(ngx_http_request_t* r) {
    static ngx_http_waf_check check_proc[] = {
        ngx_http_waf_handler_check_white_url,
        ngx_http_waf_handler_check_black_url,
        ngx_http_waf_handler_check_black_args,
        NULL
    };
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_int_t is_matched = NOT_MATCHED;
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
            ctx->checked_in_pre_access = FALSE;
            ctx->checked_in_server_rewrite = FALSE;
            ctx->read_body_done = FALSE;
            ctx->blocked = FALSE;
            ctx->rule_type[0] = '\0';
            ctx->rule_deatils[0] = '\0';
            ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
        }
    }

    if (srv_conf->waf == 0 || srv_conf->waf == NGX_CONF_UNSET || ctx->checked_in_server_rewrite == TRUE) {
        http_status = NGX_DECLINED;
    }
    else 
    {
        ctx->checked_in_server_rewrite = TRUE;
        if (srv_conf->waf_mult_mount == 0 || srv_conf->waf_mult_mount == NGX_CONF_UNSET) {
            http_status = NGX_DECLINED;
        }
        else if (CHECK_FLAG(srv_conf->waf_mode, r->method) != TRUE) {
            http_status = NGX_DECLINED;
        }
        else {
            for (size_t i = 0; check_proc[i] != NULL; i++) {
                is_matched = check_proc[i](r, &http_status);
                if (is_matched == MATCHED) {
                    break;
                }
            }
        }
    }

    if (http_status != NGX_DECLINED && http_status != NGX_DONE) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%s][%s]", ctx->rule_type, ctx->rule_deatils);
    }
    return http_status;
}


static ngx_int_t ngx_http_waf_handler_ip_url_referer_ua_args_cookie_post(ngx_http_request_t* r) {
    static ngx_http_waf_check check_proc[] = {
        ngx_http_waf_handler_check_white_ip,
        ngx_http_waf_handler_check_black_ip,
        ngx_http_waf_handler_check_white_url,
        ngx_http_waf_handler_check_black_url,
        ngx_http_waf_handler_check_black_args,
        ngx_http_waf_handler_check_black_user_agent,
        ngx_http_waf_handler_check_white_referer,
        ngx_http_waf_handler_check_black_referer,
        ngx_http_waf_handler_check_black_cookie,
        NULL
    };
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_int_t is_matched = NOT_MATCHED;
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
            ctx->checked_in_pre_access = FALSE;
            ctx->checked_in_server_rewrite = FALSE;
            ctx->read_body_done = FALSE;
            ctx->blocked = FALSE;
            ctx->rule_type[0] = '\0';
            ctx->rule_deatils[0] = '\0';
            ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
        }
    }

    

    if (srv_conf->waf == 0 || srv_conf->waf == NGX_CONF_UNSET || ctx->checked_in_pre_access == TRUE) {
        http_status = NGX_DECLINED;
    }
    else {
        ctx->checked_in_pre_access = TRUE;
        if (ngx_http_waf_handler_check_cc(r, &http_status) != MATCHED) {
            if (CHECK_FLAG(srv_conf->waf_mode, r->method) != TRUE) {
                http_status = NGX_DECLINED;
            }
            else {
                for (size_t i = 0; check_proc[i] != NULL; i++) {
                    is_matched = check_proc[i](r, &http_status);
                    if (is_matched == MATCHED) {
                        break;
                    }
                }
                /* 如果请求方法为 POST 且 本模块还未读取过请求体 且 配置中未关闭请求体检查 */
                if ((r->method & NGX_HTTP_POST) != 0
                    && ctx->read_body_done == FALSE
                    && is_matched != MATCHED
                    && CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_RB) == TRUE) {
                    r->request_body_in_persistent_file = 0;
                    r->request_body_in_clean_file = 0;
                    http_status = ngx_http_read_client_request_body(r, check_post);
                    if (http_status != NGX_ERROR && http_status < NGX_HTTP_SPECIAL_RESPONSE) {
                        http_status = NGX_DONE;
                    }
                }
            }
        }
    }

    if (http_status != NGX_DECLINED && http_status != NGX_DONE) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%s][%s]", ctx->rule_type, ctx->rule_deatils);
    }
    return http_status;
}
