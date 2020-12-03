#include <stdio.h>
#include "../inc/ngx_http_waf_module_core.h"
#include <uthash.h>
#include <time.h>
#include <math.h>
#ifndef __linux__
#include <io.h>
#include <winsock.h>
#else
#include <sys/io.h>
#endif
#include "../inc/ngx_http_waf_module_check.h"
#include "../inc/ngx_http_waf_module_config.h"

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


static ngx_int_t ngx_http_waf_blocked_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = ngx_palloc(r->pool, sizeof(u_char) * 64);

    if (ctx == NULL) {
        v->len = 0;
        v->data = NULL;
    }
    else {
        if (ctx->blocked == TRUE) {
            v->len = 4;
            strcpy((char*)v->data, "true");
        }
        else {
            v->len = 5;
            strcpy((char*)v->data, "false");
        }
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_rule_type_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (ctx == NULL) {
        v->len = 0;
        v->data = NULL;
    }
    else {
        if (ctx->blocked == TRUE) {
            v->len = strlen((char*)ctx->rule_type);
            v->data = ngx_palloc(r->pool, sizeof(u_char) * v->len);
            strcpy((char*)v->data, (char*)ctx->rule_type);
        }
        else {
            v->len = 4;
            v->data = ngx_palloc(r->pool, sizeof(u_char) * 64);
            strcpy((char*)v->data, "null");
        }
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_rule_deatils_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (ctx == NULL) {
        v->len = 0;
        v->data = NULL;
    }
    else {
        if (ctx->blocked == TRUE) {
            v->len = strlen((char*)ctx->rule_deatils);
            v->data = ngx_palloc(r->pool, sizeof(u_char) * v->len);
            strcpy((char*)v->data, (char*)ctx->rule_deatils);
        }
        else {
            v->len = 4;
            v->data = ngx_palloc(r->pool, sizeof(u_char) * 64);
            strcpy((char*)v->data, "null");
        }
    }

    return NGX_OK;
}


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
        }
        else {
            ctx->read_body_done = FALSE;
            ctx->blocked = FALSE;
            ctx->rule_type[0] = '\0';
            ctx->rule_deatils[0] = '\0';
            ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
        }
    }

    if (srv_conf->waf == 0 || srv_conf->waf == NGX_CONF_UNSET) {
        http_status = NGX_DECLINED;
    }
    else if (srv_conf->waf_mult_mount == 0 || srv_conf->waf_mult_mount == NGX_CONF_UNSET) {
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

    if (http_status != NGX_DECLINED && http_status != NGX_DONE) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%s][%s]", ctx->rule_type, ctx->rule_deatils);
    }
    return http_status;
}


static ngx_int_t ngx_http_waf_handler_ip_url_referer_ua_args_cookie_post(ngx_http_request_t* r) {
    static ngx_http_waf_check check_proc[] = {
        ngx_http_waf_handler_check_white_ipv4,
        ngx_http_waf_handler_check_black_ipv4,
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
        }
        else {
            ctx->read_body_done = FALSE;
            ctx->blocked = FALSE;
            ctx->rule_type[0] = '\0';
            ctx->rule_deatils[0] = '\0';
            ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
        }
    }

    if (srv_conf->waf == 0 || srv_conf->waf == NGX_CONF_UNSET) {
        http_status = NGX_DECLINED;
    }
    else if (srv_conf->waf_mult_mount == 0 || srv_conf->waf_mult_mount == NGX_CONF_UNSET) {
        http_status = NGX_DECLINED;
    }
    else {
        if (ngx_http_waf_handler_check_cc_ipv4(r, &http_status) != MATCHED) {
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


void check_post(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_chain_t* buf_chain = r->request_body == NULL ? NULL : r->request_body->bufs;
    ngx_buf_t* body_buf = NULL;
    ngx_str_t body_str;

    ctx->read_body_done = TRUE;

    while (buf_chain != NULL) {
        body_buf = buf_chain->buf;

        if (body_buf == NULL) {
            break;
        }

        body_str.data = body_buf->pos;
        body_str.len = body_buf->last - body_buf->pos;


        if (!ngx_buf_in_memory(body_buf)) {
            buf_chain = buf_chain->next;
            continue;
        }

        ngx_regex_elt_t* p = srv_conf->black_post->elts;
        ngx_int_t rc;
        for (size_t i = 0; i < srv_conf->black_post->nelts; i++, p++) {
            rc = ngx_regex_exec(p->regex, &body_str, NULL, 0);
            if (rc >= 0) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-POST");
                strcpy((char*)ctx->rule_deatils, (char*)p->name);
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%s][%s]", ctx->rule_type, ctx->rule_deatils);
                ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
                return;
            }
        }
        buf_chain = buf_chain->next;
    }
    ngx_http_finalize_request(r, NGX_DONE);
    ngx_http_core_run_phases(r);
}


static ngx_int_t parse_ipv4(ngx_str_t text, ipv4_t* ipv4) {
    size_t prefix = 0;
    size_t num = 0;
    size_t suffix = 32;
    u_char c;
    int is_in_suffix = FALSE;
    memcpy(ipv4->text, text.data, text.len);
    ipv4->text[text.len] = '\0';
    for (size_t i = 0; i < text.len; i++) {
        c = text.data[i];
        if (c >= '0' && c <= '9') {
            if (is_in_suffix == TRUE) {
                suffix = suffix * 10 + (c - '0');
            }
            else {
                num = num * 10 + (c - '0');
            }
        }
        else if (c == '/') {
            is_in_suffix = TRUE;
            suffix = 0;
        }
        else if (c == '.') {
            prefix = (num << 24) | (prefix >> 8);
            num = 0;
        }
        else if (c != '\r' && c != '\n') {
            return FAIL;
        }
    }
    prefix = (num << 24) | (prefix >> 8);
    size_t i = suffix, j = 1;
    suffix = 0;
    while (i > 0) {
        suffix |= j;
        j <<= 1;
        --i;
    }
    ipv4->prefix = prefix & suffix;
    ipv4->suffix = suffix;
    return SUCCESS;
}


static ngx_int_t load_into_array(ngx_conf_t* cf, const char* file_name, ngx_array_t* ngx_array, ngx_int_t mode) {
    FILE* fp = fopen(file_name, "r");
    ngx_int_t line_number = 0;
    ngx_str_t line;
    char* str = ngx_palloc(cf->pool, sizeof(char) * RULE_MAX_LEN);
    if (fp == NULL) {
        return FAIL;
    }
    while (fgets(str, RULE_MAX_LEN - 16, fp) != NULL) {
        ngx_regex_compile_t   regex_compile;
        u_char                errstr[NGX_MAX_CONF_ERRSTR];
        ngx_regex_elt_t* ngx_regex_elt;
        ipv4_t* ipv4;
        ++line_number;
        line.data = (u_char*)str;
        line.len = strlen((char*)str);

        if (line.len <= 0) {
            continue;
        }

        if (line.data[line.len - 1] == '\n') {
            line.data[line.len - 1] = '\0';
            --(line.len);
            if (line.len <= 0) {
                continue;
            }
            if (line.data[line.len - 1] == '\r') {
                line.data[line.len - 1] = '\0';
                --(line.len);
            }
        }

        if (line.len <= 0) {
            continue;
        }

        switch (mode) {
        case 0:
            ngx_memzero(&regex_compile, sizeof(ngx_regex_compile_t));
            regex_compile.pattern = line;
            regex_compile.pool = cf->pool;
            regex_compile.err.len = NGX_MAX_CONF_ERRSTR;
            regex_compile.err.data = errstr;
            ngx_regex_compile(&regex_compile);
            ngx_regex_elt = ngx_array_push(ngx_array);
            ngx_regex_elt->name = ngx_palloc(cf->pool, sizeof(u_char) * RULE_MAX_LEN);
            to_c_str(ngx_regex_elt->name, line);
            ngx_regex_elt->regex = regex_compile.regex;
            break;
        case 1:
            ipv4 = ngx_array_push(ngx_array);
            if (parse_ipv4(line, ipv4) != SUCCESS) {
                return FAIL;
            }
            break;
        }
    }
    fclose(fp);
    ngx_pfree(cf->pool, str);
    return SUCCESS;
}


static char* to_c_str(u_char* destination, ngx_str_t ngx_str) {
    if (ngx_str.len > RULE_MAX_LEN) {
        return NULL;
    }
    memcpy(destination, ngx_str.data, ngx_str.len);
    destination[ngx_str.len] = '\0';
    return (char*)destination + ngx_str.len;
}
