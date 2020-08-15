#include <stdio.h>
#include "../inc/ngx_http_waf_module_core.h"
#include "../inc/uthash/src/uthash.h"
#include <time.h>
#include <math.h>
#ifndef __linux__
#include <io.h>
#include <winsock.h>
#else
#include <sys/io.h>
#endif
#include "../inc/ngx_http_waf_module_check.h"

static ngx_int_t ngx_waf_mult_mount = 0;

static ngx_command_t ngx_http_waf_commands[] = {

   {
        ngx_string("ngx_waf_mult_mount"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
        ngx_http_waf_mult_mount,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_waf_main_conf_t, ngx_waf_mult_mount),
        NULL
   },
   {
        ngx_string("ngx_waf"),
        NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
        ngx_http_waf_conf,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_waf_srv_conf_t, ngx_waf),
        NULL
   },
   {
        ngx_string("ngx_waf_rule_path"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_waf_rule_path_conf,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_waf_srv_conf_t, ngx_waf_rule_path),
        NULL
   },
    {
        ngx_string("ngx_waf_cc_deny"),
        NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
        ngx_http_waf_cc_deny_conf,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_waf_srv_conf_t, ngx_waf_cc_deny),
        NULL
   },
    {
        ngx_string("ngx_waf_cc_deny_limit"),
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
    ngx_http_waf_create_main_conf,
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


static char* ngx_http_waf_mult_mount(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_main_conf_t* main_conf = conf;
    if (ngx_conf_set_flag_slot(cf, cmd, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    ngx_waf_mult_mount = main_conf->ngx_waf_mult_mount;
    return NGX_CONF_OK;
}


static char* ngx_http_waf_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    if (ngx_conf_set_flag_slot(cf, cmd, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


static char* ngx_http_waf_rule_path_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_srv_conf_t* srv_conf = conf;
    if (ngx_conf_set_str_slot(cf, cmd, conf) != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_waf: %s", "The path of the config file is not specified");
        return NGX_CONF_ERROR;
    }

    char* full_path = ngx_palloc(cf->pool, sizeof(char) * RULE_MAX_LEN);
    char* end = to_c_str((u_char*)full_path, srv_conf->ngx_waf_rule_path);

    CHECK_AND_LOAD_CONF(cf, full_path, end, IPV4_FILE, srv_conf->black_ipv4, 1);
    CHECK_AND_LOAD_CONF(cf, full_path, end, URL_FILE, srv_conf->black_url, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, ARGS_FILE, srv_conf->black_args, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, UA_FILE, srv_conf->black_ua, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, REFERER_FILE, srv_conf->black_referer, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, COOKIE_FILE, srv_conf->black_cookie, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, POST_FILE, srv_conf->black_post, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, WHITE_IPV4_FILE, srv_conf->white_ipv4, 1);
    CHECK_AND_LOAD_CONF(cf, full_path, end, WHITE_URL_FILE, srv_conf->white_url, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, WHITE_REFERER_FILE, srv_conf->white_referer, 0);

    ngx_pfree(cf->pool, full_path);
    return NGX_CONF_OK;
}


static char* ngx_http_waf_cc_deny_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    if (ngx_conf_set_flag_slot(cf, cmd, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


static char* ngx_http_waf_cc_deny_limit_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_srv_conf_t* srv_conf = conf;
    ngx_str_t* p_str = cf->args->elts;
    srv_conf->ngx_waf_cc_deny_limit = ngx_atoi((p_str + 1)->data, (p_str + 1)->len);
    srv_conf->ngx_waf_cc_deny_duration = ngx_atoi((p_str + 2)->data, (p_str + 2)->len);
    if (srv_conf->ngx_waf_cc_deny_limit <= 0 || srv_conf->ngx_waf_cc_deny_duration <= 0) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Cannot be converted to an integer greater than zero %d %d",
            srv_conf->ngx_waf_cc_deny_limit,
            srv_conf->ngx_waf_cc_deny_duration);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


static void* ngx_http_waf_create_main_conf(ngx_conf_t* cf) {
    ngx_http_waf_main_conf_t* main_conf = NULL;
    main_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_main_conf_t));
    if (main_conf == NULL) {
        return NULL;
    }
    main_conf->ngx_waf_mult_mount = NGX_CONF_UNSET;
    return main_conf;
}


static void* ngx_http_waf_create_srv_conf(ngx_conf_t* cf) {
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    srv_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_srv_conf_t));
    if (srv_conf == NULL) {
        return NULL;
    }
    ngx_str_null(&srv_conf->ngx_waf_rule_path);
    srv_conf->ngx_log = ngx_log_init(NULL);
    srv_conf->ngx_pool = ngx_create_pool(sizeof(ngx_pool_t) + INITIAL_SIZE, srv_conf->ngx_log);
    srv_conf->alloc_times = 0;
    srv_conf->ngx_waf = NGX_CONF_UNSET;
    srv_conf->ngx_waf_cc_deny = NGX_CONF_UNSET;
    srv_conf->ngx_waf_cc_deny_limit = NGX_CONF_UNSET;
    srv_conf->ngx_waf_cc_deny_duration = NGX_CONF_UNSET;
    srv_conf->black_ipv4 = ngx_array_create(cf->pool, 10, sizeof(ipv4_t));
    srv_conf->black_url = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_args = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_ua = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_referer = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_cookie = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_post = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->white_ipv4 = ngx_array_create(cf->pool, 10, sizeof(ipv4_t));
    srv_conf->white_url = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->white_referer = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->ipv4_times = NULL;

    if (srv_conf->ngx_log == NULL
        || srv_conf->ngx_pool == NULL
        || srv_conf->black_ipv4 == NULL
        || srv_conf->black_url == NULL
        || srv_conf->black_args == NULL
        || srv_conf->black_ua == NULL
        || srv_conf->black_referer == NULL
        || srv_conf->white_ipv4 == NULL
        || srv_conf->white_url == NULL
        || srv_conf->white_referer == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: Initialization failed");
        return NULL;
    }

    return srv_conf;
}


static ngx_int_t ngx_http_waf_init_after_load_config(ngx_conf_t* cf) {
    ngx_http_handler_pt* h;
    ngx_http_core_main_conf_t* cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_waf_handler_ip_url_referer_ua_args_cookie_post;

    if (ngx_waf_mult_mount != 0) {
        h = ngx_array_push(&cmcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers);
        *h = ngx_http_waf_handler_url_args;
    }

    ngx_str_t waf_blocked_name = ngx_string("waf_blocked");
    ngx_http_variable_t* waf_blocked = ngx_http_add_variable(cf, &waf_blocked_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_blocked->get_handler = ngx_http_waf_blocked_get_handler;
    waf_blocked->set_handler = NULL;

    ngx_str_t waf_rule_type_name = ngx_string("waf_rule_type");
    ngx_http_variable_t* waf_rule_type = ngx_http_add_variable(cf, &waf_rule_type_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_rule_type->get_handler = ngx_http_waf_rule_type_get_handler;
    waf_rule_type->set_handler = NULL;

    ngx_str_t waf_rule_details_name = ngx_string("waf_rule_deatails");
    ngx_http_variable_t* waf_rule_details = ngx_http_add_variable(cf, &waf_rule_details_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_rule_details->get_handler = ngx_http_waf_rule_deatils_handler;
    waf_rule_details->set_handler = NULL;

    return NGX_OK;
}


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
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_int_t rc = NGX_DECLINED;

    if (ctx == NULL) {
        ctx = ngx_palloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            rc = NGX_ERROR;
            goto END;
        }
        else {
            ctx->read_body_done = FALSE;
            ctx->waiting_more_body = TRUE;
            ctx->blocked = FALSE;
            ctx->rule_type[0] = '\0';
            ctx->rule_deatils[0] = '\0';
            ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
        }
    }

    if (srv_conf->ngx_waf == 0 || srv_conf->ngx_waf == NGX_CONF_UNSET) {
        rc = NGX_DECLINED;
        goto END;
    }

    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_POST))) {
        rc = NGX_DECLINED;
        goto END;
    }

    if (ngx_http_waf_check_white_url(r) == MATCHED) {
        rc = NGX_DECLINED;
        goto END;
    }

    if (ngx_http_waf_check_black_url(r) == MATCHED) {
        rc = NGX_HTTP_FORBIDDEN;
        goto END;
    }

    if (ngx_http_waf_check_black_args(r) == MATCHED) {
        rc = NGX_HTTP_FORBIDDEN;
        goto END;
    }

    END:
    if (rc != NGX_DECLINED && rc != NGX_DONE) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%s][%s]", ctx->rule_type, ctx->rule_deatils);
    }
    return rc;
}


static ngx_int_t ngx_http_waf_handler_ip_url_referer_ua_args_cookie_post(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_int_t rc = NGX_DECLINED;

    if (ctx == NULL) {
        ctx = ngx_palloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            rc = NGX_ERROR;
            goto END;
        }
        else {
            ctx->read_body_done = FALSE;
            ctx->waiting_more_body = TRUE;
            ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
        }
    }

    if (srv_conf->ngx_waf == 0 || srv_conf->ngx_waf == NGX_CONF_UNSET) {
        rc = NGX_DECLINED;
        goto END;
    }

    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_POST))) {
        rc = NGX_DECLINED;
        goto END;
    }

    if (ngx_http_waf_check_white_ipv4(r) == MATCHED) {
        rc = NGX_DECLINED;
        goto END;
    }

    if (ngx_http_waf_check_black_ipv4(r) == MATCHED) {
        rc = NGX_HTTP_FORBIDDEN;
        goto END;
    }

    if (ngx_http_waf_check_cc_ipv4(r) == MATCHED) {
        rc = NGX_HTTP_SERVICE_UNAVAILABLE;
        goto END;
    }

    if (ngx_http_waf_check_white_url(r) == MATCHED) {
        rc = NGX_DECLINED;
        goto END;
    }

    if (ngx_http_waf_check_black_url(r) == MATCHED) {
        rc = NGX_HTTP_FORBIDDEN;
        goto END;
    }

    if (ngx_http_waf_check_black_args(r) == MATCHED) {
        rc = NGX_HTTP_FORBIDDEN;
        goto END;
    }

    if (ngx_http_waf_check_black_user_agent(r) == MATCHED) {
        rc = NGX_HTTP_FORBIDDEN;
        goto END;
    }

    if (ngx_http_waf_check_white_referer(r) == MATCHED) {
        rc = NGX_DECLINED;
        goto END;
    }

    if (ngx_http_waf_check_black_referer(r) == MATCHED) {
        rc = NGX_HTTP_FORBIDDEN;
        goto END;
    }

    if (ngx_http_waf_check_black_cookie(r) == MATCHED) {
        rc = NGX_HTTP_FORBIDDEN;
        goto END;
    }

    if ((r->method & NGX_HTTP_POST) != 0 && ctx->read_body_done == FALSE) {
        r->request_body_in_persistent_file = 0;
        r->request_body_in_clean_file = 0;
        rc = ngx_http_read_client_request_body(r, check_post);
        if (rc != NGX_ERROR && rc < NGX_HTTP_SPECIAL_RESPONSE) {
            rc = NGX_DONE;
        }
        goto END;
    }

    END:
    if (rc != NGX_DECLINED && rc != NGX_DONE) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%s][%s]", ctx->rule_type, ctx->rule_deatils);
    }
    return rc;
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
    ipv4->text[text.len + 1] = '\0';
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
    ngx_str_t line;
    char* str = ngx_palloc(cf->pool, sizeof(char) * RULE_MAX_LEN);
    if (fp == NULL) {
        return FAIL;
    }
    while (fgets(str, RULE_MAX_LEN - 16, fp) != NULL) {
        ngx_regex_compile_t   rc;
        u_char                errstr[NGX_MAX_CONF_ERRSTR];
        ngx_regex_elt_t* ngx_regex_elt;
        ipv4_t* ipv4;

        line.data = (u_char*)str;
        line.len = strlen((char*)str);
        if (line.data[line.len - 1] == '\n') {
            line.data[line.len - 1] = '\0';
            if (line.data[line.len - 2] == '\r') {
                line.data[line.len - 2] = '\0';
            }
        }
        switch (mode) {
        case 0:
            ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
            rc.pattern = line;
            rc.pool = cf->pool;
            rc.err.len = NGX_MAX_CONF_ERRSTR;
            rc.err.data = errstr;
            ngx_regex_compile(&rc);
            ngx_regex_elt = ngx_array_push(ngx_array);
            ngx_regex_elt->name = ngx_palloc(cf->pool, sizeof(u_char) * RULE_MAX_LEN);
            to_c_str(ngx_regex_elt->name, line);
            ngx_regex_elt->regex = rc.regex;
            break;
        case 1:
            ipv4 = ngx_array_push(ngx_array);
            parse_ipv4(line, ipv4);
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
    for (size_t i = 0; i < ngx_str.len; i++) {
        destination[i] = ngx_str.data[i];
    }
    destination[ngx_str.len] = '\0';
    return (char*)destination + ngx_str.len;
}
