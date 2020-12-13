/**
 * @file ngx_http_waf_module_config.h
 * @brief 读取 nginx.conf 内的配置以及规则文件。
*/

#include <stdio.h>
#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_ip_hash_table.h>


#ifndef NGX_HTTP_WAF_MODULE_CONFIG_H
#define NGX_HTTP_WAF_MODULE_CONFIG_H

static ngx_int_t ngx_http_waf_handler_url_args(ngx_http_request_t* r);

static ngx_int_t ngx_http_waf_handler_ip_url_referer_ua_args_cookie_post(ngx_http_request_t* r);

/**
 * @defgroup config 配置读取和处理模块
 * @brief 读取 nginx.conf 内的配置以及规则文件。
 * @addtogroup config 配置读取和处理模块
 * @{
*/

/**
 * @brief 读取配置项 waf_mult_mount，该项表示是否将检测过程挂载到两个阶段以应对 rewrite 导致的 URL 和 ARGS 前后不一致的情况。
*/
static char* ngx_http_waf_mult_mount_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

/**
 * @brief 读取配置项 waf，该项表示是否启用模块。
*/
static char* ngx_http_waf_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

/**
 * @brief 读取配置项 waf_rule_path，该项表示存有配置文件的文件夹的绝对路径，必须以 '/' 结尾。
*/
static char* ngx_http_waf_rule_path_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

/**
 * @brief 读取配置项 waf_mode，该项表示拦截模式。
*/
static char* ngx_http_waf_mode_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

/**
 * @brief 读取配置项 _waf_cc_deny_limit，该项表示最高的访问频次以及超出后的拉黑时间。
*/
static char* ngx_http_waf_cc_deny_limit_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

/**
 * @brief 当读取 waf_blocked 变量时的回调函数，这个变量当请求被拦截的时候是 "true"，反之是 "false"。
*/
static ngx_int_t ngx_http_waf_blocked_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);

/**
 * @brief 当读取 waf_rule_type 变量时的回调函数，这个变量会显示触发了的规则类型。
*/
static ngx_int_t ngx_http_waf_rule_type_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);

/**
 * @brief 当读取 waf_rule_deatils 变量时的回调函数，这个变量会显示触发了的规则。
*/
static ngx_int_t ngx_http_waf_rule_deatils_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 初始化配置存储块的结构体
 * @warning 本函数中存在兼容 Mainline 版本的 nginx 的代码。当 nginx-1.18.0 不再是最新的 stable 版本的时候可能需要改动。 
*/
static void* ngx_http_waf_create_srv_conf(ngx_conf_t* cf);


/**
 * @brief 在读取完全部配置后进行一些操作。
 * @li 将处理函数挂载到对应的请求处理阶段。
 * @li 初始化相关的 nginx 变量。
*/
static ngx_int_t ngx_http_waf_init_after_load_config(ngx_conf_t* cf);

/**
 * @brief 读取指定文件的内容到数组中。
 * @param[in] file_name 要读取的配置文件完整路径。
 * @param[out] ngx_array 存放读取结果的数组。
 * @param[in] mode 读取模式
 * @li 当 mode = 0 时会将读取到文本编译成正则表达式再存储。
 * @li 当 mode = 1 时会将读取到的文本转化为 ipv4_t 再存储。
 * @li 当 mode = 2 时会将读取到的文本转化为 ipv6_t 再存储。
 * @return 读取操作的结果。
 * @retval SUCCESS 读取成功。
 * @retval FAIL 读取中发生错误。
*/
static ngx_int_t load_into_array(ngx_conf_t* cf, const char* file_name, ngx_array_t* ngx_array, ngx_int_t mode);

/**
 * @}
*/

static char* ngx_http_waf_mult_mount_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    if (ngx_conf_set_flag_slot(cf, cmd, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
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
    char* end = to_c_str((u_char*)full_path, srv_conf->waf_rule_path);

    CHECK_AND_LOAD_CONF(cf, full_path, end, IPV4_FILE, srv_conf->black_ipv4, 1);
    CHECK_AND_LOAD_CONF(cf, full_path, end, IPV6_FILE, srv_conf->black_ipv6, 2);
    CHECK_AND_LOAD_CONF(cf, full_path, end, URL_FILE, srv_conf->black_url, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, ARGS_FILE, srv_conf->black_args, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, UA_FILE, srv_conf->black_ua, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, REFERER_FILE, srv_conf->black_referer, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, COOKIE_FILE, srv_conf->black_cookie, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, POST_FILE, srv_conf->black_post, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, WHITE_IPV4_FILE, srv_conf->white_ipv4, 1);
    CHECK_AND_LOAD_CONF(cf, full_path, end, WHITE_IPV6_FILE, srv_conf->white_ipv6, 2);
    CHECK_AND_LOAD_CONF(cf, full_path, end, WHITE_URL_FILE, srv_conf->white_url, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, WHITE_REFERER_FILE, srv_conf->white_referer, 0);

    ngx_pfree(cf->pool, full_path);
    return NGX_CONF_OK;
}


static char* ngx_http_waf_mode_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_srv_conf_t* srv_conf = (ngx_http_waf_srv_conf_t*)conf;
    ngx_str_t* modes = cf->args->elts;

    for (size_t i = 1; i < cf->args->nelts && modes != NULL; i++) {
        if (ngx_strncasecmp(modes[i].data, (u_char*)"GET", min(modes[i].len, 5)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_GET;
        } 
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"HEAD", min(modes[i].len, 5)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_HEAD;
        } 
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"POST", min(modes[i].len, 5)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_POST;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"PUT", min(modes[i].len, 4)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_PUT;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"DELETE", min(modes[i].len, 7)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_DELETE;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"MKCOL", min(modes[i].len, 6)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_MKCOL;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"COPY", min(modes[i].len, 5)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_COPY;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"MOVE", min(modes[i].len, 5)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_MOVE;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"OPTIONS", min(modes[i].len, 8)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_OPTIONS;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"PROPFIND", min(modes[i].len, 9)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_PROPFIND;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"PROPPATCH", min(modes[i].len, 10)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_PROPPATCH;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"LOCK", min(modes[i].len, 5)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_LOCK;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"UNLOCK", min(modes[i].len, 7)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_UNLOCK;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"PATCH", min(modes[i].len, 6)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_PATCH;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"TRACE", min(modes[i].len, 6)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_TRACE;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"IP", min(modes[i].len, 3)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_IP;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"URL", min(modes[i].len, 4)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_URL;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"RBODY", min(modes[i].len, 6)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_RB;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"ARGS", min(modes[i].len, 5)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_ARGS;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"UA", min(modes[i].len, 3)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_UA;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"COOKIE", min(modes[i].len, 7)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_COOKIE;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"REFERER", min(modes[i].len, 8)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_REFERER;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"CC", min(modes[i].len, 3)) == 0) {
            srv_conf->waf_mode |= MODE_INSPECT_CC;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"STD", min(modes[i].len, 4)) == 0) {
            srv_conf->waf_mode |= MODE_STD;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"FULL", min(modes[i].len, 5)) == 0) {
            srv_conf->waf_mode |= MODE_FULL;
        }
        else {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Invalid value");
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char* ngx_http_waf_cc_deny_limit_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_srv_conf_t* srv_conf = conf;
    ngx_str_t* p_str = cf->args->elts;
    srv_conf->waf_cc_deny_limit = ngx_atoi((p_str + 1)->data, (p_str + 1)->len);
    srv_conf->waf_cc_deny_duration = ngx_atoi((p_str + 2)->data, (p_str + 2)->len);
    if (srv_conf->waf_cc_deny_limit <= 0 || srv_conf->waf_cc_deny_duration <= 0) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Cannot be converted to an integer greater than zero %d %d",
            srv_conf->waf_cc_deny_limit,
            srv_conf->waf_cc_deny_duration);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


static void* ngx_http_waf_create_srv_conf(ngx_conf_t* cf) {
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    srv_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_srv_conf_t));
    if (srv_conf == NULL) {
        return NULL;
    }
    ngx_str_null(&srv_conf->waf_rule_path);

    /* 条件为真时说明编译时 nginx 的版本小于等于 stable。反之则为 Mainline 版本。 */
    #if (nginx_version <= 1018000)
        srv_conf->ngx_log = ngx_log_init(NULL);
    #else
        srv_conf->ngx_log = ngx_log_init(NULL, NULL);
    #endif
    srv_conf->ngx_pool = ngx_create_pool(sizeof(ngx_pool_t) + INITIAL_SIZE, srv_conf->ngx_log);
    srv_conf->alloc_times = 0;
    srv_conf->waf = NGX_CONF_UNSET;
    srv_conf->waf_mult_mount = NGX_CONF_UNSET;
    srv_conf->waf_mode = 0;
    srv_conf->waf_cc_deny_limit = NGX_CONF_UNSET;
    srv_conf->waf_cc_deny_duration = NGX_CONF_UNSET;
    srv_conf->black_ipv4 = ngx_array_create(cf->pool, 10, sizeof(ipv4_t));
    srv_conf->black_ipv6 = ngx_array_create(cf->pool, 10, sizeof(ipv6_t));
    srv_conf->black_url = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_args = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_ua = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_referer = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_cookie = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_post = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->white_ipv4 = ngx_array_create(cf->pool, 10, sizeof(ipv4_t));
    srv_conf->white_ipv6 = ngx_array_create(cf->pool, 10, sizeof(ipv6_t));
    srv_conf->white_url = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->white_referer = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->ngx_pool_for_times_table = ngx_create_pool(sizeof(ngx_pool_t) + INITIAL_SIZE, srv_conf->ngx_log);

    if (ip_hash_table_init(&(srv_conf->ipv4_times_table), srv_conf->ngx_pool_for_times_table, AF_INET) != SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: Initialization failed");
    }

    if (ip_hash_table_init(&(srv_conf->ipv6_times_table), srv_conf->ngx_pool_for_times_table, AF_INET6) != SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: Initialization failed");
    }

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


static ngx_int_t ngx_http_waf_init_after_load_config(ngx_conf_t* cf) {
    ngx_http_handler_pt* h;
    ngx_http_core_main_conf_t* cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_waf_handler_ip_url_referer_ua_args_cookie_post;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers);
    *h = ngx_http_waf_handler_url_args;

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
        ipv6_t* ipv6;
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
        case 2:
            ipv6 = ngx_array_push(ngx_array);
            if (parse_ipv6(line, ipv6) != SUCCESS) {
                return FAIL;
            }
        }
    }
    fclose(fp);
    ngx_pfree(cf->pool, str);
    return SUCCESS;
}

#endif // !NGX_HTTP_WAF_MODULE_CONFIG_H
