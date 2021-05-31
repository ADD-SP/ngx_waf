/**
 * @file ngx_http_waf_module_config.h
 * @brief 读取 nginx.conf 内的配置以及规则文件。
*/

#include <stdio.h>

#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include <string.h>
#include <utarray.h>
#include <ngx_cycle.h>
#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_ip_trie.h>
#include <ngx_http_waf_module_lru_cache.h>
#include <ngx_http_waf_module_under_attack.h>


#ifndef NGX_HTTP_WAF_MODULE_CONFIG_H
#define NGX_HTTP_WAF_MODULE_CONFIG_H

extern ngx_module_t ngx_http_waf_module;


static ngx_int_t ngx_http_waf_handler_server_rewrite_phase(ngx_http_request_t* r);


static ngx_int_t ngx_http_waf_handler_access_phase(ngx_http_request_t* r);

/**
 * @defgroup config 配置读取和处理模块
 * @brief 读取 nginx.conf 内的配置以及规则文件。
 * @addtogroup config 配置读取和处理模块
 * @{
*/


/**
 * @brief 读取配置项 waf_mult_mount，该项表示是否将检测过程挂载到两个阶段以应对 rewrite 导致的 URL 和 ARGS 前后不一致的情况。
 * @warning 此配置项已经废弃，保留此函数只为了提示用户这一信息，后续版本会删除。
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
 * @brief 读取配置项 waf_cc_deny，该项表示最高的访问频次以及超出后的拉黑时间。
*/
static char* ngx_http_waf_cc_deny_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_cache，该项表示缓存相关的参数。
*/
static char* ngx_http_waf_cache_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_under_attack，该项用来设置五秒盾相关的参数。
*/
static char* ngx_http_waf_under_attack_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_priority，该项用来设置检查项目的优先级。
*/
static char* ngx_http_waf_priority_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 读取配置项 waf_http_status，该项用来设置检查项目的优先级。
*/
static char* ngx_http_waf_http_status_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


/**
 * @brief 当读取 waf_log 变量时的回调函数，这个变量当启动检查时不为空，反之为空字符串。
*/
static ngx_int_t ngx_http_waf_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_blocking_log 变量时的回调函数，这个变量当拦截时不为空，反之为空字符串。
*/
static ngx_int_t ngx_http_waf_blocking_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_blocked 变量时的回调函数，这个变量当请求被拦截的时候是 "true"，反之是 "false"。
*/
static ngx_int_t ngx_http_waf_blocked_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_rule_type 变量时的回调函数，这个变量会显示触发了的规则类型。
*/
static ngx_int_t ngx_http_waf_rule_type_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_rule_deatils 变量时的回调函数，这个变量会显示触发了的规则的细节。
*/
static ngx_int_t ngx_http_waf_rule_deatils_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


/**
 * @brief 当读取 waf_spend 变量时的回调函数，这个变量表示本次检查花费的时间（毫秒）。
*/
static ngx_int_t ngx_http_waf_spend_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data);


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
 * @brief 用于 CC 防护的共享内存的初始时的回调函数
 * @param[in] zone 正在初始化的共享内存
 * @param[in] data ngx_http_waf_srv_conf_t
*/
static ngx_int_t ngx_http_waf_shm_zone_cc_deny_init(ngx_shm_zone_t *zone, void *data);


/**
 * @brief 读取指定文件的内容到容器中。
 * @param[in] file_name 要读取的配置文件完整路径。
 * @param[out] container 存放读取结果的容器。
 * @param[in] mode 读取模式
 * @li 当 mode = 0 时会将读取到文本编译成正则表达式再存储。容器类型为 ngx_array_t。
 * @li 当 mode = 1 时会将读取到的文本转化为 ipv4_t 再存储。容器类型为 ip_trie_t。
 * @li 当 mode = 2 时会将读取到的文本转化为 ipv6_t 再存储。容器类型为 ip_trie_t。
 * @return 读取操作的结果。
 * @retval NGX_HTTP_WAF_SUCCESS 读取成功。
 * @retval FAIL 读取中发生错误。
*/
static ngx_int_t load_into_container(ngx_conf_t* cf, const char* file_name, void* container, ngx_int_t mode);

/**
 * @}
*/


static char* ngx_http_waf_mult_mount_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    /* TODO: 此配置于 v4.0.0 开始废弃，合并到配置 waf_mode 内。
        暂时保留此配置用来提示这一不向下兼容的更改，可能会在后续某个版本中删除提示。
    */
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
            "ngx_waf: \"waf_mult_mount\" is a deprecated directive since v4.0.0. Its functionality has been merged into the \"waf_mode\" directive. For more information please visit https://docs.addesp.com/ngx_waf/advance/syntax.html or https://add-sp.github.io/ngx_waf/advance/syntax.html or https://ngx-waf.pages.dev/advance/syntax.html");
    return NGX_CONF_ERROR;
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
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_waf: %s", "the path of the rule files is not specified");
        return NGX_CONF_ERROR;
    }

    char* full_path = ngx_palloc(cf->pool, sizeof(char) * NGX_HTTP_WAF_RULE_MAX_LEN);
    char* end = to_c_str((u_char*)full_path, srv_conf->waf_rule_path);

    NGX_HTTP_WAF_CHECK_AND_LOAD_CONF(cf, full_path, end, NGX_HTTP_WAF_IPV4_FILE, &srv_conf->black_ipv4, 1);
    NGX_HTTP_WAF_CHECK_AND_LOAD_CONF(cf, full_path, end, NGX_HTTP_WAF_IPV6_FILE, &srv_conf->black_ipv6, 2);
    NGX_HTTP_WAF_CHECK_AND_LOAD_CONF(cf, full_path, end, NGX_HTTP_WAF_URL_FILE, srv_conf->black_url, 0);
    NGX_HTTP_WAF_CHECK_AND_LOAD_CONF(cf, full_path, end, NGX_HTTP_WAF_ARGS_FILE, srv_conf->black_args, 0);
    NGX_HTTP_WAF_CHECK_AND_LOAD_CONF(cf, full_path, end, NGX_HTTP_WAF_UA_FILE, srv_conf->black_ua, 0);
    NGX_HTTP_WAF_CHECK_AND_LOAD_CONF(cf, full_path, end, NGX_HTTP_WAF_REFERER_FILE, srv_conf->black_referer, 0);
    NGX_HTTP_WAF_CHECK_AND_LOAD_CONF(cf, full_path, end, NGX_HTTP_WAF_COOKIE_FILE, srv_conf->black_cookie, 0);
    NGX_HTTP_WAF_CHECK_AND_LOAD_CONF(cf, full_path, end, NGX_HTTP_WAF_POST_FILE, srv_conf->black_post, 0);
    NGX_HTTP_WAF_CHECK_AND_LOAD_CONF(cf, full_path, end, NGX_HTTP_WAF_WHITE_IPV4_FILE, &srv_conf->white_ipv4, 1);
    NGX_HTTP_WAF_CHECK_AND_LOAD_CONF(cf, full_path, end, NGX_HTTP_WAF_WHITE_IPV6_FILE, &srv_conf->white_ipv6, 2);
    NGX_HTTP_WAF_CHECK_AND_LOAD_CONF(cf, full_path, end, NGX_HTTP_WAF_WHITE_URL_FILE, srv_conf->white_url, 0);
    NGX_HTTP_WAF_CHECK_AND_LOAD_CONF(cf, full_path, end, NGX_HTTP_WAF_WHITE_REFERER_FILE, srv_conf->white_referer, 0);

    ngx_pfree(cf->pool, full_path);
    return NGX_CONF_OK;
}


static char* ngx_http_waf_mode_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_srv_conf_t* srv_conf = (ngx_http_waf_srv_conf_t*)conf;
    ngx_str_t* modes = cf->args->elts;
    size_t i;

    for (i = 1; i < cf->args->nelts && modes != NULL; i++) {
        if (ngx_strncasecmp(modes[i].data, (u_char*)"GET", ngx_min(modes[i].len, sizeof("GET") - 1)) == 0
            && modes[i].len == sizeof("GET") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_GET;
        } 
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!GET", ngx_min(modes[i].len, sizeof("!GET") - 1)) == 0
            && modes[i].len == sizeof("!GET") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_HEAD;
        } 

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"HEAD", ngx_min(modes[i].len, sizeof("HEAD") - 1)) == 0
            && modes[i].len == sizeof("HEAD") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_HEAD;
        } 
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!HEAD", ngx_min(modes[i].len, sizeof("!HEAD") - 1)) == 0
            && modes[i].len == sizeof("!HEAD") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_HEAD;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"POST", ngx_min(modes[i].len, sizeof("POST") - 1)) == 0
            && modes[i].len == sizeof("POST") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_POST;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!POST", ngx_min(modes[i].len, sizeof("!POST") - 1)) == 0
            && modes[i].len == sizeof("!POST") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_POST;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"PUT", ngx_min(modes[i].len, sizeof("PUT") - 1)) == 0
            && modes[i].len == sizeof("PUT") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_PUT;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!PUT", ngx_min(modes[i].len, sizeof("!PUT") - 1)) == 0
            && modes[i].len == sizeof("!PUT") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_PUT;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"DELETE", ngx_min(modes[i].len, sizeof("DELETE") - 1)) == 0
            && modes[i].len == sizeof("DELETE") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_DELETE;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!DELETE", ngx_min(modes[i].len, sizeof("!DELETE") - 1)) == 0
            && modes[i].len == sizeof("!DELETE") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_DELETE;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"MKCOL", ngx_min(modes[i].len, sizeof("MKCOL") - 1)) == 0
            && modes[i].len == sizeof("MKCOL") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_MKCOL;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!MKCOL", ngx_min(modes[i].len, sizeof("!MKCOL") - 1)) == 0
            && modes[i].len == sizeof("!MKCOL") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_MKCOL;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"COPY", ngx_min(modes[i].len, sizeof("COPY") - 1)) == 0
            && modes[i].len == sizeof("COPY") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_COPY;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!COPY", ngx_min(modes[i].len, sizeof("!COPY") - 1)) == 0
            && modes[i].len == sizeof("!COPY") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_COPY;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"MOVE", ngx_min(modes[i].len, sizeof("MOVE") - 1)) == 0
            && modes[i].len == sizeof("MOVE") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_MOVE;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!MOVE", ngx_min(modes[i].len, sizeof("!MOVE") - 1)) == 0
            && modes[i].len == sizeof("!MOVE") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_MOVE;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"OPTIONS", ngx_min(modes[i].len, sizeof("OPTIONS") - 1)) == 0
            && modes[i].len == sizeof("OPTIONS") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_OPTIONS;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!OPTIONS", ngx_min(modes[i].len, sizeof("!OPTIONS") - 1)) == 0
            && modes[i].len == sizeof("!OPTIONS") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_OPTIONS;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"PROPFIND", ngx_min(modes[i].len, sizeof("PROPFIND") - 1)) == 0
            && modes[i].len == sizeof("PROPFIND") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_PROPFIND;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!PROPFIND", ngx_min(modes[i].len, sizeof("!PROPFIND") - 1)) == 0
            && modes[i].len == sizeof("!PROPFIND") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_PROPFIND;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"PROPPATCH", ngx_min(modes[i].len, sizeof("PROPPATCH") - 1)) == 0
            && modes[i].len == sizeof("PROPPATCH") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_PROPPATCH;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!PROPPATCH", ngx_min(modes[i].len, sizeof("!PROPPATCH") - 1)) == 0
            && modes[i].len == sizeof("!PROPPATCH") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_PROPPATCH;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"LOCK", ngx_min(modes[i].len, sizeof("LOCK") - 1)) == 0
            && modes[i].len == sizeof("LOCK") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_LOCK;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!LOCK", ngx_min(modes[i].len, sizeof("!LOCK") - 1)) == 0
            && modes[i].len == sizeof("!LOCK") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_LOCK;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"UNLOCK", ngx_min(modes[i].len, sizeof("UNLOCK") - 1)) == 0
            && modes[i].len == sizeof("UNLOCK") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_UNLOCK;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!UNLOCK", ngx_min(modes[i].len, sizeof("!UNLOCK") - 1)) == 0
            && modes[i].len == sizeof("!UNLOCK") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_UNLOCK;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"PATCH", ngx_min(modes[i].len, sizeof("PATCH") - 1)) == 0
            && modes[i].len == sizeof("PATCH") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_PATCH;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!PATCH", ngx_min(modes[i].len, sizeof("!PATCH") - 1)) == 0
            && modes[i].len == sizeof("!PATCH") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_PATCH;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"TRACE", ngx_min(modes[i].len, sizeof("TRACE") - 1)) == 0
            && modes[i].len == sizeof("TRACE") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_TRACE;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!TRACE", ngx_min(modes[i].len, sizeof("!TRACE") - 1)) == 0
            && modes[i].len == sizeof("!TRACE") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_TRACE;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"IP", ngx_min(modes[i].len, sizeof("IP") - 1)) == 0
            && modes[i].len == sizeof("IP") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_IP;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!IP", ngx_min(modes[i].len, sizeof("!IP") - 1)) == 0
            && modes[i].len == sizeof("!IP") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_IP;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"URL", ngx_min(modes[i].len, sizeof("URL") - 1)) == 0
            && modes[i].len == sizeof("URL") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_URL;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!URL", ngx_min(modes[i].len, sizeof("!URL") - 1)) == 0
            && modes[i].len == sizeof("!URL") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_URL;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"RBODY", ngx_min(modes[i].len, sizeof("RBODY") - 1)) == 0
            && modes[i].len == sizeof("RBODY") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_RB;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!RBODY", ngx_min(modes[i].len, sizeof("!RBODY") - 1)) == 0
            && modes[i].len == sizeof("!RBODY") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_RB;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"ARGS", ngx_min(modes[i].len, sizeof("ARGS") - 1)) == 0
            && modes[i].len == sizeof("ARGS") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_ARGS;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!ARGS", ngx_min(modes[i].len, sizeof("!ARGS") - 1)) == 0
            && modes[i].len == sizeof("!ARGS") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_ARGS;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"UA", ngx_min(modes[i].len, sizeof("UA") - 1)) == 0
            && modes[i].len == sizeof("UA") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_UA;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!UA", ngx_min(modes[i].len, sizeof("!UA") - 1)) == 0
            && modes[i].len == sizeof("!UA") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_UA;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"COOKIE", ngx_min(modes[i].len, sizeof("COOKIE") - 1)) == 0
            && modes[i].len == sizeof("COOKIE") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_COOKIE;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!COOKIE", ngx_min(modes[i].len, sizeof("!COOKIE") - 1)) == 0
            && modes[i].len == sizeof("!COOKIE") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_COOKIE;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"REFERER", ngx_min(modes[i].len, sizeof("REFERER") - 1)) == 0
            && modes[i].len == sizeof("REFERER") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_REFERER;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!REFERER", ngx_min(modes[i].len, sizeof("!REFERER") - 1)) == 0
            && modes[i].len == sizeof("!REFERER") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_REFERER;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"CC", ngx_min(modes[i].len, sizeof("CC") - 1)) == 0
            && modes[i].len == sizeof("CC") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_INSPECT_CC;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!CC", ngx_min(modes[i].len, sizeof("!CC") - 1)) == 0
            && modes[i].len == sizeof("!CC") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_INSPECT_CC;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"STD", ngx_min(modes[i].len, sizeof("STD") - 1)) == 0
            && modes[i].len == sizeof("STD") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_STD;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!STD", ngx_min(modes[i].len, sizeof("!STD") - 1)) == 0
            && modes[i].len == sizeof("!STD") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_STD;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"STATIC", ngx_min(modes[i].len, sizeof("STATIC") - 1)) == 0
            && modes[i].len == sizeof("STATIC") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_STATIC;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!STATIC", ngx_min(modes[i].len, sizeof("!STATIC") - 1)) == 0
            && modes[i].len == sizeof("!STATIC") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_STATIC;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"DYNAMIC", ngx_min(modes[i].len, sizeof("DYNAMIC") - 1)) == 0
            && modes[i].len == sizeof("DYNAMIC") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_DYNAMIC;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!DYNAMIC", ngx_min(modes[i].len, sizeof("!DYNAMIC") - 1)) == 0
            && modes[i].len == sizeof("!DYNAMIC") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_DYNAMIC;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"FULL", ngx_min(modes[i].len, sizeof("FULL") - 1)) == 0
            && modes[i].len == sizeof("FULL") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_FULL;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!FULL", ngx_min(modes[i].len, sizeof("!FULL") - 1)) == 0
            && modes[i].len == sizeof("!FULL") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_FULL;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"COMPAT", ngx_min(modes[i].len, sizeof("COMPAT") - 1)) == 0
            && modes[i].len == sizeof("COMPAT") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_EXTRA_COMPAT;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!COMPAT", ngx_min(modes[i].len, sizeof("!COMPAT") - 1)) == 0
            && modes[i].len == sizeof("!COMPAT") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_EXTRA_COMPAT;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"STRICT", ngx_min(modes[i].len, sizeof("STRICT") - 1)) == 0
            && modes[i].len == sizeof("STRICT") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_EXTRA_STRICT;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!STRICT", ngx_min(modes[i].len, sizeof("!STRICT") - 1)) == 0
            && modes[i].len == sizeof("!STRICT") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_EXTRA_STRICT;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"CACHE", ngx_min(modes[i].len, sizeof("CACHE") - 1)) == 0
            && modes[i].len == sizeof("CACHE") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_EXTRA_CACHE;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!CACHE", ngx_min(modes[i].len, sizeof("!CACHE") - 1)) == 0
            && modes[i].len == sizeof("!CACHE") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_EXTRA_CACHE;
        }

        else if (ngx_strncasecmp(modes[i].data, (u_char*)"LIB-INJECTION", ngx_min(modes[i].len, sizeof("LIB-INJECTION") - 1)) == 0
            && modes[i].len == sizeof("LIB-INJECTION") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_LIB_INJECTION;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!LIB-INJECTION", ngx_min(modes[i].len, sizeof("!LIB-INJECTION") - 1)) == 0
            && modes[i].len == sizeof("!LIB-INJECTION") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_LIB_INJECTION;
        }


        else if (ngx_strncasecmp(modes[i].data, (u_char*)"LIB-INJECTION-SQLI", ngx_min(modes[i].len, sizeof("LIB-INJECTION-SQLI") - 1)) == 0
            && modes[i].len == sizeof("LIB-INJECTION-SQLI") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_LIB_INJECTION_SQLI;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!LIB-INJECTION-SQLI", ngx_min(modes[i].len, sizeof("!LIB-INJECTION-SQLI") - 1)) == 0
            && modes[i].len == sizeof("!LIB-INJECTION-SQLI") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_LIB_INJECTION_SQLI;
        }


        else if (ngx_strncasecmp(modes[i].data, (u_char*)"LIB-INJECTION-XSS", ngx_min(modes[i].len, sizeof("LIB-INJECTION-XSS") - 1)) == 0
            && modes[i].len == sizeof("LIB-INJECTION-XSS") - 1) {
            srv_conf->waf_mode |= NGX_HTTP_WAF_MODE_LIB_INJECTION_XSS;
        }
        else if (ngx_strncasecmp(modes[i].data, (u_char*)"!LIB-INJECTION-XSS", ngx_min(modes[i].len, sizeof("!LIB-INJECTION-XSS") - 1)) == 0
            && modes[i].len == sizeof("!LIB-INJECTION-XSS") - 1) {
            srv_conf->waf_mode &= ~NGX_HTTP_WAF_MODE_LIB_INJECTION_XSS;
        }

        else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
            "ngx_waf: invalid value. Please visit https://docs.addesp.com/ngx_waf/advance/syntax.html or https://add-sp.github.io/ngx_waf/advance/syntax.html or https://ngx-waf.pages.dev/advance/syntax.html");
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char* ngx_http_waf_cc_deny_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    static ngx_uint_t shm_id = 1;
    ngx_http_waf_srv_conf_t* srv_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    /* 默认封禁 60 分钟 */
    srv_conf->waf_cc_deny_duration = 1 * 60 * 60;
    /* 设置默认的共享内存大小 */
    srv_conf->waf_cc_deny_shm_zone_size = NGX_HTTP_WAF_SHARE_MEMORY_CC_DENY_MIN_SIZE;

    for (size_t i = 1; i < cf->args->nelts; i++) {
        UT_array* array = NULL;
        if (ngx_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (ngx_strcmp("rate", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);

            UT_array* temp = NULL;
            if (ngx_str_split(p, '/', 256, &temp) != NGX_HTTP_WAF_SUCCESS) {
                goto error;
            }

            if (utarray_len(temp) != 2) {
                goto error;
            }

            ngx_str_t* q = NULL;
            q = (ngx_str_t*)utarray_next(temp, q);
            srv_conf->waf_cc_deny_limit = ngx_atoi(q->data, q->len - 1);
            if (srv_conf->waf_cc_deny_limit == NGX_ERROR || srv_conf->waf_cc_deny_limit <= 0) {
                goto error;
            }
            if (q->data[q->len - 1] != 'r') {
                goto error;
            }

            q = (ngx_str_t*)utarray_next(temp, q);
            if (q->data[0] != 'm' || q->len != 1) {
                goto error;
            }

            utarray_free(temp);

        } else if (ngx_strcmp("duration", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            srv_conf->waf_cc_deny_duration = parse_time(p->data);
            if (srv_conf->waf_cc_deny_duration == NGX_ERROR) {
                goto error;
            }

        } else if (ngx_strcmp("size", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            srv_conf->waf_cc_deny_shm_zone_size = parse_size(p->data);
            if (srv_conf->waf_cc_deny_shm_zone_size == NGX_ERROR) {
                goto error;
            }
            srv_conf->waf_cc_deny_shm_zone_size = ngx_max(NGX_HTTP_WAF_SHARE_MEMORY_CC_DENY_MIN_SIZE, 
                                                          srv_conf->waf_cc_deny_shm_zone_size);
        } else {
            goto error;
        }

        utarray_free(array);
    }

    if (srv_conf->waf_cc_deny_limit == NGX_CONF_UNSET) {
        goto error;
    }


    u_char* str = ngx_pcalloc(srv_conf->ngx_pool, sizeof(u_char) * 1025);
    ngx_memcpy(str, cf->conf_file->file.name.data, cf->conf_file->file.name.len);
    ngx_uint_t id = (ngx_uint_t)shm_id++;
    int index = cf->conf_file->file.name.len;
    while (id != 0) {
        str[index++] = (id % 10) + '0';
        id /= 10;
    }
    str[index] = '\0';
    strcat((char*)str, NGX_HTTP_WAF_SHARE_MEMORY_CC_DNEY_NAME);
    ngx_str_t name;
    name.data = str;
    #ifdef __STDC_LIB_EXT1__
        name.len = strnlen_s((char*)str, sizeof(u_char) * 1025 - 1);
    #else
        name.len = strlen((char*)str);
    #endif
    
    srv_conf->shm_zone_cc_deny = ngx_shared_memory_add(cf, &name, 
                                                        srv_conf->waf_cc_deny_shm_zone_size, 
                                                        &ngx_http_waf_module);

    if (srv_conf->shm_zone_cc_deny == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
                "ngx_waf: failed to add shared memory");
        return NGX_CONF_ERROR;
    }

    srv_conf->shm_zone_cc_deny->init = ngx_http_waf_shm_zone_cc_deny_init;
    srv_conf->shm_zone_cc_deny->data = srv_conf;

    return NGX_CONF_OK;

    error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


static char* ngx_http_waf_cache_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_srv_conf_t* srv_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    /* 默认每隔 60 分钟批量清理一次缓存 */
    srv_conf->waf_eliminate_inspection_cache_interval = 1 * 60 * 60;
    /* 默认每次清理一般的缓存 */
    srv_conf->waf_eliminate_inspection_cache_percent = 50;

    for (size_t i = 1; i < cf->args->nelts; i++) {
        UT_array* array = NULL;
        if (ngx_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (ngx_strcmp("capacity", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            srv_conf->waf_inspection_capacity = ngx_atoi(p->data, p->len);
            if (srv_conf->waf_inspection_capacity == NGX_ERROR
                || srv_conf->waf_inspection_capacity <= 0) {
                goto error;
            }

        } else if (ngx_strcmp("interval", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            srv_conf->waf_eliminate_inspection_cache_interval = parse_time(p->data);
            if (srv_conf->waf_eliminate_inspection_cache_interval == NGX_ERROR) {
                goto error;
            }

        } else if (ngx_strcmp("percent", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            srv_conf->waf_eliminate_inspection_cache_percent = ngx_atoi(p->data, p->len);
            if (srv_conf->waf_eliminate_inspection_cache_percent == NGX_ERROR
                || srv_conf->waf_eliminate_inspection_cache_percent <= 0
                || srv_conf->waf_eliminate_inspection_cache_percent > 100) {
                goto error;
            }
        } else {
            goto error;
        }

        utarray_free(array);
    }

    if (srv_conf->waf_inspection_capacity == NGX_CONF_UNSET) {
        goto error;
    }

    if (lru_cache_manager_init(&(srv_conf->black_url_inspection_cache), 
                                 srv_conf->waf_inspection_capacity, std, NULL) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: Failed to initialize black_url_inspection_cache.");
        return NGX_CONF_ERROR;
    }

    if (lru_cache_manager_init(&(srv_conf->black_args_inspection_cache), 
                                 srv_conf->waf_inspection_capacity, std, NULL) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: Failed to initialize black_args_inspection_cache.");
        return NGX_CONF_ERROR;
    }

    if (lru_cache_manager_init(&(srv_conf->black_ua_inspection_cache), 
                                 srv_conf->waf_inspection_capacity, std, NULL) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: Failed to initialize black_ua_inspection_cache.");
        return NGX_CONF_ERROR;
    }

    if (lru_cache_manager_init(&(srv_conf->black_referer_inspection_cache), 
                                 srv_conf->waf_inspection_capacity, std, NULL) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: Failed to initialize black_referer_inspection_cache.");
        return NGX_CONF_ERROR;
    }

    if (lru_cache_manager_init(&(srv_conf->black_cookie_inspection_cache), 
                                 srv_conf->waf_inspection_capacity, std, NULL) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: Failed to initialize black_cookie_inspection_cache.");
        return NGX_CONF_ERROR;
    }

    if (lru_cache_manager_init(&(srv_conf->white_url_inspection_cache), 
                                 srv_conf->waf_inspection_capacity, std, NULL) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: Failed to initialize white_url_inspection_cache.");
        return NGX_CONF_ERROR;
    }

    if (lru_cache_manager_init(&(srv_conf->white_referer_inspection_cache), 
                                 srv_conf->waf_inspection_capacity, std, NULL) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: Failed to initialize white_referer_inspection_cache.");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

    error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


static char* ngx_http_waf_under_attack_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_srv_conf_t* srv_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    srv_conf->waf_under_attack = NGX_CONF_UNSET;

    if (ngx_strncmp(p_str[1].data, "on", ngx_min(p_str[1].len, 2)) == 0) {
        srv_conf->waf_under_attack = 1;
    }

    if (cf->args->nelts != 3) {
        goto error;
    }

    for (size_t i = 2; i < cf->args->nelts; i++) {
        UT_array* array = NULL;
        if (ngx_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (ngx_strcmp("uri", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            if (p == NULL || p->data == NULL || p->len == 0) {
                goto error;
            }
            srv_conf->waf_under_attack_uri.data = ngx_palloc(srv_conf->ngx_pool, sizeof(u_char) * (p->len + 1));
            ngx_memzero(srv_conf->waf_under_attack_uri.data, sizeof(u_char) * (p->len + 1));
            ngx_memcpy(srv_conf->waf_under_attack_uri.data, p->data, sizeof(u_char) * p->len);
            srv_conf->waf_under_attack_uri.len = p->len;

        } else {
            goto error;
        }

        utarray_free(array);
    }

    return NGX_CONF_OK;

    error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


static char* ngx_http_waf_priority_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_srv_conf_t* srv_conf = conf;
    ngx_str_t* p_str = cf->args->elts;
    // u_char error_str[256];

    UT_array* array = NULL;
    if (ngx_str_split(p_str + 1, ' ', 20, &array) != NGX_HTTP_WAF_SUCCESS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
            "ngx_waf: invalid value");
        return NGX_CONF_ERROR;
    }


    if (utarray_len(array) != 11) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
            "ngx_waf: you must specify the priority of all inspections except for POST inspections");
        return NGX_CONF_ERROR;
    }


    ngx_str_t* p = NULL;
    size_t proc_index = 0, proc_no_cc_index = 0;
    while ((p = (ngx_str_t*)utarray_next(array, p))) {
        if (strcasecmp("CC", (char*)(p->data)) == 0) {
            srv_conf->check_proc[proc_index++] = ngx_http_waf_handler_check_cc;

        } else if (strcasecmp("W-IP", (char*)(p->data)) == 0) {
            srv_conf->check_proc[proc_index++] = ngx_http_waf_handler_check_white_ip;
            srv_conf->check_proc_no_cc[proc_no_cc_index++] = ngx_http_waf_handler_check_white_ip;
        } 
        
        else if (strcasecmp("IP", (char*)(p->data)) == 0) {
            srv_conf->check_proc[proc_index++] = ngx_http_waf_handler_check_black_ip;
            srv_conf->check_proc_no_cc[proc_no_cc_index++] = ngx_http_waf_handler_check_black_ip;
        } 
        
        else if (strcasecmp("W-URL", (char*)(p->data)) == 0) {
            srv_conf->check_proc[proc_index++] = ngx_http_waf_handler_check_white_url;
            srv_conf->check_proc_no_cc[proc_no_cc_index++] = ngx_http_waf_handler_check_white_url;
        } 
        
        else if (strcasecmp("URL", (char*)(p->data)) == 0) {
            srv_conf->check_proc[proc_index++] = ngx_http_waf_handler_check_black_url;
            srv_conf->check_proc_no_cc[proc_no_cc_index++] = ngx_http_waf_handler_check_black_url;
        } 
        
        else if (strcasecmp("ARGS", (char*)(p->data)) == 0) {
            srv_conf->check_proc[proc_index++] = ngx_http_waf_handler_check_black_args;
            srv_conf->check_proc_no_cc[proc_no_cc_index++] = ngx_http_waf_handler_check_black_args;
        } 
        
        else if (strcasecmp("UA", (char*)(p->data)) == 0) {
            srv_conf->check_proc[proc_index++] = ngx_http_waf_handler_check_black_user_agent;
            srv_conf->check_proc_no_cc[proc_no_cc_index++] = ngx_http_waf_handler_check_black_user_agent;
        } 
        
        else if (strcasecmp("W-REFERER", (char*)(p->data)) == 0) {
            srv_conf->check_proc[proc_index++] = ngx_http_waf_handler_check_white_referer;
            srv_conf->check_proc_no_cc[proc_no_cc_index++] = ngx_http_waf_handler_check_white_referer;
        } 
        
        else if (strcasecmp("REFERER", (char*)(p->data)) == 0) {
            srv_conf->check_proc[proc_index++] = ngx_http_waf_handler_check_black_referer;
            srv_conf->check_proc_no_cc[proc_no_cc_index++] = ngx_http_waf_handler_check_black_referer;
        } 
        
        else if (strcasecmp("COOKIE", (char*)(p->data)) == 0) {
            srv_conf->check_proc[proc_index++] = ngx_http_waf_handler_check_black_cookie;
            srv_conf->check_proc_no_cc[proc_no_cc_index++] = ngx_http_waf_handler_check_black_cookie;
        }

        else if (strcasecmp("UNDER-ATTACK", (char*)(p->data)) == 0) {
            srv_conf->check_proc[proc_index++] = ngx_http_waf_check_under_attack;
            srv_conf->check_proc_no_cc[proc_no_cc_index++] = ngx_http_waf_check_under_attack;
        }

        else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
                "ngx_waf: ngx_waf: invalid value [%s]", p->data);
            return NGX_CONF_ERROR;
        }
    }

    utarray_free(array);

    return NGX_CONF_OK;
}


static char* ngx_http_waf_http_status_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_srv_conf_t* srv_conf = conf;
    ngx_str_t* p_str = cf->args->elts;


    for (size_t i = 1; i < cf->args->nelts; i++) {
        UT_array* array = NULL;
        if (ngx_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (ngx_strcmp("general", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            srv_conf->waf_http_status = ngx_atoi(p->data, p->len);
            if (srv_conf->waf_http_status == NGX_ERROR
                || srv_conf->waf_http_status <= 0) {
                goto error;
            }

        } else if (ngx_strcmp("cc_deny", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            srv_conf->waf_http_status_cc = ngx_atoi(p->data, p->len);
            if (srv_conf->waf_http_status_cc == NGX_ERROR
                || srv_conf->waf_http_status_cc <= 0) {
                goto error;
            }

        } else {
            goto error;
        }

        utarray_free(array);
    }

    return NGX_CONF_OK;

    error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


static void* ngx_http_waf_create_srv_conf(ngx_conf_t* cf) {
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    srv_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_srv_conf_t));
    if (srv_conf == NULL) {
        return NULL;
    }
    ngx_str_null(&srv_conf->waf_rule_path);

    rand_str(srv_conf->random_str, sizeof(srv_conf->random_str) - 1);
    srv_conf->ngx_pool = ngx_create_pool(sizeof(ngx_pool_t) + NGX_HTTP_WAF_INITIAL_SIZE, cf->log);
    srv_conf->alloc_times = 0;
    srv_conf->waf = NGX_CONF_UNSET;
    srv_conf->waf_mode = 0;
    srv_conf->waf_under_attack = 0;
    srv_conf->waf_under_attack_uri.data = NULL;
    srv_conf->waf_under_attack_uri.len = 0;
    srv_conf->waf_cc_deny_limit = NGX_CONF_UNSET;
    srv_conf->waf_cc_deny_duration = NGX_CONF_UNSET;
    srv_conf->waf_cc_deny_shm_zone_size =  NGX_CONF_UNSET;
    srv_conf->waf_inspection_capacity = NGX_CONF_UNSET;
    srv_conf->waf_eliminate_inspection_cache_interval = 60;
    srv_conf->waf_eliminate_inspection_cache_percent = 50;
    srv_conf->waf_http_status = 403;
    srv_conf->waf_http_status_cc = 503;
    srv_conf->black_url = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_args = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_ua = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_referer = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_cookie = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->black_post = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->white_url = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->white_referer = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->shm_zone_cc_deny = NULL;
    srv_conf->ipv4_access_statistics = NULL;
    srv_conf->ipv6_access_statistics = NULL;
    srv_conf->last_clear_ip_access_statistics = NULL;


    ngx_memzero(srv_conf->check_proc, sizeof(srv_conf->check_proc));
    srv_conf->check_proc[0] = ngx_http_waf_handler_check_white_ip;
    srv_conf->check_proc[1] = ngx_http_waf_handler_check_black_ip;
    srv_conf->check_proc[2] = ngx_http_waf_handler_check_cc;
    srv_conf->check_proc[3] = ngx_http_waf_check_under_attack;
    srv_conf->check_proc[4] = ngx_http_waf_handler_check_white_url;
    srv_conf->check_proc[5] = ngx_http_waf_handler_check_black_url;
    srv_conf->check_proc[6] = ngx_http_waf_handler_check_black_args;
    srv_conf->check_proc[7] = ngx_http_waf_handler_check_black_user_agent;
    srv_conf->check_proc[8] = ngx_http_waf_handler_check_white_referer;
    srv_conf->check_proc[9] = ngx_http_waf_handler_check_black_referer;
    srv_conf->check_proc[10] = ngx_http_waf_handler_check_black_cookie;


    ngx_memzero(srv_conf->check_proc_no_cc, sizeof(srv_conf->check_proc_no_cc));
    srv_conf->check_proc_no_cc[0] = ngx_http_waf_handler_check_white_ip;
    srv_conf->check_proc_no_cc[1] = ngx_http_waf_handler_check_black_ip;
    srv_conf->check_proc_no_cc[2] = ngx_http_waf_check_under_attack;
    srv_conf->check_proc_no_cc[3] = ngx_http_waf_handler_check_white_url;
    srv_conf->check_proc_no_cc[4] = ngx_http_waf_handler_check_black_url;
    srv_conf->check_proc_no_cc[5] = ngx_http_waf_handler_check_black_args;
    srv_conf->check_proc_no_cc[6] = ngx_http_waf_handler_check_black_user_agent;
    srv_conf->check_proc_no_cc[7] = ngx_http_waf_handler_check_white_referer;
    srv_conf->check_proc_no_cc[8] = ngx_http_waf_handler_check_black_referer;
    srv_conf->check_proc_no_cc[9] = ngx_http_waf_handler_check_black_cookie;


    if (ip_trie_init(&(srv_conf->white_ipv4), std, NULL, AF_INET) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NULL;
    }

    if (ip_trie_init(&(srv_conf->white_ipv6), std, NULL, AF_INET6) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NULL;
    }

    if (ip_trie_init(&(srv_conf->black_ipv4), std, NULL, AF_INET) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NULL;
    }

    if (ip_trie_init(&(srv_conf->black_ipv6), std, NULL, AF_INET6) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NULL;
    }


    if (srv_conf->ngx_pool == NULL
        || srv_conf->black_url == NULL
        || srv_conf->black_args == NULL
        || srv_conf->black_ua == NULL
        || srv_conf->black_referer == NULL
        || srv_conf->white_url == NULL
        || srv_conf->white_referer == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NULL;
    }

    return srv_conf;
}


static ngx_int_t ngx_http_waf_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = ngx_palloc(r->pool, sizeof(u_char) * 64);

    if (ctx == NULL || ctx->checked == NGX_HTTP_WAF_FALSE) {
        v->len = 0;
        v->data = NULL;
    }
    else {
        v->len = 4;
        strcpy((char*)v->data, "true");

    }

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_blocking_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = ngx_palloc(r->pool, sizeof(u_char) * 64);

    if (ctx == NULL || ctx->blocked == NGX_HTTP_WAF_FALSE) {
        v->len = 0;
        v->data = NULL;
    }
    else {
        v->len = 4;
        strcpy((char*)v->data, "true");
    }

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
        if (ctx->blocked == NGX_HTTP_WAF_TRUE) {
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
        v->len = strlen((char*)ctx->rule_type);
        v->data = ngx_palloc(r->pool, sizeof(u_char) * ngx_max(v->len, 2));
        strcpy((char*)v->data, (char*)ctx->rule_type);
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
        v->len = strlen((char*)ctx->rule_deatils);
        v->data = ngx_palloc(r->pool, sizeof(u_char) * ngx_max(v->len, 2));
        strcpy((char*)v->data, (char*)ctx->rule_deatils);
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_spend_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (ctx == NULL) {
        v->len = 0;
        v->data = NULL;
    }
    else {
        u_char text[32] = { 0 };
        sprintf((char*)text, "%.5lf", ctx->spend);
        v->len = ngx_strlen(text);
        v->data = ngx_palloc(r->pool, sizeof(u_char) * v->len);
        strcpy((char*)v->data, (char*)text);
    }

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_init_after_load_config(ngx_conf_t* cf) {
    ngx_http_handler_pt* h;
    ngx_http_core_main_conf_t* cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_waf_handler_access_phase;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers);
    *h = ngx_http_waf_handler_server_rewrite_phase;

    ngx_str_t waf_log_name = ngx_string("waf_log");
    ngx_http_variable_t* waf_log = ngx_http_add_variable(cf, &waf_log_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_log->get_handler = ngx_http_waf_log_get_handler;
    waf_log->set_handler = NULL;

    ngx_str_t waf_blocking_log_name = ngx_string("waf_blocking_log");
    ngx_http_variable_t* waf_blocking_log = ngx_http_add_variable(cf, &waf_blocking_log_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_blocking_log->get_handler = ngx_http_waf_blocking_log_get_handler;
    waf_blocking_log->set_handler = NULL;

    ngx_str_t waf_blocked_name = ngx_string("waf_blocked");
    ngx_http_variable_t* waf_blocked = ngx_http_add_variable(cf, &waf_blocked_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_blocked->get_handler = ngx_http_waf_blocked_get_handler;
    waf_blocked->set_handler = NULL;

    ngx_str_t waf_rule_type_name = ngx_string("waf_rule_type");
    ngx_http_variable_t* waf_rule_type = ngx_http_add_variable(cf, &waf_rule_type_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_rule_type->get_handler = ngx_http_waf_rule_type_get_handler;
    waf_rule_type->set_handler = NULL;

    ngx_str_t waf_rule_details_name = ngx_string("waf_rule_details");
    ngx_http_variable_t* waf_rule_details = ngx_http_add_variable(cf, &waf_rule_details_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_rule_details->get_handler = ngx_http_waf_rule_deatils_handler;
    waf_rule_details->set_handler = NULL;

    ngx_str_t waf_spend_name = ngx_string("waf_spend");
    ngx_http_variable_t* waf_spend = ngx_http_add_variable(cf, &waf_spend_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_spend->get_handler = ngx_http_waf_spend_handler;
    waf_spend->set_handler = NULL;

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_shm_zone_cc_deny_init(ngx_shm_zone_t *zone, void *data) {
    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) zone->shm.addr;
    ngx_http_waf_srv_conf_t* srv_conf = (ngx_http_waf_srv_conf_t*)(zone->data);

    srv_conf->ipv4_access_statistics = ngx_slab_calloc(shpool, sizeof(ip_trie_t));
    if (srv_conf->ipv4_access_statistics == NULL) {
        return NGX_ERROR;
    }
    if (ip_trie_init(srv_conf->ipv4_access_statistics, 
                              slab_pool, shpool, AF_INET) != NGX_HTTP_WAF_SUCCESS) {
        return NGX_ERROR;
    }

    srv_conf->ipv6_access_statistics = ngx_slab_calloc(shpool, sizeof(ip_trie_t));
    if (srv_conf->ipv6_access_statistics == NULL) {
        return NGX_ERROR;
    }
    if (ip_trie_init(srv_conf->ipv6_access_statistics, 
                              slab_pool, shpool, AF_INET6) != NGX_HTTP_WAF_SUCCESS) {
        return NGX_ERROR;
    }

    srv_conf->last_clear_ip_access_statistics = ngx_slab_calloc(shpool, sizeof(time_t));
    if (srv_conf->last_clear_ip_access_statistics == NULL) {
        return NGX_ERROR;
    }
    *(srv_conf->last_clear_ip_access_statistics) = time(NULL);

    return NGX_OK;
}


static ngx_int_t load_into_container(ngx_conf_t* cf, const char* file_name, void* container, ngx_int_t mode) {
    FILE* fp = fopen(file_name, "r");
    ngx_int_t line_number = 0;
    ngx_str_t line;
    char* str = ngx_palloc(cf->pool, sizeof(char) * NGX_HTTP_WAF_RULE_MAX_LEN);
    if (fp == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }
    while (fgets(str, NGX_HTTP_WAF_RULE_MAX_LEN - 16, fp) != NULL) {
        ngx_regex_compile_t   regex_compile;
        u_char                errstr[NGX_MAX_CONF_ERRSTR];
        ngx_regex_elt_t* ngx_regex_elt;
        ipv4_t ipv4;
        inx_addr_t inx_addr;
        ipv6_t ipv6;
        ip_trie_node_t* ip_trie_node = NULL;
        ++line_number;
        line.data = (u_char*)str;
        #ifdef __STDC_LIB_EXT1__
            line.len = strnlen_s((char*)str. sizeof(char) * NGX_HTTP_WAF_RULE_MAX_LEN);
        #else
           line.len = strlen((char*)str);
        #endif

        memset(&ipv4, 0, sizeof(ipv4_t));
        memset(&inx_addr, 0, sizeof(inx_addr_t));
        memset(&ipv6, 0, sizeof(ipv6_t));

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
            if (ngx_regex_compile(&regex_compile) != NGX_OK) {
                char temp[NGX_HTTP_WAF_RULE_MAX_LEN] = { 0 };
                to_c_str((u_char*)temp, line);
                ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                    "ngx_waf: In %s:%d, [%s] is not a valid regex string.", file_name, line_number, temp);
                return NGX_HTTP_WAF_FAIL;
            }
            ngx_regex_elt = ngx_array_push((ngx_array_t*)container);
            ngx_regex_elt->name = ngx_palloc(cf->pool, sizeof(u_char) * NGX_HTTP_WAF_RULE_MAX_LEN);
            to_c_str(ngx_regex_elt->name, line);
            ngx_regex_elt->regex = regex_compile.regex;
            break;
        case 1:
            if (parse_ipv4(line, &ipv4) != NGX_HTTP_WAF_SUCCESS) {
                ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                    "ngx_waf: In %s:%d, [%s] is not a valid IPV4 string.", file_name, line_number, ipv4.text);
                return NGX_HTTP_WAF_FAIL;
            }
            inx_addr.ipv4.s_addr = ipv4.prefix;
            if (ip_trie_add((ip_trie_t*)container, &inx_addr, ipv4.suffix_num, ipv4.text, 32) != NGX_HTTP_WAF_SUCCESS) {
                if (ip_trie_find((ip_trie_t*)container, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
                    ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                        "ngx_waf: In %s:%d, the two address blocks [%s] and [%s] have overlapping parts.", 
                        file_name, line_number, ipv4.text, ip_trie_node->data);
                } else {
                    ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                        "ngx_waf: In %s:%d, [%s] cannot be stored because the memory allocation failed.", 
                        file_name, line_number, ipv4.text);
                        return NGX_HTTP_WAF_FAIL;
                }
            }
            break;
        case 2:
            if (parse_ipv6(line, &ipv6) != NGX_HTTP_WAF_SUCCESS) {
                ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                    "ngx_waf: In %s:%d, [%s] is not a valid IPV6 string.", file_name, line_number, ipv6.text);
                return NGX_HTTP_WAF_FAIL;
            }
            ngx_memcpy(inx_addr.ipv6.s6_addr, ipv6.prefix, 16);
            if (ip_trie_add((ip_trie_t*)container, &inx_addr, ipv6.suffix_num, ipv6.text, 64) != NGX_HTTP_WAF_SUCCESS) {
                if (ip_trie_find((ip_trie_t*)container, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
                    ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                        "ngx_waf: In %s:%d, the two address blocks [%s] and [%s] have overlapping parts.", 
                        file_name, line_number, ipv6.text, ip_trie_node->data);
                } else {
                    ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                        "ngx_waf: In %s:%d, [%s] cannot be stored because the memory allocation failed.", 
                        file_name, line_number, ipv6.text);
                        return NGX_HTTP_WAF_FAIL;
                }
            }
            break;
        }
    }
    fclose(fp);
    ngx_pfree(cf->pool, str);
    return NGX_HTTP_WAF_SUCCESS;
}

#endif // !NGX_HTTP_WAF_MODULE_CONFIG_H
