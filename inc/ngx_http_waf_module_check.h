/**
 * @file ngx_http_waf_module_check.h
 * @brief 检查诸如 IP，URL 等是否命中规则。
*/

#include <uthash.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <ngx_inet.h>
#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>


#ifndef NGX_HTTP_WAF_MODLULE_CHECK_H
#define NGX_HTTP_WAF_MODLULE_CHECK_H

extern ngx_module_t ngx_http_waf_module; /**< 模块详情 */

/**
 * @defgroup check 规则匹配模块
 * @brief 检查诸如 IP，URL 等是否命中规则。
 * @addtogroup check 规则匹配模块
 * @{
*/

/**
 * @typedef ngx_http_waf_check
 * @brief 请求检查函数的函数指针
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
*/
typedef ngx_int_t (*ngx_http_waf_check)(ngx_http_request_t* r, ngx_int_t* out_http_status);

/**
 * @brief 检查客户端 IP 地址是否在白名单中。
 * @param[out] out_http_status 当出发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED IP 地址在白名单中。
 * @retval NOT_MATCHED IP 地址不在白名单中。
*/
static ngx_int_t ngx_http_waf_handler_check_white_ip(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查客户端 IP 地址是否在黑名单中。
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED IP 地址在黑名单中。
 * @retval NOT_MATCHED IP 地址不在黑名单中。
*/
static ngx_int_t ngx_http_waf_handler_check_black_ip(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查客户端 IPV4 地址的访问频次（60 秒内）是否超出了限制。
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果超出 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 超出限制。
 * @retval NOT_MATCHED 未超出限制。
*/
static ngx_int_t ngx_http_waf_handler_check_cc_ipv4(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查 URL 是否在白名单中。
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在白名单中。
 * @retval NOT_MATCHED 不在白名单中
*/
static ngx_int_t ngx_http_waf_handler_check_white_url(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查 URL 是否在黑名单中
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在黑名单中。
 * @retval NOT_MATCHED 不在黑名单中
*/
static ngx_int_t ngx_http_waf_handler_check_black_url(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查请求参数是否在黑名单中
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在黑名单中。
 * @retval NOT_MATCHED 不在黑名单中
*/
static ngx_int_t ngx_http_waf_handler_check_black_args(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查 UserAgent 是否在黑名单中
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在黑名单中。
 * @retval NOT_MATCHED 不在黑名单中
*/
static ngx_int_t ngx_http_waf_handler_check_black_user_agent(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查 Referer 是否在白名单中
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在白名单中。
 * @retval NOT_MATCHED 不在白黑名单中
*/
static ngx_int_t ngx_http_waf_handler_check_white_referer(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查 Referer 是否在黑名单中
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在黑名单中。
 * @retval NOT_MATCHED 不在黑名单中
*/
static ngx_int_t ngx_http_waf_handler_check_black_referer(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查 Cookie 是否在黑名单中
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在黑名单中。
 * @retval NOT_MATCHED 不在黑名单中
*/
static ngx_int_t ngx_http_waf_handler_check_black_cookie(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 逐渐释放旧的哈希表所占用的内存
 * @li 第一阶段：备份现有的哈希表和现有的内存池，然后创建新的哈希表和内存池。
 * @li 第二阶段：逐渐将旧的哈希表中有用的内容转移到新的哈希表中。
 * @li 第三阶段：清空旧的哈希表。
 * @li 第四阶段：销毁旧的内存池，完成释放。
 * @return 如果正常走完了四个阶段返回 SUCCESS，如果还在释放中（第四阶段之前）返回 PROCESSING，如果出现错误返回 FAIL。
 * @retval SUCCESS 正常走完了四个阶段。
 * @retval PROCESSING 正在进行某个阶段，还未完成释放。
 * @retval FAIL 出现错误，未能完成释放。
*/
static ngx_int_t ngx_http_waf_free_hash_table(ngx_http_request_t* r, ngx_http_waf_srv_conf_t* srv_conf);

/**
* @brief 检查请求体内容是否存在于黑名单中，存在则拦截，反之放行。
*/
static void check_post(ngx_http_request_t* r);

/**
 * @}
*/


static ngx_int_t ngx_http_waf_handler_check_white_ip(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_IP) == FALSE) {
        return NOT_MATCHED;
    }

    if (r->connection->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
        uint32_t ipv4 = sin->sin_addr.s_addr;
        ipv4_t* p = srv_conf->white_ipv4->elts;
        size_t index = 0;
        for (; index < srv_conf->white_ipv4->nelts; index++, p++) {
            if (ipv4_netcmp(ipv4, p) == MATCHED) {
                ctx->blocked = FALSE;
                strcpy((char*)ctx->rule_type, "WHITE-IPV4");
                strcpy((char*)ctx->rule_deatils, (char*)p->text);
                *out_http_status = NGX_DECLINED;
                return MATCHED;
            }
        }
    } else if (r->connection->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
        ipv6_t* p = srv_conf->white_ipv6->elts;
        size_t index = 0;
        for (; index < srv_conf->white_ipv6->nelts; index++, p++) {
            if (ipv6_netcmp(sin6->sin6_addr.__in6_u.__u6_addr8, p) == MATCHED) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "WHITE-IPV6");
                strcpy((char*)ctx->rule_deatils, (char*)p->text);
                *out_http_status = NGX_DECLINED;
                return MATCHED;
            }
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_black_ip(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_IP) == FALSE) {
        return NOT_MATCHED;
    }

    if (r->connection->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
        uint32_t ipv4 = sin->sin_addr.s_addr;
        ipv4_t* p = srv_conf->black_ipv4->elts;
        size_t index = 0;
        for (; index < srv_conf->black_ipv4->nelts; index++, p++) {
            if (ipv4_netcmp(ipv4, p) == MATCHED) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-IPV4");
                strcpy((char*)ctx->rule_deatils, (char*)p->text);
                *out_http_status = NGX_HTTP_FORBIDDEN;
                return MATCHED;
            }
        }
    } else if (r->connection->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
        ipv6_t* p = srv_conf->black_ipv6->elts;
        size_t index = 0;
        for (; index < srv_conf->black_ipv6->nelts; index++, p++) {
            if (ipv6_netcmp(sin6->sin6_addr.__in6_u.__u6_addr8, p) == MATCHED) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-IPV6");
                strcpy((char*)ctx->rule_deatils, (char*)p->text);
                *out_http_status = NGX_HTTP_FORBIDDEN;
                return MATCHED;
            }
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_cc_ipv4(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;

    if (r->connection->sockaddr->sa_family != AF_INET) {
        return NOT_MATCHED;
    }

    unsigned long ipv4 = sin->sin_addr.s_addr;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_CC) == FALSE) {
        return NOT_MATCHED;
    }
    if (srv_conf->waf_cc_deny_limit == NGX_CONF_UNSET
        || srv_conf->waf_cc_deny_duration == NGX_CONF_UNSET) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_waf: CC-DENY-CONF-INVALID");
        return NOT_MATCHED;
    }
    if (srv_conf->alloc_times > 55000) {
        ngx_int_t ret = ngx_http_waf_free_hash_table(r, srv_conf);
        if (ret == SUCCESS || ret == FAIL) {
            srv_conf->alloc_times -= 55000;
        }
    }

    hash_table_item_int_ulong_t* hash_item = NULL;
    time_t now = time(NULL);
    HASH_FIND_INT(srv_conf->ipv4_times, (int*)(&ipv4), hash_item);
    if (hash_item == NULL) {
        hash_item = ngx_palloc(srv_conf->ngx_pool, sizeof(hash_table_item_int_ulong_t));
        if (hash_item == NULL) {
            // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_waf: MEM-ALLOC-ERROR");
            return NOT_MATCHED;
        }
        ++(srv_conf->alloc_times);
        hash_item->times = 1;
        hash_item->start_time = now;
        hash_item->key = ipv4;
        HASH_ADD_INT(srv_conf->ipv4_times, key, hash_item);
    }
    else {
        if (hash_item->times > (ngx_uint_t)srv_conf->waf_cc_deny_limit) {
            if (difftime(now, hash_item->start_time) > srv_conf->waf_cc_deny_duration * 60.0) {
                HASH_DEL(srv_conf->ipv4_times, hash_item);
            }
            else {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "CC-DENY");
                strcpy((char*)ctx->rule_deatils, "");
                *out_http_status = NGX_HTTP_SERVICE_UNAVAILABLE;
                return MATCHED;
            }
        }
        else {
            if (difftime(now, hash_item->start_time) > 60.0) {
                HASH_DEL(srv_conf->ipv4_times, hash_item);
            }
            else {
                ++(hash_item->times);
            }
        }
    }
    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_white_url(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_str_t* puri = &r->uri;
    ngx_regex_elt_t* p = srv_conf->white_url->elts;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_URL) == FALSE) {
        return NOT_MATCHED;
    }

    for (size_t i = 0; i < srv_conf->white_url->nelts; i++, p++) {
        ngx_int_t rc = ngx_regex_exec(p->regex, puri, NULL, 0);
        if (rc >= 0) {
            ctx->blocked = FALSE;
            strcpy((char*)ctx->rule_type, "WHITE-URL");
            strcpy((char*)ctx->rule_deatils, (char*)p->name);
            *out_http_status = NGX_DECLINED;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_black_url(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_str_t* puri = &r->uri;
    ngx_regex_elt_t* p = srv_conf->black_url->elts;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_URL) == FALSE) {
        return NOT_MATCHED;
    }

    for (size_t i = 0; i < srv_conf->black_url->nelts; i++, p++) {
        ngx_int_t rc = ngx_regex_exec(p->regex, puri, NULL, 0);
        if (rc >= 0) {
            ctx->blocked = TRUE;
            strcpy((char*)ctx->rule_type, "BLACK-URL");
            strcpy((char*)ctx->rule_deatils, (char*)p->name);
            *out_http_status = NGX_HTTP_FORBIDDEN;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_black_args(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);


    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_ARGS) == FALSE) {
        return NOT_MATCHED;
    }

    if (r->args.len == 0) {
        return NOT_MATCHED;
    }

    ngx_str_t* pargs = &r->args;
    ngx_regex_elt_t* p = srv_conf->black_args->elts;

    for (size_t i = 0; i < srv_conf->black_args->nelts; i++, p++) {
        ngx_int_t rc = ngx_regex_exec(p->regex, pargs, NULL, 0);
        if (rc >= 0) {
            ctx->blocked = TRUE;
            strcpy((char*)ctx->rule_type, "BLACK-ARGS");
            strcpy((char*)ctx->rule_deatils, (char*)p->name);
            *out_http_status = NGX_HTTP_FORBIDDEN;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_black_user_agent(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_UA) == FALSE) {
        return NOT_MATCHED;
    }

    if (r->headers_in.user_agent == NULL) {
        return NOT_MATCHED;
    }

    ngx_str_t* pua = &r->headers_in.user_agent->value;
    ngx_regex_elt_t* p = srv_conf->black_ua->elts;

    for (size_t i = 0; i < srv_conf->black_ua->nelts; i++, p++) {
        ngx_int_t rc = ngx_regex_exec(p->regex, pua, NULL, 0);
        if (rc >= 0) {
            ctx->blocked = TRUE;
            strcpy((char*)ctx->rule_type, "BLACK-USER-AGENT");
            strcpy((char*)ctx->rule_deatils, (char*)p->name);
            *out_http_status = NGX_HTTP_FORBIDDEN;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_white_referer(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_REFERER) == FALSE) {
        return NOT_MATCHED;
    }

    if (r->headers_in.referer == NULL) {
        return NOT_MATCHED;
    }

    ngx_str_t* preferer = &r->headers_in.referer->value;
    ngx_regex_elt_t* p = srv_conf->white_referer->elts;

    for (size_t i = 0; i < srv_conf->white_referer->nelts; i++, p++) {
        ngx_int_t rc = ngx_regex_exec(p->regex, preferer, NULL, 0);
        if (rc >= 0) {
            ctx->blocked = FALSE;
            strcpy((char*)ctx->rule_type, "WHITE-REFERER");
            strcpy((char*)ctx->rule_deatils, (char*)p->name);
            *out_http_status = NGX_DECLINED;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_black_referer(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_REFERER) == FALSE) {
        return NOT_MATCHED;
    }

    if (r->headers_in.referer == NULL) {
        return NOT_MATCHED;
    }

    ngx_str_t* preferer = &r->headers_in.referer->value;
    ngx_regex_elt_t* p = srv_conf->black_referer->elts;

    for (size_t i = 0; i < srv_conf->black_referer->nelts; i++, p++) {
        ngx_int_t rc = ngx_regex_exec(p->regex, preferer, NULL, 0);
        if (rc >= 0) {
            ctx->blocked = FALSE;
            strcpy((char*)ctx->rule_type, "BLACK-REFERER");
            strcpy((char*)ctx->rule_deatils, (char*)p->name);
            *out_http_status = NGX_HTTP_FORBIDDEN;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_black_cookie(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_COOKIE) == FALSE) {
        return NOT_MATCHED;
    }

    if (r->headers_in.cookies.nelts != 0) {
        ngx_regex_elt_t* p = srv_conf->black_cookie->elts;
        ngx_table_elt_t** ppcookie = r->headers_in.cookies.elts;
        size_t i = 0;
        for (; i < r->headers_in.cookies.nelts; i++, p++) {
            ngx_int_t rc = ngx_regex_exec(p->regex, &((*ppcookie)->value), NULL, 0);
            if (rc >= 0) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-COOKIE");
                strcpy((char*)ctx->rule_deatils, (char*)p->name);
                *out_http_status = NGX_HTTP_FORBIDDEN;
                return MATCHED;
            }
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_free_hash_table(ngx_http_request_t* r, ngx_http_waf_srv_conf_t* srv_conf) {
    hash_table_item_int_ulong_t* p = NULL;
    int count = 0;
    time_t now;
    switch (srv_conf->free_hash_table_step) {
    case 0:
        srv_conf->ipv4_times_old = srv_conf->ipv4_times;
        srv_conf->ipv4_times = NULL;
        srv_conf->ngx_pool_old = srv_conf->ngx_pool;
        srv_conf->ngx_pool = ngx_create_pool(sizeof(ngx_pool_t) + INITIAL_SIZE, srv_conf->ngx_log);
        ++(srv_conf->free_hash_table_step);
        return PROCESSING;
        break;
    case 1:
        now = time(NULL);
        if (srv_conf->ipv4_times_old_cur == NULL) {
            srv_conf->ipv4_times_old_cur = srv_conf->ipv4_times_old;
        }
        for (; srv_conf->ipv4_times_old_cur != NULL && count < 100; srv_conf->ipv4_times_old_cur = p->hh.next) {
            /* 判断当前的记录是否过期 */
            if (difftime(now, srv_conf->ipv4_times_old_cur->start_time) < srv_conf->waf_cc_deny_duration * 60.0) {
                /* 在新的哈希表中查找是否存在当前记录 */
                HASH_FIND_INT(srv_conf->ipv4_times, &srv_conf->ipv4_times_old_cur->key, p);
                if (p == NULL) {
                    /* 如果不存在则拷贝后插入到新的哈希表中 */
                    p = ngx_palloc(srv_conf->ngx_pool, sizeof(hash_table_item_int_ulong_t));
                    if (p == NULL) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_waf: MEM-ALLOC-ERROR");
                        return FAIL;
                    }
                    p->key = srv_conf->ipv4_times_old_cur->key;
                    p->start_time = srv_conf->ipv4_times_old_cur->start_time;
                    p->times = srv_conf->ipv4_times_old_cur->times;
                    HASH_ADD_INT(srv_conf->ipv4_times, key, p);
                }
                else {
                    /* 如果存在则合并更改 */
                    p->times += srv_conf->ipv4_times_old_cur->start_time;
                }
            }
        }
        if (p == NULL) {
            ++(srv_conf->free_hash_table_step);
        }
        return PROCESSING;
        break;
    case 2:
        HASH_CLEAR(hh, srv_conf->ipv4_times_old);
        ++(srv_conf->free_hash_table_step);
        return PROCESSING;
        break;
    case 3:
        ngx_destroy_pool(srv_conf->ngx_pool_old);
        srv_conf->ngx_pool_old = NULL;
        srv_conf->free_hash_table_step = 0;
        return PROCESSING;
        break;
    }
    return SUCCESS;
}


static void check_post(ngx_http_request_t* r) {
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


#endif
