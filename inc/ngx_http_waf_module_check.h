#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <ngx_inet.h>
#include "ngx_http_waf_module_macro.h"
#include "ngx_http_waf_module_type.h"
#include "uthash/src/uthash.h"
#ifndef __linux__
#include <io.h>
#include <winsock.h>
#else
#include <sys/io.h>
#endif

#ifndef NGX_HTTP_WAF_MODLULE_CHECK_H
#define NGX_HTTP_WAF_MODLULE_CHECK_H

extern ngx_module_t ngx_http_waf_module;


typedef ngx_int_t (*ngx_http_waf_check)(ngx_http_request_t* r, ngx_int_t* out_http_status);

/*
* 检查客户端 IPV4 地址是否在白名单中
* 如果在返回 MATCHED，返回 NOT_MATCHED
*/
static ngx_int_t ngx_http_waf_handler_check_white_ipv4(ngx_http_request_t* r, ngx_int_t* out_http_status);


/*
* 检查客户端 IPV4 地址是否在黑名单中
* 如果在返回 MATCHED，返回 NOT_MATCHED
*/
static ngx_int_t ngx_http_waf_handler_check_black_ipv4(ngx_http_request_t* r, ngx_int_t* out_http_status);


/*
* 检查客户端 IPV4 的访问频次是否超出了限制
* 如果超出限制返回 MATCHED，返回 NOT_MATCHED
*/
static ngx_int_t ngx_http_waf_handler_check_cc_ipv4(ngx_http_request_t* r, ngx_int_t* out_http_status);


/*
* 检查 URL 是否在白名单中
* 如果在返回 MATCHED，返回 NOT_MATCHED
*/
static ngx_int_t ngx_http_waf_handler_check_white_url(ngx_http_request_t* r, ngx_int_t* out_http_status);


/*
* 检查 URL 是否在黑名单中
* 如果在返回 MATCHED，返回 NOT_MATCHED
*/
static ngx_int_t ngx_http_waf_handler_check_black_url(ngx_http_request_t* r, ngx_int_t* out_http_status);


/*
* 检查请求参数是否在黑名单中
* 如果在返回 MATCHED，返回 NOT_MATCHED
*/
static ngx_int_t ngx_http_waf_handler_check_black_args(ngx_http_request_t* r, ngx_int_t* out_http_status);


/*
* 检查 UserAgent 参数是否在黑名单中
* 如果在返回 MATCHED，返回 NOT_MATCHED
*/
static ngx_int_t ngx_http_waf_handler_check_black_user_agent(ngx_http_request_t* r, ngx_int_t* out_http_status);


/*
* 检查 Referer 参数是否在白名单中
* 如果在返回 MATCHED，返回 NOT_MATCHED
*/
static ngx_int_t ngx_http_waf_handler_check_white_referer(ngx_http_request_t* r, ngx_int_t* out_http_status);


/*
* 检查 Referer 参数是否在黑名单中
* 如果在返回 MATCHED，返回 NOT_MATCHED
*/
static ngx_int_t ngx_http_waf_handler_check_black_referer(ngx_http_request_t* r, ngx_int_t* out_http_status);


/*
* 检查 Cookie 参数是否在黑名单中
* 如果在返回 MATCHED，返回 NOT_MATCHED
*/
static ngx_int_t ngx_http_waf_handler_check_black_cookie(ngx_http_request_t* r, ngx_int_t* out_http_status);


/*
* 检查两个 IPV4 是否属于同一网段
* 如果属于返回 MATCHED，返回 NOT_MATCHED
*/
static ngx_int_t ngx_http_waf_handler_check_ipv4(unsigned long ip, const ipv4_t* ipv4);


/*
* 逐渐释放旧的哈希表所占用的内存
* 第一阶段：备份现有的哈希表和现有的内存池，然后创建新的哈希表和内存池
* 第二阶段：逐渐将旧的哈希表中有用的内容转移到新的哈希表中。
* 第三阶段：清空旧的哈希表
* 第四阶段：销毁旧的内存池，完成释放。
* 如果成功返回 SUCCESS，如果还在释放中（第四阶段之前）返回 PROCESSING，如果出现错误返回 FAIL
*/
static ngx_int_t ngx_http_waf_free_hash_table(ngx_http_request_t* r, ngx_http_waf_srv_conf_t* srv_conf);


static ngx_int_t ngx_http_waf_handler_check_white_ipv4(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;

    if (srv_conf->waf_check_ipv4 == 0) {
        return NOT_MATCHED;
    }

    if (r->connection->sockaddr->sa_family == AF_INET) {
        unsigned long ipv4 = sin->sin_addr.s_addr;
        ipv4_t* p = srv_conf->white_ipv4->elts;
        size_t index = 0;
        for (; index < srv_conf->white_ipv4->nelts; index++, p++) {
            if (ngx_http_waf_handler_check_ipv4(ipv4, p) == MATCHED) {
                ctx->blocked = FALSE;
                strcpy((char*)ctx->rule_type, "WHITE-IPV4");
                strcpy((char*)ctx->rule_deatils, (char*)p->text);
                *out_http_status = NGX_DECLINED;
                return MATCHED;
            }
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_black_ipv4(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;

    if (srv_conf->waf_check_ipv4 == 0) {
        return NOT_MATCHED;
    }

    if (r->connection->sockaddr->sa_family == AF_INET) {
        unsigned long ipv4 = sin->sin_addr.s_addr;
        ipv4_t* p = srv_conf->black_ipv4->elts;
        size_t index = 0;
        for (; index < srv_conf->black_ipv4->nelts; index++, p++) {
            if (ngx_http_waf_handler_check_ipv4(ipv4, p) == MATCHED) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-IPV4");
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

    if (srv_conf->waf_cc_deny == 0 || srv_conf->waf_cc_deny == NGX_CONF_UNSET) {
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
        if (difftime(now, hash_item->start_time) >= srv_conf->waf_cc_deny_duration * 60.0) {
            HASH_DEL(srv_conf->ipv4_times, hash_item);
        }
        else {
            if (hash_item->times > (ngx_uint_t)srv_conf->waf_cc_deny_limit) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "CC-DENY");
                strcpy((char*)ctx->rule_deatils, "");
                *out_http_status = NGX_HTTP_SERVICE_UNAVAILABLE;
                return MATCHED;
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

    if (srv_conf->waf_check_url == 0) {
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

    if (srv_conf->waf_check_url == 0) {
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


    if (srv_conf->waf_check_args == 0) {
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

    if (srv_conf->waf_check_ua == 0) {
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

    if (srv_conf->waf_check_referer == 0) {
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

    if (srv_conf->waf_check_referer == 0) {
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

    if (srv_conf->waf_check_cookie == 0) {
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


static ngx_int_t ngx_http_waf_handler_check_ipv4(unsigned long ip, const ipv4_t* ipv4) {
    size_t prefix = ip & ipv4->suffix;

    if (prefix == ipv4->prefix) {
        return MATCHED;
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


#endif
