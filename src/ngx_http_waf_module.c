#include <stdio.h>
#include "../inc/ngx_http_waf_module.h"
#include "../inc/uthash/src/uthash.h"
#include <time.h>
#include <math.h>
#ifndef __linux__
#include <io.h>
#include <winsock.h>
#else
#include <sys/io.h>
#endif


static ngx_command_t ngx_http_waf_commands[] = {

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

    CHECK_AND_LOAD_CONF(cf, full_path, end, IPV4_FILE, srv_conf->block_ipv4, 1);
    CHECK_AND_LOAD_CONF(cf, full_path, end, URL_FILE, srv_conf->block_url, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, ARGS_FILE, srv_conf->block_args, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, UA_FILE, srv_conf->block_ua, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, REFERER_FILE, srv_conf->block_referer, 0);
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
    srv_conf->block_ipv4 = ngx_array_create(cf->pool, 10, sizeof(ipv4_t));
    srv_conf->block_url = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->block_args = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->block_ua = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->block_referer = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->white_ipv4 = ngx_array_create(cf->pool, 10, sizeof(ipv4_t));
    srv_conf->white_url = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->white_referer = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->ipv4_times = NULL;

    if (srv_conf->ngx_log == NULL
        || srv_conf->ngx_pool == NULL
        || srv_conf->block_ipv4 == NULL
        || srv_conf->block_url == NULL
        || srv_conf->block_args == NULL
        || srv_conf->block_ua == NULL
        || srv_conf->block_referer == NULL
        || srv_conf->white_ipv4 == NULL
        || srv_conf->white_url == NULL
        || srv_conf->white_referer == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
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
    *h = ngx_http_waf_handler;

    return NGX_OK;
}


static ngx_int_t ngx_http_waf_handler(ngx_http_request_t* r) {
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (srv_conf->ngx_waf == 0 || srv_conf->ngx_waf == NGX_CONF_UNSET) {
        return NGX_DECLINED;
    }

    struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
    unsigned long ipv4 = 0;
    /* struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr; */
    switch (r->connection->sockaddr->sa_family) {
    case AF_INET:
        ipv4 = sin->sin_addr.s_addr;
        if (check_ipv4(ipv4, srv_conf->white_ipv4) == SUCCESS) {
            return NGX_DECLINED;
        }
        break;

    }

    switch (r->connection->sockaddr->sa_family) {
    case AF_INET:
        if (check_ipv4(ipv4, srv_conf->block_ipv4) == SUCCESS) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: IP");
            return NGX_HTTP_FORBIDDEN;
        }
        if (check_cc_ipv4(r, srv_conf, ipv4) == SUCCESS) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: CC-DENY");
            return NGX_HTTP_FORBIDDEN;
        }
        break;

    }

    if (ngx_regex_exec_array(srv_conf->white_url, &r->uri, r->connection->log) == NGX_OK) {
        return NGX_DECLINED;
    }

    if (ngx_regex_exec_array(srv_conf->block_url, &r->uri, r->connection->log) == NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: URL");
        return NGX_HTTP_FORBIDDEN;
    }

    if (r->args.len != 0
        && ngx_regex_exec_array(srv_conf->block_args, &r->args, r->connection->log) == NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: ARGS");
        return NGX_HTTP_FORBIDDEN;
    }

    if (ngx_regex_exec_array(srv_conf->block_ua, &r->headers_in.user_agent->value, r->connection->log) == NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx_waf: USER-AGENT");
        return NGX_HTTP_FORBIDDEN;
    }

    if (r->headers_in.referer != NULL
        && ngx_regex_exec_array(srv_conf->white_referer, &r->headers_in.referer->value, r->connection->log) == NGX_OK) {
        return NGX_DECLINED;
    }
    if (r->headers_in.referer != NULL
        && ngx_regex_exec_array(srv_conf->block_referer, &r->headers_in.referer->value, r->connection->log) == NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx_waf: REFERER");
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_DECLINED;
}


static ngx_int_t check_cc_ipv4(ngx_http_request_t* r, ngx_http_waf_srv_conf_t* srv_conf, unsigned long ipv4) {
    if (srv_conf->ngx_waf_cc_deny == 0 || srv_conf->ngx_waf_cc_deny == NGX_CONF_UNSET) {
        return FAIL;
    }
    if (srv_conf->ngx_waf_cc_deny_limit == NGX_CONF_UNSET
        || srv_conf->ngx_waf_cc_deny_duration == NGX_CONF_UNSET) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_waf: CC-DENY-CONF-INVALID");
        return FAIL;
    }
    if (srv_conf->alloc_times > 55000) {
        ngx_int_t ret = free_hash_table(r, srv_conf);
        if (ret == SUCCESS || ret == FAIL) {
            srv_conf->alloc_times = 0;
        }
    }

    hash_table_item_int_ulong_t* hash_item = NULL;
    time_t now = time(NULL);
    HASH_FIND_INT(srv_conf->ipv4_times, (int*)(&ipv4), hash_item);
    if (hash_item == NULL) {
        hash_item = ngx_palloc(srv_conf->ngx_pool, sizeof(hash_table_item_int_ulong_t));
        if (hash_item == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_waf: MEM-ALLOC-ERROR");
            return FAIL;
        }
        ++(srv_conf->alloc_times);
        hash_item->times = 1;
        hash_item->start_time = now;
        hash_item->key = ipv4;
        HASH_ADD_INT(srv_conf->ipv4_times, key, hash_item);
    }
    else {
        if (difftime(now, hash_item->start_time) >= srv_conf->ngx_waf_cc_deny_duration * 60.0) {
            HASH_DEL(srv_conf->ipv4_times, hash_item);
        }
        else {
            if (hash_item->times > (ngx_uint_t)srv_conf->ngx_waf_cc_deny_limit) {
                return SUCCESS;
            }
            else {
                ++(hash_item->times);
            }
        }
    }
    return FAIL;
}


static ngx_int_t free_hash_table(ngx_http_request_t* r, ngx_http_waf_srv_conf_t* srv_conf) {
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
        for (;srv_conf->ipv4_times_old_cur != NULL && count < 100; srv_conf->ipv4_times_old_cur = p->hh.next) {
            /* 判断当前的记录是否过期 */
            if (difftime(now, srv_conf->ipv4_times_old_cur->start_time) < srv_conf->ngx_waf_cc_deny_duration * 60.0) {
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


static ngx_int_t parse_ipv4(ngx_str_t text, ipv4_t* ipv4) {
    size_t prefix = 0;
    size_t num = 0;
    size_t suffix = ~(size_t)0;
    u_char c;
    int is_in_suffix = FALSE;
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
    ipv4->prefix = prefix;
    ipv4->suffix = suffix;
    return SUCCESS;
}


static ngx_int_t check_ipv4(unsigned long ip, ngx_array_t* a) {
    ipv4_t* ipv4 = NULL;
    size_t i;
    for (ipv4 = a->elts, i = 0; i < a->nelts; i++) {
        size_t prefix = ip & ipv4->suffix;
        if (prefix == ipv4->prefix) {
            return SUCCESS;
        }
    }
    return FALSE;
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
            ngx_regex_elt->name = rc.names;
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
    if (ngx_str.len > 255) {
        return FAIL;
    }
    for (size_t i = 0; i < ngx_str.len; i++) {
        destination[i] = ngx_str.data[i];
    }
    destination[ngx_str.len] = '\0';
    return (char*)destination + ngx_str.len;
}