#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <ngx_inet.h>
#include <sys/io.h>
#include <stdio.h>

/* 对应配置文件的文件名 */
#define IPV4_FILE ("ipv4")
#define URL_FILE ("url")
#define ARGS_FILE ("args")
#define UA_FILE ("user-agent")
#define REFERER_FILE ("referer")
#define WHITE_IPV4_FILE ("white-ipv4")
#define WHITE_URL_FILE ("white-url")
#define WHITE_REFERER_FILE ("white-referer")

#define SUCCESS (1)
#define FAIL (0)
#define TRUE (1)
#define FALSE (0)

/* 检查对应文件是否存在，如果存在则根据 mode 的值将数据处理后存入数组中 */
#define CHECK_AND_LOAD_CONF(cf, buf, end, filename, ngx_array, mode) { \
strcat(buf, filename); \
    if (access(buf, 2) != 0 || load_into_array(cf, buf, ngx_array, mode) == FAIL) { \
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_waf: %s: %s", buf, "No such file or directory"); \
        return NGX_CONF_ERROR; \
    } \
    *end = '\0'; \
}

typedef unsigned char u_char;

typedef struct {
    ngx_int_t ngx_waf;
    ngx_str_t ngx_waf_rule_path;
    ngx_array_t* block_ipv4;
    ngx_array_t* block_url;
    ngx_array_t* block_args;
    ngx_array_t* block_ua;
    ngx_array_t* block_referer;
    ngx_array_t* white_ipv4;
    ngx_array_t* white_url;
    ngx_array_t* white_referer;
}ngx_http_waf_srv_conf_t;

typedef struct {
    size_t prefix;
    size_t suffix;
}ngx_ipv4_t;

static char* ngx_http_waf_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static char* ngx_http_waf_rule_path_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);


static ngx_int_t ngx_http_waf_init_after_load_config(ngx_conf_t* cf);


static void* ngx_http_waf_create_srv_conf(ngx_conf_t* cf);


static ngx_int_t ngx_http_waf_handler(ngx_http_request_t* r);

/*
* 将一个字符串形式的 IPV4 地址转化为 ngx_ipv4_t
* 合法的字符串只有类似 192.168.1.1 和 1.1.1.0/24 这两种形式
* 如果成功则返回 SUCCESS，反之返回 FALI
*/
static ngx_int_t parse_ipv4(ngx_str_t text, ngx_ipv4_t* ipv4);

/*
* 检查 ip 是否属于数组中的某个 ipv4 地址
* 第二个参数是一个元素类型为 ngx_ipv4_t 的数组
* 如果匹配到返回 SUCCESS，反之返回 FAIL
*/
static ngx_int_t check_ipv4(unsigned long ip, ngx_array_t* a);

/* 将 ngx_str 转化为 C 风格的字符串 */
static char* to_c_str(u_char* destination, ngx_str_t ngx_str);

/*
* 读取指定文件的内容到数组中
* 当 mode = 0 时会将读取到文本编译成正则表达式再存储
* 当 mode = 1 时会将读取到的文本转化为 ngx_ipv4_t 再存储
* 如果成功则返回 SUCCESS，反之返回 FAIL
*/
static ngx_int_t load_into_array(ngx_conf_t* cf, const char* file_name, ngx_array_t* ngx_array, ngx_int_t mode);


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
    ngx_conf_set_flag_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}


static char* ngx_http_waf_rule_path_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_srv_conf_t* srv_conf = conf;
    if (ngx_conf_set_str_slot(cf, cmd, conf) != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_waf: %s", "The path of the config file is not specified");
        return NGX_CONF_ERROR;
    }

    srv_conf->block_ipv4 = ngx_array_create(cf->pool, 10, sizeof(ngx_ipv4_t));
    srv_conf->block_url = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->block_args = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->block_ua = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->block_referer = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->white_ipv4 = ngx_array_create(cf->pool, 10, sizeof(ngx_ipv4_t));
    srv_conf->white_url = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));
    srv_conf->white_referer = ngx_array_create(cf->pool, 10, sizeof(ngx_regex_elt_t));

    char full_path[256 * 4 * 8];
    char* end = to_c_str((u_char*)full_path, srv_conf->ngx_waf_rule_path);

    CHECK_AND_LOAD_CONF(cf, full_path, end, IPV4_FILE, srv_conf->block_ipv4, 1);
    CHECK_AND_LOAD_CONF(cf, full_path, end, URL_FILE, srv_conf->block_url, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, ARGS_FILE, srv_conf->block_args, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, UA_FILE, srv_conf->block_ua, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, REFERER_FILE, srv_conf->block_referer, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, WHITE_IPV4_FILE, srv_conf->white_ipv4, 1);
    CHECK_AND_LOAD_CONF(cf, full_path, end, WHITE_URL_FILE, srv_conf->white_url, 0);
    CHECK_AND_LOAD_CONF(cf, full_path, end, WHITE_REFERER_FILE, srv_conf->white_referer, 0);

    return NGX_CONF_OK;
}


static void* ngx_http_waf_create_srv_conf(ngx_conf_t* cf) {
    ngx_http_waf_srv_conf_t* main_conf = NULL;
    main_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_srv_conf_t));
    if (main_conf == NULL) {
        return NULL;
    }
    ngx_str_null(&main_conf->ngx_waf_rule_path);
    main_conf->ngx_waf = NGX_CONF_UNSET;

    return main_conf;
}


static ngx_int_t ngx_http_waf_init_after_load_config(ngx_conf_t* cf) {
    ngx_http_handler_pt* h;
    ngx_http_core_main_conf_t* cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
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
    /* struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr; */
    switch (r->connection->sockaddr->sa_family) {
    case AF_INET:
        if (check_ipv4(sin->sin_addr.s_addr, srv_conf->white_ipv4) == SUCCESS) {
            return NGX_DECLINED;
        }
        break;

    }

    if (ngx_regex_exec_array(srv_conf->white_url, &r->uri, r->connection->log) == NGX_OK) {
        return NGX_DECLINED;
    }

    if (r->headers_in.referer != NULL 
        && ngx_regex_exec_array(srv_conf->white_referer, &r->headers_in.referer->value, r->connection->log) == NGX_OK) {
        return NGX_DECLINED;
    }


    switch (r->connection->sockaddr->sa_family) {
    case AF_INET:
        if (check_ipv4(sin->sin_addr.s_addr, srv_conf->block_ipv4) == SUCCESS) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx_waf: IP");
            return NGX_HTTP_FORBIDDEN;
        }
        break;

    }

    if (ngx_regex_exec_array(srv_conf->block_url, &r->uri, r->connection->log) == NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx_waf: URL");
        return NGX_HTTP_FORBIDDEN;
    }

    if (r->args.len != 0 
        && ngx_regex_exec_array(srv_conf->block_args, &r->args, r->connection->log) == NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: ARGS");
        return NGX_HTTP_FORBIDDEN;
    }

    if (r->headers_in.referer != NULL 
        && ngx_regex_exec_array(srv_conf->block_referer, &r->headers_in.referer->value, r->connection->log) == NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx_waf: REFERER");
        return NGX_HTTP_FORBIDDEN;
    }

    if (ngx_regex_exec_array(srv_conf->block_ua, &r->headers_in.user_agent->value, r->connection->log) == NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx_waf: USER-AGENT");
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_DECLINED;
}


static ngx_int_t parse_ipv4(ngx_str_t text, ngx_ipv4_t* ipv4) {
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
            } else {
                num = num * 10 + (c - '0');
            }
        } else if (c == '/') {
            is_in_suffix = TRUE;
            suffix = 0;
        } else if (c == '.') {
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
    ngx_ipv4_t* ipv4;
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
    char str[256 * 4 * 8];
    if (fp == NULL) {
        return FAIL;
    }
    while (fgets(str, 256 * 4 * 8, fp) != NULL) {
        ngx_regex_compile_t   rc;
        u_char                errstr[NGX_MAX_CONF_ERRSTR];
        ngx_regex_elt_t* ngx_regex_elt;
        ngx_ipv4_t* ngx_ipv4;

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
            ngx_ipv4 = ngx_array_push(ngx_array);
            parse_ipv4(line, ngx_ipv4);
            break;
        }
    }
    fclose(fp);
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