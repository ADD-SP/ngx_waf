#ifndef NGX_HTTP_WAF_MODULE_MACRO_H
#define NGX_HTTP_WAF_MODULE_MACRO_H

/* 对应配置文件的文件名 */
#define IPV4_FILE ("ipv4")
#define URL_FILE ("url")
#define ARGS_FILE ("args")
#define UA_FILE ("user-agent")
#define REFERER_FILE ("referer")
#define COOKIE_FILE ("cookie")
#define POST_FILE ("post")
#define WHITE_IPV4_FILE ("white-ipv4")
#define WHITE_URL_FILE ("white-url")
#define WHITE_REFERER_FILE ("white-referer")

#define SUCCESS (1)
#define PROCESSING (2)
#define FAIL (0)
#define TRUE (1)
#define FALSE (0)
#define MATCHED (1)
#define NOT_MATCHED (0)


#define RULE_MAX_LEN (256 * 4 * 8)
#define INITIAL_SIZE (1024 * 1024 * 5)

/* 检查对应文件是否存在，如果存在则根据 mode 的值将数据处理后存入数组中 */
#define CHECK_AND_LOAD_CONF(cf, buf, end, filename, ngx_array, mode) {                                      \
strcat((buf), (filename));                                                                                  \
    if (access((buf), 2) != 0 || load_into_array((cf), (buf), (ngx_array), (mode)) == FAIL) {               \
        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, "ngx_waf: %s: %s", (buf), "No such file or directory");    \
        return NGX_CONF_ERROR;                                                                              \
    }                                                                                                       \
    *(end) = '\0';                                                                                          \
}


#endif // !NGX_HTTP_WAF_MODULE_MACRO_H
