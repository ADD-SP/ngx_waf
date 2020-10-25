#ifndef NGX_HTTP_WAF_MODULE_MACRO_H
#define NGX_HTTP_WAF_MODULE_MACRO_H

/* 对应配置文件的文件名 */
#define IPV4_FILE               ("ipv4")
#define URL_FILE                ("url")
#define ARGS_FILE               ("args")
#define UA_FILE                 ("user-agent")
#define REFERER_FILE            ("referer")
#define COOKIE_FILE             ("cookie")
#define POST_FILE               ("post")
#define WHITE_IPV4_FILE         ("white-ipv4")
#define WHITE_URL_FILE          ("white-url")
#define WHITE_REFERER_FILE      ("white-referer")

#ifndef FALSE
#define FALSE                   (0)
#endif
#ifndef TRUE
#define TRUE                    (1)
#endif

#define SUCCESS                 (1)
#define PROCESSING              (2)
#define FAIL                    (0)
#define MATCHED                 (1)
#define NOT_MATCHED             (0)


#define RULE_MAX_LEN            (256 * 4 * 8)
#define INITIAL_SIZE            (1024 * 1024 * 5)


/* 防火墙的工作模式 */
#define MODE_INSPECT_GET                        NGX_HTTP_GET
#define MODE_INSPECT_HEAD                       NGX_HTTP_HEAD
#define MODE_INSPECT_POST                       NGX_HTTP_POST
#define MODE_INSPECT_PUT                        NGX_HTTP_PUT
#define MODE_INSPECT_DELETE                     NGX_HTTP_DELETE
#define MODE_INSPECT_MKCOL                      NGX_HTTP_MKCOL
#define MODE_INSPECT_COPY                       NGX_HTTP_COPY
#define MODE_INSPECT_MOVE                       NGX_HTTP_MOVE
#define MODE_INSPECT_OPTIONS                    NGX_HTTP_OPTIONS
#define MODE_INSPECT_PROPFIND                   NGX_HTTP_PROPFIND
#define MODE_INSPECT_PROPPATCH                  NGX_HTTP_PROPPATCH
#define MODE_INSPECT_LOCK                       NGX_HTTP_LOCK
#define MODE_INSPECT_UNLOCK                     NGX_HTTP_UNLOCK
#define MODE_INSPECT_PATCH                      NGX_HTTP_PATCH
#define MODE_INSPECT_TRACE                      NGX_HTTP_TRACE
#define MODE_INSPECT_IP                         (MODE_INSPECT_TRACE << 1)
#define MODE_INSPECT_URL                        (MODE_INSPECT_IP << 1)
#define MODE_INSPECT_RB                         (MODE_INSPECT_URL << 1)
#define MODE_INSPECT_ARGS                       (MODE_INSPECT_RB << 1)
#define MODE_INSPECT_UA                         (MODE_INSPECT_ARGS << 1)
#define MODE_INSPECT_COOKIE                     (MODE_INSPECT_UA << 1)
#define MODE_INSPECT_REFERER                    (MODE_INSPECT_COOKIE << 1)
#define MODE_INSPECT_CC                         (MODE_INSPECT_REFERER << 1)
#define MODE_STD                                (MODE_INSPECT_IP            \
                                                | MODE_INSPECT_URL          \
                                                | MODE_INSPECT_RB           \
                                                | MODE_INSPECT_ARGS         \
                                                | MODE_INSPECT_UA           \
                                                | MODE_INSPECT_GET          \
                                                | MODE_INSPECT_POST         \
                                                | MODE_INSPECT_CC)
#define MODE_FULL                               (MODE_INSPECT_IP            \
                                                | MODE_INSPECT_URL          \
                                                | MODE_INSPECT_RB           \
                                                | MODE_INSPECT_ARGS         \
                                                | MODE_INSPECT_UA           \
                                                | MODE_INSPECT_COOKIE       \
                                                | MODE_INSPECT_REFERER      \
                                                | MODE_INSPECT_GET          \
                                                | MODE_INSPECT_POST         \
                                                | MODE_INSPECT_HEAD         \
                                                | MODE_INSPECT_PUT          \
                                                | MODE_INSPECT_DELETE       \
                                                | MODE_INSPECT_MKCOL        \
                                                | MODE_INSPECT_COPY         \
                                                | MODE_INSPECT_PROPFIND     \
                                                | MODE_INSPECT_PROPPATCH    \
                                                | MODE_INSPECT_LOCK         \
                                                | MODE_INSPECT_UNLOCK       \
                                                | MODE_INSPECT_PATCH        \
                                                | MODE_INSPECT_TRACE        \
                                                | MODE_INSPECT_CC)


/* 检查对应文件是否存在，如果存在则根据 mode 的值将数据处理后存入数组中 */
#define CHECK_AND_LOAD_CONF(cf, buf, end, filename, ngx_array, mode) {                                      \
strcat((buf), (filename));                                                                                  \
    if (access((buf), 2) != 0) {                                                                            \
        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, "ngx_waf: %s: %s", (buf), "No such file or directory");    \
        return NGX_CONF_ERROR;                                                                              \
    }                                                                                                       \
    if (load_into_array((cf), (buf), (ngx_array), (mode)) == FAIL) {                                        \
        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, "ngx_waf: %s: %s", (buf), "Contains illegal format");      \
    }                                                                                                       \
    *(end) = '\0';                                                                                          \
}

#define CHECK_FLAG(origin, flag) (((origin) & (flag)) != 0 ? TRUE : FALSE)


#endif // !NGX_HTTP_WAF_MODULE_MACRO_H
