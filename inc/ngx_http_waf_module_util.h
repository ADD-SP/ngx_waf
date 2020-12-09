/**
 * @file ngx_http_waf_module_util.h
 * @brief IPV4 字符串解析，nginx 风格转化为 C 风格字符串。
*/

#ifndef NGX_HTTP_WAF_MODULE_UTIL_H
#define NGX_HTTP_WAF_MODULE_UTIL_H

#include "../inc/ngx_http_waf_module_macro.h"
#include "../inc/ngx_http_waf_module_type.h"

/**
 * @defgroup util 工具代码
 * @addtogroup util 工具代码
 * @brief IPV4 字符串解析，nginx 风格转化为 C 风格字符串。
 * @{
*/

/**
 * @brief 将一个字符串形式的 IPV4 地址转化为 ipv4_t。
 * @param[in] text 要转换的字符串
 * @param[out] ipv4 转换完成后的格式化的 ipv4
 * @return 成功返回 SUCCESS，失败返回 FAIL。
 * @retval SUCCESS 转换成功
 * @retval FAIL 转化错误
*/
static ngx_int_t parse_ipv4(ngx_str_t text, ipv4_t* ipv4);

/**
 * @brief 将 ngx_str 转化为 C 风格的字符串
 * @param[out] destination 存储 C 风格字符串的字符数组
 * @param[in] ngx_str 要转换的 nginx 风格的字符串
 * @return 转换成功则返回 C 风格字符串的结尾的 '\0' 的地址，反之返回 NULL。
 * @retval !NULL C 风格字符串的结尾的 '\0' 的地址
 * @retval NULL 转换失败
*/
static char* to_c_str(u_char* destination, ngx_str_t ngx_str);

/**
 * @}
*/

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

static char* to_c_str(u_char* destination, ngx_str_t ngx_str) {
    if (ngx_str.len > RULE_MAX_LEN) {
        return NULL;
    }
    memcpy(destination, ngx_str.data, ngx_str.len);
    destination[ngx_str.len] = '\0';
    return (char*)destination + ngx_str.len;
}

#endif