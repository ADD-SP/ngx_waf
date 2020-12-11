/**
 * @file ngx_http_waf_module_util.h
 * @brief IPV4 字符串解析，nginx 风格转化为 C 风格字符串。
*/

#ifndef NGX_HTTP_WAF_MODULE_UTIL_H
#define NGX_HTTP_WAF_MODULE_UTIL_H

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>

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
 * @brief 将一个字符串形式的 IPV6 地址转化为 ipv6_t。
 * @param[in] text 要转换的字符串
 * @param[out] ipv6 转换完成后的格式化的 ipv6
 * @return 成功返回 SUCCESS，失败返回 FAIL。
 * @retval SUCCESS 转换成功
 * @retval FAIL 转化错误
*/
static ngx_int_t parse_ipv6(ngx_str_t text, ipv6_t* ipv6);

/**
 * @brief 检查两个 IPV4 是否属于同一网段
 * @param[in] ip 整型格式的 IPV4
 * @param[in] ipv4 格式化后的 IPV4
 * @return 如果属于同一网段返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 属于同一网段。
 * @retval NOT_MATCHED 不属于同一网段。
*/
static ngx_int_t ipv4_netcmp(uint32_t ip, const ipv4_t* ipv4);

/**
 * @brief 检查两个 IPV6 是否属于同一网段
 * @param[in] ip 整型格式的 IPV6
 * @param[in] ipv6 格式化后的 IPV6
 * @return 如果属于同一网段返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 属于同一网段。
 * @retval NOT_MATCHED 不属于同一网段。
*/
static ngx_int_t ipv6_netcmp(uint8_t ip[16], const ipv6_t* ipv6);

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
    uint32_t prefix = 0;
    uint32_t suffix = 0;
    memcpy(ipv4->text, text.data, text.len);
    ipv4->text[text.len] = '\0';

    u_char* c = ipv4->text;
    ngx_uint_t prefix_len = 0;
    while (*c !='\0' && *c != '/') {
        ++prefix_len;
        ++c;
    }

    char prefix_text[32];
    struct in_addr addr4;
    if (*c =='\0' && prefix_len == text.len) {
        memcpy(prefix_text, ipv4->text, prefix_len);
        prefix_text[prefix_len] = '\0';
    } 
    else if (*c == '/' && prefix_len >= 7) {
        /* 0.0.0.0 的长度刚好是 7 */
        memcpy(prefix_text, ipv4->text, prefix_len);
        prefix_text[prefix_len] = '\0';
    } 
    else {
        return FAIL;
    }

    if (inet_pton(AF_INET, prefix_text, &addr4) != 1) {
        return FAIL;
    }
    prefix = addr4.s_addr;

    if (*c == '/') {
        ++c;
    }
    while (*c != '\0') {
        suffix = suffix * 10 + (*c - '0');
        ++c;
    }
    if (suffix == 0) {
        suffix = 32;
    }

    uint8_t temp_suffix[4] = { 0 };
    for (int i = 0; i < 4; i++) {
        uint8_t temp = 0;
        if (suffix >= 8) {
            suffix -=8;
            temp = ~0;
        } 
        else {
            for (uint32_t j = 0; j < suffix; j++) {
                temp |= 0x80 >> j;
            }
            suffix = 0;
        }
        temp_suffix[i] = temp;
    }

    suffix = 0;
    for (int i = 0; i < 4; i++) {
        suffix |= ((uint32_t)temp_suffix[i]) << (i * 8);
    }

    ipv4->prefix = prefix & suffix;
    ipv4->suffix = suffix;

    return SUCCESS;
}

static ngx_int_t parse_ipv6(ngx_str_t text, ipv6_t* ipv6) {
    uint8_t prefix[16] = { 0 };
    uint8_t suffix[16] = { 0 };
    
    memcpy(ipv6->text, text.data, text.len);

    ipv6->text[text.len] = '\0';

    u_char* c = ipv6->text;
    ngx_uint_t prefix_len = 0;
    while (*c !='\0' && *c != '/') {
        ++prefix_len;
        ++c;
    }

    char prefix_text[64];
    struct in6_addr addr6;
    if (*c =='\0' && prefix_len == text.len) {
        memcpy(prefix_text, ipv6->text, prefix_len);
        prefix_text[prefix_len] = '\0';
    } 
    else if (*c == '/' && prefix_len >= 2) {
        /* :: 的长度刚好是 2，此 IPV6 地址代表全零 */
        memcpy(prefix_text, ipv6->text, prefix_len);
        prefix_text[prefix_len] = '\0';
    } 
    else {
        return FAIL;
    }

    if (inet_pton(AF_INET6, prefix_text, &addr6) != 1) {
        return FAIL;
    }
    memcpy(prefix, &addr6.__in6_u.__u6_addr8, 16);

    uint32_t temp_suffix = 0;
    if (*c == '/') {
        ++c;
    }
    while (*c != '\0') {
        temp_suffix = temp_suffix * 10 + (*c - '0');
        ++c;
    }
    if (temp_suffix == 0) {
        temp_suffix = 128;
    }

    for (int i = 0; i < 16; i++) {
        uint8_t temp = 0;
        if (temp_suffix >= 8) {
            temp_suffix -=8;
            temp = ~0;
        } 
        else {
            for (uint32_t j = 0; j < temp_suffix; j++) {
                temp |= 0x80 >> j;
            }
            temp_suffix = 0;
        }
        suffix[i] = temp;
    }

    for (int i = 0; i < 16; i++) {
        prefix[i] &= suffix[i];
    }

    memcpy(ipv6->prefix, prefix, 16);
    memcpy(ipv6->suffix, suffix, 16);

    return SUCCESS;
}

static ngx_int_t ipv4_netcmp(uint32_t ip, const ipv4_t* ipv4) {
    size_t prefix = ip & ipv4->suffix;

    if (prefix == ipv4->prefix) {
        return MATCHED;
    }

    return NOT_MATCHED;
}

static ngx_int_t ipv6_netcmp(uint8_t ip[16], const ipv6_t* ipv6) {
    uint8_t temp_ip[16];

    memcpy(temp_ip, ip, 16);

    for (int i = 0; i < 16; i++) {
        temp_ip[i] &= ipv6->suffix[i];
    }

    if (memcmp(temp_ip, ipv6->prefix, 16) != 0) {
        return NOT_MATCHED;
    }

    return MATCHED;
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