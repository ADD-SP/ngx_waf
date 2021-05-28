/**
 * @file ngx_http_waf_module_util.h
 * @brief IPV4 字符串解析，nginx 风格转化为 C 风格字符串。
*/

#ifndef NGX_HTTP_WAF_MODULE_UTIL_H
#define NGX_HTTP_WAF_MODULE_UTIL_H

#include <utarray.h>
#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <sodium.h>

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
 * @brief 将一个形如 10s 10m 10h 10d 这样的字符串转化为整数，单位是秒。
 * @param[in] str 要解析的字符串
 * @return 失败返回 NGX_ERROR，反之则不是。
*/
static ngx_int_t parse_time(u_char* str);


/**
 * @brief 将一个形如 10k 10m 10g 这样的字符串转化为整数，单位是字节。
 * @param[in] str 要解析的字符串
 * @return 失败返回 NGX_ERROR，反之则不是。
*/
static ngx_int_t parse_size(u_char* str);


/**
 * @brief 将一个 Cookie 字符串分割为一个一个的键值对。
 * @param[in] cookies 字符串形式的 Cookie
 * @param[out] array 保存解析结果的数组
 * @return 成功则返回 SUCCESS，反之则不是。
 * @note 数组内容格式为 [key, value, key, value, ......]
 * @warning 使用完毕后请自行释放数组所占用内存。
*/
static ngx_int_t parse_cookie(ngx_str_t* native_cookie, UT_array** array);


/**
 * @brief 字符串分割
 * @param[in] str 要分割的字符串
 * @param[in] sep 分隔符
 * @param[out] max_len 分割后单个字符串的最大长度
 * @param[out] array 存放分割结果的数组
 * @return 成功则返回 SUCCESS，反之则不是。
 * @warning 使用完毕后请自行释放数组所占用内存。
*/ 
static ngx_int_t ngx_str_split(ngx_str_t* str, u_char sep, size_t max_len, UT_array** array);


/**
 * @brief 字符串分割
 * @param[in] str 要分割的字符串
 * @param[in] sep 分隔符
 * @param[out] max_len 分割后单个字符串的最大长度
 * @param[out] array 存放分割结果的数组
 * @return 成功则返回 SUCCESS，反之则不是。
 * @warning 使用完毕后请自行释放数组所占用内存。
*/ 
// static ngx_int_t str_split(u_char* str, u_char sep, size_t max_len, UT_array** array);


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
 * @brief 生成一个 C 风格的随机字符串
 * @param[out] dest 存储 C 风格字符串的字符数组
 * @param[in] len 要生成的字符串的长度，不包含结尾的 \0 。
 * @return 成功返回 NGX_HTTP_WAF_SUCCESS，反之则不是。
*/
static ngx_int_t rand_str(u_char* dest, size_t len);


/**
 * @brief 计算 SHA256 并返回 16 进制字符串。
 * @param[out] dst 存储 SHA256 字符串的缓冲区
 * @param[in] dst_len 不包含结尾的 \0
 * @param[in] buf 用来计算数据所在的缓冲区
 * @param[in] buf_len 缓冲区长度
 * @return 成功返回 NGX_HTTP_WAF_SUCCESS，反之则不是。
*/
static ngx_int_t sha256(u_char* dst, size_t dst_len, const u_char* buf, size_t buf_len);


void utarray_ngx_str_ctor(void *dst, const void *src);


void utarray_ngx_str_dtor(void* elt);


/**
 * @}
*/

static ngx_int_t parse_ipv4(ngx_str_t text, ipv4_t* ipv4) {
    uint32_t prefix = 0;
    uint32_t suffix = 0;
    uint32_t suffix_num = 0;

    if (ipv4 == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    ngx_memcpy(ipv4->text, text.data, text.len);
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
        ngx_memcpy(prefix_text, ipv4->text, prefix_len);
        prefix_text[prefix_len] = '\0';
    } 
    else if (*c == '/' && prefix_len >= 7) {
        /* 0.0.0.0 的长度刚好是 7 */
        ngx_memcpy(prefix_text, ipv4->text, prefix_len);
        prefix_text[prefix_len] = '\0';
    } 
    else {
        return NGX_HTTP_WAF_FAIL;
    }

    if (inet_pton(AF_INET, prefix_text, &addr4) != 1) {
        return NGX_HTTP_WAF_FAIL;
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

    suffix_num = suffix;

    uint8_t temp_suffix[4] = { 0 };
    int i;
    for (i = 0; i < 4; i++) {
        uint8_t temp = 0;
        if (suffix >= 8) {
            suffix -=8;
            temp = ~0;
        } 
        else {
            uint32_t j;
            for (j = 0; j < suffix; j++) {
                temp |= 0x80 >> j;
            }
            suffix = 0;
        }
        temp_suffix[i] = temp;
    }

    suffix = 0;
    for (i = 0; i < 4; i++) {
        suffix |= ((uint32_t)temp_suffix[i]) << (i * 8);
    }

    ipv4->prefix = prefix & suffix;
    ipv4->suffix = suffix;
    ipv4->suffix_num = suffix_num;

    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t parse_ipv6(ngx_str_t text, ipv6_t* ipv6) {
    uint8_t prefix[16] = { 0 };
    uint8_t suffix[16] = { 0 };
    uint32_t suffix_num = 0;

    if (ipv6 == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }
    
    ngx_memcpy(ipv6->text, text.data, text.len);

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
        ngx_memcpy(prefix_text, ipv6->text, prefix_len);
        prefix_text[prefix_len] = '\0';
    } 
    else if (*c == '/' && prefix_len >= 2) {
        /* :: 的长度刚好是 2，此 IPV6 地址代表全零 */
        ngx_memcpy(prefix_text, ipv6->text, prefix_len);
        prefix_text[prefix_len] = '\0';
    } 
    else {
        return NGX_HTTP_WAF_FAIL;
    }

    if (inet_pton(AF_INET6, prefix_text, &addr6) != 1) {
        return NGX_HTTP_WAF_FAIL;
    }
    ngx_memcpy(prefix, &addr6.s6_addr, 16);

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

    suffix_num = temp_suffix;
    int i;
    for (i = 0; i < 16; i++) {
        uint8_t temp = 0;
        if (temp_suffix >= 8) {
            temp_suffix -=8;
            temp = ~0;
        } 
        else {
            uint32_t j;
            for (j = 0; j < temp_suffix; j++) {
                temp |= 0x80 >> j;
            }
            temp_suffix = 0;
        }
        suffix[i] = temp;
    }

    for (i = 0; i < 16; i++) {
        prefix[i] &= suffix[i];
    }

    ngx_memcpy(ipv6->prefix, prefix, 16);
    ngx_memcpy(ipv6->suffix, suffix, 16);
    ipv6->suffix_num = suffix_num;

    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t parse_time(u_char* str) {
    ngx_int_t ret = 0;
    size_t len = ngx_strlen(str);
    if (len < 2) {
        return NGX_ERROR;
    }

    ret = ngx_atoi(str, len - 1);
    if (ret == NGX_ERROR || ret <= 0) {
        return NGX_ERROR;
    }

    switch (str[len - 1]) {
        case 's': ret *= 1; break;
        case 'm': ret *= 1 * 60; break;
        case 'h': ret *= 1 * 60 * 60; break;
        case 'd': ret *= 1 * 60 * 60 * 24; break;
        default: return NGX_ERROR; break;
    }

    return ret;
}


static ngx_int_t parse_size(u_char* str) {
    ngx_int_t ret = 0;
    size_t len = ngx_strlen(str);
    if (len < 2) {
        return NGX_ERROR;
    }

    ret = ngx_atoi(str, len - 1);
    if (ret == NGX_ERROR || ret <= 0) {
        return NGX_ERROR;
    }

    switch (str[len - 1]) {
        case 'k': ret *= 1 * 1024; break;
        case 'm': ret *= 1 * 1024 * 1024; break;
        case 'g': ret *= 1 * 1024 * 1024 * 1024; break;
        default: return NGX_ERROR; break;
    }

    return ret;
}


static ngx_int_t parse_cookie(ngx_str_t* native_cookie, UT_array** array) {
    if (array == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    UT_icd icd = NGX_HTTP_WAF_MAKE_UTARRAY_NGX_STR_ICD();
    utarray_new(*array, &icd);

    if (native_cookie == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }


    UT_array* cookies = NULL;
    utarray_new(cookies, &icd);

    ngx_str_split(native_cookie, ';', native_cookie->len, &cookies);
    ngx_str_t* p = NULL;

    while (p = (ngx_str_t*)utarray_next(cookies, p), p != NULL) {
        UT_array* key_and_value = NULL;
        ngx_str_t temp;
        temp.data = p->data;
        temp.len = p->len;
        if (p->data[0] == ' ') {
            temp.data += 1;
            temp.len -= 1;
        }

        ngx_str_split(&temp, '=', native_cookie->len, &key_and_value);

        if (utarray_len(key_and_value) != 2) {
            return NGX_HTTP_WAF_FAIL;
        }

        ngx_str_t* key = NULL;
        ngx_str_t* value = NULL;


        key = (ngx_str_t*)utarray_next(key_and_value, NULL);
        value = (ngx_str_t*)utarray_next(key_and_value, key);


        utarray_push_back(*array, key);
        utarray_push_back(*array, value);
        utarray_free(key_and_value);
    }

    utarray_free(cookies);

    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t ngx_str_split(ngx_str_t* str, u_char sep, size_t max_len, UT_array** array) {
    if (array == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    UT_icd icd = NGX_HTTP_WAF_MAKE_UTARRAY_NGX_STR_ICD();
    utarray_new(*array,&icd);

    if (str == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    ngx_str_t temp_str;
    temp_str.data = malloc(sizeof(u_char) * max_len);
    ngx_memzero(temp_str.data, sizeof(u_char) * max_len);
    size_t str_index = 0;

    for (size_t i = 0; i < str->len; i++) {
        u_char c = str->data[i];
        if (c != sep) {
            if (str_index >= max_len) {
                free(temp_str.data);
                return NGX_HTTP_WAF_FAIL;
            }
            temp_str.data[str_index++] = c;
        } else {
            temp_str.data[str_index] = '\0';
            temp_str.len = str_index;
            utarray_push_back(*array, &temp_str);
            str_index = 0;
        }
    }

    if (str_index != 0) {
        temp_str.data[str_index] = '\0';
        temp_str.len = str_index;
        utarray_push_back(*array, &temp_str);
        str_index = 0;
    }

    free(temp_str.data);

    return NGX_HTTP_WAF_SUCCESS;
}


// static ngx_int_t str_split(u_char* str, u_char sep, size_t max_len, UT_array** array) {
//     if (str == NULL || array == NULL) {
//         return NGX_HTTP_WAF_FAIL;
//     }

//     UT_icd icd = NGX_HTTP_WAF_MAKE_UTARRAY_NGX_STR_ICD();

//     utarray_new(*array,&icd);
//     ngx_str_t temp_str;
//     temp_str.data = malloc(sizeof(u_char) * max_len);
//     ngx_memzero(temp_str.data, sizeof(u_char) * max_len);
//     size_t str_index = 0;

//     for (size_t i = 0; str[i] != '\0'; i++) {
//         u_char c = str[i];
//         if (c != sep) {
//             if (str_index + 1 >= max_len) {
//                 return NGX_HTTP_WAF_FAIL;
//             }
//             temp_str.data[str_index++] = c;
//         } else {
//             temp_str.data[str_index] = '\0';
//             temp_str.len = str_index;
//             utarray_push_back(*array, &temp_str);
//             str_index = 0;
//         }
//     }

//     if (str_index != 0) {
//         temp_str.data[str_index] = '\0';
//         temp_str.len = str_index;
//         utarray_push_back(*array, &temp_str);
//         str_index = 0;
//     }

//     free(temp_str.data);

//     return NGX_HTTP_WAF_SUCCESS;
// }


static char* to_c_str(u_char* destination, ngx_str_t ngx_str) {
    if (ngx_str.len > NGX_HTTP_WAF_RULE_MAX_LEN) {
        return NULL;
    }
    ngx_memcpy(destination, ngx_str.data, ngx_str.len);
    destination[ngx_str.len] = '\0';
    return (char*)destination + ngx_str.len;
}


static ngx_int_t rand_str(u_char* dest, size_t len) {
    if (dest == NULL || len == 0) {
        return NGX_HTTP_WAF_FAIL;
    }

    for (size_t i = 0; i < len; i++) {
        uint32_t num = randombytes_uniform(52);
        if (num < 26) {
            dest[i] = (unsigned char)'A' + (unsigned char)num;
        } else {
            dest[i] = (unsigned char)'a' + (unsigned char)(num - 26);
        }
    }

    dest[len] = '\0';

    return NGX_HTTP_WAF_SUCCESS;
}


static ngx_int_t sha256(u_char* dst, size_t dst_len, const u_char* buf, size_t buf_len) {
    if (dst == NULL  || dst_len < crypto_hash_sha256_BYTES * 2 + 1 || buf == NULL || buf_len == 0) {
        return NGX_HTTP_WAF_FAIL;
    }

    unsigned char* out = malloc(sizeof(u_char) * crypto_hash_sha256_BYTES);
    ngx_memzero(out, sizeof(u_char) * crypto_hash_sha256_BYTES);

    crypto_hash_sha256(out, buf, buf_len);
    sodium_bin2hex((char*)dst, dst_len, out, crypto_hash_sha256_BYTES);

    free(out);
    
    return NGX_HTTP_WAF_SUCCESS;
}


void utarray_ngx_str_ctor(void *dst, const void *src) {
    ngx_str_t* _dst = (ngx_str_t*)dst;
    const ngx_str_t* _src = (const ngx_str_t*)src;

    _dst->data = malloc(sizeof(u_char) * (_src->len + 1));
    ngx_memcpy(_dst->data, _src->data, sizeof(u_char) * _src->len);
    _dst->data[_src->len] = '\0';
    _dst->len = _src->len;
}


void utarray_ngx_str_dtor(void* elt) {
    ngx_str_t* _elt = (ngx_str_t*)elt;
    free(_elt->data);
}


#endif