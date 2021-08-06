#include <ngx_http_waf_module_util.h>

ngx_int_t ngx_http_waf_parse_ipv4(ngx_str_t text, ipv4_t* ipv4) {
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
    ipv4->suffix_num = suffix_num;

    return NGX_HTTP_WAF_SUCCESS;
}


#if (NGX_HAVE_INET6)
ngx_int_t ngx_http_waf_parse_ipv6(ngx_str_t text, ipv6_t* ipv6) {
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

    ngx_memcpy(ipv6->prefix, prefix, 16);
    ngx_memcpy(ipv6->suffix, suffix, 16);
    ipv6->suffix_num = suffix_num;

    return NGX_HTTP_WAF_SUCCESS;
}
#endif


ngx_int_t ngx_http_waf_parse_time(u_char* str) {
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


ngx_int_t ngx_http_waf_parse_size(u_char* str) {
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


ngx_int_t ngx_http_waf_parse_cookie(ngx_str_t* native_cookie, UT_array** array) {
    if (array == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    UT_icd icd = ngx_http_waf_make_utarray_ngx_str_icd();
    utarray_new(*array, &icd);

    if (native_cookie == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }


    UT_array* cookies = NULL;
    utarray_new(cookies, &icd);

    ngx_http_waf_str_split(native_cookie, ';', native_cookie->len, &cookies);
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

        ngx_http_waf_str_split(&temp, '=', native_cookie->len, &key_and_value);

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


ngx_int_t ngx_http_waf_parse_query_string(ngx_str_t* native_query_string, key_value_t** hash_head) {
    if (hash_head == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (native_query_string == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }


    UT_array* kvs = NULL;

    ngx_http_waf_str_split(native_query_string, '&', native_query_string->len, &kvs);
    ngx_str_t* p = NULL;

    while (p = (ngx_str_t*)utarray_next(kvs, p), p != NULL) {
        UT_array* key_and_value = NULL;
        ngx_str_t temp;
        temp.data = p->data;
        temp.len = p->len;

        ngx_http_waf_str_split(&temp, '=', native_query_string->len, &key_and_value);

        if (utarray_len(key_and_value) != 2) {
            return NGX_HTTP_WAF_FAIL;
        }

        ngx_str_t* key = NULL;
        ngx_str_t* value = NULL;


        key = (ngx_str_t*)utarray_next(key_and_value, NULL);
        value = (ngx_str_t*)utarray_next(key_and_value, key);

        key_value_t* qs = malloc(sizeof(key_value_t));
        ngx_memzero(qs, sizeof(key_value_t));
        qs->key.data = ngx_strdup(key->data);
        qs->key.len = key->len;
        qs->value.data = ngx_strdup(value->data);
        qs->value.len = value->len;

        HASH_ADD_KEYPTR(hh, *hash_head, qs->key.data, qs->key.len * sizeof(u_char), qs);

        utarray_free(key_and_value);
    }

    utarray_free(kvs);
    return NGX_HTTP_WAF_SUCCESS;
}


ngx_int_t ngx_http_waf_parse_header(ngx_list_t* native_header, key_value_t** hash_head) {
    if (native_header == NULL || hash_head == NULL) {
        return NGX_HTTP_WAF_FALSE;
    }

    ngx_list_part_t* part = &(native_header->part);
    ngx_table_elt_t* value = part->elts;

    for (size_t i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            value = part->elts;
            i = 0;
        }

        key_value_t* temp = malloc(sizeof(key_value_t));
        ngx_memzero(temp, sizeof(key_value_t));
        temp->key.data = ngx_strdup(value[i].key.data);
        temp->key.len = value[i].key.len;
        ngx_strlow(temp->key.data, temp->key.data, temp->key.len);
        temp->value.data = ngx_strdup(value[i].value.data);
        temp->value.len = value[i].value.len;
        HASH_ADD_KEYPTR(hh, *hash_head, temp->key.data, temp->key.len * sizeof(u_char), temp);

    }

    return NGX_HTTP_WAF_TRUE;
}


ngx_int_t ngx_http_waf_ipv4_netcmp(uint32_t ip, const ipv4_t* ipv4) {
    size_t prefix = ip & ipv4->suffix;

    if (prefix == ipv4->prefix) {
        return NGX_HTTP_WAF_MATCHED;
    }

    return NGX_HTTP_WAF_NOT_MATCHED;
}


#if (NGX_HAVE_INET6)
ngx_int_t ngx_http_waf_ipv6_netcmp(uint8_t ip[16], const ipv6_t* ipv6) {
    uint8_t temp_ip[16];

    memcpy(temp_ip, ip, 16);

    for (int i = 0; i < 16; i++) {
        temp_ip[i] &= ipv6->suffix[i];
    }

    if (memcmp(temp_ip, ipv6->prefix, sizeof(uint8_t) * 16) != 0) {
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    return NGX_HTTP_WAF_MATCHED;
}
#endif


ngx_int_t ngx_http_waf_str_split(ngx_str_t* str, u_char sep, size_t max_len, UT_array** array) {
    if (array == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    UT_icd icd = ngx_http_waf_make_utarray_ngx_str_icd();
    utarray_new(*array,&icd);

    if (str == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    ngx_str_t temp_str;
    temp_str.data = malloc(sizeof(u_char) * (max_len + 1));
    ngx_memzero(temp_str.data, sizeof(u_char) * (max_len + 1));
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


// ngx_int_t str_split(u_char* str, u_char sep, size_t max_len, UT_array** array) {
//     if (str == NULL || array == NULL) {
//         return NGX_HTTP_WAF_FAIL;
//     }

//     UT_icd icd = ngx_http_waf_make_utarray_ngx_str_icd();

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


char* ngx_http_waf_to_c_str(u_char* destination, ngx_str_t ngx_str) {
    if (ngx_str.len > NGX_HTTP_WAF_RULE_MAX_LEN) {
        return NULL;
    }
    ngx_memcpy(destination, ngx_str.data, ngx_str.len);
    destination[ngx_str.len] = '\0';
    return (char*)destination + ngx_str.len;
}


ngx_int_t ngx_http_waf_rand_str(u_char* dest, size_t len) {
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


ngx_int_t ngx_http_waf_sha256(u_char* dst, size_t dst_len, const u_char* buf, size_t buf_len) {
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


void ngx_http_waf_utarray_ngx_str_ctor(void *dst, const void *src) {
    ngx_str_t* _dst = (ngx_str_t*)dst;
    const ngx_str_t* _src = (const ngx_str_t*)src;

    _dst->data = malloc(sizeof(u_char) * (_src->len + 1));
    ngx_memcpy(_dst->data, _src->data, sizeof(u_char) * _src->len);
    _dst->data[_src->len] = '\0';
    _dst->len = _src->len;
}


void ngx_http_waf_utarray_ngx_str_dtor(void* elt) {
    ngx_str_t* _elt = (ngx_str_t*)elt;
    free(_elt->data);
}


void ngx_http_waf_utarray_vm_code_ctor(void *dst, const void *src) {
    vm_code_t* _dst = (vm_code_t*)dst;
    const vm_code_t* _src = (const vm_code_t*)src;
    _dst->type = _src->type;
    _dst->argv.argc = _src->argv.argc;
    

    for (size_t i = 0; i < _src->argv.argc; i++) {
        _dst->argv.type[i] = _src->argv.type[i];

        if (_src->argv.type[i] == VM_DATA_STR) {
            size_t len = _src->argv.value[i].str_val.len;
            _dst->argv.value[i].str_val.len = len;
            _dst->argv.value[i].str_val.data = (u_char*)malloc(sizeof(u_char) * (len + 1));
            ngx_memcpy(_dst->argv.value[i].str_val.data, _src->argv.value[i].str_val.data, sizeof(u_char) * len);
            _dst->argv.value[i].str_val.data[len] = '\0';
            _dst->argv.value[i].str_val.len = len;
        } else {
            ngx_memcpy(&(_dst->argv.value[i]), &(_src->argv.value[i]), sizeof(_src->argv.value[i]));
        }
    }
}


void ngx_http_waf_utarray_vm_code_dtor(void* elt) {
    vm_code_t* _elt = (vm_code_t*)elt;

    for (size_t i = 0; i < _elt->argv.argc; i++) {
        switch (_elt->argv.type[i]) {
            case VM_DATA_STR:
                free(_elt->argv.value[i].str_val.data);
                break;
            default:
                break;
        }
    }
}