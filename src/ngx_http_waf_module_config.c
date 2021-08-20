#include <ngx_http_waf_module_config.h>

extern ngx_module_t ngx_http_waf_module;

extern FILE* ngx_http_waf_in;

char* ngx_http_waf_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    if (ngx_conf_set_flag_slot(cf, cmd, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_http_waf_loc_conf_t* loc_conf = conf;

    if (loc_conf->waf == 1) {
        if (ngx_http_waf_alloc_memory(cf, loc_conf) != NGX_HTTP_WAF_SUCCESS) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


char* ngx_http_waf_rule_path_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    if (ngx_conf_set_str_slot(cf, cmd, conf) != NGX_CONF_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ngx_waf: %s", "the path of the rule files is not specified");
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_alloc_memory(cf, loc_conf) != NGX_HTTP_WAF_SUCCESS) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_waf_load_all_rule(cf, loc_conf) != NGX_HTTP_WAF_SUCCESS) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char* ngx_http_waf_mode_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = (ngx_http_waf_loc_conf_t*)conf;
    ngx_str_t* modes = cf->args->elts;
    size_t i;


    for (i = 1; i < cf->args->nelts && modes != NULL; i++) {
        #define ngx_http_waf_parse_mode(mode_str, not_mode_str, mode_bit) {                     \
            if (ngx_strncasecmp(modes[i].data,                                                  \
                (u_char*)(mode_str),                                                            \
                ngx_min(modes[i].len, sizeof((mode_str)) - 1)) == 0                             \
                && modes[i].len == sizeof((mode_str)) - 1) {                                    \
                loc_conf->waf_mode |= mode_bit;                                                 \
                continue;                                                                       \
            } else if (ngx_strncasecmp(modes[i].data,                                           \
                                      (u_char*)(not_mode_str),                                  \
                                      ngx_min(modes[i].len, sizeof((not_mode_str)) - 1)) == 0   \
                && modes[i].len == sizeof((not_mode_str)) - 1) {                                \
                loc_conf->waf_mode &= ~mode_bit;                                                \
                continue;                                                                       \
            }                                                                                   \
        }

        ngx_http_waf_parse_mode("GET", "!GET", NGX_HTTP_WAF_MODE_INSPECT_GET);
        ngx_http_waf_parse_mode("HEAD", "!HEAD", NGX_HTTP_WAF_MODE_INSPECT_HEAD);
        ngx_http_waf_parse_mode("POST", "!POST", NGX_HTTP_WAF_MODE_INSPECT_POST);
        ngx_http_waf_parse_mode("PUT", "!PUT", NGX_HTTP_WAF_MODE_INSPECT_PUT);
        ngx_http_waf_parse_mode("DELETE", "!DELETE", NGX_HTTP_WAF_MODE_INSPECT_DELETE);
        ngx_http_waf_parse_mode("MKCOL", "!MKCOL", NGX_HTTP_WAF_MODE_INSPECT_MKCOL);
        ngx_http_waf_parse_mode("COPY", "!COPY", NGX_HTTP_WAF_MODE_INSPECT_COPY);
        ngx_http_waf_parse_mode("MOVE", "!MOVE", NGX_HTTP_WAF_MODE_INSPECT_MOVE);
        ngx_http_waf_parse_mode("OPTIONS", "!OPTIONS", NGX_HTTP_WAF_MODE_INSPECT_OPTIONS);
        ngx_http_waf_parse_mode("PROPFIND", "!PROPFIND", NGX_HTTP_WAF_MODE_INSPECT_PROPFIND);
        ngx_http_waf_parse_mode("PROPPATCH", "!PROPPATCH", NGX_HTTP_WAF_MODE_INSPECT_PROPPATCH);
        ngx_http_waf_parse_mode("LOCK", "!LOCK", NGX_HTTP_WAF_MODE_INSPECT_LOCK);
        ngx_http_waf_parse_mode("UNLOCK", "!UNLOCK", NGX_HTTP_WAF_MODE_INSPECT_UNLOCK);
        ngx_http_waf_parse_mode("PATCH", "!PATCH", NGX_HTTP_WAF_MODE_INSPECT_PATCH);
        ngx_http_waf_parse_mode("TRACE", "!TRACE", NGX_HTTP_WAF_MODE_INSPECT_TRACE);
        ngx_http_waf_parse_mode("CMN-METH", "!CMN-METH", NGX_HTTP_WAF_MODE_CMN_METH);
        ngx_http_waf_parse_mode("ALL-METH", "!ALL-METH", NGX_HTTP_WAF_MODE_ALL_METH);
        ngx_http_waf_parse_mode("IP", "!IP", NGX_HTTP_WAF_MODE_INSPECT_IP);
        ngx_http_waf_parse_mode("URL", "!URL", NGX_HTTP_WAF_MODE_INSPECT_URL);
        ngx_http_waf_parse_mode("RBODY", "!RBODY", NGX_HTTP_WAF_MODE_INSPECT_RB);
        ngx_http_waf_parse_mode("ARGS", "!ARGS", NGX_HTTP_WAF_MODE_INSPECT_ARGS);
        ngx_http_waf_parse_mode("UA", "!UA", NGX_HTTP_WAF_MODE_INSPECT_UA);
        ngx_http_waf_parse_mode("COOKIE", "!COOKIE", NGX_HTTP_WAF_MODE_INSPECT_COOKIE);
        ngx_http_waf_parse_mode("REFERER", "!REFERER", NGX_HTTP_WAF_MODE_INSPECT_REFERER);
        // ngx_http_waf_parse_mode("CC", "!CC", NGX_HTTP_WAF_MODE_INSPECT_CC);
        ngx_http_waf_parse_mode("ADV", "!ADV", NGX_HTTP_WAF_MODE_INSPECT_ADV);
        ngx_http_waf_parse_mode("STD", "!STD", NGX_HTTP_WAF_MODE_STD);
        ngx_http_waf_parse_mode("STATIC", "!STATIC", NGX_HTTP_WAF_MODE_STATIC);
        ngx_http_waf_parse_mode("DYNAMIC", "!DYNAMIC", NGX_HTTP_WAF_MODE_DYNAMIC);
        ngx_http_waf_parse_mode("FULL", "!FULL", NGX_HTTP_WAF_MODE_FULL);
        // ngx_http_waf_parse_mode("CACHE", "!CACHE", NGX_HTTP_WAF_MODE_EXTRA_CACHE);
        ngx_http_waf_parse_mode("LIB-INJECTION", "!LIB-INJECTION", NGX_HTTP_WAF_MODE_LIB_INJECTION);
        ngx_http_waf_parse_mode("LIB-INJECTION-SQLI", "!LIB-INJECTION-SQLI", NGX_HTTP_WAF_MODE_LIB_INJECTION_SQLI);
        ngx_http_waf_parse_mode("LIB-INJECTION-XSS", "!LIB-INJECTION-XSS", NGX_HTTP_WAF_MODE_LIB_INJECTION_XSS);

        #undef ngx_http_waf_parse_mode

        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
            "ngx_waf: invalid value.");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char* ngx_http_waf_cc_deny_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    /* 默认封禁 60 分钟 */
    loc_conf->waf_cc_deny_duration = 1 * 60 * 60;
    /* 设置默认的共享内存大小 */
    loc_conf->waf_cc_deny_shm_zone_size = NGX_HTTP_WAF_SHARE_MEMORY_CC_DENY_MIN_SIZE;

    if (ngx_strncmp(p_str[1].data, "on", ngx_min(p_str[1].len, 2)) == 0) {
        loc_conf->waf_cc_deny = 1;
    } else {
        loc_conf->waf_cc_deny = 0;
    }

    if (loc_conf->waf_cc_deny == 0) {
        return NGX_CONF_OK;
    }

    for (size_t i = 2; i < cf->args->nelts; i++) {
        UT_array* array = NULL;
        if (ngx_http_waf_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (ngx_strcmp("rate", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);

            UT_array* temp = NULL;
            if (ngx_http_waf_str_split(p, '/', 256, &temp) != NGX_HTTP_WAF_SUCCESS) {
                goto error;
            }

            if (utarray_len(temp) != 2) {
                goto error;
            }

            ngx_str_t* q = NULL;
            q = (ngx_str_t*)utarray_next(temp, q);
            loc_conf->waf_cc_deny_limit = ngx_atoi(q->data, q->len - 1);
            if (loc_conf->waf_cc_deny_limit == NGX_ERROR || loc_conf->waf_cc_deny_limit <= 0) {
                goto error;
            }
            if (q->data[q->len - 1] != 'r') {
                goto error;
            }

            q = (ngx_str_t*)utarray_next(temp, q);
            loc_conf->waf_cc_deny_cycle = ngx_http_waf_parse_time(q->data);
            if (loc_conf->waf_cc_deny_cycle == NGX_ERROR || loc_conf->waf_cc_deny_cycle <= 0) {
                goto error;
            }

            utarray_free(temp);

        } else if (ngx_strcmp("duration", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            loc_conf->waf_cc_deny_duration = ngx_http_waf_parse_time(p->data);
            if (loc_conf->waf_cc_deny_duration == NGX_ERROR) {
                goto error;
            }

        } else if (ngx_strcmp("size", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            loc_conf->waf_cc_deny_shm_zone_size = ngx_http_waf_parse_size(p->data);
            if (loc_conf->waf_cc_deny_shm_zone_size == NGX_ERROR) {
                goto error;
            }
            loc_conf->waf_cc_deny_shm_zone_size = ngx_max(NGX_HTTP_WAF_SHARE_MEMORY_CC_DENY_MIN_SIZE, 
                                                          loc_conf->waf_cc_deny_shm_zone_size);
        } else {
            goto error;
        }

        utarray_free(array);
    }

    if (loc_conf->waf_cc_deny_limit == NGX_CONF_UNSET) {
        goto error;
    }

    if (ngx_http_waf_init_cc_shm(cf, loc_conf) != NGX_HTTP_WAF_SUCCESS) {
        goto error;
    }

    return NGX_CONF_OK;

    error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


char* ngx_http_waf_cache_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    if (ngx_strncmp(p_str[1].data, "on", ngx_min(p_str[1].len, 2)) == 0) {
        loc_conf->waf_cache = 1;
    } else {
        loc_conf->waf_cache = 0;
    }

    if (loc_conf->waf_cache == 0) {
        return NGX_CONF_OK;
    }

    for (size_t i = 2; i < cf->args->nelts; i++) {
        UT_array* array = NULL;
        if (ngx_http_waf_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (ngx_strcmp("capacity", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            loc_conf->waf_cache_capacity = ngx_atoi(p->data, p->len);
            if (loc_conf->waf_cache_capacity == NGX_ERROR
                || loc_conf->waf_cache_capacity <= 0) {
                goto error;
            }

        } else if (ngx_strcmp("interval", p->data) == 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, NGX_EINVAL, 
                "Since v6.0.1, the parameter 'interval' is deprecated and it is recommended that you remove this parameter.");

        } else if (ngx_strcmp("percent", p->data) == 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, NGX_EINVAL, 
                "Since v6.0.1, the parameter 'percent' is deprecated and it is recommended that you remove this parameter.");
        } else {
            goto error;
        }

        utarray_free(array);
    }

    if (loc_conf->waf_cache_capacity == NGX_CONF_UNSET) {
        goto error;
    }

    if (ngx_http_waf_init_lru_cache(cf, loc_conf) != NGX_HTTP_WAF_SUCCESS) {
        goto error;
    }

    return NGX_CONF_OK;

    error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


char* ngx_http_waf_under_attack_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    loc_conf->waf_under_attack = NGX_CONF_UNSET;

    if (ngx_strncmp(p_str[1].data, "on", ngx_min(p_str[1].len, 2)) == 0) {
        loc_conf->waf_under_attack = 1;
    } else {
        loc_conf->waf_under_attack = 0;
    }

    if (loc_conf->waf_under_attack == 0) {
        return NGX_CONF_OK;
    }

    if (cf->args->nelts != 3) {
        goto error;
    }

    for (size_t i = 2; i < cf->args->nelts; i++) {
        UT_array* array = NULL;
        if (ngx_http_waf_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (ngx_strcmp("file", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            if (p == NULL || p->data == NULL || p->len == 0) {
                goto error;
            }

            FILE* fp = fopen((char*)p->data, "r");

            if (fp == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOENT, 
                    "ngx_waf: Unable to open file %s.", p->data);
                return NGX_CONF_ERROR;
            }

            fseek(fp, 0, SEEK_END);
            size_t file_size = ftell(fp);
            loc_conf->waf_under_attack_len = file_size;
            loc_conf->waf_under_attack_html = ngx_pcalloc(cf->pool, file_size + sizeof(u_char));

            fseek(fp, 0, SEEK_SET);
            if (fread(loc_conf->waf_under_attack_html, sizeof(u_char), file_size, fp) != file_size) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EPERM, 
                    "ngx_waf: Failed to read file %s completely..", p->data);
                return NGX_CONF_ERROR;
            }

            fclose(fp);


        } else {
            goto error;
        }

        utarray_free(array);
    }

    return NGX_CONF_OK;

    error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


char* ngx_http_waf_captcha_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    loc_conf->waf_captcha = NGX_CONF_UNSET;
    loc_conf->waf_captcha_expire = 60 * 30;
    loc_conf->waf_captcha_reCAPTCHAv3_score = 0.5;
    ngx_str_set(&loc_conf->waf_captcha_verify_url, "/captcha");

    if (ngx_strncmp(p_str[1].data, "on", ngx_min(p_str[1].len, 2)) == 0) {
        loc_conf->waf_captcha = 1;
    } else {
        loc_conf->waf_captcha = 0;
    }

    if (loc_conf->waf_captcha == 0) {
        return NGX_CONF_OK;
    }

    if (cf->args->nelts < 4) {
        goto error;
    }

    for (size_t i = 2; i < cf->args->nelts; i++) {
        UT_array* array = NULL;
        if (ngx_http_waf_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (ngx_strcmp("file", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            if (p == NULL || p->data == NULL || p->len == 0) {
                goto error;
            }

            FILE* fp = fopen((char*)p->data, "r");

            if (fp == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOENT, 
                    "ngx_waf: Unable to open file %s.", p->data);
                return NGX_CONF_ERROR;
            }

            fseek(fp, 0, SEEK_END);
            size_t file_size = ftell(fp);
            loc_conf->waf_captcha_html_len = file_size;
            loc_conf->waf_captcha_html = ngx_pcalloc(cf->pool, file_size + sizeof(u_char));

            fseek(fp, 0, SEEK_SET);
            if (fread(loc_conf->waf_captcha_html, sizeof(u_char), file_size, fp) != file_size) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EPERM, 
                    "ngx_waf: Failed to read file %s completely..", p->data);
                return NGX_CONF_ERROR;
            }

            fclose(fp);

        } else if (ngx_strcmp("prov", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            if (p == NULL || p->data == NULL || p->len == 0) {
                goto error;
            }
            
            if (ngx_strcmp(p->data, "hCaptcha") == 0) {
                loc_conf->waf_captcha_type = NGX_HTTP_WAF_HCAPTCHA;
            } else if (ngx_strcmp(p->data, "reCAPTCHAv2") == 0) {
                loc_conf->waf_captcha_type = NGX_HTTP_WAF_RECAPTCHA_V2;
            } else if (ngx_strcmp(p->data, "reCAPTCHAv3") == 0) {
                loc_conf->waf_captcha_type = NGX_HTTP_WAF_RECAPTCHA_V3;
            } else {
                goto error;
            }
        } else if (ngx_strcmp("secret", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            if (p == NULL || p->data == NULL || p->len == 0) {
                goto error;
            }

            loc_conf->waf_captcha_hCaptcha_secret.data = ngx_pcalloc(cf->pool, p->len + 1);
            ngx_memcpy(loc_conf->waf_captcha_hCaptcha_secret.data, p->data, p->len);
            loc_conf->waf_captcha_hCaptcha_secret.len = p->len;

            loc_conf->waf_captcha_reCAPTCHA_secret.data = ngx_pcalloc(cf->pool, p->len + 1);
            ngx_memcpy(loc_conf->waf_captcha_reCAPTCHA_secret.data, p->data, p->len);
            loc_conf->waf_captcha_reCAPTCHA_secret.len = p->len;
        } else if (ngx_strcmp("expire", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            loc_conf->waf_captcha_expire = ngx_http_waf_parse_time(p->data);
            if (loc_conf->waf_captcha_expire == NGX_ERROR) {
                goto error;
            }
        } else if (ngx_strcmp("score", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            loc_conf->waf_captcha_reCAPTCHAv3_score = atof((char*)p->data);
            if (loc_conf->waf_captcha_reCAPTCHAv3_score < 0.0 && loc_conf->waf_captcha_reCAPTCHAv3_score > 1.0) {
                goto error;
            }
        } else if (ngx_strcmp("api", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            loc_conf->waf_captcha_api.data = ngx_pcalloc(cf->pool, p->len + 1);
            ngx_memcpy(loc_conf->waf_captcha_api.data, p->data, p->len);
            loc_conf->waf_captcha_api.len = p->len;
        } else if (ngx_strcmp("verfiy", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            loc_conf->waf_captcha_verify_url.data = ngx_pcalloc(cf->pool, p->len + 1);
            ngx_memcpy(loc_conf->waf_captcha_verify_url.data, p->data, p->len);
            loc_conf->waf_captcha_verify_url.len = p->len;
        } else {
            goto error;
        }

        utarray_free(array);
    }

    if (loc_conf->waf_captcha_api.data == NULL || loc_conf->waf_captcha_api.len == 0) {
            switch (loc_conf->waf_captcha_type) {
            case NGX_HTTP_WAF_HCAPTCHA:
                ngx_str_set(&loc_conf->waf_captcha_api, "https://hcaptcha.com/siteverify");
                break;
            case NGX_HTTP_WAF_RECAPTCHA_V2:
                ngx_str_set(&loc_conf->waf_captcha_api, "https://www.recaptcha.net/recaptcha/api/siteverify");
                break;
            case NGX_HTTP_WAF_RECAPTCHA_V3:
                ngx_str_set(&loc_conf->waf_captcha_api, "https://www.recaptcha.net/recaptcha/api/siteverify");
                break;
            default:
                goto error;
        }
    }



    return NGX_CONF_OK;

    error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


char* ngx_http_waf_priority_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;
    // u_char error_str[256];

    loc_conf->is_custom_priority = NGX_HTTP_WAF_TRUE;

    UT_array* array = NULL;
    if (ngx_http_waf_str_split(p_str + 1, ' ', 20, &array) != NGX_HTTP_WAF_SUCCESS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
            "ngx_waf: invalid value");
        return NGX_CONF_ERROR;
    }


    if (utarray_len(array) != 15) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
            "ngx_waf: you must specify the priority of all inspections except for POST inspections");
        return NGX_CONF_ERROR;
    }


    ngx_str_t* p = NULL;
    size_t proc_index = 0;
    while ((p = (ngx_str_t*)utarray_next(array, p))) {
        #define ngx_http_waf_parse_priority(str, pt) {          \
            if (strcasecmp((str), (char*)(p->data)) == 0) {     \
                loc_conf->check_proc[proc_index++] = pt;        \
                continue;                                       \
            }                                                   \
        }

        ngx_http_waf_parse_priority("CC", ngx_http_waf_handler_check_cc);
        ngx_http_waf_parse_priority("W-IP", ngx_http_waf_handler_check_white_ip);
        ngx_http_waf_parse_priority("IP", ngx_http_waf_handler_check_black_ip);
        ngx_http_waf_parse_priority("W-URL", ngx_http_waf_handler_check_white_url);
        ngx_http_waf_parse_priority("URL", ngx_http_waf_handler_check_black_url);
        ngx_http_waf_parse_priority("ARGS", ngx_http_waf_handler_check_black_args);
        ngx_http_waf_parse_priority("UA", ngx_http_waf_handler_check_black_user_agent);
        ngx_http_waf_parse_priority("W-REFERER", ngx_http_waf_handler_check_white_referer);
        ngx_http_waf_parse_priority("REFERER", ngx_http_waf_handler_check_black_referer);
        ngx_http_waf_parse_priority("COOKIE", ngx_http_waf_handler_check_black_cookie);
        ngx_http_waf_parse_priority("UNDER-ATTACK", ngx_http_waf_handler_under_attack);
        ngx_http_waf_parse_priority("ADV", ngx_http_waf_vm_exec);
        ngx_http_waf_parse_priority("RBODY", ngx_http_waf_handler_check_black_post);
        ngx_http_waf_parse_priority("CAPTCHA", ngx_http_waf_handler_captcha);
        ngx_http_waf_parse_priority("VERIFY-BOT", ngx_http_waf_handler_verify_bot);

        #undef ngx_http_waf_parse_priority

        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
                          "ngx_waf: ngx_waf: invalid value [%s]", p->data);
        return NGX_CONF_ERROR;
    }

    utarray_free(array);

    return NGX_CONF_OK;
}


char* ngx_http_waf_verify_bot_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    static char* s_google_bot_ua_regexp[] = {
        "Googlebot",
        "Google Favicon",
        "Googlebot-News",
        "Googlebot-Image",
        "Googlebot-Video",
        "Google-Read-Aloud",
        "AdsBot-Google",
        "AdsBot-Google-Mobile",
        "AdsBot-Google-Mobile-Apps",
        "APIs-Google",
        "googleweblight",
        "Storebot-Google",
        "DuplexWeb-Google",
        // "FeedFetcher-Google",
        "Mediapartners-Google",
        NULL
    };

    static char* s_google_bot_domain_regexp[] = {
        "googlebot\\.com$",
        "google\\.com$",
        NULL
    };

    static char* s_bing_bot_ua_regexp[] = {
        "bingbot",
        "adidxbot",
        "BingPreview",
        NULL
    };

    static char* s_bing_bot_domain_regexp[] = {
        "search\\.msn\\.com$",
        NULL
    };

    static char* s_baidu_spider_ua_regexp[] = {
        "Baiduspider",
        "Baiduspider-ads",
        "Baiduspider-cpro",
        "Baiduspider-favo",
        "Baiduspider-news",
        "Baiduspider-video",
        "Baiduspider-image",
        NULL
    };

    static char* s_baidu_spider_domain_regexp[] = {
        "baidu\\.com$",
        "baidu\\.jp$",
        NULL
    };

    static char* s_yandex_bot_ua_regexp[] = {
        "YandexBot",
        "YandexRCA",
        "YandexNews",
        "YandexAdNet",
        "YandexMedia",
        "YandexBlogs",
        "YandexTurbo",
        "YandexVideo",
        "YandexDirect",
        "YandexVertis",
        "YandexMarket",
        "YandexOntoDB",
        "YandexImages",
        "YandexTracker",
        "YandexMetrika",
        "YandexPartner",
        "YandexSpravBot",
        "YandexCalendar",
        "YandexFavicons",
        "YandexMobileBot",
        "YandexWebmaster",
        "YandexVerticals",
        "YandexOntoDBAPI",
        "YandexDirectDyn",
        "YandexSitelinks",
        "YaDirectFetcher",
        "YandexForDomain",
        "YandexSearchShop",
        "YandexVideoParser",
        "YandexPagechecker",
        "YandexImageResizer",
        "YandexAccessibilityBot",
        "YandexMobileScreenShotBot",
        NULL
    };

    static char* s_yandex_bot_yandex_domain_regexp[] = {
        "yandex\\.com$",
        "yandex\\.net$",
        "yandex\\.ru$",
        NULL
    };

    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;

    loc_conf->waf_verify_bot = NGX_CONF_UNSET;
    loc_conf->waf_verify_bot_type = 0;

    if (ngx_strncmp(p_str[1].data, "on", ngx_min(p_str[1].len, 2)) == 0) {
        loc_conf->waf_verify_bot = 1;
    } else if (ngx_strncmp(p_str[1].data, "strict", ngx_min(p_str[1].len, 6)) == 0) {
        loc_conf->waf_verify_bot = 2;
    } else {
        loc_conf->waf_verify_bot = 0;
    }

    if (loc_conf->waf_verify_bot == 0) {
        return NGX_CONF_OK;
    }


    loc_conf->waf_verify_bot_google_ua_regexp = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    if (ngx_http_waf_make_regexp_from_array(cf->pool, s_google_bot_ua_regexp, loc_conf->waf_verify_bot_google_ua_regexp) 
            != NGX_HTTP_WAF_SUCCESS) {
        return NGX_CONF_ERROR;
    }

    loc_conf->waf_verify_bot_google_domain_regexp = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    if (ngx_http_waf_make_regexp_from_array(cf->pool, s_google_bot_domain_regexp, loc_conf->waf_verify_bot_google_domain_regexp) 
            != NGX_HTTP_WAF_SUCCESS) {
        return NGX_CONF_ERROR;
    }

    

    loc_conf->waf_verify_bot_bing_ua_regexp = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    if (ngx_http_waf_make_regexp_from_array(cf->pool, s_bing_bot_ua_regexp, loc_conf->waf_verify_bot_bing_ua_regexp) 
            != NGX_HTTP_WAF_SUCCESS) {
        return NGX_CONF_ERROR;
    }

    loc_conf->waf_verify_bot_bing_domain_regexp = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    if (ngx_http_waf_make_regexp_from_array(cf->pool, s_bing_bot_domain_regexp, loc_conf->waf_verify_bot_bing_domain_regexp) 
            != NGX_HTTP_WAF_SUCCESS) {
        return NGX_CONF_ERROR;
    }


    loc_conf->waf_verify_bot_baidu_ua_regexp = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    if (ngx_http_waf_make_regexp_from_array(cf->pool, s_baidu_spider_ua_regexp, loc_conf->waf_verify_bot_baidu_ua_regexp) 
            != NGX_HTTP_WAF_SUCCESS) {
        return NGX_CONF_ERROR;
    }

    loc_conf->waf_verify_bot_baidu_domain_regexp = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    if (ngx_http_waf_make_regexp_from_array(cf->pool, s_baidu_spider_domain_regexp, loc_conf->waf_verify_bot_baidu_domain_regexp) 
            != NGX_HTTP_WAF_SUCCESS) {
        return NGX_CONF_ERROR;
    }


    loc_conf->waf_verify_bot_yandex_ua_regexp = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    if (ngx_http_waf_make_regexp_from_array(cf->pool, s_yandex_bot_ua_regexp, loc_conf->waf_verify_bot_yandex_ua_regexp) 
            != NGX_HTTP_WAF_SUCCESS) {
        return NGX_CONF_ERROR;
    }

    loc_conf->waf_verify_bot_yandex_domain_regexp = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    if (ngx_http_waf_make_regexp_from_array(cf->pool, s_yandex_bot_yandex_domain_regexp, loc_conf->waf_verify_bot_yandex_domain_regexp) 
            != NGX_HTTP_WAF_SUCCESS) {
        return NGX_CONF_ERROR;
    }

    

    for (size_t i = 2; i < cf->args->nelts; i++) {
        #define ngx_http_waf_parse(str, flag)                                                               \
        if (ngx_strncasecmp(p_str[i].data, (u_char*)(str), ngx_min(p_str[i].len, sizeof(str) - 1)) == 0     \
        &&  p_str[i].len == sizeof(str) - 1) {                                                              \
            loc_conf->waf_verify_bot_type |= flag;                                                          \
            continue;                                                                                       \
        }                                                                                                   \

        ngx_http_waf_parse("GoogleBot", NGX_HTTP_WAF_GOOGLE_BOT);
        ngx_http_waf_parse("BingBot", NGX_HTTP_WAF_BING_BOT);
        ngx_http_waf_parse("BaiduSpider", NGX_HTTP_WAF_BAIDU_SPIDER);
        ngx_http_waf_parse("YandexBot", NGX_HTTP_WAF_YANDEX_BOT);
        
        goto error;

        #undef ngx_http_waf_parse
    }

    if (loc_conf->waf_verify_bot_type == 0) {
        loc_conf->waf_verify_bot_type = NGX_HTTP_WAF_GOOGLE_BOT 
                                      | NGX_HTTP_WAF_BING_BOT 
                                      | NGX_HTTP_WAF_BAIDU_SPIDER 
                                      | NGX_HTTP_WAF_YANDEX_BOT;
    }

    return NGX_CONF_OK;

    error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


char* ngx_http_waf_http_status_conf(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_waf_loc_conf_t* loc_conf = conf;
    ngx_str_t* p_str = cf->args->elts;


    for (size_t i = 1; i < cf->args->nelts; i++) {
        UT_array* array = NULL;
        if (ngx_http_waf_str_split(p_str + i, '=', 256, &array) != NGX_HTTP_WAF_SUCCESS) {
            goto error;
        }

        if (utarray_len(array) != 2) {
            goto error;
        }

        ngx_str_t* p = NULL;
        p = (ngx_str_t*)utarray_next(array, p);

        if (ngx_strcmp("general", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            loc_conf->waf_http_status = ngx_atoi(p->data, p->len);
            if (loc_conf->waf_http_status == NGX_ERROR
                || loc_conf->waf_http_status <= 0) {
                goto error;
            }

        } else if (ngx_strcmp("cc_deny", p->data) == 0) {
            p = (ngx_str_t*)utarray_next(array, p);
            loc_conf->waf_http_status_cc = ngx_atoi(p->data, p->len);
            if (loc_conf->waf_http_status_cc == NGX_ERROR
                || loc_conf->waf_http_status_cc <= 0) {
                goto error;
            }

        } else {
            goto error;
        }

        utarray_free(array);
    }

    return NGX_CONF_OK;

    error:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_EINVAL, 
        "ngx_waf: invalid value");
    return NGX_CONF_ERROR;
}


void* ngx_http_waf_create_loc_conf(ngx_conf_t* cf) {
    return ngx_http_waf_init_conf(cf);
}


char* ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf) {
    ngx_http_waf_loc_conf_t* parent = prev;
    ngx_http_waf_loc_conf_t* child = conf;

    if (parent == NULL || child == NULL) {
        return NGX_CONF_OK;
    }

    child->parent = parent;

    ngx_conf_merge_value(child->waf, parent->waf, NGX_CONF_UNSET);

    ngx_conf_merge_ptr_value(child->white_ipv4, parent->white_ipv4, NULL);
    ngx_conf_merge_ptr_value(child->black_ipv4, parent->black_ipv4, NULL);
#if (NGX_HAVE_INET6)
    ngx_conf_merge_ptr_value(child->white_ipv6, parent->white_ipv6, NULL);
    ngx_conf_merge_ptr_value(child->black_ipv6, parent->black_ipv6, NULL);
#endif
    ngx_conf_merge_ptr_value(child->white_url, parent->white_url, NULL);
    ngx_conf_merge_ptr_value(child->white_referer, parent->white_referer, NULL);
    ngx_conf_merge_ptr_value(child->black_url, parent->black_url, NULL);
    ngx_conf_merge_ptr_value(child->black_args, parent->black_args, NULL);
    ngx_conf_merge_ptr_value(child->black_ua, parent->black_ua, NULL);
    ngx_conf_merge_ptr_value(child->black_post, parent->black_post, NULL);
    ngx_conf_merge_ptr_value(child->black_cookie, parent->black_cookie, NULL);
    ngx_conf_merge_ptr_value(child->advanced_rule, parent->advanced_rule, NULL);
    

    ngx_conf_merge_value(child->waf_under_attack, parent->waf_under_attack, NGX_CONF_UNSET);
    ngx_conf_merge_ptr_value(child->waf_under_attack_html, parent->waf_under_attack_html, NULL);
    ngx_conf_merge_size_value(child->waf_under_attack_len, parent->waf_under_attack_len, NGX_CONF_UNSET_SIZE);
    ngx_conf_merge_value(child->waf_captcha_reCAPTCHAv3_score, parent->waf_captcha_reCAPTCHAv3_score, NGX_CONF_UNSET);

    if (child->waf_captcha_hCaptcha_secret.data == NULL || child->waf_captcha_hCaptcha_secret.len == 0) {
        ngx_memcpy(&(child->waf_captcha_hCaptcha_secret), &(parent->waf_captcha_hCaptcha_secret), sizeof(ngx_str_t));
    }

    if (child->waf_captcha_reCAPTCHA_secret.data == NULL || child->waf_captcha_reCAPTCHA_secret.len == 0) {
        ngx_memcpy(&(child->waf_captcha_reCAPTCHA_secret), &(parent->waf_captcha_reCAPTCHA_secret), sizeof(ngx_str_t));
    }

    ngx_conf_merge_value(child->waf_captcha, parent->waf_captcha, NGX_CONF_UNSET);
    ngx_conf_merge_value(child->waf_captcha_expire, parent->waf_captcha_expire, NGX_CONF_UNSET);
    ngx_conf_merge_ptr_value(child->waf_captcha_html, parent->waf_captcha_html, NULL);
    ngx_conf_merge_size_value(child->waf_captcha_html_len, parent->waf_captcha_html_len, NGX_CONF_UNSET_SIZE);

    ngx_conf_merge_value(child->waf_verify_bot, parent->waf_verify_bot, NGX_CONF_UNSET);
    ngx_conf_merge_value(child->waf_verify_bot_type, parent->waf_verify_bot_type, NGX_CONF_UNSET);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_google_ua_regexp, parent->waf_verify_bot_google_ua_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_bing_ua_regexp, parent->waf_verify_bot_bing_ua_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_baidu_ua_regexp, parent->waf_verify_bot_baidu_ua_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_yandex_ua_regexp, parent->waf_verify_bot_yandex_ua_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_google_domain_regexp, parent->waf_verify_bot_google_domain_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_bing_domain_regexp, parent->waf_verify_bot_bing_domain_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_baidu_domain_regexp, parent->waf_verify_bot_baidu_domain_regexp, NULL);
    ngx_conf_merge_ptr_value(child->waf_verify_bot_yandex_domain_regexp, parent->waf_verify_bot_yandex_domain_regexp, NULL);


    if (child->waf_mode == 0) {
        child->waf_mode = parent->waf_mode;
    }
    
    ngx_conf_merge_value(child->waf_cache, parent->waf_cache, NGX_CONF_UNSET);
    ngx_conf_merge_value(child->waf_cache_capacity, parent->waf_cache_capacity, NGX_CONF_UNSET);
    ngx_conf_merge_ptr_value(child->black_url_inspection_cache, parent->black_url_inspection_cache, NULL);
    ngx_conf_merge_ptr_value(child->black_args_inspection_cache, parent->black_args_inspection_cache, NULL);
    ngx_conf_merge_ptr_value(child->black_ua_inspection_cache, parent->black_ua_inspection_cache, NULL);
    ngx_conf_merge_ptr_value(child->black_referer_inspection_cache, parent->black_referer_inspection_cache, NULL);
    ngx_conf_merge_ptr_value(child->black_cookie_inspection_cache, parent->black_cookie_inspection_cache, NULL);
    ngx_conf_merge_ptr_value(child->white_url_inspection_cache, parent->white_url_inspection_cache, NULL);
    ngx_conf_merge_ptr_value(child->white_referer_inspection_cache, parent->white_referer_inspection_cache, NULL);


    if (parent->is_custom_priority == NGX_HTTP_WAF_TRUE
    &&  child->is_custom_priority == NGX_HTTP_WAF_FALSE) {
        ngx_memcpy(child->check_proc, parent->check_proc, sizeof(parent->check_proc));
    }

    return NGX_CONF_OK;
}


ngx_int_t ngx_http_waf_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Start the variable calculation process (waf_log).");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = ngx_palloc(r->pool, sizeof(u_char) * 64);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The memory was successfully allocated.");

    if (ctx == NULL || ctx->checked == NGX_HTTP_WAF_FALSE) {
        v->len = 0;
        v->data = NULL;
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: No context or the module did not start the inspection process.");
    }
    else {
        v->len = 4;
        strcpy((char*)v->data, "true");
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The module starts the detection process.");
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The variable calculation process is fully completed (waf_log).");
    return NGX_OK;
}


ngx_int_t ngx_http_waf_blocking_log_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Start the variable calculation process (waf_blocking_log).");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = ngx_palloc(r->pool, sizeof(u_char) * 64);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The memory was successfully allocated.");

    if (ctx == NULL || ctx->blocked == NGX_HTTP_WAF_FALSE) {
        v->len = 0;
        v->data = NULL;
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: No context or this request is not blocked.");
    }
    else {
        v->len = 4;
        strcpy((char*)v->data, "true");
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: This request has been blocked.");
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The variable calculation process is fully completed (waf_blocking_log).");
    return NGX_OK;
}


ngx_int_t ngx_http_waf_blocked_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Start the variable calculation process (waf_blocked).");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = ngx_palloc(r->pool, sizeof(u_char) * 64);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The memory was successfully allocated.");

    if (ctx == NULL) {
        v->len = 0;
        v->data = NULL;
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: No context.");
    }
    else {
        if (ctx->blocked == NGX_HTTP_WAF_TRUE) {
            v->len = 4;
            strcpy((char*)v->data, "true");
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: This request has been blocked.");
        }
        else {
            v->len = 5;
            strcpy((char*)v->data, "false");
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: This request was not blocked.");
        }
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The variable calculation process is fully completed (waf_blocked).");
    return NGX_OK;
}


ngx_int_t ngx_http_waf_rule_type_get_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Start the variable calculation process (waf_rule_type).");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (ctx == NULL) {
        v->len = 0;
        v->data = NULL;
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: No context.");
    }
    else {
        v->len = strlen((char*)ctx->rule_type);
        v->data = ngx_palloc(r->pool, sizeof(u_char) * ngx_max(v->len, 2));
        strcpy((char*)v->data, (char*)ctx->rule_type);
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The variable calculation process is fully completed (waf_rule_type).");
    return NGX_OK;
}


ngx_int_t ngx_http_waf_rule_deatils_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Start the variable calculation process (waf_rule_deatils).");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (ctx == NULL) {
        v->len = 0;
        v->data = NULL;
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: No context.");
    }
    else {
        v->len = strlen((char*)ctx->rule_deatils);
        v->data = ngx_palloc(r->pool, sizeof(u_char) * ngx_max(v->len, 2));
        strcpy((char*)v->data, (char*)ctx->rule_deatils);
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The variable calculation process is fully completed (waf_rule_deatils).");
    return NGX_OK;
}


ngx_int_t ngx_http_waf_spend_handler(ngx_http_request_t* r, ngx_http_variable_value_t* v, uintptr_t data) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Start the variable calculation process (waf_spend).");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (ctx == NULL) {
        v->len = 0;
        v->data = NULL;
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: No context.");
    }
    else {
        u_char text[32] = { 0 };
        sprintf((char*)text, "%.5lf", ctx->spend);
        v->len = ngx_strlen(text);
        v->data = ngx_palloc(r->pool, sizeof(u_char) * v->len);
        strcpy((char*)v->data, (char*)text);
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The variable calculation process is fully completed (waf_spend).");
    return NGX_OK;
}


ngx_int_t ngx_http_waf_init_after_load_config(ngx_conf_t* cf) {
    ngx_http_handler_pt* h;
    ngx_http_core_main_conf_t* cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_waf_handler_access_phase;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_waf_handler_content_phase;

    ngx_str_t waf_log_name = ngx_string("waf_log");
    ngx_http_variable_t* waf_log = ngx_http_add_variable(cf, &waf_log_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_log->get_handler = ngx_http_waf_log_get_handler;
    waf_log->set_handler = NULL;

    ngx_str_t waf_blocking_log_name = ngx_string("waf_blocking_log");
    ngx_http_variable_t* waf_blocking_log = ngx_http_add_variable(cf, &waf_blocking_log_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_blocking_log->get_handler = ngx_http_waf_blocking_log_get_handler;
    waf_blocking_log->set_handler = NULL;

    ngx_str_t waf_blocked_name = ngx_string("waf_blocked");
    ngx_http_variable_t* waf_blocked = ngx_http_add_variable(cf, &waf_blocked_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_blocked->get_handler = ngx_http_waf_blocked_get_handler;
    waf_blocked->set_handler = NULL;

    ngx_str_t waf_rule_type_name = ngx_string("waf_rule_type");
    ngx_http_variable_t* waf_rule_type = ngx_http_add_variable(cf, &waf_rule_type_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_rule_type->get_handler = ngx_http_waf_rule_type_get_handler;
    waf_rule_type->set_handler = NULL;

    ngx_str_t waf_rule_details_name = ngx_string("waf_rule_details");
    ngx_http_variable_t* waf_rule_details = ngx_http_add_variable(cf, &waf_rule_details_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_rule_details->get_handler = ngx_http_waf_rule_deatils_handler;
    waf_rule_details->set_handler = NULL;

    ngx_str_t waf_spend_name = ngx_string("waf_spend");
    ngx_http_variable_t* waf_spend = ngx_http_add_variable(cf, &waf_spend_name, NGX_HTTP_VAR_NOCACHEABLE);
    waf_spend->get_handler = ngx_http_waf_spend_handler;
    waf_spend->set_handler = NULL;

    return NGX_OK;
}


ngx_int_t ngx_http_waf_shm_zone_cc_deny_init(ngx_shm_zone_t *zone, void *data) {
    ngx_slab_pool_t  *shpool = (ngx_slab_pool_t *) zone->shm.addr;
    ngx_http_waf_loc_conf_t* loc_conf = (ngx_http_waf_loc_conf_t*)(zone->data);

    lru_cache_init(&loc_conf->ip_access_statistics, SIZE_MAX, slab_pool, shpool);

    return NGX_OK;
}


ngx_int_t load_into_container(ngx_conf_t* cf, const char* file_name, void* container, ngx_int_t mode) {
    FILE* fp = fopen(file_name, "r");
    ngx_int_t line_number = 0;
    ngx_str_t line;
    char* str = ngx_palloc(cf->pool, sizeof(char) * NGX_HTTP_WAF_RULE_MAX_LEN);
    if (fp == NULL) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (mode == 3) {
        ngx_http_waf_in = fp;
        if (ngx_http_waf_parse(container, cf->pool) != 0) {
            return NGX_HTTP_WAF_FAIL;
        }
        // print_code(container);
    } else {
        while (fgets(str, NGX_HTTP_WAF_RULE_MAX_LEN - 16, fp) != NULL) {
            ngx_regex_compile_t   regex_compile;
            u_char                errstr[NGX_MAX_CONF_ERRSTR];
            ngx_regex_elt_t* ngx_regex_elt;
            ipv4_t ipv4;
            inx_addr_t inx_addr;
#if (NGX_HAVE_INET6)
            ipv6_t ipv6;
#endif
            ip_trie_node_t* ip_trie_node = NULL;
            ++line_number;
            line.data = (u_char*)str;
            #ifdef __STDC_LIB_EXT1__
                line.len = strnlen_s((char*)str. sizeof(char) * NGX_HTTP_WAF_RULE_MAX_LEN);
            #else
            line.len = strlen((char*)str);
            #endif

            memset(&ipv4, 0, sizeof(ipv4_t));
            memset(&inx_addr, 0, sizeof(inx_addr_t));
#if (NGX_HAVE_INET6)
            memset(&ipv6, 0, sizeof(ipv6_t));
#endif

            if (line.len <= 0) {
                continue;
            }

            if (line.data[line.len - 1] == '\n') {
                line.data[line.len - 1] = '\0';
                --(line.len);
                if (line.len <= 0) {
                    continue;
                }
                if (line.data[line.len - 1] == '\r') {
                    line.data[line.len - 1] = '\0';
                    --(line.len);
                }
            }

            if (line.len <= 0) {
                continue;
            }

            switch (mode) {
            case 0:
                ngx_memzero(&regex_compile, sizeof(ngx_regex_compile_t));
                regex_compile.pattern = line;
                regex_compile.pool = cf->pool;
                regex_compile.err.len = NGX_MAX_CONF_ERRSTR;
                regex_compile.err.data = errstr;
                if (ngx_regex_compile(&regex_compile) != NGX_OK) {
                    char temp[NGX_HTTP_WAF_RULE_MAX_LEN] = { 0 };
                    ngx_http_waf_to_c_str((u_char*)temp, line);
                    ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                        "ngx_waf: In %s:%d, [%s] is not a valid regex string.", file_name, line_number, temp);
                    return NGX_HTTP_WAF_FAIL;
                }
                ngx_regex_elt = ngx_array_push((ngx_array_t*)container);
                ngx_regex_elt->name = ngx_palloc(cf->pool, sizeof(u_char) * NGX_HTTP_WAF_RULE_MAX_LEN);
                ngx_http_waf_to_c_str(ngx_regex_elt->name, line);
                ngx_regex_elt->regex = regex_compile.regex;
                break;
            case 1:
                if (ngx_http_waf_parse_ipv4(line, &ipv4) != NGX_HTTP_WAF_SUCCESS) {
                    ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                        "ngx_waf: In %s:%d, [%s] is not a valid IPV4 string.", file_name, line_number, ipv4.text);
                    return NGX_HTTP_WAF_FAIL;
                }
                inx_addr.ipv4.s_addr = ipv4.prefix;
                if (ip_trie_add((ip_trie_t*)container, &inx_addr, ipv4.suffix_num, ipv4.text, 32) != NGX_HTTP_WAF_SUCCESS) {
                    if (ip_trie_find((ip_trie_t*)container, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
                        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                            "ngx_waf: In %s:%d, the two address blocks [%s] and [%s] have overlapping parts.", 
                            file_name, line_number, ipv4.text, ip_trie_node->data);
                    } else {
                        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                            "ngx_waf: In %s:%d, [%s] cannot be stored because the memory allocation failed.", 
                            file_name, line_number, ipv4.text);
                            return NGX_HTTP_WAF_FAIL;
                    }
                }
                break;
#if (NGX_HAVE_INET6)
            case 2:
                if (ngx_http_waf_parse_ipv6(line, &ipv6) != NGX_HTTP_WAF_SUCCESS) {
                    ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                        "ngx_waf: In %s:%d, [%s] is not a valid IPV6 string.", file_name, line_number, ipv6.text);
                    return NGX_HTTP_WAF_FAIL;
                }
                ngx_memcpy(inx_addr.ipv6.s6_addr, ipv6.prefix, 16);
                if (ip_trie_add((ip_trie_t*)container, &inx_addr, ipv6.suffix_num, ipv6.text, 64) != NGX_HTTP_WAF_SUCCESS) {
                    if (ip_trie_find((ip_trie_t*)container, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
                        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                            "ngx_waf: In %s:%d, the two address blocks [%s] and [%s] have overlapping parts.", 
                            file_name, line_number, ipv6.text, ip_trie_node->data);
                    } else {
                        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, 
                            "ngx_waf: In %s:%d, [%s] cannot be stored because the memory allocation failed.", 
                            file_name, line_number, ipv6.text);
                            return NGX_HTTP_WAF_FAIL;
                    }
                }
                break;
#endif
            }
        }
    }

    
    fclose(fp);
    ngx_pfree(cf->pool, str);
    return NGX_HTTP_WAF_SUCCESS;
}


ngx_http_waf_loc_conf_t* ngx_http_waf_init_conf(ngx_conf_t* cf) {
    static u_char s_rand_str[129] = { 0 };
    if (s_rand_str[0] == '\0') {
        ngx_http_waf_rand_str(s_rand_str, 128);
    }

    ngx_http_waf_loc_conf_t* conf = NULL;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    ngx_strcpy(conf->random_str, s_rand_str);
    conf->is_alloc = NGX_HTTP_WAF_FALSE;
    conf->waf = NGX_CONF_UNSET;
    conf->waf_rule_path.len = NGX_CONF_UNSET_SIZE;
    conf->waf_mode = 0;
    conf->waf_verify_bot = NGX_CONF_UNSET;
    conf->waf_verify_bot_type = NGX_CONF_UNSET;
    conf->waf_verify_bot_google_ua_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_bing_ua_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_baidu_ua_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_yandex_ua_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_google_domain_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_bing_domain_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_baidu_domain_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_verify_bot_yandex_domain_regexp = NGX_CONF_UNSET_PTR;
    conf->waf_under_attack = NGX_CONF_UNSET;
    conf->waf_under_attack_html = NGX_CONF_UNSET_PTR;
    conf->waf_under_attack_len = NGX_CONF_UNSET_SIZE;
    conf->waf_captcha = NGX_CONF_UNSET;
    conf->waf_captcha_html = NGX_CONF_UNSET_PTR;
    conf->waf_captcha_html_len = NGX_CONF_UNSET_SIZE;
    conf->waf_captcha_expire = NGX_CONF_UNSET;
    conf->waf_captcha_reCAPTCHAv3_score = NGX_CONF_UNSET;
    conf->waf_cc_deny = NGX_CONF_UNSET;
    conf->waf_cc_deny_limit = NGX_CONF_UNSET;
    conf->waf_cc_deny_duration = NGX_CONF_UNSET;
    conf->waf_cc_deny_cycle = NGX_CONF_UNSET;
    conf->waf_cc_deny_shm_zone_size =  NGX_CONF_UNSET;
    conf->waf_cache = NGX_CONF_UNSET;
    conf->waf_cache_capacity = NGX_CONF_UNSET;
    conf->waf_http_status = 403;
    conf->waf_http_status_cc = 503;
    conf->shm_zone_cc_deny = NULL;
    conf->ip_access_statistics = NULL;
    conf->is_custom_priority = NGX_HTTP_WAF_FALSE;

    conf->black_url = NGX_CONF_UNSET_PTR;
    conf->black_args = NGX_CONF_UNSET_PTR;
    conf->black_ua = NGX_CONF_UNSET_PTR;
    conf->black_referer = NGX_CONF_UNSET_PTR;
    conf->black_cookie = NGX_CONF_UNSET_PTR;
    conf->black_post = NGX_CONF_UNSET_PTR;
    conf->white_url = NGX_CONF_UNSET_PTR;
    conf->white_referer = NGX_CONF_UNSET_PTR;
    conf->white_ipv4 = NGX_CONF_UNSET_PTR;
    conf->black_ipv4 = NGX_CONF_UNSET_PTR;
#if (NGX_HAVE_INET6)
    conf->white_ipv6 = NGX_CONF_UNSET_PTR;
    conf->black_ipv6 = NGX_CONF_UNSET_PTR;
#endif

    conf->check_proc[0] = ngx_http_waf_handler_check_white_ip;
    conf->check_proc[1] = ngx_http_waf_handler_check_black_ip;
    conf->check_proc[2] = ngx_http_waf_handler_verify_bot;
    conf->check_proc[3] = ngx_http_waf_handler_check_cc;
    conf->check_proc[4] = ngx_http_waf_handler_captcha;
    conf->check_proc[5] = ngx_http_waf_handler_under_attack;
    conf->check_proc[6] = ngx_http_waf_handler_check_white_url;
    conf->check_proc[7] = ngx_http_waf_handler_check_black_url;
    conf->check_proc[8] = ngx_http_waf_handler_check_black_args;
    conf->check_proc[9] = ngx_http_waf_handler_check_black_user_agent;
    conf->check_proc[10] = ngx_http_waf_handler_check_white_referer;
    conf->check_proc[11] = ngx_http_waf_handler_check_black_referer;
    conf->check_proc[12] = ngx_http_waf_handler_check_black_cookie;
    conf->check_proc[13] = ngx_http_waf_vm_exec;
    conf->check_proc[14] = ngx_http_waf_handler_check_black_post;

    return conf;
}


ngx_int_t ngx_http_waf_init_cc_shm(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf) {
    ngx_str_t name;
    u_char* raw_name = ngx_pnalloc(cf->pool, sizeof(u_char) * 512);

    ngx_http_waf_rand_str(raw_name, 16);
    strcat((char*)raw_name, NGX_HTTP_WAF_SHARE_MEMORY_CC_DNEY_NAME);
    name.data = raw_name;
    name.len = strlen((char*)raw_name);

    conf->shm_zone_cc_deny = ngx_shared_memory_add(cf, &name, 
                                                        conf->waf_cc_deny_shm_zone_size, 
                                                        &ngx_http_waf_module);

    if (conf->shm_zone_cc_deny == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, NGX_ENOMOREFILES, 
                "ngx_waf: failed to add shared memory");
        return NGX_HTTP_WAF_FAIL;
    }

    conf->shm_zone_cc_deny->init = ngx_http_waf_shm_zone_cc_deny_init;
    conf->shm_zone_cc_deny->data = conf;

    return NGX_HTTP_WAF_SUCCESS;
}


ngx_int_t ngx_http_waf_init_lru_cache(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf) {
    conf->black_url_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));
    conf->black_args_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));
    conf->black_ua_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));
    conf->black_referer_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));
    conf->black_cookie_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));
    conf->white_url_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));
    conf->white_referer_inspection_cache = ngx_pcalloc(cf->pool, sizeof(lru_cache_t));

    lru_cache_init(&conf->black_url_inspection_cache, 
                    conf->waf_cache_capacity, gernal_pool, cf->pool);

    lru_cache_init(&conf->black_args_inspection_cache, 
                    conf->waf_cache_capacity, gernal_pool, cf->pool);

    lru_cache_init(&conf->black_ua_inspection_cache, 
                    conf->waf_cache_capacity, gernal_pool, cf->pool);

    lru_cache_init(&conf->black_referer_inspection_cache, 
                    conf->waf_cache_capacity, gernal_pool, cf->pool);

    lru_cache_init(&conf->black_cookie_inspection_cache, 
                    conf->waf_cache_capacity, gernal_pool, cf->pool);

    lru_cache_init(&conf->white_url_inspection_cache, 
                    conf->waf_cache_capacity, gernal_pool, cf->pool);
    
    lru_cache_init(&conf->white_referer_inspection_cache, 
                    conf->waf_cache_capacity, gernal_pool, cf->pool);

    return NGX_HTTP_WAF_SUCCESS;
}


ngx_int_t ngx_http_waf_load_all_rule(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf) {
    char* full_path = ngx_palloc(cf->pool, sizeof(char) * NGX_HTTP_WAF_RULE_MAX_LEN);
    char* end = ngx_http_waf_to_c_str((u_char*)full_path, conf->waf_rule_path);

    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_IPV4_FILE, conf->black_ipv4, 1);
#if (NGX_HAVE_INET6)
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_IPV6_FILE, conf->black_ipv6, 2);
#endif
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_URL_FILE, conf->black_url, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_ARGS_FILE, conf->black_args, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_UA_FILE, conf->black_ua, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_REFERER_FILE, conf->black_referer, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_COOKIE_FILE, conf->black_cookie, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_POST_FILE, conf->black_post, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_WHITE_IPV4_FILE, conf->white_ipv4, 1);
#if (NGX_HAVE_INET6)
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_WHITE_IPV6_FILE, conf->white_ipv6, 2);
#endif
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_WHITE_URL_FILE, conf->white_url, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_WHITE_REFERER_FILE, conf->white_referer, 0);
    ngx_http_waf_check_and_load_conf(cf, full_path, end, NGX_HTTP_WAF_ADVANCED_FILE, conf->advanced_rule, 3);
    

    ngx_pfree(cf->pool, full_path);

    return NGX_HTTP_WAF_SUCCESS;
}


ngx_int_t ngx_http_waf_alloc_memory(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf) {
    if (conf->is_alloc == NGX_HTTP_WAF_SUCCESS) {
        return NGX_HTTP_WAF_SUCCESS;
    }

    conf->black_url = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->black_args = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->black_ua = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->black_referer = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->black_cookie = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->black_post = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->white_url = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->white_referer = ngx_array_create(cf->pool, 1, sizeof(ngx_regex_elt_t));
    conf->white_ipv4 = ngx_pcalloc(cf->pool, sizeof(ip_trie_t));
    conf->black_ipv4 = ngx_pcalloc(cf->pool, sizeof(ip_trie_t));
#if (NGX_HAVE_INET6)
    conf->white_ipv6 = ngx_pcalloc(cf->pool, sizeof(ip_trie_t));
    conf->black_ipv6 = ngx_pcalloc(cf->pool, sizeof(ip_trie_t));
#endif
    conf->advanced_rule = ngx_pcalloc(cf->pool, sizeof(UT_array));

    if (conf->black_url == NULL
    ||  conf->black_args == NULL
    ||  conf->black_ua == NULL
    ||  conf->black_referer == NULL
    ||  conf->black_cookie == NULL
    ||  conf->black_post == NULL
    ||  conf->white_url == NULL
    ||  conf->white_referer == NULL
    ||  conf->white_ipv4 == NULL
    ||  conf->black_ipv4 == NULL
#if (NGX_HAVE_INET6)
    ||  conf->white_ipv6 == NULL
    ||  conf->black_ipv6 == NULL
#endif
    ||  conf->advanced_rule == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NGX_HTTP_WAF_FAIL;
    }

    UT_icd icd = ngx_http_waf_make_utarray_vm_code_icd();
    utarray_init(conf->advanced_rule, &icd);


    if (ip_trie_init(conf->white_ipv4, gernal_pool, cf->pool, AF_INET) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NGX_HTTP_WAF_FAIL;
    }

    if (ip_trie_init(conf->black_ipv4, gernal_pool, cf->pool, AF_INET) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NGX_HTTP_WAF_FAIL;
    }

#if (NGX_HAVE_INET6)
    if (ip_trie_init(conf->white_ipv6, gernal_pool, cf->pool, AF_INET6) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NGX_HTTP_WAF_FAIL;
    }

    if (ip_trie_init(conf->black_ipv6, gernal_pool, cf->pool, AF_INET6) != NGX_HTTP_WAF_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "ngx_waf: initialization failed");
        return NGX_HTTP_WAF_FAIL;
    }
#endif

    conf->is_alloc = NGX_HTTP_WAF_TRUE;

    return NGX_HTTP_WAF_SUCCESS;
}


ngx_int_t ngx_http_waf_free_memory(ngx_conf_t* cf, ngx_http_waf_loc_conf_t* conf) {
    if (conf->is_alloc == NGX_HTTP_WAF_TRUE) {
        ngx_pfree(cf->pool, conf->black_url);
        ngx_pfree(cf->pool, conf->black_args);
        ngx_pfree(cf->pool, conf->black_ua);
        ngx_pfree(cf->pool, conf->black_referer);
        ngx_pfree(cf->pool, conf->black_cookie);
        ngx_pfree(cf->pool, conf->black_post);
        ngx_pfree(cf->pool, conf->white_url);
        ngx_pfree(cf->pool, conf->white_referer);
        ngx_pfree(cf->pool, conf->white_ipv4);
        ngx_pfree(cf->pool, conf->black_ipv4);
#if (NGX_HAVE_INET6)
        ngx_pfree(cf->pool, conf->white_ipv6);
        ngx_pfree(cf->pool, conf->black_ipv6);
#endif
        ngx_pfree(cf->pool, conf->advanced_rule);

        conf->black_url = NGX_CONF_UNSET_PTR;
        conf->black_args = NGX_CONF_UNSET_PTR;
        conf->black_ua = NGX_CONF_UNSET_PTR;
        conf->black_referer = NGX_CONF_UNSET_PTR;
        conf->black_cookie = NGX_CONF_UNSET_PTR;
        conf->black_post = NGX_CONF_UNSET_PTR;
        conf->white_url = NGX_CONF_UNSET_PTR;
        conf->white_referer = NGX_CONF_UNSET_PTR;
        conf->white_ipv4 = NGX_CONF_UNSET_PTR;
        conf->black_ipv4 = NGX_CONF_UNSET_PTR;
#if (NGX_HAVE_INET6)
        conf->white_ipv6 = NGX_CONF_UNSET_PTR;
        conf->black_ipv6 = NGX_CONF_UNSET_PTR;
#endif

        conf->is_alloc = NGX_HTTP_WAF_FALSE;
    }

    return NGX_HTTP_WAF_SUCCESS;
}
