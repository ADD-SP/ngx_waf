%{
    #include <ngx_http_waf_module_type.h>
    #include <ngx_http_waf_module_util.h>
    #include <ngx_http_waf_module_lexer.h>
    #include <math.h>
    #include <stdio.h>
    #include <utarray.h>
    #include <ngx_core.h>
    int ngx_http_waf_lex (void);
    void ngx_http_waf_error (UT_array* array, ngx_pool_t* pool, const char* msg);
    void ngx_http_waf_gen_push_str_code(UT_array* array, char* str);
    void ngx_http_waf_gen_push_client_ip_code(UT_array* array);
    void ngx_http_waf_gen_push_url_code(UT_array* array);
    void ngx_http_waf_gen_push_user_agent_code(UT_array* array);
    void ngx_http_waf_gen_push_referer_code(UT_array* array);
    void ngx_http_waf_gen_push_query_string_code(UT_array* array, char* index);
    void ngx_http_waf_gen_push_header_in_code(UT_array* array, char* index);
    void ngx_http_waf_gen_push_cookie_code(UT_array* array, char* index);
    void ngx_http_waf_gen_int_code(UT_array* array, int num);
    void ngx_http_waf_gen_push_op_not_code(UT_array* array);
    void ngx_http_waf_gen_op_and_code(UT_array* array);
    void ngx_http_waf_gen_op_or_code(UT_array* array);
    void ngx_http_waf_gen_op_matches_code(UT_array* array);
    void ngx_http_waf_gen_op_contains_code(UT_array* array);
    void ngx_http_waf_gen_op_equals_code(UT_array* array);
    void ngx_http_waf_gen_op_belong_to_code(UT_array* array);
    void ngx_http_waf_gen_op_sqli_detn_code(UT_array* array);
    void ngx_http_waf_gen_op_xss_detn_code(UT_array* array);
    void ngx_http_waf_gen_act_ret_code(UT_array* array, int http_status);
    void ngx_http_waf_gen_act_allow_code(UT_array* array);
%}

%define api.prefix {ngx_http_waf_}
%parse-param {UT_array* array} {ngx_pool_t* pool}

// %nterm<code> id_rule if_rule do_rule conditon conditon_ex primary rule

%nterm<push_str_code_info> str_operand
%nterm<push_op_code_pt> str_op ip_op  

%token<id_val> token_id
%token<str_val> token_str token_index
%token<int_val> token_int

%token keyword_id keyword_if keyword_do keyword_or keyword_allow
%token keyword_and keyword_matches keyword_equals
%token token_break_line token_blank keyword_not
%token keyword_url keyword_contains keyword_return
%token keyword_query_string keyword_user_agent keyword_belong_to
%token keyword_referer keyword_client_ip keyword_header_in
%token keyword_sqli_detn keyword_xss_detn keyword_cookie

%union {
    int             int_val;
    unsigned int    uint_val;
    char            id_val[256];
    char            str_val[256];
    void            (*push_op_code_pt)(UT_array* array);
    struct {
        int argc;
        void (*no_str_pt)(UT_array* array);
        void (*one_str_pt)(UT_array* array, char* str);
        char* argv[4];
    } push_str_code_info;
}


%%



base:
        rule end     
        {}

    |   %empty
        {}
    ;

rule:
        id_rule if_rule do_rule         
        {}
    ;
end:
        token_break_line token_break_line rule { }
    |   token_break_line token_break_line    {  }
    |   %empty { }
    ;


id_rule:
        keyword_id ':' token_blank token_id token_break_line            
        { ngx_http_waf_gen_push_str_code(array, $4); }
    ;

if_rule:
        keyword_if ':' token_blank conditon token_break_line            
        {  }
    ;

do_rule:
        keyword_do ':' token_blank keyword_return '(' token_int ')'     
        { 
            ngx_http_waf_gen_act_ret_code(array, $6);                   
        }

    |   keyword_do ':' token_blank keyword_allow
        { 
            ngx_http_waf_gen_act_allow_code(array);                   
        }
    ;

conditon:   
        conditon keyword_and conditon_ex    
        { 
            ngx_http_waf_gen_op_and_code(array);
        }

	|	conditon_ex                         
        {  }
	;

conditon_ex: 	
        conditon_ex keyword_or primary  
        { 
            ngx_http_waf_gen_op_or_code(array);
        }
	|	primary                        
        {  }
	;
primary:	
        '(' conditon ')'   {  }

    |   keyword_not token_blank '(' conditon ')'
        {
            ngx_http_waf_gen_push_op_not_code(array);
        }

    |   str_operand str_op str_operand
        {
            switch ($3.argc) {
                case 0:
                    $3.no_str_pt(array);
                    break;
                case 1:
                    $3.one_str_pt(array, $3.argv[0]);
                    break;
                default:
                    YYABORT;
            }

            switch ($1.argc) {
                case 0:
                    $1.no_str_pt(array);
                    break;
                case 1:
                    $1.one_str_pt(array, $1.argv[0]);
                    break;
                default:
                    YYABORT;
            }
            $2(array);
        }

    |   str_operand token_blank keyword_not str_op str_operand
        {
            switch ($5.argc) {
                case 0:
                    $5.no_str_pt(array);
                    break;
                case 1:
                    $5.one_str_pt(array, $5.argv[0]);
                    break;
                default:
                    YYABORT;
            }

            switch ($1.argc) {
                case 0:
                    $1.no_str_pt(array);
                    break;
                case 1:
                    $1.one_str_pt(array, $1.argv[0]);
                    break;
                default:
                    YYABORT;
            }
            $4(array);
            ngx_http_waf_gen_push_op_not_code(array);
        }

    |   keyword_sqli_detn token_blank str_operand 
        {
            switch ($3.argc) {
                case 0:
                    $3.no_str_pt(array);
                    break;
                case 1:
                    $3.one_str_pt(array, $3.argv[0]);
                    break;
                default:
                    YYABORT;
            }
            ngx_http_waf_gen_op_sqli_detn_code(array);
        }

    |   keyword_xss_detn token_blank str_operand 
        {
            switch ($3.argc) {
                case 0:
                    $3.no_str_pt(array);
                    break;
                case 1:
                    $3.one_str_pt(array, $3.argv[0]);
                    break;
                default:
                    YYABORT;
            }
            ngx_http_waf_gen_op_xss_detn_code(array);
        }

    |   keyword_client_ip ip_op str_operand
        {
            switch ($3.argc) {
                case 0:
                    $3.no_str_pt(array);
                    break;
                case 1:
                    $3.one_str_pt(array, $3.argv[0]);
                    break;
                default:
                    YYABORT;
            }
            ngx_http_waf_gen_push_client_ip_code(array);
            $2(array);
        }

    |   keyword_client_ip token_blank keyword_not ip_op str_operand
        {
            switch ($5.argc) {
                case 0:
                    $5.no_str_pt(array);
                    break;
                case 1:
                    $5.one_str_pt(array, $5.argv[0]);
                    break;
                default:
                    YYABORT;
            }
            ngx_http_waf_gen_push_client_ip_code(array);
            $4(array);
            ngx_http_waf_gen_push_op_not_code(array);
        }

	;

str_operand:
        keyword_url
        {
            $$.argc = 0;
            $$.no_str_pt = ngx_http_waf_gen_push_url_code;
        }

    |   keyword_user_agent
        {
            $$.argc = 0;
            $$.no_str_pt = ngx_http_waf_gen_push_user_agent_code;
        }

    |   keyword_referer
        {
            $$.argc = 0;
            $$.no_str_pt = ngx_http_waf_gen_push_referer_code;
        }

    |   token_str
        {
            $$.argc = 1;
            $$.one_str_pt = ngx_http_waf_gen_push_str_code;
            $$.argv[0] = strdup($1);
        }

    |   keyword_header_in token_index
        {
            $$.argc = 1;
            $$.one_str_pt = ngx_http_waf_gen_push_header_in_code;
            $$.argv[0] = strdup($2);
        }

    |   keyword_query_string token_index
        {
            $$.argc = 1;
            $$.one_str_pt = ngx_http_waf_gen_push_query_string_code;
            $$.argv[0] = strdup($2);
        }

    |   keyword_cookie token_index
        {
            $$.argc = 1;
            $$.one_str_pt = ngx_http_waf_gen_push_cookie_code;
            $$.argv[0] = strdup($2);
        }
    ;

str_op:
        keyword_contains
        {
            $$ = ngx_http_waf_gen_op_contains_code;
        }

    |   keyword_matches
        {
            $$ = ngx_http_waf_gen_op_matches_code;
        }

    |   keyword_equals
        {
            $$ = ngx_http_waf_gen_op_equals_code;
        }
    ;

ip_op:
        keyword_equals
        {
            $$ = ngx_http_waf_gen_op_equals_code;
        }

    |   keyword_belong_to
        {
            $$ = ngx_http_waf_gen_op_belong_to_code;
        }
    ;
%%


void
ngx_http_waf_gen_push_str_code(UT_array* array, char* str) {
    vm_code_t code;

    code.type = VM_CODE_PUSH_STR;
    code.argv.argc = 1;
    code.argv.type[0] = VM_DATA_STR;
    code.argv.value[0].str_val.data = (u_char*)strdup(str);
    code.argv.value[0].str_val.len = strlen(str);

    utarray_push_back(array, &code);
    free(code.argv.value[0].str_val.data);
}


void ngx_http_waf_gen_push_query_string_code(UT_array* array, char* index) {
    vm_code_t code;
    size_t len = strlen(index);
    code.type = VM_CODE_PUSH_QUERY_STRING;
    code.argv.argc = 1;
    code.argv.type[0] = VM_DATA_STR;
    code.argv.value[0].str_val.data = (u_char*)strdup(index);
    code.argv.value[0].str_val.len = len;

    utarray_push_back(array, &code);
    free(code.argv.value[0].str_val.data);
}


void ngx_http_waf_gen_push_header_in_code(UT_array* array, char* index) {
    vm_code_t code;
    size_t len = strlen(index);
    code.type = VM_CODE_PUSH_HEADER_IN;
    code.argv.argc = 1;
    code.argv.type[0] = VM_DATA_STR;
    code.argv.value[0].str_val.data = (u_char*)strdup(index);
    code.argv.value[0].str_val.len = len;

    utarray_push_back(array, &code);
    free(code.argv.value[0].str_val.data);
}


void ngx_http_waf_gen_push_cookie_code(UT_array* array, char* index) {
    vm_code_t code;
    size_t len = strlen(index);
    code.type = VM_CODE_PUSH_COOKIE;
    code.argv.argc = 1;
    code.argv.type[0] = VM_DATA_STR;
    code.argv.value[0].str_val.data = (u_char*)strdup(index);
    code.argv.value[0].str_val.len = len;

    utarray_push_back(array, &code);
    free(code.argv.value[0].str_val.data);
}


void ngx_http_waf_gen_push_client_ip_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_PUSH_CLIENT_IP;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_push_url_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_PUSH_URL;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_push_user_agent_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_PUSH_USER_AGENT;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_push_referer_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_PUSH_REFERER;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_int_code(UT_array* array, int num) {
    vm_code_t code;
    code.type = VM_CODE_PUSH_INT;
    code.argv.argc = 1;
    code.argv.type[0] = VM_DATA_INT;
    code.argv.value[0].int_val = num;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_push_op_not_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_NOT;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_op_and_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_AND;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_op_or_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_OR;;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}

void
ngx_http_waf_gen_op_matches_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_MATCHES;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}



void
ngx_http_waf_gen_op_contains_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_CONTAINS;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_op_equals_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_EQUALS;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_op_belong_to_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_BELONG_TO;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_op_sqli_detn_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_SQLI_DETN;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_op_xss_detn_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_OP_XSS_DETN;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_act_ret_code(UT_array* array, int http_status) {
    vm_code_t code;
    code.type = VM_CODE_ACT_RETURN;
    code.argv.argc = 1;
    code.argv.type[0] = VM_DATA_INT;
    code.argv.value[0].int_val = http_status;
    utarray_push_back(array, &code);
}


void
ngx_http_waf_gen_act_allow_code(UT_array* array) {
    vm_code_t code;
    code.type = VM_CODE_ACT_ALLOW;
    code.argv.argc = 0;
    utarray_push_back(array, &code);
}