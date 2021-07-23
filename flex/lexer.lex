%option noyywrap
%option noinput
%option nounput
%option yylineno
%option outfile="src/ngx_http_waf_module_lexer.c" header-file="inc/ngx_http_waf_module_lexer.h"
%option prefix="ngx_http_waf_"

%{
    #include <stdio.h>
    #include <math.h>
    #include <utarray.h>
    #include <ngx_core.h>
    #include <ngx_http_waf_module_parser.tab.h>
    // #define VM_DEBUG
    void ngx_http_waf_error(UT_array* array, ngx_pool_t* pool, const char* msg);
%}


KEYWORD_ID              ^(?i:id)

KEYWORD_IF              ^(?i:if)

KEYWORD_DO              ^(?i:do)

KEYWORD_URL             (?i:url)

KEYWORD_QUERY_STRING    (?i:query_string)

KEYWORD_USER_AGENT      (?i:user_agent)

KEYWORD_REFERER         (?i:referer)

KEYWORD_CLIENT_IP       (?i:client_ip)

KEYWORD_HEADER_IN       (?i:header_in)

KEYWORD_COOKIE          (?i:cookie)

KEYWORD_CONTAINS        [[:blank:]]+(?i:contains)[[:blank:]]+

KEYWORD_MATCHES         [[:blank:]]+(?i:matches)[[:blank:]]+

KEYWORD_EQUALS          [[:blank:]]+(?i:equals)[[:blank:]]+

KEYWORD_BELONG_TO       [[:blank:]]+(?i:belong_to)[[:blank:]]+

KEYWORD_SQLI_DETN       (?i:sqli_detn)

KEYWORD_XSS_DETN        (?i:xss_detn)

KEYWORD_RETURN          (?i:return)

KEYWORD_ALLOW           (?i:allow)

KEYWORD_NOT             (?i:not)

KEYWORD_OR              [[:blank:]]+(?i:or)[[:blank:]]+

KEYWORD_AND             [[:blank:]]+(?i:and)[[:blank:]]+

INDEX                   \[((-|_|[[:alnum:]])+)\]

ID                      (_|[[:alpha:]])((_|[[:alnum:]]){1,49})

STRING                  (\"[^\"]*\")|('[^']*')

INTEGER                 (-)?[[:digit:]]+

BREAK_LINE              (\r)?\n


%%


{KEYWORD_ID}            { 
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_ID\n");
                            #endif
                            return keyword_id; 
                        }

{KEYWORD_IF}            {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_IF\n");
                            #endif
                            return keyword_if; 
                        }

{KEYWORD_DO}            {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_DO\n");
                            #endif
                            return keyword_do; 
                        }


{KEYWORD_URL}           {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_URL\n");
                            #endif
                            return keyword_url; 
                        }

{KEYWORD_QUERY_STRING}  {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_QUERY_STRING\n");
                            #endif
                            return keyword_query_string; 
                        }


{KEYWORD_USER_AGENT}    {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_USER_AGENT\n");
                            #endif
                            return keyword_user_agent; 
                        }

{KEYWORD_REFERER}       {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_REFERER\n");
                            #endif
                            return keyword_referer; 
                        }


{KEYWORD_CLIENT_IP}     {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_CLIENT_IP\n");
                            #endif
                            return keyword_client_ip; 
                        }


{KEYWORD_HEADER_IN}     {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_HEADER_IN\n");
                            #endif
                            return keyword_header_in; 
                        }

{KEYWORD_COOKIE}        {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_COOKIE\n");
                            #endif
                            return keyword_cookie; 
                        }

{KEYWORD_CONTAINS}      {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_CONTAINS\n");
                            #endif
                            return keyword_contains; 
                        }

{KEYWORD_MATCHES}       {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_MATCHES\n");
                            #endif
                            return keyword_matches; 
                        }

{KEYWORD_EQUALS}        {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_EQUALS\n");
                            #endif
                            return keyword_equals; 
                        }

{KEYWORD_BELONG_TO}     {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_BELONG_TO");
                            #endif
                            return keyword_belong_to; 
                        }

{KEYWORD_SQLI_DETN}     {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_SQLI_DETN\n");
                            #endif
                            return keyword_sqli_detn; 
                        }

{KEYWORD_XSS_DETN}      {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_XSS_DETN\n");
                            #endif
                            return keyword_xss_detn; 
                        }

{KEYWORD_RETURN}        {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_RETURN\n");
                            #endif
                            return keyword_return; 
                        }

{KEYWORD_ALLOW}        {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_ALLOW\n");
                            #endif
                            return keyword_allow; 
                        }

{INDEX}                 {
                            strcpy(ngx_http_waf_lval.str_val, yytext + 1);
                            ngx_http_waf_lval.str_val[yyleng - 2] = '\0';
                            #ifdef VM_DEBUG
                            printf("Lexer - INDEX: %s\n", yytext);
                            #endif
                            return token_index; 
                        }


{BREAK_LINE}            { 
                            #ifdef VM_DEBUG
                            printf("Lexer - BREAK_LINE\n");
                            #endif
                            return token_break_line; 
                        }

{KEYWORD_NOT}           {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_NOT\n");
                            #endif
                            return keyword_not; 
                        }

{KEYWORD_OR}            {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_or\n");
                            #endif
                            return keyword_or; 
                        }

{KEYWORD_AND}           {
                            #ifdef VM_DEBUG
                            printf("Lexer - KEYWORD_and\n");
                            #endif
                            return keyword_and; 
                        }

{STRING}                { 
                            #ifdef VM_DEBUG
                            printf("Lexer - STRING: %s\n", yytext);
                            #endif
                            strcpy(ngx_http_waf_lval.str_val, yytext + 1);
                            ngx_http_waf_lval.str_val[yyleng - 2] = '\0';
                            return token_str; 
                        }

{ID}                    { 
                            #ifdef VM_DEBUG
                            printf("Lexer - ID: %s\n", yytext);
                            #endif
                            strcpy(ngx_http_waf_lval.id_val, yytext);
                            return token_id; 
                        }

{INTEGER}               {
                            #ifdef VM_DEBUG
                            printf("Lexer - INTEGER: %s\n", yytext);
                            #endif
                            ngx_http_waf_lval.int_val = atoi(yytext);
                            return token_int; 
                        }

[[:blank:]]+            {
                            #ifdef VM_DEBUG
                            printf("Lexer - [[:blank:]]+\n");
                            #endif
                            return token_blank; 
                        }

.                       {   
                            #ifdef VM_DEBUG
                            printf("Lexer - Other: %s\n", yytext);
                            #endif
                            return *yytext; 
                        }

%%

void ngx_http_waf_error(UT_array* array, ngx_pool_t* pool, const char* msg) {
    printf("error: %s in line %d\n", msg, yylineno);
}