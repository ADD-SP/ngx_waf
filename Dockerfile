FROM nginx:stable-alpine
COPY . /usr/local/src/ngx_waf
RUN apk update \
    && apk --no-cache --virtual add uthash-dev \
        python \
        py2-pip \
        gcc \
        libc-dev \
        make \
        openssl-dev \
        pcre-dev \
        zlib-dev \
        linux-headers \
        curl \
        gnupg \
        libxslt-dev \
        gd-dev \
        geoip-dev \
    && pip install lastversion \
    && nginx_version=`lastversion nginx:stable` \
    && nginx_dir="nginx-${nginx_version}" \
    && ( cd /usr/local/src \
    && wget $(lastversion --format source nginx:stable) -O ${nginx_dir}.tar.gz \
    && tar -zxf ${nginx_dir}.tar.gz \
    && cd ${nginx_dir} \
    && ./configure --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --http-client-body-temp-path=/var/cache/nginx/client_temp --http-proxy-temp-path=/var/cache/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/nginx/scgi_temp --with-perl_modules_path=/usr/lib/perl5/vendor_perl --user=nginx --group=nginx --with-compat --with-file-aio --with-threads --with-http_addition_module --with-http_auth_request_module --with-http_dav_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-mail --with-mail_ssl_module --with-stream --with-stream_realip_module --with-stream_ssl_module --with-stream_ssl_preread_module --with-cc-opt='-Os -fomit-frame-pointer' --with-ld-opt=-Wl,--as-needed --add-module=/usr/local/src/ngx_waf \
    && make \
    && cp objs/nginx /usr/sbin/nginx) \
    && rm -rf /usr/local/src/${nginx_dir} /usr/local/src/ngx_waf /usr/local/${nginx_dir}.tar.gz