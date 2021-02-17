FROM nginx:stable-alpine as builder
ARG CHANGE_SOURCE=false
ARG NGINX_VER=1.18.0

WORKDIR /usr/local/src
COPY . ./ngx_waf

SHELL ["/bin/ash", "-o", "pipefail", "-c"]
## DOCKER_BUILDKIT=1 docker build -t test/nginx --build-arg=NGINX_VER=1.18.0 --build-arg=CHANGE_SOURCE=true .
RUN set -xe \
    ## If you're in China, or you need to change sources, will be set CHANGE_SOURCE to true in .env.
    && if [ ${CHANGE_SOURCE} = true ]; then \
    # Change application source from dl-cdn.alpinelinux.org to aliyun source
    # ssed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories \
    sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/' /etc/apk/repositories \
    ;fi \
    && apk update \
    && apk --no-cache --virtual add uthash-dev \
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
        geoip-dev
RUN set -xe \
    && wget "https://nginx.org/download/nginx-${NGINX_VER}.tar.gz" -O "nginx-${NGINX_VER}.tar.gz" \
    && tar -zxf "nginx-${NGINX_VER}.tar.gz" \
    && cd "nginx-${NGINX_VER}" \
    && ./configure \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --with-perl_modules_path=/usr/lib/perl5/vendor_perl \
    --user=nginx \
    --group=nginx \
    --with-compat \
    --with-file-aio \
    --with-threads \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_mp4_module \
    --with-http_random_index_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_slice_module \
    --with-http_ssl_module \
    --with-http_stub_status_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-mail \
    --with-mail_ssl_module \
    --with-stream \
    --with-stream_realip_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-cc-opt='-Os -fomit-frame-pointer' \
    --with-ld-opt=-Wl,--as-needed \
    --add-module=/usr/local/src/ngx_waf \
    && make \
    && cp objs/nginx /usr/sbin/nginx

FROM nginx:stable-alpine
COPY --from=builder /usr/sbin/nginx /usr/sbin/
