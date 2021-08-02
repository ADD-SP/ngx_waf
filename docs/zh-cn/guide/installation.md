---
title: 安装
lang: zh-CN
sidebarDepth: 3
---

# 安装

请先阅读[版本说明](version.md)来挑选合适的版本。

nginx 提供两种安装模块的方式，即「静态链接」和「动态加载」，通过两种方式安装的模块也分别称为「静态模块」和「动态模块」。

你可以通过运行脚本 `assets/guide.sh` 来选择使用静态模块还是动态模块。

```shell
sh assets/guide.sh

# It is recommended that you use dynamic modules.
# 如果输出上面这行则建议使用动态模块。

# It is recommended that you use static modules.
# 如果输出上面这行则建议使用静态模块。
```


## 静态模块

::: warning 注意

编译安装模块可能需要一些依赖，比如 gcc，请自行解决依赖问题，本文不提供这类信息。

:::

::: danger 重要信息

编译安装一个新的模块需要知道当前的 nginx 的 `configure` 脚本的参数，您可以通过运行 `nginx -V` 来获取。
下面是一个例子。

```
nginx version: nginx/1.19.6
built by gcc 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)
built with OpenSSL 1.1.1i  8 Dec 2020
TLS SNI support enabled
configure arguments: --with-mail=dynamic --with-openssl=/usr/local/src/openssl-OpenSSL_1_1_1i --prefix=/usr/local/nginx --user=nginx --group=nginx --with-file-aio --with-http_ssl_module --with-http_geoip_module --with-http_v2_module --with-http_realip_module --with-stream_ssl_preread_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_perl_module --with-http_stub_status_module --with-http_auth_request_module --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-debug --with-cc-opt='-O3 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -m64 -mtune=generic'
```

务必记住 `configure arguments:` 后面的内容，下文中将使用 `ARG` 来代替这块内容。

:::


安装静态模块需要重新编译整个 nginx，花费的时间相对于安装动态模块比较长。

首先下载对应版本的 nginx，[下载页面](http://nginx.org/en/download.html)。
下面将以 `nginx-1.20.1` 为例。

```sh
cd /usr/local/src
wget https://nginx.org/download/nginx-1.20.1.tar.gz
tar -zxf nginx-1.20.1.tar.gz
```

然后下载本模块的源码，下文将使用稳定版的源码。

```sh
cd /usr/local/src
git clone -b lts https://github.com/ADD-SP/ngx_waf.git
cd ngx_waf
git clone https://github.com/libinjection/libinjection.git inc/libinjection
```

接下来应该运行配置脚本。

```sh
cd /usr/local/src/nginx-1.20.1
./configure ARG --add-module=/usr/local/src/ngx_waf
```

::: warning 注意

* `ARG` 的含义见[编译安装](#编译安装)。

* 如果您使用的编译器是 GCC，请在 `--with-cc-opt` 中追加 `-fstack-protector-strong`，
例如 `--with-cc-opt='-Werror -g'` ---> `--with-cc-opt='-Werror -g -fstack-protector-strong'`

:::

接着您开始编译了

```sh
# 不使用并行编译
make

# 使用并行编译
make -j$(nproc)
```

::: tip 注意

并行会提升编译速度，但是有概率出现莫名奇妙的错误，如果并行编译出错，可以禁用并行编译。

:::

最后您应该关闭 nginx，然后替换 nginx 的二进制文件，
此处假设 nginx 的二进制文件的绝对路径为 `/usr/local/nginx/sbin/nginx`。

```sh
cp objs/nginx /usr/local/nginx/sbin/nginx
```

::: tip 热部署

如果您不想在替换二进制文件时关闭 nginx，可以参考[官方文档的热部署方案](http://nginx.org/en/docs/control.html)。

:::

## 动态模块

### 下载预构建的模块

您可以通过执行脚本 `assets/download.sh` 来下载动态模块。下面是一些用例。

```shell
# 用于 nginx-1.20.1 的 LTS 版的模块
sh assets/download.sh 1.20.1 lts

# 用于 nginx-1.21.1 的 LTS 版的模块
sh assets/download.sh 1.21.1 lts

# 用于 nginx-1.20.1 的最新版的模块
sh assets/download.sh 1.20.1 current

# 用于 nginx-1.21.1 的最新版的模块
sh assets/download.sh 1.21.1 current
```

执行脚本后你会看到类似下面这样的输出。

```
checking for command ... yes
checking for libc implementation ... yes
 + GNU C libary
Pulling remote image addsp/ngx_waf-prebuild:ngx-1.21.1-module-beta-glibc
......
......
......
Download complete!
```

如果你看到 `Download complete!` 则说明下载成功，模块会被保存在当前目录下。
你可以将其拷贝到一个目录下，然后在 `nginx.conf` 的顶部添加一行。

```nginx
load_module "/path/to/ngx_http_waf_module.so";
```

然后关闭 nginx 并运行 `nginx -t`。如果没有出错则说明模块被正常加载，反之则说明您的 nginx 不支持预构建的模块，请编译安装模块。


::: tip 注意

当我们更新了模块后，大约需要两个小时来编译和上传模块。

:::


### 编译动态模块

编译安装动态模块并不需要重新编译整个 nginx，只需要重新编译所有的模块，所以
速度相对静态模块快一些，这也是本文档推荐的方式。

下载 nginx 源码和模块源码的过程同[静态模块](#静态模块)，不再赘述。

运行配置脚本

```sh
./configure --add-dynamic-module=/usr/local/src/ngx_waf --with-compat
```

::: warning 注意

* 如果您使用的编译器是 GCC，请在 `--with-cc-opt` 中追加 `-fstack-protector-strong`，
例如 `--with-cc-opt='-Werror -g'` ---> `--with-cc-opt='-Werror -g -fstack-protector-strong'`

:::

然后开始编译动态模块

```sh
make modules
```

接着您应该关闭 nginx，然后将动态模块拷贝到模块目录，
此处假设模块目录的绝对路径为 `/usr/local/nginx/modules`。

```sh
cp objs/*.so /usr/local/nginx/modules
```

最后在 nginx 的配置文件顶部添加一行
```vim
load_module "/usr/local/nginx/modules/ngx_http_waf_module.so";
```