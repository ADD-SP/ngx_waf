# ngx_waf 安装指南

本文档提供两种安装方式：

+ 通过 Docker 安装
+ 编译安装

## 使用 Docker 安装

在项目根目录运行下面的命令，运行完成后会生成一个已经安装完模块的 nginx image。
```bash
docker build -t nginx:stable-alpine-with-ngx_waf --build-arg=CHANGE_SOURCE=true
```
镜像基于 Docker 官方镜像 `nginx:stable-alpine` 构建，其余用法与[官方镜像文档](https://hub.docker.com/_/nginx)所示一样。

## 编译安装

### 下载 nginx 源码

nginx 添加新的模块必须要重新编译，所以先[下载 nginx 源码](http://nginx.org/en/download.html)。

```bash
cd /usr/local/src
wget http://nginx.org/download/nginx-version.tar.gz
tar -zxf nginx-version.tar.gz
```

> 推荐使用 nginx-1.18.0 的源码，若使用低版本的 nginx 源码则不保证本模块可以正常使用。本模块对 Mainline 版本的 nginx 做了兼容性处理，但考虑到 Mainline 版本仍在开发中，所以不保证一直可以兼容。如果遇到了兼容性问题请提 issue。

### 下载 ngx-waf 源码

```bash
cd /usr/local/src
git clone https://github.com/ADD-SP/ngx_waf.git
cd ngx_waf
```

### 编译和安装模块

从 nginx-1.9.11 开始，nginx 开始支持动态模块。

静态模块将所有模块编译进一个二进制文件中，所以增删改模块都需要重新编译 nginx 并替换。

动态模块则动态加载 `.so` 文件，无需重新编译整个 nginx。只需要将模块编译成 `.so` 文件然后修改`nginx.conf`即可加载对应的模块。

***

**使用静态模块**

```bash
cd /usr/local/src/nginx-version
./configure xxxxxx --add-module=/usr/local/src/ngx_waf
make
```
> xxxxxx 为其它的编译参数，一般来说是将 xxxxxx 替换为`nginx -V`显示的编译参数。

如果您已经安装了 nginx 则可以直接替换二进制文件（假设原有的二进制文件的全路径为`/usr/local/nginx/sbin/nginx`）

```bash
nginx -s stop
mv /usr/local/nginx/sbin/nginx /usr/local/nginx/sbin/nginx.old
cp objs/nginx /usr/local/nginx/sbin/nginx
nginx
```

> 如果不想中断 nginx 服务则可以通过热部署的方式来实现升级，热部署方法见[官方文档](https://nginx.org/en/docs/control.html)。

如果您之前没有安装则直接执行下列命令
```bash
make install
```

***

**使用动态模块**

```bash
cd /usr/local/src/nginx-version
./configure xxxxxx --add-dynamic-module=/usr/local/src/ngx_waf
make modules
```
> xxxxxx 为其它的编译参数，一般来说是将 xxxxxx 替换为`nginx -V`显示的编译参数。

此时你需要找到一个目录用来存放模块的 .so 文件，本文假设存储在`/usr/local/nginx/modules`下

```bash
cp objs/ngx_http_waf_module.so /usr/local/nginx/modules/ngx_http_waf_module.so
```

然后修改`nginx.conf`，在最顶部添加一行。
```text
load_module "/usr/local/nginx/modules/ngx_http_waf_module.so";
```