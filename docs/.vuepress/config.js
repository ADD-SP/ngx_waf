module.exports = {
    base: process.env.docsBaseUrl == undefined ? "/" : process.env.docsBaseUrl,
    plugins: ['fulltext-search'],
    head: [
        ['link', { rel: 'icon', href: 'https://cdn.jsdelivr.net/gh/ADD-SP/ngx_waf@master/assets/logo.png' }],
        ['meta', { name: 'robots', content: 'noindex, nofollow, noarchive, nosnippet, noimageindex, noodp, notranslate, max-video-preview:-1'}]
    ],
    locales: {
        '/': {
            lang: "en",
            title: "ngx_waf",
            description: "A web application firewall module for nginx without complex configuration.'"
        },
        '/zh-cn/': {
            lang: "zh-CN",
            title: "ngx_waf",
            description: "使用简单的 nginx 防火墙模块"
        }
    },
    themeConfig: {
        repo: "https://github.com/ADD-SP/ngx_waf/",
        repoLabel: "Github",
        docsRepo: "https://github.com/ADD-SP/ngx_waf/",
        docsDir: "docs",
        editLinks: true,
        smoothScroll: true,
        locales: {
            '/': {
                selectText: "Languages",
                label: "English",
                lastUpdated: "Last Updated",
                editLinkText: "Help us improve this page!",
                sidebar: [
                    {
                        title: "Quick Start",
                        path: "/guide/overview.html",
                        children: [
                            "/guide/overview.md",
                            "/guide/version.md",
                            "/guide/compatibility.md",
                            "/guide/installation.md",
                            "/guide/configuration.md",
                            "/guide/test.md",
                            "/guide/faq.md"
                        ]
                    },
                    {
                        title: "Advanced Guide",
                        path: "/advance/directive.html",
                        children: [
                            "/advance/directive.md",
                            "/advance/rule.md",
                            "/advance/priority.md",
                            "/advance/variable.md",
                            "/advance/log.md",
                            "/advance/upgrade.md",
                            "/advance/issue.md",
                        ]
                    },
                    {
                        title: "Best Practices",
                        path: "/practice/overview.html",
                        children: [
                            "/practice/overview.md",
                            "/practice/limit-the-rate-per-arbitrary-url.md"
                        ]
                    },
                    {
                        title: "Change Log",
                        path: "/changes/overview.html",
                        children: [
                            "/changes/overview.md",
                            "/changes/lts.md",
                            "/changes/current.md",
                            "/changes/6_0_x.md",
                            "/changes/5_x_x.md",
                            "/changes/4_x_x.md",
                            "/changes/3_x_x.md",
                            "/changes/2_x_x.md"
                        ]
                    },
                    {
                        title: "Roadmap (Advice Needed)",
                        path: "/roadmap/overview.html",
                        children: [
                        ]
                    }
                ]
            },
            '/zh-cn/': {
                selectText: "选择语言",
                label: "简体中文",
                lastUpdated: "最后一次更新",
                editLinkText: "帮助我们改善此页面！",
                sidebar: [
                    {
                        title: "快速上手",
                        path: "/zh-cn/guide/overview.html",
                        children: [
                            "/zh-cn/guide/overview.md",
                            "/zh-cn/guide/version.md",
                            "/zh-cn/guide/compatibility.md",
                            "/zh-cn/guide/installation.md",
                            "/zh-cn/guide/configuration.md",
                            "/zh-cn/guide/test.md",
                            "/zh-cn/guide/faq.md"
                        ]
                    },
                    {
                        title: "进阶指南",
                        path: "/zh-cn/advance/directive.html",
                        children: [
                            "/zh-cn/advance/directive.md",
                            "/zh-cn/advance/rule.md",
                            "/zh-cn/advance/priority.md",
                            "/zh-cn/advance/variable.md",
                            "/zh-cn/advance/log.md",
                            "/zh-cn/advance/upgrade.md",
                            "/zh-cn/advance/issue.md",
                        ]
                    },
                    {
                        title: "最佳实践",
                        path: "/zh-cn/practice/overview.html",
                        children: [
                            "/zh-cn/practice/overview.md",
                            "/zh-cn/practice/limit-the-rate-per-arbitrary-url.md"
                        ]
                    },
                    {
                        title: "更新日志",
                        path: "/zh-cn/changes/overview.html",
                        children: [
                            "/zh-cn/changes/overview.md",
                            "/zh-cn/changes/lts.md",
                            "/zh-cn/changes/current.md",
                            "/zh-cn/changes/6_0_x.md",
                            "/zh-cn/changes/5_x_x.md",
                            "/zh-cn/changes/4_x_x.md",
                            "/zh-cn/changes/3_x_x.md",
                            "/zh-cn/changes/2_x_x.md"
                        ]
                    },
                    {
                        title: "开发计划（建议征集）",
                        path: "/zh-cn/roadmap/overview.html",
                        children: [
                        ]
                    }
                ]
            }
        }
    }
}