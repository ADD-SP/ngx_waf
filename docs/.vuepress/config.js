module.exports = {
    head: [
        ["script", {defer: "defer", src: "https://static.cloudflareinsights.com/beacon.min.js", "data-cf-beacon": "{token: \"31808613233f4695a54fa83eb9b6946c\", spa: true}"}],
        ["script", {defer: "defer", src: "https://static.cloudflareinsights.com/beacon.min.js", "data-cf-beacon": "{token: \"287102ea31d144d2b99b6b85802bcc20\", spa: true}"}],
        ["script", {defer: "defer", src: "https://static.cloudflareinsights.com/beacon.min.js", "data-cf-beacon": "{token: \"0877160a6e4640aebfe8eaf6a724858c\", spa: true}"}]
    ],
    base: process.env.docsBaseUrl == undefined ? "/" : process.env.docsBaseUrl,
    plugins: ['fulltext-search'],
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
                        path: "/guide/",
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
                        path: "/advance/",
                        children: [
                            "/advance/syntax.md",
                            "/advance/rule.md",
                            "/advance/priority.md",
                            "/advance/variable.md",
                            "/advance/log.md",
                            "/advance/issue.md",
                            "/advance/changes.md"
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
                        path: "/zh-cn/guide/",
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
                        title: "Advanced Guide",
                        path: "/zh-cn/advance/",
                        children: [
                            "/zh-cn/advance/syntax.md",
                            "/zh-cn/advance/rule.md",
                            "/zh-cn/advance/priority.md",
                            "/zh-cn/advance/variable.md",
                            "/zh-cn/advance/log.md",
                            "/zh-cn/advance/issue.md",
                            "/zh-cn/advance/changes.md"
                        ]
                    }
                ]
            }
        }
    }
}