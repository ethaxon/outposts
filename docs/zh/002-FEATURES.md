# 功能

## Confluence

Confluence 是一个 Clash 订阅管理器与配置混流器。

- 管理 Confluence、Profile、订阅源和 Profile transform。
- 按可配置的 Cron 计划刷新订阅源，并在可用时展示订阅流量元数据。
- 将选定订阅源合并为 Clash 兼容的输出 Profile。
- 使用 Monaco 编辑 YAML 和 transform 脚本。
- 使用 Markdown、Mermaid、KaTeX 与 Prism 预览渲染后的文档内容。

API 位于 `/api` 下；Web 客户端只通过 `/api/auth/config` 获取公开 OIDC client
配置，该端点不会被 Bearer token interceptor 拦截。

## 认证

- `AUTH_TYPE=OIDC` 在浏览器使用 Authorization Code + PKCE，在 Confluence
  使用 Securitydept resource-server 校验。
- 路由保护通过 Securitydept token-set requirement 声明，而不是应用自有的登录
  wrapper。
- Angular authorization interceptor 只会为已配置的 Confluence API origin 与路径
  附加 Bearer token。
- `AUTH_TYPE=DEV` 是本地开发绕过模式，生产前端构建和 release 后端构建均不支持。

必需配置见[认证](003-AUTH.md)。

## Outposts-web

- 基于 Nx 23 工作区的 Angular 22 SPA。
- Spartan NG / Helm 原语、Tailwind CSS v4 与 Lucide 图标。
- 通过 Transloco 提供英文和简体中文 UI 文案。
- 响应式应用壳、工作区表单、Dialog、Toast 反馈和加载状态。
- 文档资源按特性加载，因此 Prism、Mermaid 和 KaTeX 不会扩大初始页面。

---

[English](../en/002-FEATURES.md) | [中文](002-FEATURES.md)
