# 架构

## 技术栈

| 层级 | 当前实现                                                                             |
| ---- | ------------------------------------------------------------------------------------ |
| 前端 | Angular 22、Nx 23、Spartan NG（Helm/Brain）、Tailwind CSS v4、Lucide 图标、Transloco |
| 后端 | Rust、Axum、Sea-ORM、PostgreSQL、Tokio                                               |
| 认证 | Securitydept resource-server 校验与前端 OIDC client registry                         |
| 交付 | Docker Compose、nginx 静态 host、Bun/Node projection host                            |
| 工具 | pnpm 11、TypeScript 6、mise、cargo、just                                             |

`outposts-web` 是仅在浏览器运行的 SPA，当前不提供 SSR。

## 项目结构

```text
outposts/
├── apps/
│   ├── confluence/         # Rust API 与订阅混流服务
│   ├── outposts-web/       # Angular 应用
│   ├── outposts-web-host/  # 运行时 OIDC projection 注入器
│   └── dev-proxy/          # 开发反向代理
├── assets/                 # 共享静态资源
├── docs/                   # 中英文产品文档
└── docker-compose*.yml     # 本地与部署编排
```

## Confluence

Confluence 管理订阅源、Profile 以及合并后的 Clash 兼容配置。

- Axum 提供 HTTP API，Sea-ORM 将数据持久化到 PostgreSQL。
- Tokio Cron Scheduler 按配置的计划刷新订阅源。
- OIDC 模式下，Securitydept 通过 provider discovery、JWKS、可选 audience
  校验和 required scopes 校验 access token。
- `AUTH_TYPE=DEV` 仅允许 Rust debug build 在无凭据下接受请求；release build
  会明确拒绝此模式。

## Web 应用与运行时配置

Angular 应用只构建一次并由 nginx 提供服务，OIDC 设置不会写入应用 bundle：

1. `outposts-web-host` 获取各后端公开的 `/api/auth/config` projection。
2. 它将 bootstrap script 写入共享的、实际对外提供的 `index.html`。
3. Angular 的 Securitydept client registry 依次解析注入 projection、持久化
   缓存，最后才回退到后端端点。

应用壳使用 Spartan NG 原语与本地生成的 Helm component library；业务布局与
功能样式仍由应用自身维护。Transloco 提供英文和简体中文 UI 文案。Monaco、
Chart.js、Mermaid、KaTeX 与 Prism 均保留为特性级集成；Prism、Mermaid 和 KaTeX
仅在文档内容实际需要时加载。

## 开发

```sh
docker compose -f docker-compose.dev-deps.yml up -d
just dev-confluence
just dev-webui
just dev-proxy
```

启动服务前先将 `.env.example` 复制为 `.env`。环境变量约定见
[认证](003-AUTH.md)。

---

[English](../en/001-ARCHITECTURE.md) | [中文](001-ARCHITECTURE.md)
