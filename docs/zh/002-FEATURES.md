# 功能

## Confluence (Clash 订阅管理器)

**目的**: 管理和混流多个 Clash 订阅源为统一配置。

### 核心功能

- **订阅源管理**: 添加/删除/更新订阅 URL，含名称和标签
- **被动同步**: 按配置的 cron 计划自动刷新订阅
- **Profile 管理**: 创建关联到 confluence 的 profile（配置）
- **配置混流**: 将多个订阅源合并为单个 Clash 配置
- **用户信息提取**: 从 HTTP 头解析 Clash 订阅用户信息（上传/总量/下载/过期）
- **JWT 认证**: 通过 biscuit JWT/JWK 验证令牌，缓存 JWKS
- **OIDC SSO**: 基于标准 OIDC / Authentik-first contract 进行认证

### API 端点

- `POST /api/confluences` — 创建 confluence
- `GET /api/confluences` — 列出用户的 confluences
- `GET /api/confluences/:id` — 获取 confluence 及其 profiles 和 sources
- `PUT /api/confluences/:id` — 更新 confluence
- `DELETE /api/confluences/:id` — 删除 confluence
- `POST /api/confluences/:id/sources` — 添加订阅源
- `PUT /api/sources/:id` — 更新订阅源
- `DELETE /api/sources/:id` — 移除订阅源
- `GET /api/confluences/:id/mux` — 获取混流的 Clash 配置
- `POST /api/confluences/:id/profiles` — 创建 profile
- `PUT /api/profiles/:id` — 更新 profile
- `DELETE /api/profiles/:id` — 删除 profile

## SSO / OIDC

- 当前后端按标准 OIDC discovery + JWKS + JWT 校验工作
- 前端认证层当前以标准 OIDC driver 作为单 `confluence` 主链路基线，并继续朝 provider-neutral auth boundary 演进
- 近期目标是支持第三方 OIDC provider（如 Authentik），而不是继续绑定单一 IdP SDK

## Outposts-web (前端门户)

- Angular 20 SPA
- PrimeNG UI 组件
- 通过 Transloco 实现国际化
- Angular SSR 优化 SEO

---

[English](../en/002-FEATURES.md) | [中文](002-FEATURES.md)
