# 架构

## 技术栈

| 层级 | 技术 |
|------|------|
| 前端 | Angular 20, Nx, PrimeNG, TailwindCSS, `@jsverse/transloco` |
| 后端 | Rust, Axum, Sea-ORM, PostgreSQL, tokio |
| 认证 | 基于 Logto 的 OIDC, biscuit (JWT/JWK) |
| 容器 | Docker Compose |
| 工具 | mise, pnpm, cargo, just |

## 项目结构

```
outposts/
├── apps/
│   ├── confluence/      # Rust 后端服务
│   │   └── src/
│   │       ├── auth/       # OIDC 认证
│   │       ├── clash/      # Clash 配置解析
│   │       ├── models/     # Sea-ORM 实体
│   │       ├── migrations/ # 数据库迁移
│   │       ├── services.rs # 业务逻辑
│   │       ├── tasks/      # Cron 定时任务
│   │       └── mux/        # 配置混流
│   ├── outposts-web/   # Angular 前端
│   └── dev-proxy/      # 开发代理
├── assets/             # 静态资源
└── docker-compose*.yml # 容器编排
```

## Confluence 后端

Confluence 是管理 Clash 订阅源的核心后端服务：

- **HTTP 层**: Axum + tower-http (CORS, tracing, 静态文件)
- **数据库**: PostgreSQL via Sea-ORM
- **认证**: openidconnect + biscuit 处理 JWT/JWK
- **调度**: tokio-cron-scheduler 同步订阅
- **状态**: 共享 `AppState` 含 DB 连接、配置、JWKS 缓存、OIDC 提供者缓存

### 核心模块

- `clash/` — 解析 Clash 订阅用户信息头
- `services.rs` — Confluence、Profile、SubscribeSource 的 CRUD
- `mux/` — 合并多个订阅配置
- `auth/` — JWT 验证、OIDC 提供者配置

## 前端

Angular 20 单页应用：

- Nx monorepo 工作区
- PrimeNG 组件库
- TailwindCSS 样式
- Transloco 国际化
- Angular SSR 首屏加载

---

[English](../en/001-ARCHITECTURE.md) | [中文](001-ARCHITECTURE.md)
