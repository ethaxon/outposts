# Outposts 概述

Outposts 是一个用于管理个人项目和 homelab 服务的个人 **数字哨站**（Digital Outpost）。

## 组件

| 代码 | 描述 | 状态 |
|------|------|------|
| **Confluence** | Clash 订阅源混流与管理 | 已实现 |
| **SSO** | 面向 Authentik / 标准 OIDC provider 的单点登录基线 | 已实现 |
| **Outposts-web** | Angular 20 门户 | 已实现 |
| **SecurityDept** | L4 服务的 MFA 检核点 | 规划中 |
| **CelestialGates** | 服务 Web 入口/跳转 | 规划中 |
| **Yü-shih** | 系统监控客户端与中心 | 规划中 |

## 快速开始

```sh
# 编辑 .env 后：
docker compose up
```

## 开发环境

```sh
# 开发依赖
docker compose -f docker-compose.dev-deps.yml up -d

# 后端
just dev-confluence

# 前端
just dev-webui

# 代理
just dev-proxy
```

## 文档索引

- [001-ARCHITECTURE.md](../en/001-ARCHITECTURE.md)
- [002-FEATURES.md](../en/002-FEATURES.md)
- [100-ROADMAP.md](../en/100-ROADMAP.md)
