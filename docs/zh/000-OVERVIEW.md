# Outposts 概述

Outposts 是一个用于管理个人项目和 homelab 服务的个人 **数字哨站**（Digital Outpost）。

## 组件

| 代码               | 描述                                               | 状态   |
| ------------------ | -------------------------------------------------- | ------ |
| **Confluence**     | Clash 订阅源混流与管理                             | 已实现 |
| **SSO**            | 面向 Authentik / 标准 OIDC provider 的单点登录基线 | 已实现 |
| **Outposts-web**   | 基于 Spartan NG 的 Angular 22 门户                 | 已实现 |
| **Securitydept**   | 安全与认证基础设施工具包                           | 已集成 |
| **CelestialGates** | 服务 Web 入口/跳转                                 | 规划中 |
| **Yü-shih**        | 系统监控客户端与中心                               | 规划中 |

## 快速开始

```sh
cp .env.example .env
# 检查并编辑 .env 后：
docker compose up
```

Compose 会启动 PostgreSQL、Confluence、静态 Web host，以及向 HTML 注入公开
OIDC 配置的 web-host sidecar。

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

- [001-ARCHITECTURE.md](001-ARCHITECTURE.md)
- [002-FEATURES.md](002-FEATURES.md)
- [003-AUTH.md](003-AUTH.md)
- [100-ROADMAP.md](100-ROADMAP.md)

---

[English](../en/000-OVERVIEW.md) | [中文](000-OVERVIEW.md)
