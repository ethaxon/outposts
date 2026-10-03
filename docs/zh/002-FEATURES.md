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

## EasyTier VLAN 订阅

在左侧边栏打开 **应用 → Confluence → EasyTier VLAN**，集中管理 VLAN 和 supplicant。每个 VLAN 独立配置网关、路由与 supplicant 授权，槽位可写为 `2,4,10-100`。在工作区勾选已有 VLAN 卡片并保存引用。同一创建者可在多个工作区复用一个 VLAN，修改后会对所有引用它的工作区生效。删除工作区会解除该工作区的引用，删除 VLAN 会解除所有工作区对它的引用。删除 supplicant 前需先移除相关授权。

在订阅 UA 中使用 `confluence/supplicant=example-user&vlans=example-network:10,another-network:20`，或在 URL 中使用 `?supplicant=example-user&vlans=example-network:10,another-network:20`。两处同时使用时，解析结果必须一致。重复网络、缺失身份、停用网络及越权槽位会使整个请求失败。Rust 在自定义变换后注入选定节点和路由，并使用共享 supplicant 的 age X25519 公钥加密完整配置。客户端配置对应私钥，响应禁用共享缓存。

Portal 使用规范的 IPv4 `/24` 地址池，并预先登记 `subscription-slot-N` 客户端。密钥使用 EasyTier 原生 HKDF-SHA256 派生。同一 Portal 的并发设备需使用不同槽位。分发授权控制订阅凭据，实际网络可达范围由 Portal 网络及 ACL 控制。网关私钥存于数据库，管理接口隐藏其值。编辑时留空可按已有 VLAN 和网关身份保留密钥。

### 数据库迁移

要求 PostgreSQL 18+。业务主键使用原生 `uuid` 列，通过数据库 `uuidv7()` 默认值生成。历史记录及外键统一迁移，保留原有时间戳和订阅 `resource_token`。管理 API 标识及路由使用 UUID 字符串。ts-rs 将这些 Rust `Uuid` 字段映射为具名 TypeScript scalar `UUIDV7 = string`，提供可见的语义名称并兼容字符串类型。订阅凭据使用独立的随机 UUIDv4 token，导出为 TypeScript scalar `UUIDV4 = string`。

上线时停止 Confluence，保留可恢复的数据库备份，依次执行主键迁移和 VLAN 建表迁移，再启动匹配版本的后端与前端。旧整数管理地址失效。主键迁移回退需恢复数据库备份及旧应用版本。登记 Portal 槽位、配置独立 VLAN 与 supplicant 授权，关联到对应工作区，移除脚本中的旧 VLAN 注入，再更新客户端 UA/URL 和 age 设置。浏览器脚本预览覆盖自定义变换，原生 VLAN 处理通过获取订阅验证。

---

[English](../en/002-FEATURES.md) | [中文](002-FEATURES.md)
