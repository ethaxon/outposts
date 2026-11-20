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

## VLAN 订阅

在左侧边栏打开 **应用 → Confluence → VLAN**。工作区可引用多个 VLAN。每个 VLAN 设置目标 CIDR 和允许接入的 supplicant。各隧道从该名单中选取授权对象。移除 VLAN 成员会一并删除其隧道授权与凭据。

- **EasyTier Portal** 使用 IPv4 /24 地址池、Portal 服务端私钥和预先登记的 subscription-slot-N 客户端。slot 范围属于具体隧道授权。客户端导出可填入端点、建议地址池和 AllowedIPs，服务端私钥需单独填写。
- **WireGuard** 为每条隧道授权保存一份客户端配置，支持导入一个 [Interface] 和一个或多个 [Peer]。可导入 Address、PrivateKey、MTU、Endpoint、PublicKey、PresharedKey、AllowedIPs 和 PersistentKeepalive。所有 Peer 使用相同保活设置。同一 supplicant 的多个设备共用该隧道的客户端凭据。

各隧道的 AllowedIPs 必须在 VLAN CIDR 内。**从隧道重算 VLAN CIDR** 会用所有已配置的 AllowedIPs 和 EasyTier Portal 子网的规范化并集替换路由草稿。每条隧道是一个可选的 Mihomo 代理，WireGuard 自行选择 Peer。VLAN 路由统一指向同一个选择组，选中的隧道可能只覆盖部分网段。管理接口只返回密钥配置状态。

在订阅 URL 使用 `?supplicant=example-user&vlans=office,lab:10`，或在 User-Agent 追加 `confluence/supplicant=example-user&vlans=office,lab:10`。两处同时提供时须一致。省略 slot 时仅选择已授权的 WireGuard 隧道，填写 slot 还会选择允许该 slot 的 EasyTier 隧道。请求者须具备 VLAN 成员资格。已授权但没有匹配隧道时，仍会返回 VLAN 规则和选择组，REJECT 排在首位，用户可手动选择 DIRECT。订阅在自定义变换后用当前 supplicant 的 age 公钥加密，响应禁用共享缓存。

### 数据库迁移

要求 PostgreSQL 18+。业务主键使用原生 `uuid` 列，通过数据库 `uuidv7()` 默认值生成。历史记录及外键统一迁移，保留原有时间戳和订阅 `resource_token`。管理 API 标识及路由使用 UUID 字符串。ts-rs 将这些 Rust `Uuid` 字段映射为具名 TypeScript scalar `UUIDV7 = string`，提供可见的语义名称并兼容字符串类型。订阅凭据使用独立的随机 UUIDv4 token，导出为 TypeScript scalar `UUIDV4 = string`。

上线前停止 Confluence 并保留可恢复的数据库备份。隧道迁移保留 VLAN 成员、工作区引用和 EasyTier 网关标识，把旧 slot 权限复制到各 EasyTier 隧道，并将隐式 Portal 子网路由写入 VLAN。迁移后启动匹配版本的后端和前端。回退时恢复备份和上一版应用。

---

[English](../en/002-FEATURES.md) | [中文](002-FEATURES.md)
