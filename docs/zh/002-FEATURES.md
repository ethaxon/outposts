# 功能

## Confluence

Confluence 是一个 Clash 订阅管理器与配置混流器。

- 管理 Confluence、Profile、订阅源和 Profile transform。
- 在 **应用 → Confluence** 下浏览各页面：**Confluence 列表**（`/confluence/confluences`）、
  单个 Confluence（`/confluence/confluence/{id}`）、**VLAN**（`/confluence/vlans`）和
  **Supplicants**（`/confluence/supplicants`）。旧路径 `/confluence/dashboard` 与
  `/confluence/workspace/{id}` 会重定向到新路径。
- 按可配置的 Cron 计划刷新订阅源，并在可用时展示订阅流量元数据。
- 将选定订阅源合并为 Clash 兼容的输出 Profile。
- 使用 Monaco 编辑 YAML 和 transform 脚本。
- 使用 Markdown、Mermaid、KaTeX 与 Prism 预览渲染后的文档内容。

API 位于 `/api` 下；Web 客户端只通过 `/api/auth/config` 获取公开 OIDC client
配置，该端点不会被 Bearer token interceptor 拦截。

### API 路由

管理接口需要登录，且只返回调用者自己的记录。集合使用复数、kebab-case 名词，
针对单个对象的操作使用子路由，例如 `POST /{id}/sync`。

| 资源       | 路由                                                                                                                                             |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Confluence | `GET, POST /api/confluences`；`GET, PUT, DELETE /api/confluences/{id}`；`PUT /{id}/cron`、`PUT /{id}/vlans`、`POST /{id}/sync`、`POST /{id}/mux` |
| 订阅源     | `POST /api/subscribe_sources`；`PUT, DELETE /api/subscribe_sources/{id}`；`POST /{id}/sync`                                                      |
| Profile    | `POST /api/profiles`；`PUT, DELETE /api/profiles/{id}`；`POST /{id}/preview`                                                                     |
| VLAN       | `GET, POST /api/vlans`（列表同时包含可引用的 supplicant）；`PUT, DELETE /api/vlans/{id}`；`POST /api/vlans/routes/aggregate`                     |
| Supplicant | `GET, POST /api/supplicants`；`PUT, DELETE /api/supplicants/{id}`                                                                                |

公开路由：`GET /api/profile_token/{token}`（客户端保存的订阅 URL）、`GET /api/health`
和 `GET /api/auth/config`。

### 订阅源刷新

刷新要求上游返回成功的 HTTP 响应，并提供包含非空 `proxies` 列表的 Clash YAML。刷新失败时，Confluence 保留上次成功保存的内容和流量数据，合并时仍可使用这些内容。合并要求每个订阅源都有已保存的内容。

订阅源卡片按创建时间从早到晚排列。刷新失败时，状态指示器变红，卡片操作区会出现错误详情按钮。收到上游响应时，详情包含 HTTP 状态、响应头和最多 64 KiB 的响应正文。下次刷新成功后会清除该错误。

### Profile age 加密

在 **应用 → Confluence → Supplicants** 添加或编辑 Profile 和 VLAN 共用的 age 公钥。页面显示两类引用数量。删除 supplicant 前需解除这些引用。

编辑 Profile，在 **age 加密接收者** 中选择一个或多个 Confluence supplicant。省略选择参数时使用全部已关联接收者，并返回一份各接收者可用自己的私钥解密的 age 密文。接收者列表为空时，返回不注入 VLAN 隧道的明文 YAML。删除 supplicant 前，需将其从引用它的 Profile 接收者名单中移除。

如果客户端无法加载 age 密文，可以在 Profile 编辑页开启 **允许不安全的 age 私钥兼容模式**。该选项默认关闭。在 HTTPS 请求的 `User-Agent` 中追加下列标记，将 `PRIVATE_KEY` 换成指定 supplicant 的 X25519 age 私钥。

```text
Client/1 confluence/supplicants=example-user&_unsafe_supplicant_private=PRIVATE_KEY
Client/1 confluence/supplicants=example-user&vlans=office&_unsafe_supplicant_private=PRIVATE_KEY
```

该请求必须恰好选中一个 supplicant。Confluence 会用其公钥校验私钥，并检查 Profile 和 VLAN 授权后返回明文 YAML。URL 查询里的该参数会被拒绝，Profile transform 也不会收到它。未携带该参数的请求继续使用原有订阅格式。客户端和反向代理可能记录 User-Agent，请为此模式使用专用密钥。

### 测试 Profile

Profile 卡片上的 **测试配置转换** 会在服务端按订阅 URL 的同一流程渲染已保存的 Profile。修改请求 URL（含 `vlans`/`supplicants` 选择参数）和 `User-Agent` 等请求头后点击 **刷新**。结果同时展示加密前的 YAML 和实际下发的内容，以及所选 supplicant、实际包含的 VLAN 与 age 接收者。预览按 Profile ID 访问，仅登录后的 Confluence 创建者可用。

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
- 响应式应用壳、Confluence 表单、Dialog、Toast 反馈和加载状态。
- 文档资源按特性加载，因此 Prism、Mermaid 和 KaTeX 不会扩大初始页面。

## VLAN 订阅

在左侧边栏打开 **应用 → Confluence → VLAN**。每个 Confluence 可引用多个 VLAN。每个 VLAN 设置目标 CIDR 和允许接入的 supplicant。各隧道从该名单中选取授权对象。移除 VLAN 成员会一并撤销其隧道授权。

每条 **WireGuard** 隧道保存一份客户端配置。可填写或导入配置后再授权，允许选择零个或多个 VLAN 成员。所有获准成员各自在订阅中收到同一套 WireGuard 配置。撤销授权会保留配置。支持导入一个 [Interface] 和一个或多个 [Peer]，包括 Address、PrivateKey、MTU、Endpoint、PublicKey、PresharedKey、AllowedIPs 和 PersistentKeepalive。所有 Peer 使用相同保活设置。

各隧道的 AllowedIPs 必须在 VLAN CIDR 内。**从隧道重算 VLAN CIDR** 会用各 Peer AllowedIPs 的规范化并集替换路由草稿。每条隧道是一个可选的 Mihomo 代理，WireGuard 自行选择 Peer。VLAN `office` 生成选择组 `VLAN-OFFICE`，其隧道 `west-wire` 生成代理 `VLAN-OFFICE::WEST-WIRE-WG`。VLAN 路由统一指向同一个选择组，选中的隧道可能只覆盖部分网段。管理接口只返回密钥配置状态。

两个选择参数都默认使用通配符。`vlans=*` 选择 Confluence 已关联且启用的 VLAN，`supplicants=*` 选择 Profile 已关联的全部 supplicant。用逗号分隔的名称列表可缩小任一范围。例如，订阅 URL 使用 `?vlans=office,lab&supplicants=alice,bob`，或在 User-Agent 追加 `confluence/vlans=office,lab&supplicants=alice,bob`。同一参数出现在两处时，其取值须一致。

只有全部所选 supplicant 都有权访问的 VLAN 和隧道才会进入结果。通配符会跳过未共同授权的 VLAN，显式请求这类 VLAN 会报错。共同授权的 VLAN 若没有可用的共享隧道，仍会返回 VLAN 规则和选择组，REJECT 排在首位，用户可手动选择 DIRECT。Confluence 先执行 Profile transform，再注入 VLAN 并使用所选 supplicant 的 age 公钥加密。加密订阅和兼容模式均禁用共享缓存。

### 数据库迁移

要求 PostgreSQL 18+。业务主键使用原生 `uuid` 列，通过数据库 `uuidv7()` 默认值生成。历史记录及外键统一迁移，保留原有时间戳和订阅 `resource_token`。管理 API 标识及路由使用 UUID 字符串。ts-rs 将这些 Rust `Uuid` 字段映射为具名 TypeScript scalar `UUIDV7 = string`，提供可见的语义名称并兼容字符串类型。订阅凭据使用独立的随机 UUIDv4 token，导出为 TypeScript scalar `UUIDV4 = string`。

升级前停止 Confluence 并保留可恢复的数据库备份。对于处于 UUIDv7 迁移或更早版本的数据库，Confluence 0.5 直接创建最终的 WireGuard 和 Profile 表结构。如果数据库已执行原来的七条迁移，启动 0.5 前需在 `seaql_migrations` 中将这七条记录替换为 `m20261121_000001_confluence_vlan_and_profile`，并保留原末条迁移的时间戳。如果数据库只执行了原序列的一部分，请先使用上一构建完成迁移，再更新迁移记录。订阅 URL 和 User-Agent 中的 VLAN 名称应移除 slot 后缀。迁移后启动匹配版本的后端和前端。

回滚合并迁移会恢复到 UUIDv7 表结构，并删除 VLAN 和 WireGuard 数据、Profile 接收者关联及 age 兼容性设置，以及已保存的订阅同步错误。继续回滚 UUIDv7 会重新分配整数 ID，并保留外键关系、时间戳和订阅 token。恢复已删除的数据或原整数 ID，需要使用对应的数据库备份和应用构建。

---

[English](../en/002-FEATURES.md) | [中文](002-FEATURES.md)
