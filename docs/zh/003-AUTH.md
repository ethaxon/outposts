# 认证方案

本文档描述 `outposts` 当前的认证基线与后续方向。当前单 `confluence` 主链路已经收口到**标准 OIDC / Authentik-first** 运行面，后续重点是继续在这个基线上验证多后端、多 OIDC client 场景，而不是保留任何 Logto 过渡态假设。

当前项目范围至少包括：

- `outposts-web`
- `confluence`
- 未来的 `app1`
- 未来的 `app2`

## 当前判断

### 1. 前端当前问题

`outposts-web` 当前已经具备标准 OIDC driver 与单 `confluence` focused evidence，但仍有两个真实约束：

- route guard / callback / token 获取 / user state 仍主要收口在同一个 `AuthService`
- 当前运行面仍偏向“单 app、单 OIDC client、单 resource happy path”

这在只接 `confluence` 时还勉强成立；一旦同一个前端宿主要同时承载 `confluence`、`app1`、`app2`，就会遇到更真实的问题：

- 不同 app 可能有不同 OIDC client
- 不同 app 可能需要不同 audience / scope
- 某个前端路由区域可能同时要求多个 app 的资格

### 2. 后端当前问题

`confluence` 后端当前虽然仍通过 `AUTH_TYPE=OIDC` 选择 OIDC 分支，但 Bearer 校验已经直接收口到 `securitydept-oauth-resource-server`：

- OIDC discovery
- provider metadata / JWKS 拉取与刷新
- issuer 校验
- audience 校验
- required scopes 校验

因此近期真正需要重构的重心主要是：

- 前端 provider-neutral auth boundary
- 多 requirement 的 route-level orchestration
- 不同服务之间统一而可配置的 issuer / audience / scope contract

而不是先把所有后端都重写成一套新认证框架。

## 目标架构

### 前端：provider-neutral auth boundary

`outposts-web` 近期应朝以下边界收口：

1. **认证核心接口保持 provider-neutral**
   - 登录
   - 登出
   - callback 处理
   - access token 获取
   - user/auth state 查询

2. **OIDC provider SDK 作为可替换 driver**
   - 当前单 `confluence` 主链路已经以标准 OIDC client 作为唯一运行面
   - 近期现实目标是 Authentik 或任意标准 OIDC provider
   - 前端继续保持标准 OIDC client + provider-neutral boundary，而不是重新绑定某个 provider SDK

3. **route guard 不直接写死某个 IdP 调用习惯**
   - guard 只表达“这个路由需要哪些 requirement”
   - 真正的授权调度交给单独的 orchestration 层

### 后端：继续走 provider-neutral OIDC contract

每个后端服务应继续坚持：

- Bearer token 校验走标准 OIDC discovery / JWT resource-server verification
- issuer / audience / scope 由配置决定
- 不反向依赖某个前端 SDK 的内部行为

对于 `confluence` 来说，当前单链路 OIDC contract 应明确为：

- `OIDC_ISSUER`：标准 OIDC issuer
- `OUTPOSTS_WEB_OIDC_CLIENT_ID`：前端 OIDC client id
- `CONFLUENCE_API_ENDPOINT`：前端访问 `confluence` 的 API base URL，同时作为当前单 resource request targeting 参数
- `CONFLUENCE_OIDC_AUDIENCE`：后端 Bearer token 的 audience 校验值
- `CONFLUENCE_OIDC_SCOPES`：当前单链路前后端共用的 scope contract，默认值为 `openid profile email confluence offline_access`

其中：

- `outposts-web` 用这组 scopes 生成 OIDC authorize / code / refresh 请求所依赖的 scope 参数
- `confluence` 通过 `securitydept-oauth-resource-server` 用同一组 scopes 做 required scopes 校验

在当前部署里，`CONFLUENCE_API_ENDPOINT` 与 `CONFLUENCE_OIDC_AUDIENCE` 可以取同一个值；但语义上两者已经被明确拆开，避免继续把“浏览器请求地址”和“JWT audience”混成一个字段。

## 多后端 / 多 OIDC client 场景

这是这轮规划里最重要的新约束。

`outposts-web` 未来不是“一个前端只对接一个受保护后端”，而是：

- 一个前端宿主
- 多个后端服务
- 不同服务可能分别使用不同 OIDC client / audience / scope

这意味着前端不能再只建模“当前是否已登录”，而要能表达：

- 当前有哪些 app requirement
- 每个 requirement 当前是否已满足
- 哪个 requirement 可静默获取
- 哪个 requirement 需要交互式跳转

## 路由同时需要多个资格时，如何调度

例如某个路由区域同时需要：

- `app1`
- `app2`

这里不建议把行为写死成“自动连跳两个授权”，因为真实产品里可能出现：

- 用户根本不知道为什么被连续跳转
- 某些 requirement 可以静默拿，某些必须交互
- 某些 requirement 失败不应阻塞整页
- 某些场景更适合先让用户选择

因此推荐边界是：

1. **应用自己拥有充分自由度**
   - 是否先展示 chooser
   - 是否按顺序授权
   - 某一步失败时如何降级
   - 是否允许部分功能先显示、部分功能后补授权

2. **底层 orchestration 尽量 headless**
   - 输入：当前 route requirements、当前 token 状态、pending callback state
   - 输出：下一步动作

推荐的动作模型可以类似：

- `satisfied`
- `acquire_silently(requirement)`
- `redirect(requirement)`
- `prompt_user(choices, remaining)`
- `blocked(reason)`

推荐默认策略：

1. 先检查当前状态，已满足 requirement 直接跳过
2. 能静默补齐的 requirement 先静默补齐
3. 如果只剩一个必须交互的 requirement，允许默认直接跳转
4. 如果剩多个必须交互的 requirement，默认返回 `prompt_user`
5. callback 返回后，恢复 pending plan，继续处理剩余 requirement

## SDK 与应用的职责边界

结合 `securitydept` 的后续方向，当前建议边界是：

### 应用自己负责

- chooser UI
- router policy
- 页面级 auth UX
- 某个 requirement 失败后的业务降级策略

### 未来可考虑由 SDK 提供

- requirement model
- headless scheduler / orchestrator
- pending callback recovery primitive
- 最薄的 `web` / `angular` / `react` 适配

换句话说：

- `outposts` 应先在应用层验证这套调度模型
- 真正稳定的部分，后续再反哺到 `securitydept` SDK

## 近期实施阶段

近期建议按下面的顺序推进，而不是一次性大迁移。

### 阶段 1：标准 OIDC / Authentik-first baseline

目标：

- 当前单 `confluence` 主链路已切到标准 OIDC driver
- 前端配置命名已收口到 `OIDC_ISSUER` / `OUTPOSTS_WEB_OIDC_CLIENT_ID`
- focused tests 已锁住 callback / redirect / target-resource contract

### 阶段 2：后端对齐 issuer / audience / scope

目标：

- 让 `confluence` 先完成与 Authentik 的 claims 对齐
- 直接使用 `securitydept-oauth-resource-server` 承担单链路 Bearer token 校验
- 明确每个服务自己的：
  - issuer
  - audience
  - required scopes

### 阶段 3：route-level requirement orchestration 原型

目标：

- 先在 `outposts-web` 里做应用侧原型
- 不急着上升为 SDK
- 重点验证“多 requirement 时，headless scheduler + chooser UI”的组合是否合理

### 阶段 4：反哺 `securitydept`

目标：

- 把真正稳定的 requirement model / scheduler 抽象回 `securitydept`
- 保留 chooser UI、router glue 在 `outposts` 侧

## 本地工作区依赖规则

在这个重构阶段，禁止优先依赖已发布包版本。

### Rust

继续使用 workspace `path` 依赖，例如：

```toml
[workspace.dependencies]
securitydept-core = { path = "../securitydept/packages/core" }
```

如果未来 `confluence` 还需要更多本地 crate，也继续走同样的 `path` 方式。

### Node / pnpm

优先使用本地 `link:`，例如：

```json
{
  "dependencies": {
    "@securitydept/token-set-context-client": "link:../securitydept/sdks/ts/packages/token-set-context-client",
    "@securitydept/session-context-client": "link:../securitydept/sdks/ts/packages/session-context-client"
  }
}
```

规则：

- dependency 只写包根，不为 subpath 单独声明依赖
- 在活跃重构期，不先接 published version 再回切本地 link
- 本地 link 的意义就是让 `outposts` 及时验证 `securitydept` 最新边界

## 当前结论

`outposts` 当前不应被理解为“仍在 Logto 迁移过渡态”的项目。  
更准确的目标是：

- 当前单 `confluence` 主链路先稳定在标准 OIDC / Authentik-first baseline
- 当前单 `confluence` 后端 Bearer 校验直接建立在 `oauth-resource-server` 上
- 前端继续从单 provider happy path 演进为 provider-neutral auth boundary
- 后端保持 provider-neutral OIDC 验证
- 用真实多后端、多 requirement 路由场景验证后续 scheduler 抽象
- 把稳定的部分再回灌到 `securitydept`

---

[English](../en/003-AUTH.md) | [中文](003-AUTH.md)
