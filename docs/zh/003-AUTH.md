# 认证

Outposts 当前只有一条受保护的应用链路：`outposts-web` 访问 Confluence API。
浏览器使用标准 OpenID Connect Authorization Code + PKCE，后端使用
Securitydept resource-server 校验。Authentik 是参考 provider，但协议契约是标准
OIDC。

## 模式

| `AUTH_TYPE` | 适用场景                    | 行为                                                                                                |
| ----------- | --------------------------- | --------------------------------------------------------------------------------------------------- |
| `OIDC`      | 正常本地开发、CI 与部署配置 | 浏览器通过配置的 provider 认证；Confluence 校验 Bearer access token。                               |
| `DEV`       | 仅本地开发                  | Angular development build 跳过 OIDC；Rust debug build 将请求视为 `AUTH_DEV_USER_ID`（默认 `dev`）。 |

生产 Angular build 和 Rust release build 都会拒绝 `DEV`。它绝不能作为部署认证
模式使用。

## OIDC 流程

1. `outposts-web-host` 从 Confluence 请求无需认证的公开 projection：
   `GET /api/auth/config?redirect_uri=<web-callback-url>`。
2. host sidecar 将该 projection 注入 nginx 实际提供的 HTML。它只包含公开的
   provider metadata、client ID、scope、PKCE 设置和 callback URL，不包含 client
   secret 或用户数据。
3. Angular 的 Securitydept registry 先以 lazy 模式注册 client。首个需要它的路由、
   callback 或授权请求再按以下顺序解析配置：注入的 Realm projection、持久化
   projection 缓存、最后是规范的 Confluence endpoint。
4. 受保护的 `/confluence` 路由使用
   `TokenSetClientRegistryAuthRequirement`。需要认证时，SDK 发起 OIDC redirect。
5. `/auth/callback` 承载 `TokenSetFrontendCallbackComponent`；应用随后通过 Angular
   Router 导航到返回的 post-auth URL。
6. Angular authorization interceptor 只会向配置的 Confluence API origin 和路径附加
   Bearer token。`/api/auth/config` 被明确排除，以避免递归初始化 client。

Confluence 通过 provider discovery 和 JWKS 校验 access token，并校验配置的
scope。仅在设置 `CONFLUENCE_OIDC_AUDIENCE` 时才校验 audience。

## Client 错误消息

Outposts 保持由 `AppOverlayService` 唯一负责应用 toast 展示。根作用域的
`AuthService` 负责不属于 Securitydept SDK 的 Outposts auth orchestration；当前它将
Token Set 生命周期连接到该展示 owner：

```text
Token Set client operation 或 materialization failure
  -> registry.errors（non-replay aggregate）
  -> AuthService
  -> AppOverlayService.showClientError()
  -> Sonner toast
```

registry 负责动态 client subscription。其 `errors` 流将所有 ready client 的
operation error 与 configuration、projection 及其它 factory/materialization failure
合并。`AuthService` 只订阅该聚合流；它不选择 client、不 flatten per-client
resource，也不会 start、refresh、restore 或执行其它 client operation。

Angular application initializer 会调用一次幂等的 `AuthService.start()`，在 lazy
client 初始化前安装所有根作用域 auth bridge。client 初始化本身仍按需进行，并由
registry、route coordination、callback component 和 authorization interceptor
负责。

`AppOverlayService` 只通过 `readErrorPresentationDescriptor()` 将
`ClientError` 投影为展示信息。标题可以包含 error span 捕获的 client 和
operation，而 tracing-only attributes、runtime message、token、authorization
header 和 provider payload 都不会显示。lifecycle event 有意保持 non-replay：
当前认证状态由 SDK Resource/Signal API 提供，历史诊断属于显式 tracing 或日志。

该默认 bridge 不处理普通 Confluence API error、Angular `HttpErrorResponse`、
query/mutation failure、router boundary、表单校验或调用方持有的 Promise
rejection。这些错误仍由对应的应用调用位置负责。

## 配置

从仓库中的模板开始：

```sh
cp .env.example .env
```

### Web 共用配置

| 变量                      | 必需 | 用途                                                                        |
| ------------------------- | ---: | --------------------------------------------------------------------------- |
| `AUTH_TYPE`               |   是 | 正常运行使用 `OIDC`；`DEV` 仅限本地 debug 开发。                            |
| `CONFLUENCE_API_ENDPOINT` |   是 | Confluence 的公开 API base URL，例如 `https://confluence.example.com/api`。 |
| `OUTPOSTS_WEB_HOST`       |   是 | projection host 内置 Confluence topology 使用的公开 Web hostname。          |

### OIDC 配置

当 `AUTH_TYPE=OIDC` 时，以下变量均为必需。

| 变量                          | 用途                                                                |
| ----------------------------- | ------------------------------------------------------------------- |
| `OIDC_ISSUER`                 | OIDC issuer URL。                                                   |
| `OUTPOSTS_WEB_OIDC_CLIENT_ID` | 公开的浏览器 OIDC client ID；由 Confluence 写入 config projection。 |
| `CONFLUENCE_OIDC_SCOPES`      | 以空格或逗号分隔的请求/必需 scope。                                 |
| `CONFLUENCE_OIDC_AUDIENCE`    | 可选的预期 token audience；省略时跳过 audience 校验。               |
| `CONFLUENCE_OIDC_USER_CLAIM`  | 可选 principal claim；默认 `sub`。                                  |

前端构建会校验 `AUTH_TYPE`、`CONFLUENCE_API_ENDPOINT` 和
`OUTPOSTS_WEB_HOST`；在 OIDC 模式下还会校验 `OIDC_ISSUER`、
`OUTPOSTS_WEB_OIDC_CLIENT_ID` 与 `CONFLUENCE_OIDC_SCOPES`。后端还需要
`.env` 中的数据库和监听地址等常规设置。

## 开发

OIDC 开发时，应按本地 Web 与 API origin 配置变量，然后运行：

```sh
docker compose -f docker-compose.dev-deps.yml up -d
just dev-confluence
just dev-webui
```

需要免认证的本地调试时，设置 `AUTH_TYPE=DEV`，并可选设置
`AUTH_DEV_USER_ID`。通过 `just dev-webui` 启动前端、`just dev-confluence`
启动后端；二者均为开发命令，因此符合此模式的限制。

## CI 与部署

`.github/workflows/ci.yaml` 中的 `build-web` job 在 GitHub Actions 的 `BUILD`
environment 内运行。repository 或 environment variable 必须映射到其 dotenv
生成步骤。尤其要将 `AUTH_TYPE` 与 OIDC、URL 变量一同映射；否则 Web build 会在
生成 bundle 前按设计失败。

Confluence Rust build 使用仓库根 `rust-toolchain.toml` 声明的固定 toolchain。
本地 mise 与 Linux amd64/arm64 GitHub job 都读取同一个文件；CI 不再安装另一套
移动 nightly toolchain。

部署时可使用 `PROJECTION_SOURCES` 描述一个或多个 projection endpoint。若未设置，
`outposts-web-host` 会使用 `OUTPOSTS_WEB_HOST` 回退到单个 Confluence source。
projection host 会定期刷新注入后的 HTML；浏览器 token 的持久化仍由 Securitydept
负责。

## 安全边界

- 公开 config projection 只暴露启动 OIDC 所需的数据。
- 后端是 resource server，不保存浏览器 client secret。
- 浏览器 token 不会被附加到配置 API 边界外的请求。
- 认证模式在 build/startup 时显式校验，而不是从缺失变量中推断。

---

[English](../en/003-AUTH.md) | [中文](003-AUTH.md)
