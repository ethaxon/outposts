# 路线图

## 已实现

| 组件                               | 状态               |
| ---------------------------------- | ------------------ |
| Confluence                         | 核心功能完成       |
| SSO（标准 OIDC / Authentik-first） | 已集成             |
| Outposts-web                       | Angular 门户运行中 |

## 横向能力：鉴权 E2E

- [ ] 引入可重现的本地 OIDC Provider，例如 Dex 或运行在浏览器端的测试
      Provider，并提供确定的用户、客户端与令牌生命周期
- [ ] 覆盖完整的前后端 OIDC 流程，包括登录回调、受保护路由目标 URL、刷新、
      已确认撤销、重新认证以及非撤销故障
- [ ] 待 Provider 启动、浏览器安装和测试隔离足够稳定且执行时间适合日常迭代后，
      将该套件接入 CI

## 阶段一：Confluence 增强

- [ ] 订阅健康监控
- [ ] 混流前配置预览/差异对比
- [ ] 批量导入/导出订阅源
- [ ] 使用统计仪表盘

## 阶段二：Securitydept

Securitydept 是已集成的安全与认证基础设施工具包。Outposts 当前使用其 OIDC
能力；后续计划中的 L4 MFA gateway 面向 RDP、SSH 等服务：

- [ ] Basic Auth 区域模式
- [ ] MFA 挑战集成
- [ ] IP 白名单/黑名单
- [ ] 审计日志

## 阶段三：CelestialGates

服务 Web 入口/跳转：

- [ ] 统一服务入口
- [ ] SSO 感知路由
- [ ] 服务健康聚合
- [ ] 快速访问书签

## 阶段四：Yü-shih

系统监控客户端与中心：

- [ ] 指标采集代理
- [ ] 时序数据存储
- [ ] 告警规则引擎
- [ ] 仪表盘可视化

---

[English](../en/100-ROADMAP.md) | [中文](100-ROADMAP.md)
