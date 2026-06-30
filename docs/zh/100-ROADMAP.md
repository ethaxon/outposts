# 路线图

## 已实现

| 组件                               | 状态               |
| ---------------------------------- | ------------------ |
| Confluence                         | 核心功能完成       |
| SSO（标准 OIDC / Authentik-first） | 已集成             |
| Outposts-web                       | Angular 门户运行中 |

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
