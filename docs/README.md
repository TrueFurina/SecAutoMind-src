# SecAutoMind Documentation

[中文](#中文文档) | [English](#english-documentation)

SecAutoMind documentation is organized by user journey. Start with deployment, then move to the topic that matches your task.

## 中文文档

### 按目标开始

- **快速体验**：[部署指南](zh-CN/deployment.md) → [配置参考](zh-CN/configuration.md) → [排错指南](zh-CN/troubleshooting.md)
- **生产部署**：[配置画像](zh-CN/configuration-profiles.md) → [安全加固](zh-CN/security-hardening.md) → [运维 Runbooks](zh-CN/runbooks.md) → [审计与监控](zh-CN/audit-and-monitoring.md)
- **接入与自动化**：[API 参考](zh-CN/api-reference.md) → [API Recipes](zh-CN/api-recipes.md) → [MCP 联邦](zh-CN/mcp-federation.md)
- **参与开发**：[开发者指南](zh-CN/developer-guide.md) → [测试指南](zh-CN/testing.md) → [贡献规范](zh-CN/contributing-guide.md)

### 核心概念与编排

- [架构说明](zh-CN/architecture.md)
- [安全模型](zh-CN/security-model.md)
- [Agent 与角色](zh-CN/agent-and-role-guide.md)
- [Skills 指南](zh-CN/skills-guide.md)
- [Eino 多代理](zh-CN/MULTI_AGENT_EINO.md)
- [工作流](zh-CN/workflow-graph.md)
- [工具执行治理](zh-CN/tool-execution-governance.md)
- [人机协同最佳实践](zh-CN/hitl-best-practices.md)

### 功能指南

- [知识库](zh-CN/knowledge-base.md)
- [RBAC 权限管理](zh-CN/rbac.md)
- [机器人接入](zh-CN/robot.md)
- [视觉分析](zh-CN/VISION.md)
- [WebShell 管理](zh-CN/webshell.md)
- [C2 使用说明](zh-CN/c2.md)

### 开发与发布

- [开发者指南](zh-CN/developer-guide.md)
- [插件开发](zh-CN/plugin-development.md)
- [前端国际化](zh-CN/frontend-i18n.md)
- [测试指南](zh-CN/testing.md)
- [贡献规范](zh-CN/contributing-guide.md)
- [发布流程](zh-CN/release-process.md)

### 工程纪律（2026-10-20 起）

- [MCP 工具分级注册方案](MCP工具分级注册方案-2026-10-19.md)：注册哪些、驻留哪些、**Tier 迁移判据**、未验证项台账
- [工具契约与输出边界](工具契约与输出边界-2026-10-20.md)：契约四件套（错误投影/schema/响应预算/溯源）、选定事实视图、`NOT_ENOUGH_INFO`
- [工具故障分诊模板](../templates/工具故障分诊.md)：六层分诊（注册/授权/入参/provider/数据/运行时）
- [审计报告模板（findings 四分法）](../templates/审计报告模板-findings四分法.md)：已复现缺陷 / 有据成本 / 假设 / 不可得证据
- 工具**配方**契约（tools/*.yaml，89 份）与依赖清单盘点：见上条文档 §6 / §7；入口脚本 `scripts/audit_yaml_tool_contracts.py`、`scripts/env_fingerprint.py --root`

## English Documentation

### Choose a path

- **Try locally**: [Deployment](en-US/deployment.md) → [Configuration](en-US/configuration.md) → [Troubleshooting](en-US/troubleshooting.md)
- **Run in production**: [Configuration Profiles](en-US/configuration-profiles.md) → [Security Hardening](en-US/security-hardening.md) → [Runbooks](en-US/runbooks.md) → [Audit and Monitoring](en-US/audit-and-monitoring.md)
- **Integrate and automate**: [API Reference](en-US/api-reference.md) → [API Recipes](en-US/api-recipes.md) → [MCP Federation](en-US/mcp-federation.md)
- **Contribute code**: [Developer Guide](en-US/developer-guide.md) → [Testing](en-US/testing.md) → [Contributing](en-US/contributing-guide.md)

### Concepts and orchestration

- [Architecture](en-US/architecture.md)
- [Security Model](en-US/security-model.md)
- [Agents and Roles](en-US/agent-and-role-guide.md)
- [Skills](en-US/skills-guide.md)
- [Eino Multi-Agent](en-US/MULTI_AGENT_EINO.md)
- [Workflows](en-US/workflow-graph.md)
- [Tool Execution Governance](en-US/tool-execution-governance.md)
- [HITL Best Practices](en-US/hitl-best-practices.md)

### Feature guides

- [Knowledge Base](en-US/knowledge-base.md)
- [RBAC Administration](en-US/rbac.md)
- [Robot / Chatbot](en-US/robot.md)
- [Vision Analysis](en-US/VISION.md)
- [WebShell Management](en-US/webshell.md)
- [C2 Guide](en-US/c2.md)

### Development and release

- [Developer Guide](en-US/developer-guide.md)
- [Plugin Development](en-US/plugin-development.md)
- [Frontend i18n](en-US/frontend-i18n.md)
- [Testing](en-US/testing.md)
- [Contributing](en-US/contributing-guide.md)
- [Release Process](en-US/release-process.md)

## Documentation conventions

- Commands assume the repository root unless stated otherwise.
- Examples use placeholders; never commit real credentials or target systems without explicit authorization.
- Runtime behavior and configuration defaults are authoritative in `config.example.yaml` and the source code. If a document differs, report it as documentation drift.
