<div align="center">

# SecAutoMind

**多智能体自主决策通用网络安全平台**

[中文](README_CN.md) | [English](README.md)

[![CI](https://github.com/TrueFurina/SecAutoMind-src/actions/workflows/ci.yml/badge.svg)](https://github.com/TrueFurina/SecAutoMind-src/actions/workflows/ci.yml)

</div>

## 项目简介

SecAutoMind 是一个基于 Go 与大语言模型构建的多智能体自主决策通用网络安全平台。系统通过规划、执行、审计、复盘四类 Agent 协同工作，配合共享事实黑板，实现从目标侦察到漏洞发现再到后渗透的端到端安全运营——只需一句自然语言意图。

平台内置 **91 个 YAML 安全工具配方**与 **50+ 个内置工具**（MCP 协议），支持敏感操作的人工审批（HITL），全程审计留痕可追溯。可完全离线运行在单台机器上，无需集群或云端账号。

## 核心特性

- **四类 Agent 协同** — 规划/执行/审计/复盘，三种编排模式（Deep / Plan-Execute / Supervisor）按任务复杂度自动选型
- **自主决策** — 自动识别目标环境、规划多步攻击链、实时适应发现结果
- **90+ 个运行时工具** — 91 个 YAML 安全工具配方（侦察/Web/云/二进制分析/取证/后渗透）+ 50+ 个内置/MCP 工具
- **人机协同安全** — 敏感操作（命令执行/提权/数据删除）需人工审批，含倒计时与拒绝机制
- **8 通道 IM 机器人**（可选）— 钉钉/飞书/企业微信/Telegram/Slack/Discord/QQ/个人微信，默认关闭；钉钉、飞书走长连接，无需公网回调
- **轻量部署** — 单二进制（Go，零外部依赖），首次启动向导设密码，Windows/Linux/macOS 三端可用

## 快速开始

### 下载

从 [GitHub Releases](https://github.com/TrueFurina/SecAutoMind-src/releases) 获取最新版本。

### 启动

**Windows**：双击 `secautomind-ai.exe`，浏览器自动打开。

**Linux / macOS**：
```bash
chmod +x secautomind-ai
./secautomind-ai --http
```

首次启动时，控制台会输出访问地址与一次性 `admin` 密码（同时保存到 `data/admin_initial_password.txt`）。登录后请立即修改密码。

### 配置 AI 通道

编辑 `config.yaml`（或通过 Web 界面「系统设置 → AI 通道配置」）添加至少一个通道：

```yaml
ai:
  default_channel: deepseek
  channels:
    deepseek:
      name: DeepSeek
      provider: openai_compatible
      base_url: https://api.deepseek.com/v1
      api_key: ""          # 留空，通过环境变量注入
      model: deepseek-chat
```

API 密钥可通过环境变量注入（如 `DEEPSEEK_API_KEY`）——config.yaml 中零明文。

## 架构总览

```
┌───────────────────────────────────────────────────────┐
│  Web 控制台                                           │
│  (仪表盘 / 对话 / 资产 / 漏洞 / 工作流 / C2 ...)       │
└───────────────────────────────────────────────────────┘
                         ▲
                         │  SSE / WebSocket
                         ▼
┌───────────────────────────────────────────────────────┐
│  编排器（Deep / Plan-Execute / Supervisor）             │
└───────────────────────────────────────────────────────┘
    ▲            ▲            ▲            ▲
    │            │            │            │
┌───┴────┐  ┌────┴────┐  ┌────┴────┐  ┌────┴─────┐
│ 规划器  │  │ 执行器   │  │ 审计器   │  │ 复盘器   │
│  Agent │  │  Agents │  │  Agent │  │  Agent  │
└────────┘  └─────────┘  └─────────┘  └──────────┘
                       │
                       ▼
       ┌───────────────────────────────┐
       │ 工具库 (YAML) + MCP Server  │
       └───────────────────────────────┘
```

## 目录结构

```
SecAutoMind/
├── cmd/server/          # Web 服务入口
├── internal/            # Agent / MCP / 路由 / 数据库 / 安全
├── web/static/          # 前端静态资源（嵌入二进制）
├── tools/               # 91 个 YAML 工具配方
├── agents/              # 18 个 Agent 角色定义
├── skills/              # Agent 技能
├── roles/               # 13 个 RBAC 角色定义
├── docs/                # 文档（部署/API 参考/机器人说明）
├── config.example.yaml  # 配置模板（无真实密钥）
└── README.md
```

## 适用场景

- **高校网络安全实训** — 攻防演练自动化，标准化评分
- **CTF 竞赛训练** — AI 辅助解题，工具自动化
- **安全研究** — CVE 复现、PoC 验证、攻击链分析
- **企业蓝队培训** — 检测能力训练，告警研判练习

## 许可证

源码可用，非开源。完整条款见 `installer/LICENSE.txt`。

## 免责声明

SecAutoMind 仅用于已获得明确授权的安全测试与教学科研目的。使用者需自行确保符合当地法律法规及所在机构的使用规范。维护者不对任何未授权使用承担责任。使用前请阅读 `SECURITY.md` 与内置安全模型文档。
