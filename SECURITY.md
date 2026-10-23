# Security Policy

[中文](#安全政策) | [English](#security-policy)

## Security Policy

SecAutoMind is a security testing and automation platform. It can execute tools, call MCP servers, manage WebShell connections, and optionally run C2 workflows. Please treat every deployment as a high-privilege security system.

### Supported Versions

This project does not currently maintain multiple long-term support branches. Security fixes are expected to land on the latest mainline release/source tree.

If you are running an older version, please reproduce the issue against the latest code before reporting when possible.

### Reporting a Vulnerability

Please do not publicly disclose exploitable details before maintainers have had a reasonable chance to investigate.

Preferred report contents:

- affected version or commit;
- deployment mode and relevant configuration;
- clear reproduction steps;
- impact assessment;
- affected component, such as auth, MCP, tool execution, WebShell, C2, knowledge base, frontend, or API;
- whether the issue requires authentication;
- suggested mitigation, if known.

If the project repository has private vulnerability reporting enabled, use that channel. Otherwise, open a minimal public issue that states there is a security concern and avoid posting exploit details, credentials, target data, or weaponized payloads.

#### Log hygiene before attaching anything (2026-10-20)

Logs and config dumps are the most common accidental leak vector in a security
product. Before pasting logs into an issue, a report, or a chat with support,
remove or mask:

- credentials and tokens: passwords, API keys, session cookies, JWT/Auth headers;
- C2 / WebShell / socket tokens and callback URLs (they are operational secrets);
- target identifiers: hostnames, IPs, internal domains, bucket names;
- personal data and machine paths (`C:\Users\<name>`, `/home/<name>`, browser profiles);
- payload bytes and captured traffic contents — describe them, do not paste them.

If a value is essential to reproduce the issue, replace it with a stable
placeholder of the same shape (e.g. `ak_live_<redacted-32>`) and say so.

### Scope

In scope:

- authentication and session handling issues;
- authorization bypass in protected APIs;
- unsafe command execution behavior;
- unintended file read/write through tools or Skills;
- external MCP trust-boundary flaws;
- WebShell or C2 management vulnerabilities;
- sensitive data leakage from logs, audit records, uploads, or APIs;
- cross-site scripting or frontend injection in the Web UI;
- security-impacting configuration handling bugs.

Out of scope:

- reports against systems you do not own or are not authorized to test;
- denial-of-service testing against public services without permission;
- social engineering, phishing, or credential theft;
- issues caused only by intentionally disabling documented security controls;
- vulnerabilities in third-party tools invoked by SecAutoMind, unless SecAutoMind makes them materially worse.

### Authorized Use Boundary

SecAutoMind must only be used for education, research, and authorized security testing. Do not use it against systems without explicit permission.

CTF practice is in scope **only against the competition's own challenge targets**.
A CTF flag is not an authorization to touch the scoring platform, other teams, or
any infrastructure outside the provided instances — bypassing a platform's access
control (rate limits, submission endpoints, anti-bot) is out of scope even during
a competition.

High-risk capabilities such as Shell execution, WebShell management, C2, payload generation, external MCP tools, and batch scanning should be enabled only in controlled, authorized environments.

### Deployment Hardening

Before production use:

- change the default password;
- use HTTPS or a trusted reverse proxy;
- restrict access by IP, VPN, or bastion;
- enable audit logging;
- keep C2 disabled unless explicitly needed;
- review external MCP servers before enabling them;
- keep high-risk tools out of global HITL allowlists;
- back up `config.yaml`, `data/`, and custom resource directories.

See:

- [Security Model](docs/en-US/security-model.md)
- [Security Hardening](docs/en-US/security-hardening.md)
- [Runbooks](docs/en-US/runbooks.md)

---

# 安全政策

SecAutoMind 是一个安全测试与自动化平台。它可以执行工具、调用 MCP 服务、管理 WebShell 连接，并可选运行 C2 工作流。请把每个部署实例都视为高权限安全系统。

## 支持版本

本项目目前不维护多个长期支持分支。安全修复通常会合入最新主线版本或源码树。

如果你运行的是旧版本，建议在报告前尽量用最新代码复现问题。

## 漏洞报告

在维护者有合理时间调查前，请不要公开披露可利用细节。

建议报告内容：

- 受影响版本或 commit；
- 部署方式和相关配置；
- 清晰复现步骤；
- 影响评估；
- 受影响组件，例如认证、MCP、工具执行、WebShell、C2、知识库、前端或 API；
- 是否需要登录认证；
- 已知缓解建议。

如果仓库启用了私有漏洞报告，请优先使用该渠道。否则可以提交一个最小公开 Issue，说明存在安全问题，但不要发布利用细节、凭证、目标数据或武器化载荷。

#### 附日志前的清洗清单（2026-10-20）

日志与配置导出是安全产品最常见的意外泄露面。粘贴到 Issue / 报告 / 客服聊天前先删或打码：

- 凭证与令牌：口令、API Key、会话 Cookie、JWT / Authorization 头；
- C2 / WebShell / socket 令牌与回连地址（属运行期机密）；
- 目标标识：主机名、IP、内网域名、bucket 名；
- 个人信息与机器路径（`C:\Users\<name>`、`/home/<name>`、浏览器配置目录）；
- 载荷字节与被捕获流量内容——**描述它，不要粘贴它**。

若某个值对复现确有必要，用同形状占位符替换并注明（如 `ak_live_<redacted-32>`）。

## 范围

范围内：

- 认证和会话处理问题；
- 受保护 API 的授权绕过；
- 不安全的命令执行行为；
- 通过工具或 Skills 意外读写文件；
- 外部 MCP 信任边界问题；
- WebShell 或 C2 管理漏洞；
- 日志、审计、上传文件或 API 泄露敏感数据；
- Web UI 的 XSS 或前端注入；
- 影响安全的配置处理缺陷。

范围外：

- 针对未授权系统的报告；
- 未经许可的拒绝服务测试；
- 社工、钓鱼或凭证窃取；
- 仅因主动关闭文档化安全控制导致的问题；
- 第三方工具自身漏洞，除非 SecAutoMind 明显放大了风险。

## 授权使用边界

SecAutoMind 仅可用于教育、研究和授权安全测试。不要在没有明确授权的系统上使用。

CTF 演练**只在赛题自带靶机范围内**成立。拿到 flag 不等于获得对计分平台、其他队伍
或靶机之外任何设施的授权——即使在比赛期间，绕过平台的访问控制（限流、提交接口、
反机器人）也属于范围外。

Shell 执行、WebShell 管理、C2、payload 生成、外部 MCP 工具、批量扫描等高风险能力，只应在受控且授权明确的环境中启用。

## 部署加固

生产使用前：

- 修改默认密码；
- 使用 HTTPS 或可信反向代理；
- 通过 IP、VPN 或堡垒机限制访问；
- 开启审计日志；
- 不需要 C2 时保持关闭；
- 启用外部 MCP 前进行审查；
- 高风险工具不要加入全局 HITL 白名单；
- 备份 `config.yaml`、`data/` 和自定义资源目录。

参见：

- [安全模型](docs/zh-CN/security-model.md)
- [安全加固指南](docs/zh-CN/security-hardening.md)
- [运维 Runbooks](docs/zh-CN/runbooks.md)
