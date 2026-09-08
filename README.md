<div align="center">

# SecAutoMind

**Multi-Agent Autonomous Cybersecurity Platform**

[English](README.md) | [中文](README_CN.md)

</div>

## Overview

SecAutoMind is a multi-agent autonomous cybersecurity platform built with Go and large language models. It coordinates a layered agent stack (planning / execution / audit / review) through a shared fact blackboard, enabling end-to-end security operations — from target reconnaissance to vulnerability discovery to post-exploitation — with a single natural language intent.

The platform ships with **90 YAML-defined security tool recipes** and **50+ built-in tools** (MCP protocol), supports human-in-the-loop approval for sensitive operations, and produces audit-trail-backed reports. It runs fully offline on a single machine — no cluster or cloud account required.

## Key Features

- **4-agent orchestration** — planning, execution, audit, and review agents collaborate through a shared fact blackboard with three selectable modes (Deep / Plan-Execute / Supervisor).
- **Autonomous decision making** — the orchestrator identifies the target environment, plans multi-step attack chains, and adapts to findings in real time.
- **90+ runtime tools** — 90 YAML-defined security tool recipes (recon, web, cloud, binary analysis, forensics, post-exploitation) + 50+ built-in/MCP tools.
- **Human-in-the-loop safety** — sensitive operations (command execution, privilege escalation, data deletion) require explicit user approval with countdown timer and reject path.
- **8-channel IM integration** — DingTalk / Feishu / WeCom / Telegram / Slack / Discord / QQ / WeChat (optional, off by default, long-connection mode for DingTalk & Feishu — no public callback needed).
- **Lightweight deployment** — single binary (Go, no external dependencies), first-run wizard for admin password, works on Windows / Linux / macOS.

## Quick Start

### Download

Grab the latest release from [GitHub Releases](https://github.com/TrueFurina/SecAutoMind-src/releases).

### Run

**Windows**: Double-click `secautomind-ai.exe`. A browser window opens automatically.

**Linux / macOS**:
```bash
chmod +x secautomind-ai
./secautomind-ai --http
```

On first start, a one-time admin password is printed to the console and saved to `data/admin_initial_password.txt`. Open the URL, log in, and change the password immediately.

### Configure an AI Channel

Edit `config.yaml` (or use the web UI under **Settings → AI Channels**) to add at least one channel:

```yaml
ai:
  default_channel: deepseek
  channels:
    deepseek:
      name: DeepSeek
      provider: openai_compatible
      base_url: https://api.deepseek.com/v1
      api_key: ""          # leave empty, inject via env var
      model: deepseek-chat
```

API keys can be injected via environment variables (e.g., `DEEPSEEK_API_KEY`) — no plaintext in config files.

## Architecture

```
┌───────────────────────────────────────────────────────┐
│  Web Console                                          │
│  (Dashboard / Chat / Assets / Vulns / Workflow / C2)  │
└───────────────────────────────────────────────────────┘
                         ▲
                         │  SSE / WebSocket
                         ▼
┌───────────────────────────────────────────────────────┐
│  Orchestrator (Deep / Plan-Execute / Supervisor)       │
└───────────────────────────────────────────────────────┘
        ▲            ▲            ▲            ▲
        │            │            │            │
   ┌────┴───┐   ┌────┴────┐  ┌────┴────┐  ┌────┴─────┐
   │ Planner │   │ Executor │  │ Auditor │  │ Reviewer │
   │  Agent  │   │  Agents  │  │  Agent  │  │  Agent   │
   └────────┘   └──────────┘  └─────────┘  └──────────┘
                         │
                         ▼
        ┌────────────────────────────────────┐
        │  Tool Library (YAML) + MCP Servers  │
        └────────────────────────────────────┘
```

## Project Structure

```
SecAutoMind/
├── cmd/server/          # Web service entry point
├── internal/            # Agent / MCP / routing / database / security
├── web/static/          # Frontend assets (embedded in binary)
├── tools/               # 90 YAML tool recipes
├── agents/              # 18 agent role definitions
├── skills/              # Agent skills
├── roles/               # 13 RBAC role definitions
├── docs/                # Documentation (deployment, API reference, robot guide)
├── config.example.yaml  # Configuration template (no real keys)
└── README.md
```

## Use Cases

- **University cyber range training** — automated attack-defense simulation with standardized grading
- **CTF competition training** — AI-assisted problem solving with tool automation
- **Security research** — CVE reproduction, PoC validation, attack chain analysis
- **Blue team training** — detection capability training, alert triage drills

## License

Source-available, non-open-source. See `installer/LICENSE.txt` for terms.

## Disclaimer

SecAutoMind is intended for use only on systems you own or have explicit written authorization to test. The maintainers disclaim responsibility for any misuse. Please read `SECURITY.md` before operating this tool in any shared or production environment.
