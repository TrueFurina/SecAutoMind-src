<div align="center">

# SecAutoMind

**Multi-Agent Autonomous Cybersecurity Platform**

[English](README.md) | [中文](README_CN.md)

[![CI](https://github.com/TrueFurina/SecAutoMind-src/actions/workflows/ci.yml/badge.svg)](https://github.com/TrueFurina/SecAutoMind-src/actions/workflows/ci.yml)

</div>

## Overview

SecAutoMind is a multi-agent autonomous cybersecurity platform built with Go and large language models. It coordinates a layered agent stack (planning / execution / audit / review) through a shared fact blackboard, enabling end-to-end security operations — from target reconnaissance to vulnerability discovery to post-exploitation — with a single natural language intent.

The platform ships with **91 YAML-defined security tool recipes** and **50+ built-in tools** (MCP protocol), supports human-in-the-loop approval for sensitive operations, and produces audit-trail-backed reports. It runs fully offline on a single machine — no cluster or cloud account required.

## Key Features

- **4-agent orchestration** — planning, execution, audit, and review agents collaborate through a shared fact blackboard with three selectable modes (Deep / Plan-Execute / Supervisor).
- **Autonomous decision making** — the orchestrator identifies the target environment, plans multi-step attack chains, and adapts to findings in real time.
- **90+ runtime tools** — 91 YAML-defined security tool recipes (recon, web, cloud, binary analysis, forensics, post-exploitation) + 50+ built-in/MCP tools.
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
├── tools/               # 91 YAML tool recipes
├── agents/              # 18 agent role definitions
├── skills/              # Agent skills
├── roles/               # 13 RBAC role definitions
├── docs/                # Documentation (deployment, API reference, robot guide)
├── config.example.yaml  # Configuration template (no real keys)
└── README.md
```

## Use Cases

- **University cyber range training** — automated attack-defense simulation with standardized grading
- **CTF competition training** — AI-assisted problem solving with tool automation, **scoped to the competition's own challenge targets**; bypassing platform access control is out of scope (see [SECURITY.md](SECURITY.md#authorized-use-boundary))
- **Security research** — CVE reproduction, PoC validation, attack chain analysis
- **Blue team training** — detection capability training, alert triage drills

## License

Source-available, non-open-source. See `installer/LICENSE.txt` for terms.

## Honest Capability Boundary

Carried over from the frozen [xihu-sword-ctf-agent](https://github.com/TrueFurina/xihu-sword-ctf-agent) project, where this honesty policy was first written:

- **No claim of autonomous LLM reasoning.** On the live competition platform the verified count of **autonomous LLM-solved challenges is 0**. The real, reproducible capability is a **deterministic static analyzer (presolve)** covering common CTF categories — the LLM is a fallback, gated by a whitelist, token budget, and wall-clock stop-loss.
- **Every public number is registered with its provenance.** Offline figures in `docs/` refer to **deterministic analysis of historical challenge corpora**, never to any live contest score. Each figure is backed by an evidence file (e.g. [`presolve_baseline_41_20261008.md`](docs/2027决赛作战规划/evidence/presolve_baseline_41_20261008.md), [`presolve_9of17_pollution_20261008.md`](docs/2027决赛作战规划/evidence/presolve_9of17_pollution_20261008.md)).
- **Corrections supersede originals.** When a later run overturns an earlier figure, the README keeps the original as a historical record but the correction notice is what governs. Never divide one denominator by another (capability pool vs. runnable pool are separate sets).

This is the same honesty discipline that governed xihu: state what the system can and cannot do, cite the evidence, and correct in public when wrong.

> 🔍 The "honesty as a CI gate" methodology has been distilled into a standalone shareable repo: [honesty-ci-patterns](https://github.com/TrueFurina/honesty-ci-patterns) (extracted from the marl-ecdsa source research).

## Disclaimer

SecAutoMind is intended for use only on systems you own or have explicit written authorization to test. The maintainers disclaim responsibility for any misuse. Please read `SECURITY.md` before operating this tool in any shared or production environment.
