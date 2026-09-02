<div align="center">

# SecAutoMind

**多智能体驱动的靶场自主攻防推演平台**

[English](README.md) | [中文](README_CN.md)

</div>

## Overview

SecAutoMind is a multi-agent platform purpose-built for autonomous attack–defense
simulation in authorized range environments. It coordinates a layered agent
stack (planning / execution / audit / review) so that high-fidelity offensive
and defensive scenarios can be reproduced end-to-end with a single natural
language intent.

The system integrates a curated library of 100+ security tools, supports
human-in-the-loop approval, and produces standardized review reports suitable
for classroom and lab evaluation.

## Key Features

- **Layered multi-agent orchestration** — planning, execution, audit, and
  review agents collaborate through a shared fact blackboard.
- **Autonomous decision making** — the orchestrator can identify the target
  environment, plan next steps, and adapt to findings on the fly.
- **Tooling library** — 100+ YAML-defined security tools (recon, web, cloud,
  binary analysis, forensics, post-exploitation) ready to be invoked by the
  agent layer.
- **Human-in-the-loop safety** — sensitive operations require explicit user
  approval with an auditable trail.
- **Standardized reporting** — every run produces a structured report that
  can be exported for grading and post-mortem discussion.
- **Lightweight deployment** — designed to run on a single student laptop
  with a local LLM, no cluster or cloud account required.

## Quick Start

### Requirements

- Go 1.25+
- Python 3.10+

### Run

```bash
git clone https://github.com/<your-org>/SecAutoMind.git
cd SecAutoMind
chmod +x run.sh
./run.sh
```

The server will print the local URL and an initial `admin` password on the
first start. Open the URL, log in, and you are ready to go.

### Configuration

Edit `config.yaml` to register at least one AI channel (provider, base URL,
API key, model). The default channel is used for new conversations and
unspecified tasks.

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
        ▲                ▲                ▲
        │                │                │
   ┌────┴───┐       ┌────┴────┐      ┌────┴────┐
   │ Planner │       │ Executor │      │ Auditor │
   │  Agent  │       │  Agents  │      │  Agent  │
   └────────┘       └──────────┘      └─────────┘
                         │
                         ▼
        ┌────────────────────────────────────┐
        │  Tool Library (YAML) + MCP Servers  │
        └────────────────────────────────────┘
```

## License

Apache License 2.0. See `LICENSE` for the full text.

## Disclaimer

SecAutoMind is intended for use only on systems you own or have explicit
written authorization to test. The maintainers disclaim responsibility for
any misuse. Please read `SECURITY.md` before operating this tool in any
shared or production environment.
