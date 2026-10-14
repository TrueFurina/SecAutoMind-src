# Security Triage Agent MCP

[中文](README_CN.md)

A **defensive-side** security alert triage and false-positive elimination MCP service. SecAutoMind can feed a **security alert** into a complete triage chain and get back a structured verdict (event type / risk level / confidence / false-positive flag / evidence / recommendations), then continue into playbook matching and ticket generation.

How it differs from the other MCP servers here: this one covers the **defensive** capability surface — alert triage, false-positive elimination, response orchestration. It complements SecAutoMind's existing offensive capabilities (recon / pentest / post-exploitation / C2 / CTF solving) and fills the defensive gap in a "general-purpose cybersecurity agent".

## Tools

11 tools in total; 10 are exposed by default (`command_executor` requires explicit opt-in).

| Tool | Description | Input requirements |
|------|-------------|--------------------|
| `asset_lookup` | Asset profile (owner / criticality / maintenance window / baseline processes) | `event` |
| `log_lookup` | Related logs by host and account | `event` |
| `intel_lookup` | Outbound intelligence lookup (IP / domain reputation) | `event` |
| `history_alert_lookup` | Historical alert retrieval | `event` |
| `ioc_search` | IOC hit search (intel + knowledge base) | `event` |
| `false_positive_check` | False-positive signal detection (maintenance window / baseline process / change ticket / whitelist) | `event` + `asset_observation` + `log_observation` |
| `incident_triage` | **Triage engine**: LLM decision + rule fallback, produces risk level and verdict | `event` + all 5 `*_observation` |
| `playbook_matcher` | Response playbook matching (branches on FP flag / risk level) | `event` + `analysis` |
| `ticket_generator` | Ticket generation (low-confidence degrades to a "review record") | `event` + `analysis` |
| `host_isolation_simulator` | Host isolation recommendation (simulated; requires human approval to execute) | `event` + `analysis` |
| `command_executor` | Command execution (**disabled by default**) | `command` |

> **Input requirements are hard constraints, not optional hints.** See "Call chain" below.

## Call chain (important)

These are **in-pipeline tools**: later stages take the output of earlier stages and pass it back **verbatim**; the server restores it into internal objects. Calling `incident_triage` with only `event` returns an actionable error message instead of a verdict.

```text
event (JSON)
  │
  ├─► asset_lookup ──────────┐
  ├─► log_lookup ────────────┤  Stage 1: context acquisition (each needs only event)
  ├─► intel_lookup ──────────┤
  ├─► history_alert_lookup ──┤
  └─► ioc_search ────────────┘
                             │  put upstream JSON back into arguments verbatim
                             ▼
                 false_positive_check (needs asset + log observation)
                             │
                             ▼
                 incident_triage (needs all 5 observations)
                             │  produces analysis
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
      playbook_matcher  ticket_generator  host_isolation_simulator
```

Two ways to supply the event:

- **By id**: `{"event": {"id": "EVENT-001"}}` — takes the authoritative record from the bundled sample store (most complete fields); good for demos and regression.
- **Inline**: `{"event": {"host": "...", "process": "...", "raw_log": "...", ...}}` — pass fields from any alert source you own.

## Requirements

- Python 3.13+ (3.10+ should work; the repository's actual test target governs)
- **Zero third-party dependencies**: standard library only. No `mcp` package, no PyYAML. It still runs if `pip install` fails.

## Configuration

Reads `security_triage_agent_config.yaml` from this directory by default. Override with `--config /path/to/config.yaml`.

Format limits and precedence are documented inside that file (flat top-level `key: value`; **environment variables > config file > code defaults**).

Only `command_tool_enabled` changes this service's external behavior:

- `false` (default) → exposes the 10 read-only / triage tools;
- `true` → additionally exposes `command_executor` (executes the given command text; enable only in an isolated environment with trusted callers).

## Connecting to SecAutoMind

1. **Web UI** → **Settings** → **External MCP** → **Add External MCP**, paste the JSON below (replace paths with your actual ones):

```json
{
  "security-triage-agent": {
    "command": "/your/absolute/path/venv/bin/python3",
    "args": [
      "/your/absolute/path/SecAutoMind/mcp-servers/security_triage_agent/mcp_security_triage_agent.py",
      "--config",
      "/your/absolute/path/SecAutoMind/mcp-servers/security_triage_agent/security_triage_agent_config.yaml"
    ],
    "description": "Defensive alert triage and false-positive elimination: alert in, verdict and response advice out",
    "timeout": 120,
    "external_mcp_enable": true
  }
}
```

   - `command`: the project venv Python, or system `python3`. Zero dependencies, so any Python 3.10+ works.
   - `args`: **absolute paths are required**.
   - `timeout`: 120 recommended. Triage is slower with an LLM call; rule fallback is fast.
   - Save, then click **Start** on that MCP.

2. **Recommended alongside**:
   - `command_executor` is off by default. If you enable it, do **not** add it to the HITL approval whitelist.
   - If many external MCP tools are registered, use `multi_agent.eino_middleware.tool_search_*` so these tools are unlocked on demand instead of occupying context.

3. **Example flow**:
   - `asset_lookup({"event": {"id": "EVENT-001"}})` for the asset profile.
   - Feed the returned JSON into `false_positive_check` as `asset_observation`.
   - After chaining all 5 observations, call `incident_triage` for the risk level and verdict.
   - Pass that verdict as `analysis` to `playbook_matcher` / `ticket_generator`.

## Local self-test (recommended before connecting)

```bash
python mcp_security_triage_agent.py --selftest
```

Lists all tools and makes one real `asset_lookup` call. Use it to tell "the service is broken" apart from "the client config is broken", instead of staring at a bare "startup failed" in the client.

## Boundaries and honest disclosures

Please read before connecting, so capability is not misjudged:

1. **Does not affect single-binary deployment.** This service attaches as a **separate process via external MCP federation**. It does not enter the SecAutoMind main binary and adds no Go-side dependency. The main program stays single-binary; with this MCP unconfigured nothing changes. The trade-off: the target host needs a Python runtime — **without Python this service is unavailable; it is an optional enhancement, not a required component**.
2. **The tool layer does not call an LLM.** All 10 tools are rule / retrieval implementations. `incident_triage` does contain an LLM path, but with no usable LLM it degrades to the rule engine and explicitly states "AI unavailable, using rule engine fallback" in `reasoning_summary` — it never silently passes a fallback off as an LLM verdict.
3. **Bundled sample dataset.** The service reads and writes the sample alerts, assets, intel and ledger under `security_agent/data/` (~101 KB). This is a **demo and regression dataset**, not a production alert store. To use your own data, replace the JSON files there or use the inline-event mode.
4. **Writes a local ledger.** Every tool call appends an audit record under `security_agent/data/ledger/` (by design, for traceability). Delete the directory if unwanted; it will be recreated.
5. **`command_executor` really executes.** It runs the given command text through a shell — not simulated. Off by default. `host_isolation_simulator` is a **simulation**: it only outputs advice and performs no action.

## License

Same as the upstream repository; see `LICENSE` at the repository root.
