"""1024 快闪赛正式赛启动器：等待开赛 → 确保 Agent 进入比赛 → 拉起 runner。

用法（比赛开始后）：
  python final_entry.py [--comp b10634a1-7534-46af-950e-8395367bab6b] [--max-concurrent 4] [--models ...]

环境变量：CTF2_AGENT_TOKEN / OPENAI_NEXT_API_KEY
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

import click

ENTRY_ENDPOINTS = [
    "/enter/",
    "/join/",
    "/enter",
    "/join",
]


async def _try_enter(client_path, comp_id: str) -> bool:
    import httpx
    base_url = os.environ.get("CTF2_BASE_URL", "https://ctf2.dasctf.com")
    token = os.environ.get("CTF2_AGENT_TOKEN", "")
    h = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(base_url=base_url, verify=False, timeout=30) as c:
        for ep in ENTRY_ENDPOINTS:
            try:
                r = await c.post(f"/api/open/v1/user/agent/competitions/{comp_id}{ep}", json={}, headers=h)
                print(f"  enter 尝试 {ep}: HTTP {r.status_code} {r.text[:120]}", flush=True)
                if r.status_code in (200, 201, 204):
                    return True
                if r.status_code == 404:
                    continue
            except Exception as e:
                print(f"  enter {ep}: {e}", flush=True)
    return False


async def main(comp_id: str, max_concurrent: int, models: list[str], no_submit: bool, wait_start: bool) -> None:
    import httpx
    base_url = os.environ.get("CTF2_BASE_URL", "https://ctf2.dasctf.com")
    token = os.environ.get("CTF2_AGENT_TOKEN", "")
    h = {"Authorization": f"Bearer {token}"}

    # 1) 等待比赛 running
    if wait_start:
        print("等待比赛开始…（19:00）", flush=True)
        while True:
            async with httpx.AsyncClient(base_url=base_url, verify=False, timeout=30) as c:
                r = await c.get("/api/open/v1/user/agent/me/", headers=h)
                comps = (r.json().get("data") or {}).get("active_competitions") or []
                comp = next((x for x in comps if x.get("id") == comp_id), None)
                if comp and comp.get("status") == "running":
                    print(f"比赛已开始: {comp.get('name')}", flush=True)
                    break
                if not comp:
                    print("正式赛未出现在 active_competitions，等待…", flush=True)
            await asyncio.sleep(15)

    # 2) 确保 entered
    while True:
        async with httpx.AsyncClient(base_url=base_url, verify=False, timeout=30) as c:
            r = await c.get("/api/open/v1/user/agent/me/", headers=h)
            comps = (r.json().get("data") or {}).get("active_competitions") or []
            comp = next((x for x in comps if x.get("id") == comp_id), None)
            if comp and comp.get("entered"):
                print("Agent 已进入正式赛 ✓", flush=True)
                break
            print("entered=false，尝试进入…", flush=True)
            if await _try_enter(comp_id, comp_id):
                await asyncio.sleep(5)
                continue
        await asyncio.sleep(10)

    # 3) 启动 runner
    cmd = [sys.executable, "-u", str(Path(__file__).parent / "runner_ctf2.py"),
           "--poll", "5", "--max-concurrent", str(max_concurrent)]
    if no_submit:
        cmd.append("--no-submit")
    for m in models:
        cmd += ["--models", m]
    env = dict(os.environ)
    env["CTF2_COMPETITION_ID"] = comp_id
    print("启动 runner:", " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd, env=env)
    proc.wait()


@click.command()
@click.option("--comp", default="b10634a1-7534-46af-950e-8395367bab6b")
@click.option("--max-concurrent", default=4, type=int)
@click.option("--models", multiple=True)
@click.option("--no-submit", is_flag=True)
@click.option("--wait-start/--no-wait-start", default=True, help="等待比赛 running（默认等待）")
def run(comp: str, max_concurrent: int, models: tuple[str, ...], no_submit: bool, wait_start: bool) -> None:
    if not os.environ.get("CTF2_AGENT_TOKEN"):
        print("缺少 CTF2_AGENT_TOKEN", file=sys.stderr)
        sys.exit(1)
    model_list = list(models) or None
    asyncio.run(main(comp, max_concurrent, model_list or ["azure/gpt-5.1"], no_submit, wait_start))


if __name__ == "__main__":
    run()
