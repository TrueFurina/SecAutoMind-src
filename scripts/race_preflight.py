#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""参赛预检（race preflight）——把《赛前检查清单_事故模式库》#15-18 的血训机器化。

对应事故模式：
  #15 共享 venv 依赖漂移      → python_bridge（解释器/skills 可导入）+ pip_check（依赖图健康）
  #16 基础设施预检缺项        → docker_engine + go_build
  #17 看门狗误判/双进程幻觉   → runner_conflicts（按命令行匹配计数，非进程名）
  #18 跨会话协调缺位          → ctf2_identity（平台地面真值）+ 活跃比赛/环境槽位上报

用法：
  python scripts/race_preflight.py                # 全量（含 go build，约 1-2 分钟）
  python scripts/race_preflight.py --skip-slow    # 跳过 go_build（快速轮）
  python scripts/race_preflight.py --json         # 机器可读输出
  python scripts/race_preflight.py --skip-procs   # 已知有 runner 在跑时跳过双开检查

退出码：0 = 无 FAIL；1 = 任一 FAIL（fail-closed）。WARN/SKIP 不影响退出码。
纪律：本脚本不硬编码任何对外数字（count_stats 单一真值源），只做存在性/健康性断言。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "CTF-Agent_融合" / "ctf_agent" / "skills"
# 代表性技能：覆盖 通用/crypto/misc 三类；只验证「可导入 + run 可调用」，不执行。
PROBE_SKILLS = ["task_analyzer", "crypto_zip_bkcrack", "misc_grid_resample"]
RUNNER_PATTERNS = ["runner_ctf2", "cmd/runner", "runner.exe", "final_entry"]

_results: list[dict] = []


def add(name: str, verdict: str, detail: str) -> None:
    _results.append({"check": name, "verdict": verdict, "detail": detail})
    mark = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️ ", "SKIP": "⏭️ "}[verdict]
    print(f"{mark} [{name}] {verdict} — {detail}")


def run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def resolve_python() -> str | None:
    """与 cmd/runner/pyskill_bridge.go 的解析序完全一致：CTF_PYTHON_PATH 优先，
    然后 python3/python PATH 探测（注意：PATH 上的 python 可能是 miniconda 等错误解释器，
    解析结果会在 check_python_bridge 里显式上报并给出处置）。"""
    env = os.environ.get("CTF_PYTHON_PATH", "").strip()
    if env and Path(env).exists():
        return env
    for c in ("python3", "python",
              r"C:\Users\Lenovo\.workbuddy\binaries\python\envs\default\Scripts\python.exe"):
        if shutil.which(c) or Path(c).exists():
            return c
    return None


GOOD_PYTHON = r"C:\Users\Lenovo\.workbuddy\binaries\python\envs\default\Scripts\python.exe"


def check_docker() -> None:
    if not shutil.which("docker"):
        add("docker_engine", "FAIL", "docker 不在 PATH——Docker Desktop 未安装或未启动（事故 #16）")
        return
    r = run(["docker", "info"], timeout=60)
    if r.returncode == 0:
        add("docker_engine", "PASS", "Docker engine 可达")
    else:
        add("docker_engine", "FAIL",
            f"docker info rc={r.returncode}——Docker Desktop 未启动（事故 #16）。"
            "处置：启动 Docker Desktop 后重检")


def check_go_build(skip_slow: bool) -> None:
    if skip_slow:
        add("go_build", "SKIP", "--skip-slow")
        return
    go = shutil.which("go") or (Path("D:/DevCache/go/bin/go.exe")
                                if Path("D:/DevCache/go/bin/go.exe").exists() else None)
    if not go:
        add("go_build", "FAIL", "go 不在 PATH 且 D:/DevCache/go/bin/go.exe 不存在")
        return
    env = dict(os.environ)
    env.setdefault("APPDATA", os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Roaming"))
    r = subprocess.run([str(go), "build", "./..."], cwd=ROOT, capture_output=True,
                       text=True, timeout=600, env=env)
    if r.returncode == 0:
        add("go_build", "PASS", "go build ./... RC=0")
    else:
        tail = (r.stderr or r.stdout or "")[-300:].replace("\n", " | ")
        add("go_build", "FAIL", f"rc={r.returncode}: {tail}")


def check_python_bridge() -> None:
    py = resolve_python()
    if not py:
        add("python_bridge", "FAIL", "找不到 Python 解释器（与 pyskill_bridge 同序探测均失败）")
        return
    if Path(py).resolve() != Path(GOOD_PYTHON).resolve():
        hint = ("CTF_PYTHON_PATH 未设或失效，bridge 回退落到 PATH 解释器——"
                "若其缺技能依赖，赛时 numpy/重依赖类技能全灭（事故 #15 实证）。"
                "处置：setx CTF_PYTHON_PATH <workbuddy python 全路径>")
        add("python_bridge", "WARN" if not os.environ.get("CTF_PYTHON_PATH") else "PASS",
            f"解析解释器 = {py}（≠ 已知好环境）。{hint}")
    if not SKILLS_DIR.is_dir():
        add("python_bridge", "FAIL", f"skills 目录不存在: {SKILLS_DIR}")
        return
    code = (
        "import importlib,sys\n"
        f"sys.path.insert(0, r'{SKILLS_DIR}')\n"
        + "".join(f"m=importlib.import_module('{s}'); assert hasattr(m,'run'), '{s}.run 缺失'\n"
                  for s in PROBE_SKILLS)
        + "print('OK')"
    )
    r = run([py, "-c", code], timeout=120)
    if r.returncode == 0 and "OK" in r.stdout:
        add("python_bridge", "PASS",
            f"{Path(py).name} 可导入 {len(PROBE_SKILLS)} 个代表技能（interpreter+skills_dir 健康）")
    else:
        tail = (r.stderr or r.stdout or "")[-300:].replace("\n", " | ")
        add("python_bridge", "FAIL", f"rc={r.returncode}: {tail}（事故 #15：解释器/依赖/skills 完整性）")
    # pip check：依赖图健康（logfire×opentelemetry 型漂移在此暴露）
    r2 = run([py, "-m", "pip", "check"], timeout=120)
    if r2.returncode == 0:
        add("pip_check", "PASS", "依赖图无断裂")
    else:
        lines = [l for l in (r2.stdout or "").splitlines() if l.strip()][:3]
        add("pip_check", "FAIL", "pip check 发现依赖冲突: " + " | ".join(lines) + "（事故 #15）")


def check_runner_conflicts(skip: bool) -> None:
    if skip:
        add("runner_conflicts", "SKIP", "--skip-procs（已知 runner 在跑）")
        return
    found: list[str] = []
    if os.name == "nt":
        ps = ("Get-CimInstance Win32_Process -Filter \"name='python.exe' or name='go.exe'\""
              " | ForEach-Object { $_.CommandLine }")
        r = run(["powershell", "-NoProfile", "-Command", ps], timeout=60)
        for line in (r.stdout or "").splitlines():
            if any(p in (line or "") for p in RUNNER_PATTERNS):
                found.append(line.strip()[:120])
    else:
        r = run(["pgrep", "-af", "|".join(RUNNER_PATTERNS)], timeout=30)
        found = [l.strip()[:120] for l in (r.stdout or "").splitlines() if l.strip()]
    if found:
        add("runner_conflicts", "FAIL",
            f"检测到 {len(found)} 个疑似参赛进程——先裁决再启动（事故 #17：双开=初赛 0 解根因）。"
            f" 有意保留请 --skip-procs。样例: {found[0]}")
    else:
        add("runner_conflicts", "PASS", "无存活参赛进程")


def check_ctf2() -> None:
    token = os.environ.get("CTF2_AGENT_TOKEN", "")
    if not token:
        add("ctf2_identity", "FAIL", "CTF2_AGENT_TOKEN 未设置（User 级环境变量）")
        return
    import time
    import urllib.request
    data = None
    last_err = None
    for attempt in range(3):  # DNS/网络瞬断重试（误报会误阻开赛）
        req = urllib.request.Request(
            "https://ctf2.dasctf.com/api/open/v1/user/agent/me/",
            headers={"Authorization": f"Bearer {token}",
                     "User-Agent": "SecAutoMind-ctf-agent/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8")).get("data", {})
            break
        except Exception as e:  # noqa: BLE001 — 门禁边界：重试后仍失败才 fail-closed
            last_err = e
            time.sleep(3)
    if data is None:
        add("ctf2_identity", "FAIL", f"agent/me 请求失败（3 次重试后）: {last_err}")
        return
    agent = (data.get("agent") or {})
    comps = data.get("active_competitions") or []
    running = [c.get("name", "?") for c in comps if c.get("status") == "running"]
    add("ctf2_identity", "PASS",
        f"agent={agent.get('name', '?')} | 活跃比赛 {len(comps)} 个，running {len(running)}"
        + (f": {'、'.join(running)}" if running else "（当前无进行中比赛——非参赛态属正常）"))


def main() -> int:
    ap = argparse.ArgumentParser(description="参赛预检（事故模式 #15-18 机验化）")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    ap.add_argument("--skip-slow", action="store_true", help="跳过 go build")
    ap.add_argument("--skip-procs", action="store_true", help="跳过双开检查")
    args = ap.parse_args()

    print("== SecAutoMind 参赛预检 ==")
    check_docker()
    check_go_build(args.skip_slow)
    check_python_bridge()
    check_runner_conflicts(args.skip_procs)
    check_ctf2()

    fails = [r for r in _results if r["verdict"] == "FAIL"]
    print(f"== 结论：{'FAIL' if fails else 'PASS'}"
          f"（FAIL {len(fails)} / PASS {sum(1 for r in _results if r['verdict'] == 'PASS')}"
          f" / WARN {sum(1 for r in _results if r['verdict'] == 'WARN')}"
          f" / SKIP {sum(1 for r in _results if r['verdict'] == 'SKIP')}）==")
    if args.json:
        print(json.dumps({"conclusion": "FAIL" if fails else "PASS",
                          "results": _results}, ensure_ascii=False, indent=1))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
