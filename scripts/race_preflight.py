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
import time
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


# 版本漂移盯防清单（1024 快闪赛事故 #19：opentelemetry 1.32 → 1.45 静默漂移，
# 赛前才发现，白烧 8 分钟赛程）。基线在 scripts/dep_baseline.json，
# 与基线不一致即 FAIL——必须人工确认后 --freeze-baseline 才允许刷新。
WATCH_DEPS = ["opentelemetry-api", "opentelemetry-sdk", "pydantic-ai",
              "logfire", "httpx"]
DEP_BASELINE = ROOT / "scripts" / "dep_baseline.json"
DEFAULT_DST_SKILLS = Path(r"E:\Program\ctf-agent\skills")


def check_docker_path() -> None:
    """交接卡/文档里抄来的 docker 路径必须先验证存在（事故 #19 正解）。"""
    cfg = os.environ.get("CTF_DOCKER_PATH", "").strip()
    if cfg:
        if Path(cfg).exists():
            add("docker_path", "PASS", f"CTF_DOCKER_PATH 存在: {cfg}")
        else:
            add("docker_path", "FAIL",
                f"CTF_DOCKER_PATH 指向不存在: {cfg}——文档里抄来的路径未经验证即采信，"
                "正是 1024 快闪赛白烧 8 分钟的根因（事故 #19）")
        return
    w = shutil.which("docker")
    if w and Path(w).exists():
        add("docker_path", "PASS",
            f"docker 解析到 {w}（未设 CTF_DOCKER_PATH；建议把该路径写进交接卡并设环境变量）")
    elif w:
        add("docker_path", "FAIL", f"which(docker)={w} 但文件不存在（失效安装/符号链接）")
    else:
        add("docker_path", "FAIL", "docker 不在 PATH——无从解析可执行文件真实路径")


def _installed_versions(py: str):
    code = ("import importlib.metadata as m, json\n"
            "d={}\n"
            + "".join(
                f"try:\n    d['{n}']=m.version('{n}')\nexcept Exception:\n    d['{n}']=None\n"
                for n in WATCH_DEPS)
            + "print(json.dumps(d))")
    r = run([py, "-c", code], timeout=120)
    if r.returncode != 0:
        return None, (r.stderr or r.stdout or "")[-200:].replace("\n", " | ")
    try:
        return json.loads((r.stdout or "").strip().splitlines()[-1]), ""
    except Exception:  # noqa: BLE001
        return None, "版本输出解析失败"


def check_dep_versions(py) -> None:
    """依赖版本漂移门禁：与基线逐项比对（事故 #19）。"""
    if not py:
        add("dep_versions", "FAIL", "无可用解释器，无法读取依赖版本")
        return
    vers, err = _installed_versions(py)
    if vers is None:
        add("dep_versions", "FAIL", f"版本读取失败: {err}")
        return
    missing = [n for n, v in vers.items() if not v]
    if not DEP_BASELINE.exists():
        add("dep_versions", "WARN",
            f"无基线 {DEP_BASELINE.name}——当前版本 "
            + "、".join(f"{k}={v}" for k, v in vers.items() if v)
            + ("；缺装: " + "、".join(missing) if missing else "")
            + "。确认无误后执行 --freeze-baseline 固化")
        return
    try:
        base = json.loads(DEP_BASELINE.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        add("dep_versions", "FAIL", f"基线解析失败: {e}")
        return
    drift = [f"{k}: {base.get(k)} → {v}" for k, v in vers.items()
             if v and base.get(k) and str(base.get(k)) != str(v)]
    if drift:
        add("dep_versions", "FAIL",
            "依赖漂移（事故 #19）：" + "；".join(drift)
            + "。处置：确认兼容后 --freeze-baseline，或 pin 回基线版本")
    else:
        add("dep_versions", "PASS",
            f"{len(vers)} 个盯防依赖与基线一致"
            + ("；缺装: " + "、".join(missing) if missing else ""))


def check_skills_parity() -> None:
    """skill 双写一致性：仓内真值源 vs 实战引擎目录（2026-10-25 新增）。"""
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import sync_ctf_agent_skills as sync
    except Exception as e:  # noqa: BLE001
        add("skills_parity", "FAIL", f"无法加载同步模块: {e}")
        return
    dst = DEFAULT_DST_SKILLS
    if not dst.is_dir():
        add("skills_parity", "WARN", f"实战引擎目录不存在: {dst}（换机属正常，赛前必须确认）")
        return
    src_files = sync.collect(sync.SRC)
    if not sync.SRC.is_dir():
        add("skills_parity", "FAIL",
            f"真值源目录不存在: {sync.SRC}——不得按空集合=一致静默放行（fail-closed）")
        return
    st = sync.diff_state(src_files, sync.collect(dst))
    if st["in_sync"] and not st["only_in_dst"]:
        add("skills_parity", "PASS",
            f"双写一致（真值源 {len(src_files)} 个资产与实战引擎逐字节相同）")
    else:
        n_src, n_chg, n_dst = (len(st["only_in_src"]), len(st["changed"]),
                               len(st["only_in_dst"]))
        add("skills_parity", "FAIL",
            f"双写不一致：only_in_src={n_src} changed={n_chg} only_in_dst={n_dst}"
            "——skill 只放了一边，赛时引擎看不到新能力。处置：scripts/sync_ctf_agent_skills.py")


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


def check_python_bridge() -> str | None:
    py = resolve_python()
    if not py:
        add("python_bridge", "FAIL", "找不到 Python 解释器（与 pyskill_bridge 同序探测均失败）")
        return None
    if Path(py).resolve() != Path(GOOD_PYTHON).resolve():
        hint = ("CTF_PYTHON_PATH 未设或失效，bridge 回退落到 PATH 解释器——"
                "若其缺技能依赖，赛时 numpy/重依赖类技能全灭（事故 #15 实证）。"
                "处置：setx CTF_PYTHON_PATH <workbuddy python 全路径>")
        add("python_bridge", "WARN" if not os.environ.get("CTF_PYTHON_PATH") else "PASS",
            f"解析解释器 = {py}（≠ 已知好环境）。{hint}")
    if not SKILLS_DIR.is_dir():
        add("python_bridge", "FAIL", f"skills 目录不存在: {SKILLS_DIR}")
        return None
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
    return py


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


def check_engine_watch(root: Path | None = None) -> None:
    """事故 #19（2026-10-24 快闪赛）：引擎进程守护缺失/被关掉，退出无人接管。

    现场：`final_entry.py` 静默退出 3 次，每次都要人工发现 + 重启。
    根因不是没守护代码，而是 launch_runner.ps1 的看护：
      (a) 只守护 runner_ctf2.py，不覆盖 final_entry.py；
      (b) `-NoWatch` 一加就整段关掉，**没有任何门禁报警**（fail-open）；
      (c) HealthInterval=15s > 10s 自恢复验收线。
    判据（fail-closed 但不假红）：
      - 引擎目录不存在 → SKIP（CI 常态）
      - 上次以 -NoWatch 启动 / 心跳里出现 WATCH_DISABLED → FAIL
      - 有心跳且新鲜 → PASS；心跳过期或无心跳 → WARN（不阻断，但必须看见）
    """
    import sync_ctf_agent_skills as sync

    root = root or sync.DEFAULT_DST.parent
    if not root.is_dir():
        add("engine_watch", "SKIP",
            f"实战引擎目录不存在: {root}（CI 常态；赛前本机必查）")
        return

    logs = root / "logs"
    wlog = logs / "runner_watch.log"
    hb = logs / "engine_watchdog.log"

    if wlog.is_file():
        try:
            tail = wlog.read_text(encoding="utf-8", errors="replace").splitlines()[-30:]
        except Exception:
            tail = []
        if any("未启用看护" in l for l in tail):
            add("engine_watch", "FAIL",
                "上次 runner 以 -NoWatch 启动，进程退出无人接管——1024 快闪赛静默退出 "
                "3 次的事故现场（事故 #19）。处置：去掉 -NoWatch 重跑 "
                "launch_runner.ps1，或改用 scripts/engine_watchdog.py")
            return

    if hb.is_file():
        try:
            hb_tail = hb.read_text(encoding="utf-8", errors="replace").splitlines()[-5:]
        except Exception:
            hb_tail = []
        if any("WATCH_DISABLED" in l for l in hb_tail):
            add("engine_watch", "FAIL",
                "最近一次守护是显式关闭的（WATCH_DISABLED）——等同无人值守。"
                "处置：去掉 --no-watch 重启守护")
            return
        age = time.time() - hb.stat().st_mtime
        if age <= 90:
            add("engine_watch", "PASS", f"守护心跳新鲜（{age:.0f}s 前）")
        else:
            add("engine_watch", "FAIL",
                f"守护心跳已停滞 {age:.0f}s——守护进程本身可能已死"
                "（事故 #19：静默退出无人发现）")
        return

    add("engine_watch", "WARN",
        f"未发现守护心跳 {hb}——当前无人值守引擎进程。"
        "处置：python scripts/engine_watchdog.py --cmd \"...\" --cwd <引擎目录>")


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
    ap.add_argument("--freeze-baseline", action="store_true",
                    help="把当前依赖版本固化为基线（人工确认后执行）")
    args = ap.parse_args()

    if args.freeze_baseline:
        py0 = resolve_python()
        vers, err = _installed_versions(py0) if py0 else (None, "no python")
        if vers is None:
            print(f"❌ 固化失败: {err}")
            return 1
        DEP_BASELINE.write_text(json.dumps(vers, ensure_ascii=False, indent=1),
                                encoding="utf-8")
        print(f"✅ 已固化基线到 {DEP_BASELINE}: "
              + "、".join(f"{k}={v}" for k, v in vers.items() if v))
        return 0

    print("== SecAutoMind 参赛预检 ==")
    check_docker()
    check_docker_path()
    check_go_build(args.skip_slow)
    py = check_python_bridge()
    check_dep_versions(py)
    check_skills_parity()
    check_runner_conflicts(args.skip_procs)
    check_engine_watch()
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
