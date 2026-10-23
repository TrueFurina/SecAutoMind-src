"""xhlj_legacy runner：SecAutoMind Go presolve 的 Python 兜底求解入口。

用途
----
Go 求解器（157 注册 + 硬编码）全 miss 后，由 Go 侧 `presolve_python.go` 调用本脚本，
遍历迁移的西湖论剑 79 个确定性 skill，统一以 {'text': <题干>} 调用 run()，
收集 flag 形态候选输出 JSON。fail-closed：任何异常/超时由 Go 侧兜底，本脚本不抛。

输入
----
    --text-file <path>   题干文本文件（必填）
    --legacy-dir <path>  xhlj_legacy 根目录（含 skills/、core/），缺省取脚本所在目录

输出
----
    stdout JSON: {"solves": [{"skill": <name>, "flag": <候选>}, ...]}
    无候选时 {"solves": []}。单 skill 异常捕获后继续，不中断。

安全与边界
----------
- 仅传 {'text': text}：需要 path/附件/网络参数的 skill 因缺参快速 fail（多数毫秒级）。
- SKIP 清单：交互型/二进制依赖型（pwn_*、web 交互链、bkcrack）不调用，避免挂起。
- 内部时间预算：--budget-sec（默认 40s），超时即停并输出已收集结果。
- 候选过滤：只收 flag 形态（DASCTF{..}/flag{..}/CTF{..}/vnctf{..} 等），其余丢弃。
"""
from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import re
import sys
import time

# 交互型 / 二进制依赖型 / 无参必然挂起类，不调用
SKIP_SKILLS = {
    "pwn_exploit_flow", "pwn_libc_fingerprint", "pwn_nogdb_flow",
    "pwn_ret2dlresolve", "pwn_sandbox_escape", "pwn_tcache_safelinking",
    "web_target_interact", "web_multi_step_chain", "crypto_zip_bkcrack",
    "crypto_enigma_crib",  # numpy 海选慢且题绑定，跳过
}

FLAG_RE = re.compile(
    r"(?:DASCTF|N1CTF|VNCTF|CTF|flag|Flag|FLAG)\{[^}\s]{1,200}\}",
    re.I,
)


def _load_skill_module(legacy_dir: str, name: str):
    """从 skills/<name>.py 加载模块（绕过包级 import 副作用，仅加载单文件）。"""
    path = os.path.join(legacy_dir, "skills", name + ".py")
    if not os.path.isfile(path):
        return None
    spec = importlib.util.spec_from_file_location("xhlj_skill_" + name, path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _collect_flags(result) -> list:
    """从 run() 返回 dict 中提取 flag 形态候选。"""
    if not isinstance(result, dict):
        return []
    out = []
    # 直接字段优先
    for k in ("flag", "flag_candidate", "flag_pattern"):
        v = result.get(k)
        if isinstance(v, str) and v.strip() and FLAG_RE.search(v):
            out.append(v.strip())
    # 再扫全部值
    for v in result.values():
        if isinstance(v, str) and FLAG_RE.search(v):
            for m in FLAG_RE.findall(v):
                out.append(m)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--text-file", required=True)
    ap.add_argument("--legacy-dir", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--budget-sec", type=float, default=40.0)
    args = ap.parse_args()

    if not os.path.isfile(args.text_file):
        print(json.dumps({"solves": [], "error": "no text file"}))
        return 0
    with open(args.text_file, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    if not text.strip():
        print(json.dumps({"solves": [], "error": "empty text"}))
        return 0

    legacy_dir = os.path.abspath(args.legacy_dir)
    sys.path.insert(0, os.path.join(legacy_dir, "core"))

    solves, seen = [], set()
    deadline = time.monotonic() + args.budget_sec
    names = sorted(
        n[:-3] for n in os.listdir(os.path.join(legacy_dir, "skills"))
        if n.endswith(".py") and n != "__init__.py"
    )
    for name in names:
        if name in SKIP_SKILLS:
            continue
        if time.monotonic() > deadline:
            break
        mod = _load_skill_module(legacy_dir, name)
        if mod is None or not hasattr(mod, "run"):
            continue
        try:
            res = mod.run({"text": text})
        except Exception:
            continue
        if inspect.iscoroutine(res) or inspect.isawaitable(res):
            continue  # 异步 skill 不在兜底路径调用
        for cand in _collect_flags(res):
            if cand not in seen:
                seen.add(cand)
                solves.append({"skill": name, "flag": cand})

    print(json.dumps({"solves": solves}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
