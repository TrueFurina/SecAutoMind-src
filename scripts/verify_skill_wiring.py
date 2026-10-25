#!/usr/bin/env python3
"""
验证 Runner v4 Layer 2 的 skill 接线是否真实可用。
镜像 pyskill_bridge.go 里 runSkill 的 Python shim 行为：
  import <skill>; _r = skill.run(params); 递归 sanitize bytes -> base64 dict; json.dumps(_r)
逐个 skill 报告：
  import 是否成功 / 是否需要 angr·pwntools 等缺失依赖 / run() 返回值类型 / 是否触发 bytes 包装。
不依赖 Go 工具链，纯 Python，用于在没有 go build 的环境坐实"接线打通"。
"""
import sys, os, json, importlib.util, traceback, asyncio

SKILLS_DIR = r"E:/Program/SecAutoMind/CTF-Agent_融合/ctf_agent/skills"

# 桥接侧已知的依赖门控（与 pyskill_bridge.go tryCategory 对齐）
def needs_dep(name: str) -> str | None:
    n = name.lower()
    if "angr" in n:
        return "angr"
    if "pwn" in n or "ret2" in n:
        return "pwntools"
    return None

def main():
    if not os.path.isdir(SKILLS_DIR):
        print(f"SKILLS_DIR 不存在: {SKILLS_DIR}")
        sys.exit(1)

    skills = sorted(f for f in os.listdir(SKILLS_DIR)
                    if f.endswith(".py") and f != "__init__.py")
    # 镜像桥接 shim：把 ctf_agent/ 父目录也加进 path，使 skill 内的 `from core import` 可解析
    sys.path.insert(0, os.path.dirname(SKILLS_DIR))
    print(f"扫描到 {len(skills)} 个 skill 文件\n")

    rows = []
    for fname in skills:
        name = fname[:-3]
        # 模拟桥接：把 skills 目录加进 sys.path 后 import
        spec = importlib.util.spec_from_file_location(name, os.path.join(SKILLS_DIR, fname))
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            dep = needs_dep(name)
            rows.append((name, "IMPORT_FAIL", f"{type(e).__name__}: {str(e)[:80]}", dep))
            continue

        run_fn = getattr(mod, "run", None)
        if not callable(run_fn):
            rows.append((name, "NO_RUN", "无 def run()", None))
            continue

        # 模拟桥接传入的 params（无真实附件，仅验证契约）
        params = {"name": name, "category": name.split("_")[0], "description": "(verify)"}
        try:
            _r = run_fn(params)
            if asyncio.iscoroutine(_r):
                _r = asyncio.run(_r)
        except Exception as e:
            dep = needs_dep(name)
            rows.append((name, "RUN_ERROR", f"{type(e).__name__}: {str(e)[:80]}", dep))
            continue

        # 递归 sanitize（与 Go 侧 shim 一致）：bytes -> base64 包装
        def sanitize(o):
            if isinstance(o, bytes):
                return {"__base64__": "..."}
            if isinstance(o, dict):
                return {k: sanitize(v) for k, v in o.items()}
            if isinstance(o, list):
                return [sanitize(i) for i in o]
            return o
        try:
            sr = sanitize(_r)
            json.dumps(sr)  # 桥接侧最终会 print(json.dumps(_r))
            is_b64 = isinstance(_r, bytes) or (isinstance(_r, dict) and "__base64__" in _r)
            rtype = type(_r).__name__
            rows.append((name, "OK" if not is_b64 else "OK_BYTES", rtype, None))
        except Exception as e:
            rows.append((name, "SERIALIZE_FAIL", f"{type(e).__name__}: {str(e)[:80]}", None))

    # 汇总
    from collections import Counter
    by_status = Counter(r[1] for r in rows)
    print(f"{'SKILL':42} {'STATUS':14} {'RETURN':16} DEP")
    print("-" * 80)
    for name, status, detail, dep in rows:
        print(f"{name:42} {status:14} {detail:16} {dep or ''}")
    print("-" * 80)
    print("汇总:", dict(by_status))
    n_import_fail = sum(1 for r in rows if r[1] == "IMPORT_FAIL")
    n_bytes = sum(1 for r in rows if r[1] == "OK_BYTES")
    print(f"可调用(OK/OK_BYTES): {by_status.get('OK',0)+by_status.get('OK_BYTES',0)}/{len(rows)}")
    print(f"导入失败(多为缺 angr/pwntools): {n_import_fail}")
    print(f"返回 bytes 被桥接容错包装: {n_bytes}")

if __name__ == "__main__":
    main()
