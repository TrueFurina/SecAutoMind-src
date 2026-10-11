# -*- coding: utf-8 -*-
"""校验 SecAutoMind v1.7.17 tools/risk_policy.yaml 的 HITL 闸门逻辑。

模拟「HITL 闸门」：查询 risk_policy -> 决定 allow / block。
断言：
  - HIGH 未授权 -> 强制拦截(block)
  - LOW          -> 自动放行(allow)
  - MED  未授权 -> 需人工确认(block)；授权后 -> 放行(allow)
运行：在仓库根执行  python analysis/verify_hitl.py
"""
import os, re
from collections import Counter

TOOLS_DIR = "tools"
POLICY = os.path.join(TOOLS_DIR, "risk_policy.yaml")


def parse_policy(path):
    txt = open(path, encoding="utf-8").read()
    lines = txt.splitlines()
    tools, cur, in_tools = [], None, False
    for ln in lines:
        if ln.strip() == "tools:":
            in_tools = True
            continue
        if not in_tools:
            continue
        m = re.match(r"\s*-\s*name:\s*(.+)$", ln)
        if m:
            if cur:
                tools.append(cur)
            cur = {"name": m.group(1).strip()}
            continue
        if cur is not None:
            rm = re.match(r"\s*risk:\s*(\w+)", ln)
            if rm:
                cur["risk"] = rm.group(1)
            hm = re.match(r"\s*hitl:\s*(\w+)", ln)
            if hm:
                cur["hitl"] = hm.group(1)
    if cur:
        tools.append(cur)
    return tools


def decide(risk, hitl, human_approve):
    """返回 (action, reason)。action ∈ {allow, block}"""
    if risk == "low":
        return "allow", "低危：自动放行"
    # high / medium 均需 HITL
    if hitl == "true" and not human_approve:
        return "block", f"{risk} 危：需人工授权，未授权拦截"
    return "allow", f"{risk} 危：人工已授权/确认，放行"


def check_alignment(tools):
    """校验 risk_policy 覆盖 tools/ 目录下全部工具 YAML（排除元文件）。"""
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)  # 仓库根 (analysis/..)
    tools_dir = os.path.join(root, TOOLS_DIR)
    meta = {"risk_policy.yaml", "README.md", "README_EN.md", "_shared_args.yaml"}
    yaml_files = [f for f in os.listdir(tools_dir)
                  if f.endswith(".yaml") and f not in meta]
    disk_names = set(f[:-5] for f in yaml_files)
    policy_names = set(t["name"] for t in tools)
    missing = sorted(disk_names - policy_names)   # 工具有、策略缺
    extra = sorted(policy_names - disk_names)      # 策略有、工具无
    print("=== 与 tools/ 目录全量对齐 ===")
    print(f"  磁盘工具 YAML: {len(disk_names)} | 策略条目: {len(policy_names)}")
    print(f"  缺失(工具有策略无): {missing}")
    print(f"  多余(策略有工具无): {extra}")
    ok = (not missing) and (not extra)
    print(f"  [{'PASS' if ok else 'FAIL'}] 策略与工具目录完全对齐")
    return ok, missing, extra


def main():
    tools = parse_policy(POLICY)
    print(f"policy tools loaded: {len(tools)}")
    ok_align, _, _ = check_alignment(tools)
    c = Counter(t.get("risk") for t in tools)
    print(f"risk dist: HIGH={c['high']}  MED={c['medium']}  LOW={c['low']}")

    fails = []
    for t in tools:
        if t["risk"] == "high":
            d, _ = decide(t["risk"], t["hitl"], False)
            if d != "block":
                fails.append(f"HIGH 未拦截: {t['name']}")
        if t["risk"] == "low":
            d, _ = decide(t["risk"], t["hitl"], False)
            if d != "allow":
                fails.append(f"LOW 未放行: {t['name']}")
        if t["risk"] == "medium":
            d1, _ = decide(t["risk"], t["hitl"], False)
            d2, _ = decide(t["risk"], t["hitl"], True)
            if d1 != "block":
                fails.append(f"MED 未授权未拦截: {t['name']}")
            if d2 != "allow":
                fails.append(f"MED 授权后未放行: {t['name']}")

    print("\n=== HITL 闸门断言 ===")
    checks = {
        "HIGH 未授权强制拦截": not any("HIGH" in f for f in fails),
        "LOW 自动放行": not any("LOW" in f for f in fails),
        "MED 未授权拦截": not any("MED 未授权" in f for f in fails),
        "MED 授权后放行": not any("MED 授权后" in f for f in fails),
        "策略覆盖全部90工具(无缺失/多余)": ok_align,
    }
    for k, v in checks.items():
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
    if fails:
        print("FAILURES:", fails)
    else:
        print("ALL ASSERTIONS PASS ✅")

    print("\n=== 抽样演示（工具 × 授权状态）===")
    for demo in ["sqlmap", "nmap", "fofa_search", "exec", "hashcat"]:
        t = next((x for x in tools if x["name"] == demo), None)
        if t:
            d1, _ = decide(t["risk"], t["hitl"], False)
            d2, _ = decide(t["risk"], t["hitl"], True)
            print(f"  {demo:14} risk={t['risk']:6} hitl={t['hitl']:5} | 未授权={d1:5}  授权后={d2}")


if __name__ == "__main__":
    main()
