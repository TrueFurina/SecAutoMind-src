#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""决赛冻结闸门（规划总纲 §4.3）：决赛前 N 天起拒绝"架构改动"，只允许改材料/证据/配置/文档。

为什么需要（本项目 09-12 的血案逻辑）：
  决赛前最大的风险不是"能力不够"，而是**临阵改架构**——改一处内部接口，全库测试、
  交付包、exe、官网数字、PPT 口径全部要重刷，而时间只剩几天。09-12 已定下三条停工边界，
  其中第③条"距决赛 < 14 天 → 不动架构"此前只写在文档里。本脚本把它变成**可机验的闸门**。

策略由 `config.share.yaml` 的 `freeze:` 段驱动（Go 侧不解析该段，不影响运行时）：
    freeze:
      enabled: false
      final_date: ""            # YYYY-MM-DD；窗口 = final_date - freeze_days ~ final_date
      freeze_days: 14
      protected_paths: [internal/, agents/, cmd/]
      override_ack_env: FREEZE_OVERRIDE_ACK

用法：
  python scripts/freeze_gate.py --status                 # 只看是否进入冻结窗口
  python scripts/freeze_gate.py                          # 检查**暂存区**改动（pre-commit 用法）
  python scripts/freeze_gate.py --worktree               # 检查工作树全部改动（pre-push 用法）
  python scripts/freeze_gate.py --base <sha>             # 检查 base...HEAD 的改动（CI/PR 用法）
  python scripts/freeze_gate.py --files a.md,internal/x.go   # 显式指定文件（自测/排查用）

逃生阀（仅安全官/主理人）：
  --freeze-override "<≥20 字理由>" 且环境变量 FREEZE_OVERRIDE_ACK=1
  二者缺一不可；触发后会**追加**一条记录到 docs/freeze-override-log.md（可审计）。

退出码：0 = 放行（含未启用/未进窗口）；1 = 拦截或策略配置错误（fail-closed）。
"""
import os
import re
import sys
import json
import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_POLICY_FILE = os.path.join(ROOT, "config.share.yaml")
# 逃生阀审计日志；允许用环境变量改路径（**仅供 scripts/freeze_gate_test.py 隔离自测**，
# 避免测试污染仓库里的真实审计日志）。
OVERRIDE_LOG = os.environ.get("FREEZE_OVERRIDE_LOG") or os.path.join(
    ROOT, "docs", "freeze-override-log.md")
MIN_OVERRIDE_REASON_LEN = 20


# --------------------------------------------------------------------------
# 零依赖解析：只支持 freeze 段需要的子集（标量 + 行内列表）
# 为什么不 import yaml：本机有 PyYAML，但 CI 的 setup-python 不保证装它；
# 两条解析路径（有/无 PyYAML）会随时间分叉，而分叉的解析器比手写解析器更危险。
# 该子集由 scripts/freeze_gate_test.py 用**真实 config.share.yaml** 做断言兜底。
# --------------------------------------------------------------------------
def parse_freeze_block(text):
    """从 YAML 文本中提取 freeze: 段，返回 dict（键为 str，值为 str 或 list[str]）。"""
    lines = text.splitlines()
    block = []
    started = False
    base_indent = None
    for raw in lines:
        if not started:
            if re.match(r"^freeze\s*:\s*(#.*)?$", raw):
                started = True
                base_indent = None
            continue
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0:  # 回到顶层 → 段结束
            break
        if base_indent is None:
            base_indent = indent
        if indent < base_indent:
            break
        block.append(raw)
    if not started:
        return None

    out = {}
    for raw in block:
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", raw)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        # 去掉行内注释（值里带引号时保守处理：只在引号外找 #）
        val = _strip_inline_comment(val).strip()
        if val.startswith("[") and val.endswith("]"):
            items = [x.strip().strip("'\"") for x in val[1:-1].split(",")]
            out[key] = [x for x in items if x]
        else:
            out[key] = val.strip("'\"")
    return out


def _strip_inline_comment(v):
    out, in_s = [], None
    for ch in v:
        if in_s:
            out.append(ch)
            if ch == in_s:
                in_s = None
        elif ch in "\"'":
            in_s = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out)


def _rel(p):
    """转成相对仓库根的路径；**跨盘符时退化为绝对路径**。

    坑（2026-09-16 自测实锤）：Windows 下仓库在 E:、临时文件在 C:（tempfile 默认落在系统盘）时，
    `os.path.relpath` 会抛 `ValueError: path is on mount 'C:', start on mount 'E:'`
    → 闸门自己崩掉，rc=1 但看不出原因，**所有用例会"恰好"变成 BLOCK**（假绿/假红的典型来源）。
    """
    try:
        return os.path.relpath(p, ROOT).replace("\\", "/")
    except ValueError:
        return p.replace("\\", "/")


def load_policy(path):
    if not os.path.isfile(path):
        return None, "策略文件不存在：%s" % path
    try:
        text = open(path, "r", encoding="utf-8", errors="replace").read()
    except Exception as e:
        return None, "策略文件读取失败：%s" % e
    blk = parse_freeze_block(text)
    if blk is None:
        return None, "未在 %s 中找到 freeze: 段" % _rel(path)
    pol = {
        "enabled": (blk.get("enabled", "false").strip().lower() in ("true", "1", "yes", "on")),
        "final_date": (blk.get("final_date") or "").strip(),
        "freeze_days": blk.get("freeze_days", "14"),
        # ⚠️ 必须用 `is None` 判断，不能写 `blk.get(...) or 默认值`：
        #    显式空列表 `protected_paths: []`（自测用它做因果验证）是**有意义**的配置，
        #    用 `or` 会把它当缺失、把默认值塞回去（2026-09-16 自测抓到的真 bug）。
        "protected_paths": (blk["protected_paths"] if blk.get("protected_paths") is not None
                            else ["internal/", "agents/", "cmd/"]),
        "override_ack_env": (blk.get("override_ack_env") or "FREEZE_OVERRIDE_ACK").strip(),
    }
    try:
        pol["freeze_days"] = int(str(pol["freeze_days"]).strip() or "14")
    except ValueError:
        pol["freeze_days"] = None
    return pol, None


# --------------------------------------------------------------------------
# 窗口判定
# --------------------------------------------------------------------------
def window_state(pol, today):
    """返回 (state, start, end, note)。

    state ∈ inactive / error / before / in_window / released。
    ⚠️ 2026-09-16 自测抓到真 bug：早期版本把"窗口开始前"也返回 armed（与"窗口内"同名），
    导致**窗口还没开始就拦架构改动**。两种情形语义完全不同，必须分开命名。
    """
    if not pol["enabled"]:
        return "inactive", None, None, "策略 enabled=false（闸门未武装）"
    if pol["freeze_days"] is None:
        return "error", None, None, "freeze_days 不是整数"
    fd = (pol["final_date"] or "").strip()
    if not fd:
        return "error", None, None, "enabled=true 但 final_date 为空"
    try:
        end = datetime.date.fromisoformat(fd)
    except ValueError:
        return "error", None, None, "final_date 不是合法 YYYY-MM-DD：%r" % fd
    start = end - datetime.timedelta(days=pol["freeze_days"])
    if today < start:
        return "before", start, end, "尚未进入冻结窗口（还有 %d 天，窗口 %s 起）" % (
            (start - today).days, start.isoformat())
    if start <= today <= end:
        return "in_window", start, end, "处于冻结窗口内（第 %d/%d 天）" % (
            (today - start).days + 1, pol["freeze_days"] + 1)
    return "released", start, end, "决赛日已过（%s），冻结自动解除" % fd


# --------------------------------------------------------------------------
# 改动文件收集
# --------------------------------------------------------------------------
def _run_git(args):
    import subprocess
    try:
        r = subprocess.run(["git"] + args, cwd=ROOT, shell=False,
                           capture_output=True, encoding="utf-8", errors="ignore", timeout=120)
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except Exception as e:
        return 1, "", str(e)


def changed_files(args):
    """返回 (files, source, error)。files 为归一化后的相对路径列表。"""
    if args.get("files"):
        raw = args["files"].replace("\n", ",").split(",")
        return [f.strip().replace("\\", "/") for f in raw if f.strip()], "--files", None
    if args.get("base"):
        rc, out, err = _run_git(["diff", "--name-only", "%s...HEAD" % args["base"]])
        if rc != 0:
            # 某些 CI 浅克隆下三点比较不可用 → 退回两点
            rc, out, err = _run_git(["diff", "--name-only", args["base"], "HEAD"])
        if rc != 0:
            return [], "git diff", "git diff 失败（rc=%d）：%s" % (rc, err.strip()[:200])
        return [l.strip().replace("\\", "/") for l in out.splitlines() if l.strip()], \
            "git diff %s...HEAD" % args["base"], None
    if args.get("worktree"):
        rc, out, err = _run_git(["status", "--porcelain"])
        if rc != 0:
            return [], "git status", "git status 失败（rc=%d）：%s" % (rc, err.strip()[:200])
        files = []
        for line in out.splitlines():
            if len(line) < 4:
                continue
            path = line[3:].strip()
            if " -> " in path:  # 重命名：两侧都算改动
                old, new = path.split(" -> ", 1)
                files += [old.strip().strip('"'), new.strip().strip('"')]
            else:
                files.append(path.strip('"'))
        return [f.replace("\\", "/") for f in files], "git status", None
    rc, out, err = _run_git(["diff", "--cached", "--name-only"])
    if rc != 0:
        return [], "git diff --cached", "git diff --cached 失败：%s" % err.strip()[:200]
    return [l.strip().replace("\\", "/") for l in out.splitlines() if l.strip()], \
        "git diff --cached（暂存区）", None


def protected_hits(files, protected_paths):
    hits = []
    for f in files:
        for p in protected_paths:
            p = p.strip()
            if not p:
                continue
            if f == p.rstrip("/") or f.startswith(p):
                hits.append((f, p))
                break
    return hits


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def main():
    argv = sys.argv[1:]
    args = {}
    override_reason = None
    for i, a in enumerate(argv):
        if a == "--status":
            args["status"] = True
        elif a == "--worktree":
            args["worktree"] = True
        elif a == "--base":
            args["base"] = argv[i + 1] if i + 1 < len(argv) else ""
        elif a == "--files":
            args["files"] = argv[i + 1] if i + 1 < len(argv) else ""
        elif a == "--policy-file":
            args["policy_file"] = argv[i + 1] if i + 1 < len(argv) else ""
        elif a == "--today":
            args["today"] = argv[i + 1] if i + 1 < len(argv) else ""
        elif a == "--freeze-override":
            override_reason = argv[i + 1] if i + 1 < len(argv) else ""
        elif a == "--json":
            args["json"] = True
        elif a == "--quiet":
            args["quiet"] = True

    policy_file = args.get("policy_file") or DEFAULT_POLICY_FILE
    pol, err = load_policy(policy_file)
    if pol is None:
        print("[BLOCK] 冻结策略加载失败：%s" % err)
        print("        策略由 config.share.yaml 的 freeze: 段提供；缺失即视为配置故障（fail-closed）。")
        return 1

    if args.get("today"):
        try:
            today = datetime.date.fromisoformat(args["today"])
        except ValueError:
            print("[BLOCK] --today 不是合法 YYYY-MM-DD：%r" % args["today"])
            return 1
    else:
        today = datetime.date.today()

    state, start, end, note = window_state(pol, today)
    rel_policy = _rel(policy_file)

    if args.get("json"):
        print(json.dumps({
            "policy_file": rel_policy, "enabled": pol["enabled"], "state": state,
            "today": today.isoformat(),
            "final_date": pol["final_date"], "freeze_days": pol["freeze_days"],
            "window_start": start.isoformat() if start else None,
            "window_end": end.isoformat() if end else None,
            "protected_paths": pol["protected_paths"], "note": note,
        }, ensure_ascii=False, indent=2))
        return 0 if state != "error" else 1

    print("=" * 70)
    print("决赛冻结闸门（策略来源 %s）" % rel_policy)
    print("=" * 70)
    print("  今天        %s" % today.isoformat())
    print("  策略        enabled=%s final_date=%r freeze_days=%s" % (
        pol["enabled"], pol["final_date"], pol["freeze_days"]))
    print("  受保护路径  %s" % ", ".join(pol["protected_paths"]))
    print("  窗口        %s" % (
        "%s ~ %s" % (start.isoformat(), end.isoformat()) if start else "（未生效）"))
    print("  状态        %s —— %s" % (state, note))

    if state == "inactive":
        print("\n[SKIP] 闸门未武装 → 放行。")
        print("       决赛日期确定后，把 config.share.yaml 的 freeze.enabled 置 true 并填 final_date")
        print("       （示例：enabled: true / final_date: \"2026-11-15\"）")
        print("\n冻结闸门：SKIP（未武装）")
        return 0

    if state == "error":
        print("\n[BLOCK] 策略配置错误，按 fail-closed 处理：%s" % note)
        print("        修正 config.share.yaml 的 freeze 段后重试。")
        print("\n冻结闸门：BLOCK（配置故障）")
        return 1

    if state == "released":
        print("\n[PASS] 冻结已解除 → 放行。")
        print("\n冻结闸门：PASS（已解除）")
        return 0

    if state == "before":
        print("\n[PASS] 尚未进入冻结窗口 → 放行（窗口期内才会拒绝架构改动）。")
        print("       窗口 %s ~ %s，今天距窗口开始还有 %d 天" % (
            start.isoformat(), end.isoformat(), (start - today).days))
        print("\n冻结闸门：PASS（窗口未开始）")
        return 0

    # state == in_window
    if args.get("status"):
        print("\n冻结闸门：处于冻结窗口（%s ~ %s）" % (start.isoformat(), end.isoformat()))
        return 0

    files, source, ferr = changed_files(args)
    if ferr:
        print("\n[BLOCK] 无法获取改动清单（fail-closed）：%s" % ferr)
        print("\n冻结闸门：BLOCK（无法判定）")
        return 1
    print("  改动来源    %s（%d 个文件）" % (source, len(files)))

    if not files:
        print("\n[PASS] 无改动文件 → 放行。")
        print("\n冻结闸门：PASS（无改动）")
        return 0

    hits = protected_hits(files, pol["protected_paths"])
    if not hits:
        print("\n[PASS] 改动均不在受保护路径内 → 放行（冻结期允许改材料/证据/文档/配置）。")
        print("\n冻结闸门：PASS（非架构改动）")
        return 0

    print("\n[BLOCK] 冻结窗口内检测到 %d 处受保护路径改动：" % len(hits))
    for f, p in hits[:30]:
        print("        %-56s （命中 %s）" % (f, p))
    if len(hits) > 30:
        print("        ... 另有 %d 处" % (len(hits) - 30))

    # 逃生阀
    ack_env = pol["override_ack_env"]
    acked = os.environ.get(ack_env) == "1"
    if override_reason:
        if len(override_reason.strip()) < MIN_OVERRIDE_REASON_LEN:
            print("\n[BLOCK] 逃生阀理由过短（< %d 字），拒绝放行。" % MIN_OVERRIDE_REASON_LEN)
            print("\n冻结闸门：BLOCK（逃生阀理由不合规）")
            return 1
        if not acked:
            print("\n[BLOCK] 逃生阀需二次确认：请先 `export %s=1`（防误触）。" % ack_env)
            print("\n冻结闸门：BLOCK（缺二次确认）")
            return 1
        _append_override_log(today, files, hits, override_reason.strip())
        print("\n[OVERRIDE] 逃生阀已启用（理由已记入 docs/freeze-override-log.md）。")
        print("冻结闸门：OVERRIDE 放行（已审计）")
        return 0

    print("\n  冻结期纪律：只跑「构建 + 全测 + 交付包自检 + 演练」，不动架构。")
    print("  若确属必须（如决赛现场致命缺陷），用逃生阀并留下理由：")
    print("    export %s=1 && python scripts/freeze_gate.py --freeze-override \"<≥%d 字理由>\"" % (
        ack_env, MIN_OVERRIDE_REASON_LEN))
    print("\n冻结闸门：BLOCK")
    return 1


def _append_override_log(today, files, hits, reason):
    os.makedirs(os.path.dirname(OVERRIDE_LOG), exist_ok=True)
    header = "# 冻结期逃生阀审计日志\n\n> 由 scripts/freeze_gate.py 自动追加。任何 `--freeze-override` 都会留痕。\n"
    if not os.path.isfile(OVERRIDE_LOG):
        with open(OVERRIDE_LOG, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(header)
    with open(OVERRIDE_LOG, "a", encoding="utf-8", newline="\n") as fh:
        fh.write("\n## %s\n\n- 理由：%s\n- 命中受保护路径 %d 处：\n" % (
            today.isoformat(), reason, len(hits)))
        for f, p in hits[:30]:
            fh.write("  - `%s` （命中 `%s`）\n" % (f, p))
        if len(hits) > 30:
            fh.write("  - ... 另有 %d 处\n" % (len(hits) - 30))


if __name__ == "__main__":
    sys.exit(main())
