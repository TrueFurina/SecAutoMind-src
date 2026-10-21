#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""U1000 死代码台账：把"110 条未使用"从一条类级豁免拆成逐条可裁定的明细。

为什么要有这个脚本
------------------
基线里原本躺着这么一条豁免：

    {"code": "U1000", "file": "*", "symbol": "110 处未使用的函数/类型/变量"}

`file: "*"` 意味着**任何新增死代码都会被这条挡住**——门禁形同虚设。今天写
一个没人调的函数，明天加十个，门禁一路绿灯。这不是"登记"，是"闭眼"。

所以本脚本做三件事：

  1. **拆**：把 U1000 按 (文件, 符号) 拆成逐条明细，键里**不含行号**
     （REA #258：删两行循环就能让行号整体漂移，行号做键会凭空造出"新增")。
  2. **判引用图**：U1000 报的是"从导出 API 不可达的**整个闭包**"，
     所以必须区分两类，否则修复优先级全错：
       * `dead_root`     —— 没有任何调用者。真·接线缺口，修它一个，一片复活。
       * `dead_dependent`—— 只被其他 unused 符号调用。根活了它就活，**别去动它**。
  3. **守**：`--gate` 检查台账覆盖率。台账里没有的 U1000 → 红。

还有一个副产品：**重复实现**。同一个方法名在三个 receiver 上各写一遍，
其中两份没人用（`(*ExternalMCPManager).cleanupOldExecutions` vs
`(*Server).cleanupOldExecutions`）。staticcheck 只说"未使用"，台账会标
`dup_of_live`——这不是死代码，是**三份同源实现只活了一份**。

已知局限（诚实标注，不装作没有）
--------------------------------
  * 调用者判定基于文本搜索 + "向上找最近的 func 声明"，不解析 AST。
    若出现 `live_caller_anomaly`（声称未被使用却有活调用者），脚本转红要求
    人工看，而不是自作聪明地判绿。
  * 只处理行注释（`//`），不剥离块注释 `/* */`；块注释里提到符号名会被算作
    引用点，表现为 `comment_only_reference` 被过滤。

fail-closed
-----------
报告缺失 / 为空 / 无法解析 → exit 2。"扫不到"不等于"没有死代码"。

用法
----
    staticcheck -f json ./... > /tmp/sc.json
    python scripts/dead_code_ledger.py --report /tmp/sc.json --write   # 重建明细
    python scripts/dead_code_ledger.py --report /tmp/sc.json --gate    # 门禁
    python scripts/dead_code_ledger.py --report /tmp/sc.json --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
LEDGER_PATH = HERE / "dead_code_ledger.json"

#: 报告在服务器上生成时是绝对路径，用它归一化（同 check_staticcheck_baseline）
_SCAN_ROOT_ENV = "SECAUTOMIND_STATICCHECK_ROOT"

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_UNVERIFIABLE = 2

#: 只搜这些后缀，避免扫二进制 / node_modules
TEXT_EXT = {".go"}

#: 死代码只可能在本包内被引用（未导出），所以搜索面 = 定义文件所在目录
_SKIP_DIRS = {".git", "node_modules", "scans", ".workbuddy", "dist", "web"}


# ── 报告解析 ────────────────────────────────────────────────────────────────

def load_report(path: str) -> list[dict]:
    """逐行解析 staticcheck -f json。坏行单独计数，不静默丢弃。"""
    rows: list[dict] = []
    bad = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
    return rows, bad


def norm_path(raw: str, root: str | None = None, repo: Path = REPO_ROOT) -> str:
    """报告里的绝对路径 → 仓库相对路径。

    坑（2026-10-21 实测）：报告在服务器上生成，拿回 Windows 用 Git Bash 传
    SECAUTOMIND_STATICCHECK_ROOT=/home/user/... 时，MSYS 会把它改写成
    D:/.../PortableGit/home/user/...，env 前缀匹配不上。所以不能只靠 env，
    再按"能在仓库里定位到的最长后缀"兜底。
    """
    if not raw:
        return ""
    p = raw.replace("\\", "/")
    if root:
        r = root.replace("\\", "/").rstrip("/")
        if p.startswith(r + "/"):
            p = p[len(r) + 1:]
    if p.startswith("./"):
        p = p[2:]
    if p.startswith("/") or (len(p) > 1 and p[1] == ":"):
        # 空段必须过滤："/home/x/a.go".split("/") 首元素是空串，拼回去又变绝对路径
        parts = [x for x in p.split("/") if x]
        # 倒序（**由短到长**）：若由长到短，第一个候选就是完整绝对路径，
        # 而 Path.__truediv__ 遇到带盘符的绝对路径会直接返回右操作数，
        # (repo / cand).exists() 因此为真，key 会退化成绝对路径——
        # 定义行随之匹配不上，凭空造出 referenced_only_by_unknown（2026-10-22 自测抓到）。
        for i in range(len(parts) - 1, -1, -1):
            cand = "/".join(parts[i:])
            if (repo / cand).is_file():
                return cand
    return p


def parse_symbol(message: str) -> tuple[str, str]:
    """`func (*T).meth is unused` → ("func", "(*T).meth")"""
    m = message.replace(" is unused", "").strip()
    parts = m.split(None, 1)
    if len(parts) != 2:
        return ("?", m)
    return parts[0], parts[1]


def bare_name(symbol: str) -> str:
    """`(*T).meth` → `meth`；`WorkflowInput.toStateInputs` → `toStateInputs`"""
    s = symbol
    if s.startswith("("):
        s = s.split(").", 1)[1] if ")." in s else s
    if "." in s:
        s = s.rsplit(".", 1)[-1]
    return s


# ── 引用图 ──────────────────────────────────────────────────────────────────

_FUNC_DECL = re.compile(
    r"^func\s+(?:\(\s*(?P<recv_name>\w+)\s+(?P<recv_type>[^)]+?)\s*\)\s*)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_TYPE_DECL = re.compile(r"^type\s+([A-Za-z_][A-Za-z0-9_]*)")


def enclosing_decl(lines: list[str], idx: int) -> dict | None:
    """从第 idx 行（0-based）往上找最近的 func/type 声明。

    返回 {"name":..., "recv":...}。recv 为 None 表示普通函数/类型声明。

    为什么要带 receiver：第一版只取函数名，于是 `(*Server).handleCallTool`
    里的 `s.cleanupOldExecutions()` 被算成了 `(*ExternalMCPManager)`.
    cleanupOldExecutions 的调用者，凭空造出 5 条 live_caller_anomaly。
    方法名在本仓是重的（三个 receiver 各有一份），**不看 receiver 就不能
    判断谁在调谁**。
    """
    for i in range(idx, -1, -1):
        s = lines[i].strip()
        m = _FUNC_DECL.match(s)
        if m:
            return {"name": m.group("name"), "recv": m.group("recv_type")}
        m = _TYPE_DECL.match(s)
        if m:
            return {"name": m.group(1), "recv": None}
    return None


def split_method(symbol: str) -> tuple[str | None, str]:
    """`(*T).meth` → ("*T", "meth")；`T.meth` → ("T", "meth")；`f` → (None, "f")"""
    if "." not in symbol:
        return None, symbol
    if symbol.startswith("("):
        recv, _, name = symbol.partition(").")
        return recv[1:], name
    recv, _, name = symbol.rpartition(".")
    return recv, name


def _norm_recv(r: str | None) -> str:
    """`*ExternalMCPManager` / `ExternalMCPManager` → `externalmcpmmanager` 级归一。"""
    return (r or "").replace("*", "").replace("&", "").strip()


def same_receiver(a: str | None, b: str | None) -> bool:
    """两个 receiver 是否同一个类型（忽略指针/引用修饰）。"""
    na, nb = _norm_recv(a), _norm_recv(b)
    if not na or not nb:
        return False  # 有一方不是方法 → 不适用 receiver 匹配
    return na == nb


def strip_comment(line: str) -> str:
    """去掉行注释；块注释不处理（局限已在模块 docstring 声明）。"""
    i = line.find("//")
    return line[:i] if i >= 0 else line


def collect_references(pkg_dir: Path, bare: str, def_file: str, def_line: int,
                       unused_keys: set[str],
                       repo: Path | None = None) -> tuple[list[dict], list[str]]:
    """在包目录内找 bare 的引用点，返回 (引用点列表, 调用者符号名列表)。

    repo 显式传入而非读模块级 REPO_ROOT：本脚本会被 --gate 以子进程方式调用，
    测试里改模块属性传不进子进程（2026-10-22 自测抓到）。
    """
    root = repo or REPO_ROOT
    refs: list[dict] = []
    callers: list[str] = []
    pat = re.compile(r"\b" + re.escape(bare) + r"\b")
    for go in sorted(pkg_dir.glob("*.go")):
        rel = go.relative_to(root).as_posix()
        try:
            lines = go.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for i, raw in enumerate(lines, 1):
            if rel == def_file and i == def_line:
                continue  # 定义行自身
            code = strip_comment(raw)
            if not pat.search(code):
                continue
            refs.append({"file": rel, "line": i, "text": code.strip()[:120]})
            d = enclosing_decl(lines, i - 1)
            if d:
                callers.append(d)
    return refs, callers


def build_entries(rows: list[dict], root: str | None,
                  repo: Path | None = None) -> list[dict]:
    repo = repo or REPO_ROOT
    u1000 = [r for r in rows if r.get("code") == "U1000"]
    # 先建符号表：key = "file::symbol"
    meta: dict[str, dict] = {}
    for r in u1000:
        f = norm_path(r["location"]["file"], root, repo)
        line = r["location"]["line"]
        kind, symbol = parse_symbol(r["message"])
        bare = bare_name(symbol)
        key = f"{f}::{symbol}"
        meta[key] = {
            "key": key, "file": f, "line": line, "kind": kind,
            "symbol": symbol, "bare": bare,
            "exported": bare[:1].isupper(),
            "in_test": f.endswith("_test.go"),
        }
    unused_bare = {m["bare"] for m in meta.values()}

    # 同名符号的 live 版本：同一个 bare 名在别处有 **未** 被报 unused 的声明？
    # 这里退一步：只要 U1000 里有 ≥2 个不同 key 共用同一个 bare 名，
    # 说明存在多份实现（其中至多一份是活的）→ 标 dup_candidate。
    bare_count: dict[str, list[str]] = {}
    for k, m in meta.items():
        bare_count.setdefault(m["bare"], []).append(k)

    entries: list[dict] = []
    for key, m in meta.items():
        pkg_dir = (repo / m["file"]).parent
        refs, callers = ([], [])
        if pkg_dir.exists():
            refs, callers = collect_references(
                pkg_dir, m["bare"], m["file"], m["line"], set(meta), repo
            )

        recv, _name = split_method(m["symbol"])
        # 只保留"同名 + 同 receiver"（方法）或"普通函数"的调用者。
        # different-receiver 的调用者记下来但不算数 —— 它们是另一个类型上的
        # 同名方法，与本符号无关（这正是 5 条 anomaly 的来源）。
        dead_callers: list[str] = []
        live_callers: list[str] = []
        cross_recv: list[str] = []
        seen: set[str] = set()
        for c in callers:
            cname, crecv = c["name"], c["recv"]
            if cname == m["bare"]:
                continue
            if recv and not same_receiver(recv, crecv):
                tag = f"{cname}@{crecv}" if crecv else cname
                if tag not in seen:
                    cross_recv.append(tag)
                    seen.add(tag)
                continue
            if cname in seen:
                continue
            (dead_callers if cname in unused_bare else live_callers).append(cname)
            seen.add(cname)

        # dup_of_live：同一个方法名，在别的 receiver 上有**活着**的实现。
        # 这不是死代码，是"三份同源实现只活了一份"（ExternalMCPManager /
        # Server / ExecutionService 各写一遍 abort note 那套）。
        dup_of_live = bool(recv) and bool(cross_recv)

        if m["in_test"]:
            auto = "test_only"
        elif dup_of_live:
            auto = "dup_of_live"
        elif len(bare_count.get(m["bare"], [])) > 1:
            auto = "dup_candidate"
        elif live_callers:
            auto = "live_caller_anomaly"
        elif dead_callers:
            auto = "dead_dependent"
        elif refs:
            auto = "referenced_only_by_unknown"
        else:
            auto = "dead_root"

        entries.append({
            **m,
            "auto_class": auto,
            "dead_callers": dead_callers,
            "live_callers": live_callers,
            "cross_receiver_refs": cross_recv,
            "ref_count": len(refs),
            "refs_sample": refs[:3],
        })
    entries.sort(key=lambda e: (e["auto_class"], e["file"], e["symbol"]))
    return entries


# ── 台账合并 ────────────────────────────────────────────────────────────────

REQUIRED_RULE_FIELDS = ("verdict", "reason")


def merge_ledger(entries: list[dict], ledger: dict) -> tuple[list[dict], list[str]]:
    """把人工裁定（台账 rules）合并进自动明细。缺裁定 = 未裁定。"""
    rules = {r.get("key"): r for r in ledger.get("rules", [])}
    unruled: list[str] = []
    merged = []
    for e in entries:
        r = rules.get(e["key"])
        if not r or any(not r.get(f) for f in REQUIRED_RULE_FIELDS):
            unruled.append(e["key"])
            merged.append({**e, "verdict": None, "reason": None,
                           "reviewed_on": None, "reviewed_by": None})
        else:
            merged.append({**e,
                           "verdict": r.get("verdict"),
                           "reason": r.get("reason"),
                           "reviewed_on": r.get("reviewed_on"),
                           "reviewed_by": r.get("reviewed_by")})
    return merged, unruled


# ── 输出 ────────────────────────────────────────────────────────────────────

def summarize(entries: list[dict]) -> dict:
    cls: dict[str, int] = {}
    verd: dict[str, int] = {}
    for e in entries:
        cls[e["auto_class"]] = cls.get(e["auto_class"], 0) + 1
        v = e.get("verdict") or "UNRULED"
        verd[v] = verd.get(v, 0) + 1
    return {
        "total": len(entries),
        "by_auto_class": dict(sorted(cls.items())),
        "by_verdict": dict(sorted(verd.items())),
        "unruled": [e["key"] for e in entries if not e.get("verdict")],
    }


def print_human(entries: list[dict], s: dict) -> None:
    print("U1000 死代码台账")
    print("=" * 72)
    print(f"  总计 {s['total']} 条")
    print(f"  自动分类：{s['by_auto_class']}")
    print(f"  人工裁定：{s['by_verdict']}")
    print()
    print("【死链根】修它一个，被拖累的叶子自动复活：")
    for e in entries:
        if e["auto_class"] == "dead_root":
            print(f"  {e['key']}")
    print()
    print("【需人工看】脚本不自作聪明判绿：")
    for e in entries:
        if e["auto_class"] in ("live_caller_anomaly", "referenced_only_by_unknown"):
            print(f"  [{e['auto_class']}] {e['key']}  活调用者={e['live_callers']}")
    print()
    if s["unruled"]:
        print(f"【未裁定】{len(s['unruled'])} 条（--gate 下判红）：")
        for k in s["unruled"][:15]:
            print(f"  {k}")
        if len(s["unruled"]) > 15:
            print(f"  ... 另 {len(s['unruled']) - 15} 条")
    else:
        print("【未裁定】0 条 —— 台账全覆盖")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", required=True, help="staticcheck -f json 的输出")
    ap.add_argument("--root", default=os.environ.get(_SCAN_ROOT_ENV),
                    help="报告里的仓库根前缀（用于还原相对路径）")
    ap.add_argument("--ledger", default=str(LEDGER_PATH),
                    help="台账路径（默认 scripts/dead_code_ledger.json）")
    ap.add_argument("--repo-root", default=None,
                    help="仓库根（默认取 scripts 的上一级；子进程调用时可显式指定）")
    ap.add_argument("--write", action="store_true",
                    help="把自动明细写回台账文件的 entries 段（保留 rules）")
    ap.add_argument("--gate", action="store_true", help="门禁：有未裁定则红")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.report):
        print(f"[FATAL] 报告不存在：{args.report}", file=sys.stderr)
        return EXIT_UNVERIFIABLE
    rows, bad = load_report(args.report)
    if bad:
        print(f"[WARN] {bad} 行无法解析（已单独计数，未静默丢弃）", file=sys.stderr)
    if not rows:
        print("[FATAL] 报告为空 —— 扫不到不等于没有死代码", file=sys.stderr)
        return EXIT_UNVERIFIABLE

    if args.repo_root:
        global REPO_ROOT
        REPO_ROOT = Path(args.repo_root).resolve()
    entries = build_entries(rows, args.root, REPO_ROOT)
    if not entries:
        print("[FATAL] 报告里没有 U1000 条目 —— 确认扫描范围是否覆盖了全仓",
              file=sys.stderr)
        return EXIT_UNVERIFIABLE

    ledger: dict = {}
    if os.path.exists(args.ledger):
        with open(args.ledger, encoding="utf-8") as fh:
            ledger = json.load(fh)

    merged, unruled = merge_ledger(entries, ledger)
    s = summarize(merged)

    if args.write:
        ledger["entries"] = merged
        ledger["generated_on"] = ledger.get("generated_on")
        with open(args.ledger, "w", encoding="utf-8") as fh:
            json.dump(ledger, fh, ensure_ascii=False, indent=1)
        print(f"[OK] 明细已写入 {args.ledger}（{len(merged)} 条）")

    if args.json:
        print(json.dumps({"summary": s, "entries": merged},
                         ensure_ascii=False, indent=1))
        return EXIT_OK

    print_human(merged, s)

    # live_caller_anomaly 说明脚本的调用者判定与 staticcheck 不一致，
    # 必须人工核对，不能悄悄放过。
    anomalies = [e for e in merged
                 if e["auto_class"] in ("live_caller_anomaly",
                                        "referenced_only_by_unknown")]
    if args.gate:
        if unruled:
            print(f"\n[GATE] 未裁定 {len(unruled)} 条", file=sys.stderr)
            return EXIT_BLOCKED
        if anomalies:
            print(f"\n[GATE] {len(anomalies)} 条引用判定异常，需人工核对",
                  file=sys.stderr)
            return EXIT_BLOCKED
        print("\n[GATE] PASS：台账全覆盖，无引用判定异常")
        return EXIT_OK

    # 非 gate 模式：有异常/未裁定也要在末尾报出来（负结果先报）
    if anomalies or unruled:
        print(f"\n[NOTE] 未裁定 {len(unruled)} 条 / 异常 {len(anomalies)} 条"
              f"（--gate 下判红）")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
