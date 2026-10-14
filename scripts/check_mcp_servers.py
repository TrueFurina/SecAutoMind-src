#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MCP 服务清单与契约一致性门禁。

背景（2026-10-14）：
    mcp-servers/ 是对外可交付资产（任意 MCP 客户端都能接），但 CI 此前**没有任何
    job 覆盖它**：服务能不能启动、索引表有没有漏列、README 写的工具名跟实现对不对
    得上，全靠人眼。开写本门禁时做了一遍人工审计，当场命中两处既存缺陷：
      ① README{,_CN}.md 的服务表漏列了目录里真实存在的 pent_claude_agent；
      ② 新入驻服务的 README 声明「零第三方依赖」，代码里却 try/except 导入了 httpx。
    两者都是「写了没人验」，与 AGENTS 第八条「定义齐全 ≠ 接线」同族。

真值源：
    - 「有哪些服务」= mcp-servers/ 的**目录本身**（目录即清单，不是 README）；
    - 「有哪些工具」= 服务的 `tools/list`（真启动子进程问出来的，不是读 README）。

检查项：
    A 清单完整性：目录 ↔ README{,_CN}.md 服务表 双向一致（漏列与死链都红）。
    B 服务必备件：入口脚本 mcp_*.py、README.md、README_CN.md。
    C 依赖声明一致：AST 扫出的第三方顶层模块必须在该服务的两份 README 里点名
      （防「README 说零依赖、代码里有隐藏依赖」）。
    D 协议自证（仅对纯标准库服务，见下）：把服务整包**复制到临时目录**再启动——
      既验证「整包可搬移」，又保证不在工作树留下运行痕迹。断言：
        D1 initialize 返回 protocolVersion
        D2 notifications/initialized 不得产生任何响应（回 id=null 的错误即违规）
        D3 ping 有响应
        D4 tools/list 非空，且每个工具有 name + inputSchema
        D5 tools/call 未知工具名必须报错（不得静默成功）
        D6 非法调用后服务仍存活（还能 ping）
        D7 README 工具表 ⊇ tools/list；README 多出的工具须标注「默认不暴露」
        D8 入口支持 --selftest 时真跑一次：rc=0 且无 traceback

    D 的适用范围是**静态判定**的：只有当服务的 .py 里扫不出任何第三方顶层模块时
    才启动它。这条规则不依赖「当前机器装没装那些包」，因此本地与 CI 行为一致
    （AGENTS 第四条：本地与 CI 环境不同的门禁必须仿真一次 —— 这里从设计上消除差异）。
    其余服务显式 SKIP 并打印原因（AGENTS：取不到真值不许静默放过）。

用法：
    python scripts/check_mcp_servers.py              # 全量（含协议自证）
    python scripts/check_mcp_servers.py --no-probe   # 只做静态检查
    python scripts/check_mcp_servers.py --dir DIR    # 检查任意 mcp-servers 形态目录
    python scripts/check_mcp_servers.py --json
退出码：0 = 合规（含显式跳过）；1 = 不合规；2 = 无法完成（fail-closed）
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:  # pragma: no cover - 非 UTF-8 控制台
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MCP_DIR = os.path.join(ROOT, "mcp-servers")

INDEX_FILES = ("README.md", "README_CN.md")
ENTRY_RE = re.compile(r"^mcp_[A-Za-z0-9_]+\.py$")
SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv", "node_modules", ".idea"}

# 索引表行：| [name](name/) | 说明 |
INDEX_ROW_RE = re.compile(r"^\|\s*\[([^\]]+)\]\(([^)\s]+?)/?\)", re.M)
# README 工具表行：| `tool_name` | 说明 | ...
TOOL_ROW_RE = re.compile(r"^\|\s*`([A-Za-z0-9_]+)`\s*\|(.+?)\|?\s*$", re.M)

# 「默认不暴露」类标注：README 多出 tools/list 的工具时，必须写明它是可选项，否则
# 使用者会误以为开箱就能调。
OPT_IN_MARKERS = (
    "默认关闭", "默认不暴露", "默认不启用", "默认未开启", "需显式开启", "需手动开启",
    "off by default", "not exposed by default", "disabled by default",
    "requires explicit", "opt-in",
)

PROBE_INIT_TIMEOUT = 40.0    # 冷启动 + initialize
PROBE_QUIET_WINDOW = 1.5     # 通知不得产生响应的静默观察窗
PROBE_PING_TIMEOUT = 15.0
PROBE_SELFTEST_TIMEOUT = 120.0


# ── 静态扫描 ──────────────────────────────────────────────


def list_services(base):
    """mcp-servers/ 下的服务目录（按名排序，跳过缓存/隐藏目录）。"""
    out = []
    for name in sorted(os.listdir(base)):
        path = os.path.join(base, name)
        if not os.path.isdir(path) or name in SKIP_DIRS or name.startswith("."):
            continue
        out.append((name, path))
    return out


def index_entries(path):
    """从索引 README 解析服务表 → {service_name: link_target}。"""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    table = {}
    for label, target in INDEX_ROW_RE.findall(text):
        table[label.strip()] = target.strip().strip("/")
    return table


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def py_files(svc_dir):
    out = []
    for dirpath, dirnames, filenames in os.walk(svc_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".py"):
                out.append(os.path.join(dirpath, fn))
    return out


def local_module_names(svc_dir):
    """该服务内部的包名 / 顶层模块名（用于把它们从「第三方」里排除）。"""
    names = set()
    for path in py_files(svc_dir):
        rel = os.path.relpath(path, svc_dir).replace("\\", "/")
        parts = rel.split("/")
        names.add(parts[0][:-3] if len(parts) == 1 else parts[0])
    return names


def _module_scope_imports(node, guarded, out):
    """收集「模块导入期就会执行」的 import → [(top_module, 是否被 try 兜住)]。

    不进入函数体（函数内 import 是惰性的，不影响服务能否启动）；但进入
    try / if / with / for 体。guarded=True 表示该 import 被 try/except 包着
    —— 典型是 httpx 这类可选依赖：缺了它服务照样起得来。
    """
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        g = guarded or isinstance(child, ast.Try)
        if isinstance(child, ast.Import):
            for alias in child.names:
                out.append((alias.name.split(".")[0], g))
        elif isinstance(child, ast.ImportFrom) and not child.level:
            out.append(((child.module or "").split(".")[0], g))
        _module_scope_imports(child, g, out)


def third_party_modules(svc_dir):
    """AST 扫出第三方顶层模块 → {module: {"files": [...], "blocking": bool}}。

    不靠注释、不靠 requirements.txt（本项目真实事故：README 写「零依赖」，
    代码里 try/except 导入 httpx —— 只有扫 AST 才看得见）。

    blocking = 未被 try 兜住、模块导入期即执行 —— 缺了它服务根本起不来，
    因此这类服务不纳入协议自证；被 try 兜住的（可选依赖）仍然自证，
    但同样必须在文档里点名。
    """
    std = set(sys.stdlib_module_names)
    local = local_module_names(svc_dir)
    found = {}
    for path in py_files(svc_dir):
        try:
            tree = ast.parse(read_text(path))
        except SyntaxError:
            continue
        rel = os.path.relpath(path, svc_dir).replace("\\", "/")
        scope = []
        _module_scope_imports(tree, False, scope)
        for top, guarded in scope:
            if not top or top in std or top in local:
                continue
            item = found.setdefault(top, {"files": [], "blocking": False})
            if rel not in item["files"]:
                item["files"].append(rel)
            if not guarded:
                item["blocking"] = True
    return found


def readme_tool_table(text):
    """README 工具表 → {tool_name: 该行文本}。"""
    rows = {}
    for name, rest in TOOL_ROW_RE.findall(text):
        rows[name] = rest
    return rows


def has_opt_in_marker(row_text):
    low = row_text.lower()
    return any(m.lower() in low for m in OPT_IN_MARKERS)


# ── 协议自证（子进程） ────────────────────────────────────


class StdioClient:
    """最小 MCP stdio 客户端：逐行 JSON-RPC，读线程 + 队列（Windows 上 select 不可用于管道）。"""

    def __init__(self, argv, cwd, err_path):
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUNBUFFERED"] = "1"
        self._err = open(err_path, "wb")
        self.proc = subprocess.Popen(
            argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self._err, env=env,
        )
        self._q = queue.Queue()
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    def _pump(self):
        stream = self.proc.stdout
        if stream is None:
            return
        for raw in iter(stream.readline, b""):
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                self._q.put(json.loads(line))
            except ValueError:
                self._q.put({"_raw": line})

    def send(self, obj):
        if self.proc.stdin is None:
            raise RuntimeError("stdin 已关闭")
        self.proc.stdin.write((json.dumps(obj) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def collect(self, seconds):
        """在 seconds 秒内收集到的所有消息。"""
        out, end = [], time.time() + seconds
        while True:
            remain = end - time.time()
            if remain <= 0:
                break
            try:
                out.append(self._q.get(timeout=min(0.2, remain)))
            except queue.Empty:
                continue
        return out

    def wait_id(self, want_id, timeout):
        end = time.time() + timeout
        while True:
            remain = end - time.time()
            if remain <= 0:
                return None
            try:
                msg = self._q.get(timeout=min(0.25, remain))
            except queue.Empty:
                continue
            if isinstance(msg, dict) and msg.get("id") == want_id:
                return msg

    def close(self):
        try:
            if self.proc.stdin is not None:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 - 尽力而为
            try:
                self.proc.kill()
            except Exception:  # noqa: BLE001
                pass
        try:
            self._err.close()
        except OSError:
            pass


def _fail(checks, key, detail):
    checks[key] = {"ok": False, "detail": detail}


def probe_service(svc_dir, entry_name, readmes, note):
    """在临时副本上跑协议自证。返回 (checks, temp_note)。"""
    checks = {}
    tmp = tempfile.mkdtemp(prefix="mcpprobe_")
    work = os.path.join(tmp, "svc")
    try:
        shutil.copytree(
            svc_dir, work,
            ignore=shutil.ignore_patterns(*SKIP_DIRS, "*.pyc"),
        )
    except OSError as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        return {k: {"ok": False, "detail": "临时副本创建失败：%s" % exc}
                for k in ("D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8")}, ""

    err_path = os.path.join(tmp, "stderr.txt")
    client = None
    try:
        client = StdioClient([sys.executable, entry_name], work, err_path)

        # D1 initialize
        client.send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "secautomind-gate", "version": "1"}}})
        resp = client.wait_id(1, PROBE_INIT_TIMEOUT)
        proto = None
        if isinstance(resp, dict):
            proto = (resp.get("result") or {}).get("protocolVersion")
        if proto:
            checks["D1"] = {"ok": True, "detail": "protocolVersion=%s" % proto}
        else:
            _fail(checks, "D1", "initialize 无结果或无 protocolVersion：%s"
                  % json.dumps(resp, ensure_ascii=False)[:200])
            _fail(checks, "D2", "前置 D1 失败，未继续")
            _fail(checks, "D3", "前置 D1 失败，未继续")
            _fail(checks, "D4", "前置 D1 失败，未继续")
            _fail(checks, "D5", "前置 D1 失败，未继续")
            _fail(checks, "D6", "前置 D1 失败，未继续")
            _fail(checks, "D7", "前置 D1 失败，未继续")
            _fail(checks, "D8", "前置 D1 失败，未继续")
            return checks, ""

        # D2 通知不得产生任何响应
        client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        stray = [m for m in client.collect(PROBE_QUIET_WINDOW)
                 if isinstance(m, dict) and "id" in m]
        if stray:
            _fail(checks, "D2", "通知引出了带 id 的响应（协议规定通知不得被响应）：%s"
                  % json.dumps(stray[0], ensure_ascii=False)[:200])
        else:
            checks["D2"] = {"ok": True, "detail": "%.1fs 静默窗内无 id 响应" % PROBE_QUIET_WINDOW}

        # D3 ping
        client.send({"jsonrpc": "2.0", "id": 2, "method": "ping"})
        pong = client.wait_id(2, PROBE_PING_TIMEOUT)
        if isinstance(pong, dict) and "result" in pong:
            checks["D3"] = {"ok": True, "detail": "ping 有 result"}
        else:
            _fail(checks, "D3", "ping 无有效响应：%s"
                  % json.dumps(pong, ensure_ascii=False)[:200])

        # D4 tools/list
        client.send({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        tl = client.wait_id(3, PROBE_PING_TIMEOUT)
        tools = []
        if isinstance(tl, dict):
            tools = ((tl.get("result") or {}).get("tools") or [])
        if not tools:
            _fail(checks, "D4", "tools/list 为空或失败：%s"
                  % json.dumps(tl, ensure_ascii=False)[:200])
            names = []
        else:
            bad = [t for t in tools
                   if not isinstance(t.get("name"), str)
                   or not isinstance(t.get("inputSchema"), dict)]
            names = [t["name"] for t in tools if isinstance(t.get("name"), str)]
            if bad:
                _fail(checks, "D4", "%d 个工具缺 name/inputSchema" % len(bad))
            else:
                checks["D4"] = {"ok": True, "detail": "%d 个工具，均有 name+inputSchema" % len(tools)}

        # D5 未知工具必须报错
        client.send({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                     "params": {"name": "__gate_no_such_tool__", "arguments": {}}})
        unk = client.wait_id(4, PROBE_PING_TIMEOUT)
        if isinstance(unk, dict) and ("error" in unk
                                      or (unk.get("result") or {}).get("isError") is True):
            checks["D5"] = {"ok": True, "detail": "未知工具返回错误（未静默成功）"}
        else:
            _fail(checks, "D5", "未知工具未报错，疑似静默成功：%s"
                  % json.dumps(unk, ensure_ascii=False)[:200])

        # D6 非法调用后仍存活
        client.send({"jsonrpc": "2.0", "id": 5, "method": "ping"})
        alive = client.wait_id(5, PROBE_PING_TIMEOUT)
        if isinstance(alive, dict) and alive.get("result") is not None:
            checks["D6"] = {"ok": True, "detail": "非法调用后仍响应 ping"}
        else:
            _fail(checks, "D6", "非法调用后服务无响应（可能已退出）：%s"
                  % json.dumps(alive, ensure_ascii=False)[:200])

        # D7 README 工具表 vs tools/list
        d7_ok, d7_detail = check_tool_table(readmes, names)
        checks["D7"] = {"ok": d7_ok, "detail": d7_detail}

        # D8 --selftest（约定式，入口实现即跑）
        entry_text = read_text(os.path.join(work, entry_name))
        if "--selftest" not in entry_text:
            checks["D8"] = {"ok": True, "skipped": True,
                            "detail": "入口未提供 --selftest，跳过（真调用由 D4/D5 覆盖协议面）"}
        else:
            proc = subprocess.run(
                [sys.executable, entry_name, "--selftest"], cwd=work,
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=PROBE_SELFTEST_TIMEOUT, env={**os.environ,
                                                     "PYTHONIOENCODING": "utf-8"},
            )
            blob = (proc.stdout or "") + (proc.stderr or "")
            if proc.returncode == 0 and "Traceback" not in blob:
                checks["D8"] = {"ok": True, "detail": "--selftest rc=0 且无 traceback"}
            else:
                _fail(checks, "D8", "--selftest rc=%d：%s"
                      % (proc.returncode, blob.strip()[-300:]))
        return checks, note
    except Exception as exc:  # noqa: BLE001 - 探测本身失败也是不合规
        for k in ("D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8"):
            checks.setdefault(k, {"ok": False, "detail": "探测异常：%r" % exc})
        return checks, note
    finally:
        if client is not None:
            client.close()
        shutil.rmtree(tmp, ignore_errors=True)


def check_tool_table(readmes, live_names):
    """D7：tools/list ⊆ README 工具表；README 多出的工具必须标注「默认不暴露」。"""
    problems, skipped = [], []
    live = set(live_names)
    for label, text in readmes.items():
        if not text:
            skipped.append(label)
            continue
        rows = readme_tool_table(text)
        missing = sorted(live - set(rows))
        if missing:
            problems.append("%s 未收录实现已暴露的工具：%s" % (label, ", ".join(missing)))
        extra = sorted(set(rows) - live)
        unmarked = [t for t in extra if not has_opt_in_marker(rows[t])]
        if unmarked:
            problems.append("%s 列了未暴露的工具却未标注「默认不暴露」：%s"
                            % (label, ", ".join(unmarked)))
    if problems:
        return False, "；".join(problems)
    detail = "README 工具表与 tools/list 一致（实现 %d 个）" % len(live)
    if skipped:
        detail += "；%s 未解析（跳过）" % ", ".join(skipped)
    return True, detail


# ── 主流程 ────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=None, help="mcp-servers 目录（默认仓内）")
    ap.add_argument("--no-probe", action="store_true", help="跳过子进程协议自证")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    base = os.path.abspath(args.dir) if args.dir else MCP_DIR
    if not os.path.isdir(base):
        print("[FAIL-CLOSED] mcp-servers 目录不存在：%s" % base, file=sys.stderr)
        return 2

    index_paths = {}
    for fn in INDEX_FILES:
        path = os.path.join(base, fn)
        if not os.path.isfile(path):
            print("[FAIL-CLOSED] 索引文件缺失：%s" % path, file=sys.stderr)
            return 2
        index_paths[fn] = path

    indexes = {fn: index_entries(path) for fn, path in index_paths.items()}
    services = list_services(base)
    disk_names = [name for name, _ in services]

    findings = []
    report = []

    # A 清单完整性（双向）
    for fn, table in indexes.items():
        for name in disk_names:
            if name not in table:
                findings.append({"check": "A", "target": fn,
                                 "detail": "目录存在但索引未收录：%s" % name})
    indexed_targets = set()
    for fn, table in indexes.items():
        for name, target in table.items():
            indexed_targets.add(target)
            if not os.path.isdir(os.path.join(base, target)):
                findings.append({"check": "A", "target": fn,
                                 "detail": "索引指向不存在的目录：%s → %s/" % (name, target)})

    for name, svc_dir in services:
        entry = None
        for fn in sorted(os.listdir(svc_dir)):
            if ENTRY_RE.match(fn) and os.path.isfile(os.path.join(svc_dir, fn)):
                entry = fn
                break
        readme_files = {}
        for fn in ("README.md", "README_CN.md"):
            p = os.path.join(svc_dir, fn)
            if os.path.isfile(p):
                readme_files[fn] = read_text(p)
            else:
                findings.append({"check": "B", "target": name, "detail": "缺 %s" % fn})
        if entry is None:
            findings.append({"check": "B", "target": name, "detail": "缺入口脚本 mcp_*.py"})

        # C 依赖声明一致（必需 + 可选都要点名）
        deps = third_party_modules(svc_dir)
        for mod in sorted(deps):
            norm = mod.replace("_", "-").lower()
            kind = "必需" if deps[mod]["blocking"] else "可选（try/except 兜住）"
            for fn, text in readme_files.items():
                if norm not in text.replace("_", "-").lower():
                    findings.append({
                        "check": "C", "target": "%s/%s" % (name, fn),
                        "detail": "第三方模块 %s（%s；%s；出现在 %s）未在文档点名——"
                                  "使用者会以为零依赖"
                                  % (mod, kind, "模块导入期执行" if deps[mod]["blocking"]
                                     else "缺失即降级", ", ".join(deps[mod]["files"])),
                    })

        # D 协议自证
        probe = {}
        probe_state, probe_note = "skipped", ""
        blocking = sorted(m for m, v in deps.items() if v["blocking"])
        if entry is None:
            probe_state, probe_note = "skipped", "无入口脚本，无法启动"
        elif blocking:
            probe_state = "skipped"
            probe_note = ("有启动必需的第三方依赖（%s），按静态规则不启动子进程"
                          "——本地与 CI 行为一致" % ", ".join(blocking))
        elif args.no_probe:
            probe_state, probe_note = "skipped", "--no-probe 指定跳过"
        else:
            probe, probe_note = probe_service(
                svc_dir, entry,
                {k: v for k, v in readme_files.items()}, "")
            probe_state = "run"
            for key in sorted(probe):
                if not probe[key]["ok"]:
                    findings.append({"check": key, "target": name,
                                     "detail": probe[key]["detail"]})
        report.append({
            "service": name, "entry": entry,
            "third_party": [{"module": m, "blocking": deps[m]["blocking"],
                             "files": sorted(deps[m]["files"])} for m in sorted(deps)],
            "probe": probe_state, "probe_note": probe_note,
            "checks": {k: {"ok": v["ok"], "skipped": v.get("skipped", False),
                           "detail": v["detail"]} for k, v in sorted(probe.items())},
        })

    ok = not findings
    if args.json:
        print(json.dumps({
            "root": base, "ok": ok,
            "indexed": {fn: sorted(t) for fn, t in indexes.items()},
            "services": report, "findings": findings,
        }, ensure_ascii=False, indent=2))
        return 0 if ok else 1

    print("MCP 服务清单与契约一致性 · 目录 %s" % base)
    print("  目录内服务 %d 个：%s" % (len(disk_names), ", ".join(disk_names) or "（无）"))
    for fn, table in indexes.items():
        print("  %s 收录 %d 个：%s" % (fn, len(table), ", ".join(sorted(table)) or "（无）"))
    for item in report:
        if item["probe"] == "run":
            failed = [k for k, v in item["checks"].items() if not v["ok"]]
            skipped = [k for k, v in item["checks"].items() if v.get("skipped")]
            tail = "协议自证 %d 项全过" % len(item["checks"])
            if skipped:
                tail += "（%s 约定未实现，跳过）" % ",".join(skipped)
            if failed:
                tail = "协议自证失败：%s" % ",".join(failed)
            print("  [%s] %s ← %s" % ("FAIL" if failed else "PASS", item["service"], tail))
            for k in sorted(item["checks"]):
                v = item["checks"][k]
                if not v["ok"] or not v.get("skipped"):
                    print("        %s %s %s" % ("ok " if v["ok"] else "BAD", k, v["detail"]))
        else:
            print("  [SKIP] %s ← %s" % (item["service"], item["probe_note"]))
            if item["third_party"]:
                print("        第三方依赖：%s" % ", ".join(
                    "%s%s" % (d["module"], "" if d["blocking"] else "(可选)")
                    for d in item["third_party"]))
    for f in findings:
        print("  [FAIL] (%s) %s：%s" % (f["check"], f["target"], f["detail"]))
    if ok:
        print("  [PASS] 清单/依赖/协议三层一致（目录 ↔ 索引 ↔ tools/list）")
    else:
        print("  [BLOCK] %d 处不一致（使用者会照着一份错的清单或文档配置）" % len(findings))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
