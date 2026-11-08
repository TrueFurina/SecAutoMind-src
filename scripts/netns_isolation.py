#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解题子进程的网络隔离：**免 root 的 network namespace**（2026-11-08）。

为什么要有这个文件
------------------
第 13 轮起，「agentic 跑批是否真的断网」一直靠 `iptables -m owner --uid-owner 995`
（专用 UID `ctfsbx`）。两个问题在服务器上同时成立：

  ① 需要 root：`sudo -n` 要密码 ⇒ 规则**施不上**，隔离跑批停摆；
  ② 规则**不跨重启**：第 17 轮实测跑前只剩 `-P ACCEPT`，上一轮的隔离早已不存在，
     而"已隔离"这句话还留在历史证据里 —— 状态性证据会腐烂。

`unshare -Un`（user + network namespace）不需要 root（内核允许非特权 userns，
服务器 `unprivileged_userns_clone=1`），且**每个子进程一份新的 netns**：
出网能力从一开始就不存在，没有需要持久化、也没有会腐烂的规则。

实测（服务器 172.16.222.99, kernel 允许非特权 userns）：
    unshare -Un python3 -c "socket.create_connection(('14.103.2.83',443),3)"
    → OSError errno=101 ENETUNREACH（不是 timeout，是**没有路由**）
    同一命令不加 unshare → 连上（服务器确有外网）

🔴 关键约束：降权到 `nobody`
`unshare -U` 不带 `-r` 时进程 uid=65534。而 `/home/user` 是 0750 ⇒ **读不到 home
下的任何东西**。所以被隔离的工作目录必须放在 world 可读可写的位置（`/tmp/...`），
`prepare_cwd()` 负责把它 chmod 出去。反过来这也是个好处：即使模型代码绕过正则去读
题库文件，也读不到 —— 权限层替正则兜底。

用法
----
    python scripts/netns_isolation.py --probe            # 打印探测结果（JSON）
    python scripts/netns_isolation.py --selftest         # 判据自测（不需要 root）
    python scripts/netns_isolation.py --proof out.json   # 生成证据（含 A/B 对照）
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

#: 探测目标：**只认 IP 直连**（域名会引入 DNS，DNS 失败与"断网"同形，分辨不出）
DEFAULT_TARGETS = ("14.103.2.83:443", "1.1.1.1:443", "8.8.8.8:53")

#: 在隔离命名空间内跑的探针。输出**一行 JSON**，不依赖包外任何东西。
_PROBE_SRC = r"""
import json, os, socket, sys
targets = [t.split(":") for t in %r]
out = {"egress": [], "uid": os.getuid(), "loopback_ok": False}
for host, port in targets:
    try:
        s = socket.create_connection((host, int(port)), 3)
        s.close()
        out["egress"].append({"target": host + ":" + port, "connected": True, "errno": 0})
    except OSError as e:
        # errno 可能是 None（超时/被上游黑洞）；用数字格式会 TypeError，故保留原始值
        out["egress"].append({"target": host + ":" + port, "connected": False,
                              "errno": e.errno, "strerror": e.strerror or type(e).__name__})
try:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    out["loopback_ok"] = True
    out["loopback_port"] = srv.getsockname()[1]
    srv.close()
except OSError as e:
    out["loopback_error"] = type(e).__name__ + ": " + str(e)
sys.stdout.write(json.dumps(out))
"""


def python_exe() -> str:
    return sys.executable or "python3"


def _run_probe(prefix, targets, timeout):
    """跑一次探针，返回 (payload_dict, error_text)。prefix 为空=不隔离。"""
    argv = [*prefix, python_exe(), "-I", "-c", _PROBE_SRC % (tuple(targets),)]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"子进程起不来: {type(exc).__name__}: {exc}"
    if proc.returncode != 0:
        return None, "执行失败: " + (proc.stderr or "").strip()[:300]
    try:
        return json.loads((proc.stdout or "").strip().splitlines()[-1]), None
    except (ValueError, IndexError):
        return None, "输出无法解析: " + repr((proc.stdout or "")[:200])


def probe(targets=DEFAULT_TARGETS, timeout: int = 90, control: bool = True) -> dict:
    """探测本机能否「免 root 建 netns 并真的断网」。返回 dict（不抛异常）。

    🔴 判据必须**逐目标做内外对照**，不能只看"里面连不上"：
      服务器实测 `1.1.1.1:443` 在**不隔离**时也连不上（超时，errno=None），
      拿它当"被 netns 挡住"的证据是自证 —— 上游本来就把这个 IP 黑洞了。
      所以每个目标要跑两遍：
        · 外面能连 + 里面连不上 ⇒ 这个目标**有分辨力**，算证据
        · 外面也连不上        ⇒ 无分辨力，不算证据（既不能证有、也不能证无）
        · 里面也能连上        ⇒ 隔离失效，直接不可用（fail-closed）

    判定 available 需要：unshare 存在 + 子进程能起 + **至少一个**有分辨力的目标
    + 这些目标全部在里面断开 + loopback 在里面可用。
    """
    rep = {"mechanism": "unshare -Un (user+net namespace)",
           "available": False, "checked_at": datetime.now(timezone.utc).isoformat(),
           "targets": list(targets)}
    exe = shutil.which("unshare")
    if not exe:
        rep["why"] = "unshare 不存在（util-linux 未安装）"
        return rep
    rep["unshare"] = exe
    inner, err = _run_probe([exe, "-Un"], targets, timeout)
    if inner is None:
        # 典型：`unshare: 写失败：/proc/self/uid_map: 不允许的操作`（`-r` 才会写 uid_map，
        # 所以本模块**不用 -r**）、或 seccomp 挡掉 CLONE_NEWUSER。
        rep["why"] = "netns 建立失败 → " + str(err)
        return rep
    rep.update(inner)
    outer = None
    if control:
        outer, cerr = _run_probe([], targets, timeout)
        if outer is None:
            rep["why"] = "对照组跑不起来（无法判定隔离是否生效）→ " + str(cerr)
            return rep
        rep["control_outside"] = outer
    rep["per_target"] = _merge(inner, outer)
    decisive = [t for t in rep["per_target"] if t.get("outside_connected") is True]
    leaked = [t for t in rep["per_target"] if t.get("inside_connected")]
    rep["decisive_targets"] = [t["target"] for t in decisive]
    rep["leaked"] = leaked
    if leaked:
        rep["why"] = f"隔离未生效：{len(leaked)} 个目标在 netns 内仍可直连"
    elif not inner.get("loopback_ok"):
        rep["why"] = "loopback 不可用（隔离过头，工具子进程无法正常工作）"
    elif control and not decisive:
        rep["why"] = ("所有探测目标在不隔离时也连不上 ⇒ 本机对这批 IP 无分辨力，"
                      "不能据此声称已隔离")
    else:
        rep["available"] = True
        rep["why"] = (f"{len(decisive)} 个目标外面可连、里面 ENETUNREACH，loopback 正常")
    return rep


def _merge(inner, outer):
    """把内外两次探测按目标对齐成一张表（缺一侧记 None，不猜）。"""
    out_map = {}
    if outer:
        out_map = {e["target"]: e for e in outer.get("egress", [])}
    rows = []
    for e in inner.get("egress", []):
        o = out_map.get(e["target"])
        rows.append({"target": e["target"],
                     "inside_connected": bool(e.get("connected")),
                     "inside_errno": e.get("errno"),
                     "inside_strerror": e.get("strerror"),
                     "outside_connected": None if o is None else bool(o.get("connected")),
                     "outside_errno": None if o is None else o.get("errno")})
    return rows


def wrap(argv, targets=DEFAULT_TARGETS):
    """把命令包进新的 user+net namespace。不可用则抛 RuntimeError（fail-closed）。"""
    rep = probe(targets)
    if not rep["available"]:
        raise RuntimeError("netns 隔离不可用：" + rep.get("why", "未知"))
    exe = rep["unshare"]
    return [exe, "-Un", *argv]


def prepare_cwd(path) -> dict:
    """把工作目录放开到 world 可读可写（隔离后 uid=65534 才进得去、写得下）。

    只对 `/tmp` 下的目录做，避免把题库/仓库目录的权限改宽 —— 那会把"隔离"
    变成"顺手把 home 打开"。
    """
    p = os.path.abspath(str(path))
    if not p.startswith(("/tmp/", "/var/tmp/")):
        return {"ok": False, "path": p,
                "why": "拒绝改权限：只允许 /tmp 或 /var/tmp 下的工作目录"}
    changed = 0
    os.chmod(p, 0o777)
    for root, dirs, files in os.walk(p):
        for d in dirs:
            os.chmod(os.path.join(root, d), 0o777)
            changed += 1
        for f in files:
            os.chmod(os.path.join(root, f), 0o666)
            changed += 1
    return {"ok": True, "path": p, "entries_chmod": changed}


# ── 自测：判据本身要能被变异变红（不依赖 root / 不依赖本机是否支持 userns） ──
def _fake_runner(inside_payload, outside_payload):
    """伪造 subprocess.run：按 argv[0] 是不是 unshare 区分"里面/外面"两次调用。"""
    def _run(argv, **kwargs):  # noqa: ANN001
        class R:
            pass
        r = R()
        is_inside = bool(argv) and str(argv[0]).endswith("unshare")
        r.returncode = 0
        r.stdout = inside_payload if is_inside else outside_payload
        r.stderr = ""
        return r
    return _run


def _payload(rows, loopback=True):
    """构造探针输出：rows = [(target, connected, errno)]"""
    return json.dumps({
        "egress": [{"target": t, "connected": c, "errno": e,
                    "strerror": "Network is unreachable" if e == 101 else "ok"}
                   for t, c, e in rows],
        "loopback_ok": loopback, "uid": 65534})


def selftest() -> int:
    results = []
    # 用 `sys.modules[__name__]` 而不是再 import 一次：脚本方式运行时 `import
    # netns_isolation` 会拿到**第二个**模块对象，而 probe() 里读的 `shutil` 是模块级
    # 引用 —— 两个对象会各自持有一份，monkeypatch 打不到被测的那个（假绿温床）。
    self_mod = sys.modules[__name__]

    real_run = subprocess.run
    real_which = shutil.which

    def _with(inside, outside, which=lambda n: "/usr/bin/unshare"):
        shutil.which = which  # type: ignore[assignment]
        subprocess.run = _fake_runner(inside, outside)  # type: ignore[assignment]

    try:
        # ① 里面全断、外面有一个能连 ⇒ 有分辨力且隔离生效
        _with(_payload([("1.1.1.1:443", False, 101), ("8.8.8.8:53", False, 101)]),
              _payload([("1.1.1.1:443", False, None), ("8.8.8.8:53", True, 0)]))
        r = self_mod.probe()
        results.append(("decisive_target_is_available",
                        r["available"] is True and r["decisive_targets"] == ["8.8.8.8:53"],
                        f"decisive={r.get('decisive_targets')} why={r.get('why')}"))

        # ② 里面也能连 ⇒ 隔离没生效（fail-closed，不给自己发"已隔离"）
        _with(_payload([("8.8.8.8:53", True, 0)]), _payload([("8.8.8.8:53", True, 0)]))
        r = self_mod.probe()
        results.append(("inside_leak_is_unavailable", r["available"] is False, r.get("why")))

        # ③ 里外都连不上 ⇒ **无分辨力**，不能声称已隔离（服务器上 1.1.1.1 就是这样）
        _with(_payload([("1.1.1.1:443", False, None)]),
              _payload([("1.1.1.1:443", False, None)]))
        r = self_mod.probe()
        results.append(("no_decisive_target_is_unavailable",
                        r["available"] is False and "无分辨力" in r.get("why", ""),
                        r.get("why")))

        # ④ loopback 挂掉 ⇒ 不可用（隔离过头同样是故障）
        _with(_payload([("8.8.8.8:53", False, 101)], loopback=False),
              _payload([("8.8.8.8:53", True, 0)]))
        r = self_mod.probe()
        results.append(("no_loopback_is_unavailable", r["available"] is False, r.get("why")))

        # ⑤ unshare 不存在 ⇒ 不可用（且要说清是"没装"而不是"跑不起来"）
        _with(_payload([], loopback=False), _payload([], loopback=False),
              which=lambda n: None)
        r = self_mod.probe()
        results.append(("no_unshare_is_unavailable",
                        r["available"] is False and "不存在" in r.get("why", ""),
                        r.get("why")))

        # ⑥ wrap() 在不可用时必须抛（不许静默降级成"没隔离但继续跑"）
        try:
            self_mod.wrap(["python3", "-c", "pass"])
            results.append(("wrap_fail_closed", False, "未抛异常"))
        except RuntimeError as exc:
            results.append(("wrap_fail_closed", True, str(exc)[:60]))

        # ⑦ prepare_cwd 拒绝改题库/家目录权限
        r = self_mod.prepare_cwd(os.path.expanduser("~"))
        results.append(("prepare_cwd_refuses_home",
                        r["ok"] is False and "拒绝" in r.get("why", ""), r.get("why")))
    finally:
        subprocess.run = real_run  # type: ignore[assignment]
        shutil.which = real_which  # type: ignore[assignment]

    failed = [x for x in results if not x[1]]
    for name, ok, msg in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:32} {msg}")
    print(f"\n{len(results) - len(failed)}/{len(results)} 通过")
    return 1 if failed else 0


def build_proof(targets=DEFAULT_TARGETS) -> dict:
    """生成证据：每目标「外面 / 里面」对照表（probe() 已含两次探测）。"""
    rep = probe(targets)
    return {"generated_at": datetime.now(timezone.utc).isoformat(),
            "host": os.uname().nodename if hasattr(os, "uname") else "",
            "python": python_exe(),
            "with_isolation": rep,
            "conclusion": (
                f"隔离生效：{len(rep['decisive_targets'])} 个目标在普通进程里可连、"
                f"在 netns 内 ENETUNREACH；loopback 正常（uid={rep.get('uid')}）"
                if rep["available"] else "不成立：" + rep.get("why", "未知"))}


def main() -> int:
    ap = argparse.ArgumentParser(description="解题子进程网络隔离（免 root netns）")
    ap.add_argument("--probe", action="store_true", help="打印探测结果")
    ap.add_argument("--selftest", action="store_true", help="判据自测")
    ap.add_argument("--proof", default=None, help="生成证据 JSON 的路径")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.proof:
        data = build_proof()
        with open(args.proof, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
        print(f"证据已写入: {args.proof}")
        print("结论:", data["conclusion"])
        return 0 if data["with_isolation"]["available"] else 1
    data = probe()
    print(json.dumps(data, ensure_ascii=False, indent=1))
    return 0 if data["available"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
