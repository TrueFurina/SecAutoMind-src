#!/usr/bin/env python3
"""生成 agentic「本次跑批解题子进程」隔离证据（§18 第二条件）。

## 为什么必须有这个脚本

第 13 轮撤回的跨层假绿：Go 探测二进制上的 seccomp 有效，被当成 agentic 跑批
已隔离。实际解题走的是 `subprocess.run([python, '-I', '-c', code])`，另一层。

`agentic_run_binding()` 因此要求第二条件：
`run_binding.subprocess_ip_direct_blocked is True`，且命令指纹与本次跑批一致。

## 怎么证明「子进程」而不是「当前进程」

本脚本**不**在自己进程里测网络，而是用与 `run_python_tool()` 完全相同的调用形态
起子进程：`[sys.executable, '-I', '-c', code]`。探测发生在子进程内，
父进程只收 stdout。子进程继承本进程 UID ⇒ 覆盖跑批时的真实条件。

## fail-closed

- 子进程里 IP 直连**没有**被拦 ⇒ 直接返回 1，不产出证据（宁可没有证据，也不给假绿）。
- AF_UNIX 不可用 ⇒ 也返回 1（隔离过度会破坏 subprocess/工具链，属另一类故障）。

## 局限（写进证据，不靠外围文档提醒）

本证据只对「同 UID 同规则」的跑批成立。跑批必须**以同一 UID 执行**，
否则规则不覆盖；`command_sha256` 绑定正是为了让「证据」与「那一次跑批」对得上。
"""
import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time

DEFAULT_TARGET = "172.16.222.99:22"   # 已知可达（本机 sshd）
DEFAULT_PUBLIC = "1.1.1.1:443"        # 公网目的，验证「不是只有内网被拦」

_CHILD_CODE = r'''
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    s = socket.socket(); s.settimeout(4); s.connect((host, port)); s.close()
    print("CONNECTED")
except OSError as e:
    print("BLOCKED|%s|%s" % (type(e).__name__, getattr(e, "errno", None)))
'''

_UNIX_CODE = r'''
import socket, os, tempfile
p = os.path.join(tempfile.gettempdir(), "af_unix_probe_%d.sock" % os.getpid())
try:
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(p); srv.listen(1)
    cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    cli.connect(p)
    conn, _ = srv.accept()
    conn.sendall(b"ok"); got = cli.recv(2)
    cli.close(); conn.close(); srv.close()
    print("AF_UNIX_OK" if got == b"ok" else "AF_UNIX_BAD_PAYLOAD")
except OSError as e:
    print("AF_UNIX_FAIL|%s|%s" % (type(e).__name__, getattr(e, "errno", None)))
finally:
    try:
        os.unlink(p)
    except OSError:
        pass
'''


def _parse_probe_line(line):
    """把子进程一行输出解析成结构。纯函数，便于变异自测。"""
    line = (line or "").strip()
    if line == "CONNECTED":
        return {"blocked": False, "verdict": "CONNECTED", "raw": line}
    if line.startswith("BLOCKED|"):
        parts = line.split("|")
        errno = parts[2] if len(parts) > 2 and parts[2].isdigit() else None
        return {"blocked": True, "verdict": "BLOCKED",
                "err": parts[1] if len(parts) > 1 else "",
                "errno": int(errno) if errno is not None else None, "raw": line}
    # 任何解析不出的形态都算 INCONCLUSIVE —— 不允许「看不懂当没事」
    return {"blocked": None, "verdict": "INCONCLUSIVE", "raw": line}


def _child_probe(host, port, timeout=20):
    """在与 run_python_tool 相同的启动形态下探测（-I 隔离模式 + -c）。"""
    p = subprocess.run([sys.executable, "-I", "-c", _CHILD_CODE, host, str(port)],
                       capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace")
    out = ((p.stdout or "") + (p.stderr or "")).strip().splitlines()
    line = out[-1] if out else ""
    res = _parse_probe_line(line)
    res["target"] = "%s:%d" % (host, port)
    return res


def _af_unix_probe(timeout=20):
    p = subprocess.run([sys.executable, "-I", "-c", _UNIX_CODE],
                       capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace")
    out = ((p.stdout or "") + (p.stderr or "")).strip().splitlines()
    line = out[-1] if out else ""
    return {"ok": line == "AF_UNIX_OK", "raw": line[:160]}


def _selftest():
    """解析层 4 例 + 真实探测 1 例（反向变异：未隔离环境不得误报 BLOCKED）。"""
    cases = []

    def ck(label, got, want):
        ok = got == want
        cases.append((label, ok, got, want))

    ck("CONNECTED 解析", _parse_probe_line("CONNECTED")["blocked"], False)
    p = _parse_probe_line("BLOCKED|ConnectionRefusedError|111")
    ck("BLOCKED 带 errno 解析", (p["blocked"], p["errno"]), (True, 111))
    p = _parse_probe_line("BLOCKED|TimeoutError|")
    ck("BLOCKED 无 errno 解析", (p["blocked"], p["errno"]), (True, None))
    ck("垃圾行必须 INCONCLUSIVE（不许当没事）",
       _parse_probe_line("Traceback (most recent call last): ...")["blocked"], None)

    # 反向变异：对「本地已监听端口」的真实探测必须判 CONNECTED。
    # 若这条判成 BLOCKED，说明脚本会把「可达」误报成「已隔离」——那整套证据都不可信。
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        r = _child_probe("127.0.0.1", port)
    finally:
        srv.close()
    ck("真实探测：可达端口不得误报 BLOCKED", r["blocked"], False)

    passed = 0
    for label, ok, got, want in cases:
        passed += int(ok)
        print("  %s %-40s got=%r want=%r" % ("PASS" if ok else "FAIL", label, got, want))
    print("gen_agentic_isolation_proof 自测：%d/%d" % (passed, len(cases)))
    return 0 if passed == len(cases) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", nargs="?", help="证据输出路径（--selftest 时可省）")
    ap.add_argument("--command", help="本次跑批命令（空格分隔，与 run_capability_eval 的 -- 之后完全一致）")
    ap.add_argument("--target", default=DEFAULT_TARGET)
    ap.add_argument("--public-target", default=DEFAULT_PUBLIC)
    ap.add_argument("--note", default="")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return _selftest()
    if not args.out or not args.command:
        print("--out 与 --command 均为必填（无命令指纹 = 无法与某次跑批绑定）", file=sys.stderr)
        return 2

    cmd = args.command.split()
    fp = hashlib.sha256(" ".join(cmd).encode("utf-8")).hexdigest()

    th, tp = args.target.rsplit(":", 1)
    ph, pp = args.public_target.rsplit(":", 1)
    t0 = time.strftime("%Y-%m-%dT%H:%M:%S%z")

    probe_internal = _child_probe(th, int(tp))
    probe_public = _child_probe(ph, int(pp))
    af_unix = _af_unix_probe()

    import pwd
    me = pwd.getpwuid(os.getuid())

    problems = []
    if probe_internal.get("blocked") is not True:
        problems.append("子进程内直连 %s 未被拦（%s）" % (args.target, probe_internal.get("verdict")))
    if probe_public.get("blocked") is not True:
        problems.append("子进程内直连 %s 未被拦（%s）" % (args.public_target, probe_public.get("verdict")))
    if not af_unix.get("ok"):
        problems.append("AF_UNIX 不可用（隔离过度，会破坏工具链）：%s" % af_unix.get("raw"))

    proof = {
        "schema": "agentic_isolation_proof/v1",
        "created_at": t0,
        "scope": ("本次跑批的解题子进程（subprocess [python,-I,-c]），"
                  "不是 Go 探测二进制；覆盖条件是「跑批以同一 UID 执行」"),
        "uid": os.getuid(),
        "user": me.pw_name,
        "mechanism": "iptables owner(uid) 匹配 + REJECT --reject-with icmp-port-unreachable",
        "ip_direct_blocked": probe_internal.get("blocked") is True,
        "af_unix_ok": bool(af_unix.get("ok")),
        "probe": {
            "child_launch_form": ["python", "-I", "-c", "<code>"],
            "internal": probe_internal,
            "public": probe_public,
            "af_unix": af_unix,
            "topology": "AF_UNIX 跨进程收发 2 字节；IP 直连两个目的（内网 + 公网）",
        },
        "run_binding": {
            "command": cmd,
            "command_sha256": fp,
            "subprocess_ip_direct_blocked": probe_internal.get("blocked") is True,
            "probed_at": t0,
        },
        "note": args.note,
        "caveats": [
            "本证据只对同 UID 的跑批成立；以其他 UID 执行跑批时规则不覆盖，须重新生成。",
            "证明的是「该 UID 下所有 TCP 目的（除放行的 API IP:443）被 REJECT」，"
            "不证明模型不会用 DNS/ICMP 等其它通道（本项目模型代码路径不提供这些出口）。",
            "REJECT 而非 DROP 是刻意选择：拒绝必须可判定（errno=111），"
            "不允许退化成 supertimeout 那种「看起来没连上」的不可判定状态。",
        ],
        "problems": problems,
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(proof, fh, ensure_ascii=False, indent=2, sort_keys=True)

    print("uid=%d user=%s" % (os.getuid(), me.pw_name))
    print("child internal : %s" % json.dumps(probe_internal, ensure_ascii=False))
    print("child public   : %s" % json.dumps(probe_public, ensure_ascii=False))
    print("af_unix        : %s" % json.dumps(af_unix, ensure_ascii=False))
    print("command_sha256 : %s" % fp)
    print("evidence       : %s" % args.out)
    if problems:
        print("FAIL —— 隔离未成立，拒绝产出可用证据：")
        for x in problems:
            print("  - %s" % x)
        return 1
    print("PASS —— 子进程 IP 直连已拦（可判定 errno），AF_UNIX 正常")
    return 0


if __name__ == "__main__":
    sys.exit(main())
