#!/usr/bin/env python3
"""
执行基准集判定器：对 execution_benchmark.json 每道题真正执行工具提取 flag，
SHA-256 对齐验证。覆盖 strings / git / base64源码 / cookie / 小端序 / pcap。

运行：
  python data/ctf_benchmark/judge_exec.py
"""
import json
import os
import re
import sys
import time
import base64
import struct
import subprocess
import hashlib
import threading
import urllib.request
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "execution_benchmark.json")
EXEC_DIR = os.path.join(HERE, "execution")
LIVE_DIR = os.path.join(HERE, "live_target")


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def scan_flags(text: str) -> list:
    out = []
    for m in re.finditer(r'(?i)[a-zA-Z0-9_]*(?:flag|ctf|key)[a-zA-Z0-9_]*\s*[=:：]?\s*\{[^}]+\}', text):
        if m.group(0) not in out:
            out.append(m.group(0))
    for m in re.finditer(r'[A-Z][A-Z0-9]{2,15}\{[^}]+\}', text):
        if m.group(0) not in out:
            out.append(m.group(0))
    return out


# ── 执行求解器（真实调用工具） ──────────────────────────

def try_strings(path: str):
    """真正调用系统 strings 工具（不可用时 Python 等价）。"""
    try:
        out = subprocess.run(["strings", path], capture_output=True, text=True, timeout=30).stdout
    except Exception:
        data = open(path, "rb").read()
        out = "".join(chr(b) if 32 <= b < 127 else "\n" for b in data)
    return scan_flags(out)


def try_git_log(path: str):
    """真正执行 git log -p 提取历史泄露的 flag。"""
    try:
        out = subprocess.run(["git", "-C", path, "log", "-p", "--all", "--no-color"],
                             capture_output=True, text=True, timeout=60).stdout
    except Exception as e:
        return ["ERR:" + str(e)]
    return scan_flags(out)


def try_base64_source(path: str):
    text = open(path, encoding="utf-8", errors="ignore").read()
    for m in re.finditer(r'[A-Za-z0-9+/=]{16,}', text):
        try:
            dec = base64.b64decode(m.group(0) + "=" * ((4 - len(m.group(0)) % 4) % 4)).decode("utf-8", "ignore")
        except Exception:
            continue
        f = scan_flags(dec)
        if f:
            return f
    return []


def try_cookie(path: str):
    text = open(path, encoding="utf-8", errors="ignore").read()
    for m in re.finditer(r'(?:session|cookie|token)=([A-Za-z0-9+/=]+)', text):
        try:
            dec = base64.b64decode(m.group(1) + "=" * ((4 - len(m.group(1)) % 4) % 4)).decode("utf-8", "ignore")
        except Exception:
            continue
        f = scan_flags(dec)
        if f:
            return f
    return []


def try_endian(path: str):
    raw = open(path, "rb").read()
    dec = raw[::-1].decode("utf-8", "ignore")
    return scan_flags(dec)


def try_pcap_http(path: str):
    """纯 Python pcap 解析（等价 tshark 提取 HTTP 请求体）。"""
    data = open(path, "rb").read()
    if len(data) < 24:
        return []
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0xa1b2c3d4:
        return []
    off = 24
    stream = b""
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, orig = struct.unpack_from("<IIII", data, off)
        off += 16
        pkt = data[off:off + incl]
        off += incl
        # 跳 Ethernet(14)+IP(20)+TCP(20)，余下为 TCP 载荷
        if len(pkt) > 54:
            stream += pkt[54:]
        else:
            stream += pkt
    text = stream.decode("latin1", "ignore")
    return scan_flags(text)


SOLVERS = {
    "strings_flag": try_strings,
    "git_history": try_git_log,
    "web_source_audit": try_base64_source,
    "cookie_decode": try_cookie,
    "endian_swap": try_endian,
    "pcap_http": try_pcap_http,
}


# ── 实时靶机利用求解器（真正起服务 + 发 payload） ──────────

def _start_target(port: int) -> subprocess.Popen:
    proc = subprocess.Popen([sys.executable, os.path.join(LIVE_DIR, "vuln_app.py"), str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # 等端口起来
    for _ in range(50):
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=1)
            return proc
        except Exception:
            time.sleep(0.1)
    return proc


def try_live_sqli(path: str = "") -> list:
    """真正起靶机，POST SQL 注入绕过 payload 提取 flag。"""
    port = 18099
    proc = _start_target(port)
    try:
        data = urllib.parse.urlencode({"user": "admin' OR '1'='1", "pass": "x"}).encode()
        resp = urllib.request.urlopen("http://127.0.0.1:%d/login" % port, data=data, timeout=10).read().decode()
        return scan_flags(resp)
    except Exception as e:
        return ["ERR:" + str(e)]
    finally:
        proc.terminate()


def try_live_ssti(path: str = "") -> list:
    """真正起靶机，GET SSTI payload {{flag()}} 触发 flag。"""
    port = 18099
    proc = _start_target(port)
    try:
        url = "http://127.0.0.1:%d/ssti?name=%s" % (port, urllib.parse.quote("{{flag()}}"))
        resp = urllib.request.urlopen(url, timeout=10).read().decode()
        return scan_flags(resp)
    except Exception as e:
        return ["ERR:" + str(e)]
    finally:
        proc.terminate()


LIVE_SOLVERS = {
    "live_sqli": try_live_sqli,
    "live_ssti": try_live_ssti,
}


def main():
    bench = json.load(open(BENCH, encoding="utf-8"))
    problems = bench["problems"]
    hit = miss = 0
    results = []
    for pid, p in problems.items():
        skill = p.get("presolve_skill", "")
        flag = None
        # 实时靶机题：真正起服务发 payload
        if skill in LIVE_SOLVERS:
            found = LIVE_SOLVERS[skill]()
            if found:
                flag = found[0]
        else:
            fn = SOLVERS.get(skill)
            if fn:
                atts = p.get("attachments", {})
                rel = list(atts.values())[0]
                full = os.path.join(EXEC_DIR, rel)
                found = fn(full)
                if found:
                    flag = found[0]
        matched = False
        if flag:
            matched = sha256(flag) == p["flag_sha256"]
            if matched:
                hit += 1
            else:
                miss += 1
        else:
            miss += 1
        results.append({"id": pid, "skill": skill, "flag": flag, "sha256_match": matched})
        print("  %s %s  skill=%s flag=%s" % (
            "✅" if matched else "❌", pid, skill,
            (flag[:40] + "…") if flag and len(flag) > 40 else flag))
    total = len(problems)
    print("\n=== 执行基准集覆盖率 ===")
    print("总数: %d  命中: %d  未命中: %d  覆盖率: %.1f%%" % (total, hit, miss, hit / total * 100))
    json.dump({"total": total, "hit": hit, "miss": miss,
               "coverage_pct": round(hit / total * 100, 1), "results": results},
              open(os.path.join(HERE, "execution_coverage_report.json"), "w"),
              indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
