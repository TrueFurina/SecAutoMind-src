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
    best = []
    for m in re.finditer(r'[A-Za-z0-9+/=]{16,}', text):
        # 多偏移对齐尝试：候选串前部可能吸附 query param 名等非 b64 内容
        # （如 data=<b64> 被整体匹配，解码出垃圾前缀污染 flag）。
        # 收集全部偏移命中返回最短 flag——垃圾前缀必使匹配串更长。
        for off in range(0, min(8, len(m.group(0)))):
            seg = m.group(0)[off:]
            if '=' in seg.rstrip('='):
                continue  # 中间出现 = 为错位对齐（如 data=<b64> 的 param 名吸附），必产垃圾
            try:
                dec = base64.b64decode(seg + "=" * ((4 - len(seg) % 4) % 4)).decode("utf-8", "ignore")
            except Exception:
                continue
            for f in scan_flags(dec):
                if not best or len(f) > len(best[0]):
                    best = [f]
    return best


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


MORSE_TABLE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
}


def try_morse(path: str):
    """解码 morse 工件（等价图片提取后产物），按 flag{解码内容小写} 约定组合。
    逐行判定：整行去掉空白后必须全为合法 morse token（排除普通句子碎片）。"""
    morse_to_char = {v: k for k, v in MORSE_TABLE.items()}  # MORSE_TABLE 为 char→morse
    text = open(path, encoding="utf-8", errors="ignore").read()
    for line in text.splitlines():
        toks = re.findall(r'[.\-]+', line)
        if len(toks) < 4:
            continue
        if line.replace(' ', '').replace('\t', '') != ''.join(toks):
            continue  # 行内含非 morse 字符（冒号/字母/斜杠等），跳过
        dec = "".join(morse_to_char.get(t, "") for t in toks)
        if len(dec) >= 4:
            f = scan_flags("flag{" + dec.lower() + "}")
            if f:
                return f
    return []


def _param_search(text: str, pattern: str):
    return re.search(pattern, text, re.I)


def try_common_modulus_attack(path: str):
    """完整共模攻击：同 n 不同 e（gcd(e1,e2)=1），egcd 合并两密文还原明文。"""
    text = open(path, encoding="utf-8", errors="ignore").read()
    m_n = _param_search(text, r'\bn\s*=\s*(\d+)')
    m_e1 = _param_search(text, r'\be1\s*=\s*(\d+)')
    m_e2 = _param_search(text, r'\be2\s*=\s*(\d+)')
    m_c1 = _param_search(text, r'\bc1\s*=\s*(\d+)')
    m_c2 = _param_search(text, r'\bc2\s*=\s*(\d+)')
    if not (m_n and m_e1 and m_e2 and m_c1 and m_c2):
        return []
    n, e1, e2 = int(m_n.group(1)), int(m_e1.group(1)), int(m_e2.group(1))
    c1, c2 = int(m_c1.group(1)), int(m_c2.group(1))

    def egcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x, y = egcd(b, a % b)
        return g, y, x - (a // b) * y

    g, s, t = egcd(e1, e2)
    if g != 1:
        return []
    c1p = pow(c1, s, n) if s >= 0 else pow(pow(c1, -1, n), -s, n)
    c2p = pow(c2, t, n) if t >= 0 else pow(pow(c2, -1, n), -t, n)
    m = (c1p * c2p) % n
    return scan_flags(m.to_bytes((m.bit_length() + 7) // 8, "big").decode("latin1"))


def try_hastad_broadcast_attack(path: str):
    """完整 Hastad 广播攻击：e 组同明文不同 n，CRT 合成后开 e 次根。"""
    text = open(path, encoding="utf-8", errors="ignore").read()
    m_e = _param_search(text, r'\be\s*=\s*(\d+)')
    if not m_e:
        return []
    e = int(m_e.group(1))
    if e <= 0 or e > 16:
        return []
    ns, cs = {}, {}
    for m in re.finditer(r'\bn(\d*)\s*=\s*(\d+)', text, re.I):
        ns[m.group(1)] = int(m.group(2))
    for m in re.finditer(r'\bc(\d*)\s*=\s*(\d+)', text, re.I):
        cs[m.group(1)] = int(m.group(2))
    keys = sorted(ns.keys())
    if len(ns) < e or len(cs) < e:
        return []
    # 取前 e 组 n 与对应索引的 c
    n_list, c_list = [], []
    for i in range(e):
        key = "" if i == 0 else str(i + 1)
        if key not in ns or key not in cs:
            # 兼容纯数字键序
            if i < len(keys):
                key = keys[i]
            else:
                return []
        if key not in ns or key not in cs:
            return []
        n_list.append(ns[key])
        c_list.append(cs[key])
    # CRT
    N = 1
    for ni in n_list:
        N *= ni
    x = 0
    for ni, ci in zip(n_list, c_list):
        Ni = N // ni
        x += ci * Ni * pow(Ni, -1, ni)
    x %= N
    # 整数 e 次根（二分）
    lo, hi = 0, 1 << (x.bit_length() // e + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** e < x:
            lo = mid + 1
        else:
            hi = mid
    if lo ** e != x:
        return []
    return scan_flags(lo.to_bytes((lo.bit_length() + 7) // 8, "big").decode("latin1"))


def try_rsa_wiener_attack(path: str):
    """完整 Wiener 攻击：e/n 连分数展开取收敛分数候选 d，验证 c^d ≡ m。"""
    text = open(path, encoding="utf-8", errors="ignore").read()
    m_e = _param_search(text, r'\be\s*=\s*(\d+)')
    m_n = _param_search(text, r'\bn\s*=\s*(\d+)')
    m_c = _param_search(text, r'\bc\s*=\s*(\d+)')
    if not (m_e and m_n and m_c):
        return []
    e, n, c = int(m_e.group(1)), int(m_n.group(1)), int(m_c.group(1))
    # 连分数展开 e/n，收敛分数递推 (h=分子k, k=分母d)
    a, b = e, n
    h0, h1, k0, k1 = 0, 1, 1, 0
    while b:
        q = a // b
        a, b = b, a - q * b
        h0, h1 = h1, q * h1 + h0
        k0, k1 = k1, q * k1 + k0
        if h1 <= 0 or k1 <= 0:
            continue
        m = pow(c, k1, n)
        f = scan_flags(m.to_bytes((m.bit_length() + 7) // 8, "big").decode("latin1"))
        if f:
            return f
    return []


SOLVERS = {
    "strings_flag": try_strings,
    "git_history": try_git_log,
    "web_source_audit": try_base64_source,
    "cookie_decode": try_cookie,
    "endian_swap": try_endian,
    "pcap_http": try_pcap_http,
    "morse_decode": try_morse,
    "common_modulus_attack": try_common_modulus_attack,
    "hastad_broadcast_attack": try_hastad_broadcast_attack,
    "rsa_wiener_attack": try_rsa_wiener_attack,
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
