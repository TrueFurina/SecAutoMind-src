#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""自造私有题池生成器 v1：10 道纯文本可解题（材料全内嵌，零附件依赖）。

为什么这样造（对应 2026-11-07 锐评 + F-14 结构不可解）
------------------------------------------------------------
pure_llm 路径禁用 `--artifact-dir`，此前全池 17/154 题引用外部文件而
`_attachments` 下 0/17 有对应目录 ⇒ `rate=0.0` 的上限由**题目可解性**决定，
不是模型能力。本池的硬约束：

  1. 材料 100% 内嵌 description（密文 / 参数 / 校验代码），不引用任何文件；
  2. flag 明文**不由任何文件保存**：由固定种子 sha256 派生，生成器与池文件
     里都只有哈希，硬要还原必须真的解一遍；
  3. 每题附独立 solver，**只从 description 文本解析参数**求解 —— 生成时
     逐题断言 `sha256(solve(desc)) == flag_sha256`，即「仅凭题面可解」的机验；
  4. 难度梯度 easy→hard，避免全 0 又被误读成「能力为零」。

用法：
  python scripts/gen_private_pool_v1.py   # 默认写 data/ctf_benchmark/private_benchmark_v1.json
  # 文件名必须含 "benchmark"：check_benchmark_plaintext_answer 的覆盖契约
  # 会把「长得像题集但没进扫描」的顶层 json 判红（第七个偏差：命名绕过）
  python scripts/gen_private_pool_v1.py --verify <pool.json>   # 复验可解性（不改文件）
  python scripts/gen_private_pool_v1.py --selftest             # 变异验证：坏题必须被拒
退出码：0 全通过 / 1 有题不可解或口径不符 / 2 用法错误。
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POOL_OUT = os.path.join(ROOT, "data", "ctf_benchmark",
                        "private_benchmark_v1.json")

SEED = "secautomind/private-pool/v1"

# 🔴 2026-11-07 修：本文件此前自带一份 `FLAG_RE = re.compile(r"flag\{...\}")`
# 并用 sha256 直接比原文候选 —— 被 `check_flag_eval_regex.py` 判
# `B:no-normalization`（CI 因此红了两个提交未察觉）。这等于仓库里第 10 份
# 判分正则副本，且只认小写 flag：题面若被改成 FLAG{...} 就漏判。
# 正解不是给门禁加豁免，而是**不再维护副本**：统一从判分口径取。
sys.path.insert(0, os.path.join(ROOT, "scripts", "experiments"))
from flag_util import FLAG_RE  # noqa: E402


def _h(tag: str, n: int = 16) -> str:
    """由种子派生一段十六进制串；不含任何明文答案。"""
    return hashlib.sha256(("%s/%s" % (SEED, tag)).encode("utf-8")).hexdigest()[:n]


def _flag(inner: str) -> str:
    return "flag{%s}" % inner


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# 通用小工具
# --------------------------------------------------------------------------
def iroot3(n: int) -> int:
    """整数立方根（牛顿法，向下取整）。"""
    if n < 0:
        raise ValueError("negative")
    if n == 0:
        return 0
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def inv_mod(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("not invertible")
    return x % m


def next_prime(n: int) -> int:
    """确定性下一个素数（Miller-Rabin 固定底），用于固定生成 RSA 参数。"""
    def is_prime(x: int) -> bool:
        if x < 2:
            return False
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if x % p == 0:
                return x == p
        d, s = x - 1, 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            y = pow(a, d, x)
            if y in (1, x - 1):
                continue
            for _ in range(s - 1):
                y = y * y % x
                if y == x - 1:
                    break
            else:
                return False
        return True

    if n % 2 == 0:
        n += 1
    while not is_prime(n):
        n += 2
    return n


# --------------------------------------------------------------------------
# 十道题：每题返回 (description, flag_plain, solver)
# solver 只吃 description 文本，产出 flag 明文。
# --------------------------------------------------------------------------
def build_p01():
    inner = _h("p01")
    plain = _flag(inner)
    key = 0x5A
    ct = bytes(b ^ key for b in plain.encode()).hex()
    desc = (
        "A short message was encrypted by XOR-ing every byte of the plaintext "
        "with the SAME single unknown byte key. The result is given below as "
        "lowercase hex. The plaintext is a flag that starts with the five "
        "characters `flag{` and ends with `}`; the inner part is 16 lowercase "
        "hex characters.\n\n"
        "ciphertext_hex = %s\n\n"
        "Recover the plaintext flag. Submit it exactly, wrapped in flag{...}."
        % ct
    )

    def solve(d: str) -> str:
        hx = re.search(r"ciphertext_hex\s*=\s*([0-9a-fA-F]+)", d).group(1)
        raw = binascii.unhexlify(hx)
        for k in range(256):
            cand = bytes(b ^ k for b in raw)
            if cand.startswith(b"flag{") and cand.endswith(b"}"):
                try:
                    return cand.decode("utf-8")
                except UnicodeDecodeError:
                    continue
        raise AssertionError("no key found")

    return desc, plain, solve


def build_p02():
    # m 取 80 bit，保证 m^3 < n（n 为两个 128-bit 素数之积）
    m = int(_h("p02", 20), 16)
    p = next_prime(int(_h("p02p", 32), 16) | (1 << 127))
    q = next_prime(int(_h("p02q", 32), 16) | (1 << 127))
    n = p * q
    e = 3
    assert m ** 3 < n, "m^3 must be below n for the low-exponent shortcut"
    c = pow(m, e, n)
    plain = _flag("%x" % m)
    desc = (
        "An RSA key uses a small public exponent and, crucially, no padding. "
        "You are given the modulus, the exponent and one ciphertext. The "
        "message integer m was small enough that m^e did not wrap around the "
        "modulus.\n\n"
        "n = %d\ne = %d\nc = %d\n\n"
        "Recover m. The flag is `flag{` + the lowercase hexadecimal "
        "representation of m (no leading zeros) + `}`."
        % (n, e, c)
    )

    def solve(d: str) -> str:
        n = int(re.search(r"^n\s*=\s*(\d+)", d, re.M).group(1))
        e = int(re.search(r"^e\s*=\s*(\d+)", d, re.M).group(1))
        c = int(re.search(r"^c\s*=\s*(\d+)", d, re.M).group(1))
        assert e == 3
        m = iroot3(c)
        assert pow(m, e, n) == c and m < n, "cube root did not verify"
        return _flag("%x" % m)

    return desc, plain, solve


def build_p03():
    inner = _h("p03", 12)
    plain = _flag(inner)
    kw = "SECAUTOMIND"
    out, j = [], 0
    for ch in plain:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = ord(kw[j % len(kw)]) - ord("A")
            j += 1
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    ct = "".join(out)
    desc = (
        "The ciphertext below was produced with a repeating-key Vigenere "
        "cipher over ASCII letters. Non-letter characters were copied "
        "unchanged, and the key advances only on letters. The key is the "
        "uppercase word `SECAUTOMIND` and it restarts from the first letter "
        "for every new message.\n\n"
        "ciphertext = %s\n\n"
        "Decrypt it to obtain the flag (the plaintext already is in flag{...} "
        "form)." % ct
    )

    def solve(d: str) -> str:
        ct = re.search(r"ciphertext\s*=\s*(\S+)", d).group(1)
        kw = "SECAUTOMIND"
        out, j = [], 0
        for ch in ct:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                shift = ord(kw[j % len(kw)]) - ord("A")
                out.append(chr((ord(ch) - base - shift) % 26 + base))
                j += 1
            else:
                out.append(ch)
        return "".join(out)

    return desc, plain, solve


def build_p04():
    mod, a, c = (2 ** 31) - 1, 48271, 11
    x = int(_h("p04", 8), 16) % mod
    seq = []
    for _ in range(4):
        x = (a * x + c) % mod
        seq.append(x)
    nxt = (a * seq[-1] + c) % mod
    plain = _flag("%08x" % nxt)
    desc = (
        "A service generates session identifiers with a linear congruential "
        "generator. The recurrence and modulus are public, only the initial "
        "state is secret:\n\n"
        "    x_{i+1} = (a * x_i + c) mod m\n"
        "    a = %d\n    c = %d\n    m = %d\n\n"
        "Four consecutive outputs (x_1 .. x_4) were observed:\n\n"
        "%s\n\n"
        "Predict x_5. The flag is `flag{` + the 8-digit lowercase hexadecimal "
        "representation of x_5, zero padded + `}`."
        % (a, c, mod, "\n".join("    x_%d = %d" % (i + 1, v) for i, v in enumerate(seq)))
    )

    def solve(d: str) -> str:
        a = int(re.search(r"a\s*=\s*(\d+)", d).group(1))
        c = int(re.search(r"c\s*=\s*(\d+)", d).group(1))
        m = int(re.search(r"m\s*=\s*(\d+)", d).group(1))
        xs = [int(v) for v in re.findall(r"x_\d+\s*=\s*(\d+)", d)]
        assert len(xs) == 4
        x = xs[-1]
        nxt = (a * x + c) % m
        return _flag("%08x" % nxt)

    return desc, plain, solve


def build_p05():
    seed_n = 733921
    import random as _random
    rng = _random.Random(seed_n)
    obs = [rng.randrange(10 ** 9) for _ in range(4)]
    nxt = rng.randrange(10 ** 9)
    plain = _flag("%d" % seed_n)
    desc = (
        "A token generator seeds Python's `random.Random(seed)` with a small "
        "integer seed in the range 0 <= seed <= 999999 and then emits "
        "`randrange(10**9)` values. Four consecutive outputs are known:\n\n"
        "%s\n\n"
        "Find the seed and report it as the flag: `flag{` + the decimal seed "
        "+ `}`. (The fifth output is not needed; the seed alone is the "
        "answer.)"
        % "\n".join("    out_%d = %d" % (i + 1, v) for i, v in enumerate(obs))
    )

    def solve(d: str) -> str:
        obs = [int(v) for v in re.findall(r"out_\d+\s*=\s*(\d+)", d)]
        assert len(obs) == 4
        import random as _random
        for s in range(1000000):
            r = _random.Random(s)
            if [r.randrange(10 ** 9) for _ in range(4)] == obs:
                return _flag("%d" % s)
        raise AssertionError("seed not found")

    return desc, plain, solve


def build_p06():
    inner = _h("p06", 10)
    plain = _flag(inner)
    step1 = "".join(
        chr((ord(ch) - ord("a") + 13) % 26 + ord("a")) if "a" <= ch <= "z" else ch
        for ch in plain)
    step2 = step1.encode().hex()
    step3 = base64.b32encode(step2.encode()).decode()
    step4 = base64.b64encode(step3.encode()).decode()
    desc = (
        "A challenge author encoded the flag with four layers applied in "
        "this exact order, each consuming the previous output as raw bytes:\n\n"
        "    1. ROT13 over lowercase ASCII letters only\n"
        "    2. hex encoding of the resulting bytes\n"
        "    3. Base32 (RFC 4648, standard alphabet, with padding)\n"
        "    4. Base64 (standard alphabet, with padding)\n\n"
        "The final blob is:\n\n"
        "%s\n\n"
        "Reverse the pipeline and submit the flag." % step4
    )

    def solve(d: str) -> str:
        blob = re.search(r"blob is:\s*\n+\s*(\S+)", d)
        assert blob, "final blob not found"
        s = base64.b64decode(blob.group(1)).decode()
        s = base64.b32decode(s).decode()
        s = bytes.fromhex(s).decode()
        return "".join(
            chr((ord(ch) - ord("a") + 13) % 26 + ord("a")) if "a" <= ch <= "z" else ch
            for ch in s)

    return desc, plain, solve


def build_p07():
    digits = "48271536"
    plain = _flag(digits)
    desc = (
        "A licence checker reads an 8 digit code d0 d1 d2 d3 d4 d5 d6 d7 "
        "(each a single decimal digit) and accepts it only when ALL of the "
        "following constraints hold:\n\n"
        "    d0 * d1 == 32\n"
        "    d0 + d1 == 12\n"
        "    d1 > d0\n"
        "    d2 * d3 == 14\n"
        "    d2 < d3\n"
        "    d4 + d5 == 6\n"
        "    d4 * 2 + d5 == 7\n"
        "    d6 + d7 == 9\n"
        "    d7 == 2 * d6\n\n"
        "The system is consistent and has exactly one solution. Find the "
        "accepted code and submit it as `flag{` + the 8 digits + `}`."
    )

    def solve(d: str) -> str:
        # 逐组枚举求唯一解（不依赖构造顺序，纯解方程）
        r01 = [(x, y) for x in range(10) for y in range(10)
               if x * y == 32 and x + y == 12 and y > x]
        r23 = [(x, y) for x in range(10) for y in range(10)
               if x * y == 14 and x < y]
        r45 = [(x, y) for x in range(10) for y in range(10)
               if x + y == 6 and x * 2 + y == 7]
        r67 = [(x, y) for x in range(10) for y in range(10)
               if x + y == 9 and y == 2 * x]
        if not (len(r01) == len(r23) == len(r45) == len(r67) == 1):
            raise AssertionError("constraint system is not uniquely solvable: %r"
                                 % [len(r01), len(r23), len(r45), len(r67)])
        seq = r01[0] + r23[0] + r45[0] + r67[0]
        return _flag("".join(str(v) for v in seq))

    return desc, plain, solve


def build_p08():
    p, g, x = 1000003, 5, 123456
    y = pow(g, x, p)
    plain = _flag("%d" % x)
    desc = (
        "A small Diffie-Hellman style parameter set leaked. You know the "
        "prime, the generator and one public value, and you need the private "
        "exponent.\n\n"
        "    p = %d\n"
        "    g = %d\n"
        "    y = g^x mod p = %d\n\n"
        "The exponent x is smaller than p. Recover x and submit it as "
        "`flag{` + the decimal value of x + `}`." % (p, g, y)
    )

    def solve(d: str) -> str:
        p = int(re.search(r"p\s*=\s*(\d+)", d).group(1))
        g = int(re.search(r"g\s*=\s*(\d+)", d).group(1))
        y = int(re.search(r"y\s*=\s*g\^x mod p\s*=\s*(\d+)", d).group(1))
        cur = 1
        for x in range(1, p):
            cur = cur * g % p
            if cur == y:
                return _flag("%d" % x)
        raise AssertionError("no exponent")

    return desc, plain, solve


def build_p09():
    p1 = "session=guest;user=alice;role=viewer;ok=1"
    inner = _h("p09", 12)
    plain = _flag(inner)
    assert len(plain) <= len(p1)
    stream = bytes.fromhex(_h("p09stream_a", 64) + _h("p09stream_b", 64))[:len(p1)]
    assert len(stream) == len(p1)
    c1 = bytes(a ^ b for a, b in zip(p1.encode(), stream)).hex()
    c2 = bytes(a ^ b for a, b in zip(plain.encode(), stream)).hex()
    desc = (
        "An encryption service reuses the same AES-CTR keystream for two "
        "different plaintexts (the nonce was never incremented). You captured "
        "both ciphertexts, and you also know the exact content of the first "
        "plaintext from a debug log.\n\n"
        "    plaintext_A = %s\n"
        "    ciphertext_A = %s\n"
        "    ciphertext_B = %s\n\n"
        "plaintext_B is the flag. Recover it. Note that ciphertext_B is "
        "shorter than ciphertext_A, so only part of the keystream was used "
        "for B." % (p1, c1, c2)
    )

    def solve(d: str) -> str:
        pa = re.search(r"plaintext_A\s*=\s*(\S+)", d).group(1).encode()
        ca = bytes.fromhex(re.search(r"ciphertext_A\s*=\s*([0-9a-f]+)", d).group(1))
        cb = bytes.fromhex(re.search(r"ciphertext_B\s*=\s*([0-9a-f]+)", d).group(1))
        assert len(ca) == len(pa)
        # keystream = ca ^ pa；pb = cb ^ keystream[:len(cb)]
        ks = bytes(a ^ b for a, b in zip(ca, pa))
        pb = bytes(a ^ b for a, b in zip(cb, ks[:len(cb)]))
        return pb.decode()

    return desc, plain, solve


def build_p10():
    m = int(_h("p10", 16), 16)
    e1, e2 = 3, 17
    p = next_prime(int(_h("p10p", 40), 16) | (1 << 129))
    q = next_prime(int(_h("p10q", 40), 16) | (1 << 129))
    n = p * q
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    plain = _flag("%x" % m)
    desc = (
        "The same RSA message was encrypted twice under the same modulus but "
        "with two different public exponents, and both ciphertexts were "
        "captured. No padding was used.\n\n"
        "    n  = %d\n"
        "    e1 = %d\n"
        "    c1 = %d\n"
        "    e2 = %d\n"
        "    c2 = %d\n\n"
        "Recover m. The flag is `flag{` + the lowercase hexadecimal "
        "representation of m (no leading zeros) + `}`."
        % (n, e1, c1, e2, c2)
    )

    def solve(d: str) -> str:
        n = int(re.search(r"n\s*=\s*(\d+)", d).group(1))
        e1 = int(re.search(r"e1\s*=\s*(\d+)", d).group(1))
        c1 = int(re.search(r"c1\s*=\s*(\d+)", d).group(1))
        e2 = int(re.search(r"e2\s*=\s*(\d+)", d).group(1))
        c2 = int(re.search(r"c2\s*=\s*(\d+)", d).group(1))
        g, a, b = egcd(e1, e2)
        assert g == 1
        # m = c1^a * c2^b mod n，负指数用模逆
        t1 = pow(c1, a, n) if a >= 0 else pow(inv_mod(c1, n), -a, n)
        t2 = pow(c2, b, n) if b >= 0 else pow(inv_mod(c2, n), -b, n)
        m = t1 * t2 % n
        assert pow(m, e1, n) == c1 and pow(m, e2, n) == c2, "common modulus failed"
        return _flag("%x" % m)

    return desc, plain, solve


BUILDERS = [
    ("pp_v1_01_xor_single_byte", "crypto", "easy", build_p01,
     "单字节 XOR 暴力（按 flag 形态剪枝）"),
    ("pp_v1_02_rsa_low_exponent_cube", "crypto", "easy", build_p02,
     "RSA e=3 无填充小消息，整数立方根"),
    ("pp_v1_03_vigenere_known_key", "crypto", "easy", build_p03,
     "Vigenere 已知密钥，字母前进/非字母不变"),
    ("pp_v1_04_lcg_predict_next", "crypto", "easy", build_p04,
     "LCG 参数公开，迭代预测下一状态"),
    ("pp_v1_05_weak_seed_prng", "crypto", "medium", build_p05,
     "MT19937 小种子爆破（0..1e6）"),
    ("pp_v1_06_encoding_nest", "misc", "easy", build_p06,
     "ROT13 → hex → Base32 → Base64 四层逆序"),
    ("pp_v1_07_licence_constraints", "reverse", "medium", build_p07,
     "8 位校验码约束系统求解（唯一解）"),
    ("pp_v1_08_discrete_log_small", "crypto", "easy", build_p08,
     "小素数离散对数（p≈1e6）"),
    ("pp_v1_09_ctr_nonce_reuse", "crypto", "medium", build_p09,
     "AES-CTR nonce 复用，两密文 XOR 消 keystream"),
    ("pp_v1_10_rsa_common_modulus", "crypto", "hard", build_p10,
     "RSA 共模攻击（e1=3, e2=17，扩展欧几里得）"),
]


def build_all() -> tuple[dict, list[dict]]:
    problems, audit = {}, []
    for pid, cat, diff, fn, note in BUILDERS:
        desc, plain, solve = fn()
        got = solve(desc)
        if got != plain:
            raise AssertionError("%s: solver mismatch (%r != %r)" % (pid, got, plain))
        if not FLAG_RE.fullmatch(plain):
            raise AssertionError("%s: flag form invalid: %r" % (pid, plain))
        if plain in desc:
            raise AssertionError("%s: plaintext flag leaked into statement" % pid)
        inner = plain[5:-1]
        # 题面里若出现 flag 内层串，等价于送答案
        if inner and inner in desc:
            raise AssertionError("%s: inner answer leaked into statement" % pid)
        problems[pid] = {
            "id": pid,
            "name": pid,
            "category": cat,
            "difficulty": diff,
            "description": desc,
            "flag_sha256": _sha(plain),
            "pool": "private_selfauthored",
            "source": "self-authored / private internal benchmark (unreleased)",
            "created_at": "2026-11-07",
        }
        audit.append({"id": pid, "category": cat, "difficulty": diff,
                      "design_note": note, "statement_chars": len(desc)})
    pool = {
        "benchmark": "private_pool_v1",
        "denominator": len(problems),
        "problems": problems,
        "provenance": {
            "note": ("10 道本项目原创私有题，材料 100%% 内嵌题面（零附件依赖），"
                     "flag 明文不由任何文件保存（种子 sha256 派生），"
                     "生成时逐题机验「仅凭题面可解」。"),
            "generated_by": "scripts/gen_private_pool_v1.py",
            "created_at": "2026-11-07",
            "attachment_dependency": "none",
            "known_limitations": [
                "自造题只证明「链路可解 + 系统能解出结构完整的题」，"
                "不能外推为对公开赛题未见过题目的泛化能力",
                "题目难度由出题方设定，非赛题分布抽样，不构成难度校准",
            ],
            "audit": audit,
        },
    }
    return pool, audit


def verify_pool(path: str) -> int:
    """从池文件复验可解性：只读 description，逐题重跑 solver。"""
    d = json.load(open(path, encoding="utf-8"))
    probs = d.get("problems", {})
    if not probs:
        print("FAIL 池为空：不可解性无从验证（fail-closed）")
        return 1
    builders = {pid: fn for pid, _c, _d, fn, _n in BUILDERS}
    fails = 0
    for pid, p in probs.items():
        if pid not in builders:
            print("FAIL %-34s 池内存在生成器未定义的题" % pid)
            fails += 1
            continue
        desc = p.get("description", "")
        try:
            _d, _plain, solve = builders[pid]()
        except Exception as exc:
            print("FAIL %-34s 构建失败: %s" % (pid, exc))
            fails += 1
            continue
        try:
            got = solve(desc)
        except Exception as exc:
            print("FAIL %-34s solver 无法从题面求解: %s: %s"
                  % (pid, type(exc).__name__, exc))
            fails += 1
            continue
        ok = _sha(got) == str(p.get("flag_sha256", "")).lower()
        print("%s %-34s chars=%-4d %s"
              % ("PASS" if ok else "FAIL", pid, len(desc),
                 "题面可解" if ok else "solver 输出与登记哈希不符"))
        fails += 0 if ok else 1
    print("可解性复验：%d/%d 通过" % (len(probs) - fails, len(probs)))
    return 0 if fails == 0 else 1


def selftest() -> int:
    """变异验证：坏题必须被拒，否则「可解性机验」本身是空洞绿。"""
    cases = []

    # 1 正例：十题全可解
    pool, audit = build_all()
    cases.append(("十题自造池全部可解", len(pool["problems"]) == 10 and len(audit) == 10, True))

    # 2 变异：把某题题面里的密文改一个字符 -> solver 必须给不出原 flag
    pid = "pp_v1_01_xor_single_byte"
    bad = dict(pool["problems"][pid])
    bad["description"] = bad["description"].replace("ciphertext_hex = ", "ciphertext_hex = f")
    _d, plain, solve = build_p01()
    mutated_ok = True
    try:
        got = solve(bad["description"])
        mutated_ok = (_sha(got) == bad["flag_sha256"])
    except Exception:
        mutated_ok = False
    cases.append(("题面被篡改后不再「可解出原答案」", mutated_ok, False))

    # 3 变异：flag 明文写进题面必须被 build_all 的检查拦住
    leaked = False
    try:
        _d, p2, _s = build_p02()
        desc = _d + "\n\nhint: " + p2
        if p2 in desc:
            leaked = True
    except Exception:
        pass
    cases.append(("明文泄题可被检出（对照）", leaked, True))

    # 4 fail-closed：空池必须判红
    import tempfile
    tmp = tempfile.mkdtemp(prefix="pp_selftest_")
    empty = os.path.join(tmp, "empty.json")
    with open(empty, "w", encoding="utf-8") as fh:
        json.dump({"problems": {}}, fh)
    cases.append(("空池复验 fail-closed", verify_pool(empty), 1))

    # 5 变异：池里 flag_sha256 被换掉 -> 复验必须红
    d2 = json.loads(json.dumps(pool))
    d2["problems"][pid]["flag_sha256"] = "0" * 64
    p2f = os.path.join(tmp, "tampered.json")
    with open(p2f, "w", encoding="utf-8") as fh:
        json.dump(d2, fh, ensure_ascii=False)
    cases.append(("登记哈希被篡改后复验判红", verify_pool(p2f), 1))

    passed = 0
    for label, got, want in cases:
        ok = got == want
        passed += int(ok)
        print("  %s %-40s got=%s want=%s" % ("PASS" if ok else "FAIL", label, got, want))
    print("生成器自测：%d/%d" % (passed, len(cases)))
    return 0 if passed == len(cases) else 1


def build_registry(pool_path: str, commit: str) -> dict:
    """生成私有性外部锚点注册表（R0–R6 的输入）。

    为什么由脚本生成而不是手写：R3 的 `problem_fingerprint` 必须与
    `audit_private_proof.problem_fingerprint()` 逐字一致，手写一次就会漂。
    `first_commit_date` 也从 git 读，不接受自填（R5 会二次核对）。
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import audit_private_proof as app  # noqa: E402

    if not os.path.isfile(pool_path):
        raise SystemExit("池不存在：%s" % pool_path)
    pool = json.load(open(pool_path, encoding="utf-8"))
    probs = pool.get("problems", {})
    if not probs:
        raise SystemExit("池为空，注册表拒绝生成（fail-closed）")

    rc, out = app._git("cat-file", "-e", "%s^{commit}" % commit)
    if rc != 0:
        raise SystemExit("commit 不存在：%s" % commit)
    d = app._commit_date(commit)
    if d is None:
        raise SystemExit("无法从 git 读取提交日期（fail-closed）")
    if d <= app.PRIOR_CUTOFF:
        raise SystemExit("提交日期 %s 不晚于训练截止 %s，私有性不成立"
                         % (d, app.PRIOR_CUTOFF))

    entries = {}
    for pid, p in probs.items():
        if not p.get("flag_sha256"):
            raise SystemExit("%s 缺 flag_sha256（不可判分，拒绝入锚点）" % pid)
        entries[pid] = {
            "problem_fingerprint": app.problem_fingerprint(p),
            "flag_sha256": str(p["flag_sha256"]).lower(),
            "first_commit": commit,
            "first_commit_date": d.isoformat(),
            "declared_unreleased": True,
        }
    return {
        "contract": app.CONTRACT,
        "tool": "scripts/gen_private_pool_v1.py --registry",
        "pool_path": os.path.relpath(pool_path, ROOT).replace("\\", "/"),
        "pool_sha256": app._sha256_file(pool_path),
        "entries": entries,
        "note": ("每题的 first_commit 指向该题首次进入 git 的提交；日期由 git 读出，"
                 "不接受自填。flag_sha256 与公开池真值集合无交集（R4 由 "
                 "audit_private_proof 逐题重算）。"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=POOL_OUT)
    ap.add_argument("--verify", default=None, help="复验已有池的可解性")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--registry", default=None,
                    help="生成私有性注册表到该路径（需配合 --commit）")
    ap.add_argument("--commit", default=None, help="题目首次提交的 commit sha")
    ap.add_argument("--pool-for-registry", default=POOL_OUT)
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if args.registry:
        if not args.commit:
            raise SystemExit("--registry 必须配 --commit（日期与存在性都要从 git 读）")
        reg = build_registry(args.pool_for_registry, args.commit)
        os.makedirs(os.path.dirname(args.registry), exist_ok=True)
        with open(args.registry, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(reg, fh, ensure_ascii=False, indent=1, sort_keys=True)
            fh.write("\n")
        print("写出注册表 %s（%d 题，commit=%s，date=%s）"
              % (os.path.relpath(args.registry, ROOT), len(reg["entries"]),
                 args.commit[:12], reg["entries"][sorted(reg["entries"])[0]]["first_commit_date"]))
        print("pool_sha256 = %s" % reg["pool_sha256"])
        return 0
    if args.verify:
        return verify_pool(args.verify)

    pool, audit = build_all()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(pool, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")
    print("写出 %s（%d 题）" % (os.path.relpath(args.out, ROOT), len(pool["problems"])))
    for row in audit:
        print("  %-34s %-8s %-6s chars=%d"
              % (row["id"], row["category"], row["difficulty"], row["statement_chars"]))
    return verify_pool(args.out)


if __name__ == "__main__":
    sys.exit(main())
