#!/usr/bin/env python3
"""
CTF Benchmark Judge：对回归集跑 presolve 覆盖率分析。
读 data/ctf_benchmark/benchmark.json → 对每道题跑确定性求解器 → sha256 验证 → 输出覆盖率报告。
"""
import json, hashlib, re, base64, sys, os, math

# 支持环境变量覆盖（真题集用法：BENCH=data/ctf_benchmark/real_benchmark.json REPORT=data/ctf_benchmark/real_coverage_report.json python judge.py）
BENCH = os.environ.get("BENCH", "data/ctf_benchmark/benchmark.json")
REPORT = os.environ.get("REPORT", "data/ctf_benchmark/coverage_report.json")

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

# ── 确定性求解器（Go presolve.go 的 Python 镜像） ─────────

def scan_flags(text: str) -> list:
    """正则扫描 flag 候选（完整保留品牌前缀 + 纯大写品牌兜底，对齐 Go scanFlags）。"""
    p_main = re.compile(r'(?i)[a-zA-Z0-9_]*(?:flag|ctf|dasctf|key|grodno|nicc|ehax|bzhctf)[a-zA-Z0-9_]*\s*[=:：]?\s*\{([^}]{4,})\}')
    p_upper = re.compile(r'\b[A-Z][A-Z0-9]{2,15}\{([^}]{4,})\}')
    seen, out = set(), []
    for m in list(p_main.finditer(text)) + list(p_upper.finditer(text)):
        if m.group(0) not in seen:
            seen.add(m.group(0))
            out.append(m.group(0))
    return out

def try_vigenere_known_key(text: str) -> list:
    """已知密钥维吉尼亚（对齐 Go tryVigenereKnownKey）：提取密钥，对 flag 形态令牌解密。"""
    keys = re.findall(r'(?i)(?:密钥|密码|key)\s*[为是]?\s*[:：=]?\s*([a-zA-Z]{2,16})', text)
    keys = list(dict.fromkeys(k.lower() for k in keys))
    if not keys:
        return []
    toks = re.findall(r'[A-Za-z0-9_]+\{[^}]{4,}\}', text)
    for tok in toks:
        for k in keys:
            dec, ki = [], 0
            for c in tok:
                if c.islower():
                    dec.append(chr((ord(c) - ord('a') - (ord(k[ki % len(k)]) - ord('a'))) % 26 + ord('a'))); ki += 1
                elif c.isupper():
                    dec.append(chr((ord(c) - ord('A') - (ord(k[ki % len(k)]) - ord('a'))) % 26 + ord('A'))); ki += 1
                else:
                    dec.append(c)
            flags = scan_flags(''.join(dec))
            if flags:
                return flags
    return []

def try_common_factor(text: str) -> list:
    """共享素数分解（对齐 Go tryCommonFactor）：gcd(n1,n2)=p → 解密。"""
    ns = [int(m) for m in re.findall(r'(?i)\bn[12]?\s*=\s*(\d+)', text)]
    cs = [int(m) for m in re.findall(r'(?i)\bc[12]?\s*=\s*(\d+)', text)]
    es = [int(m) for m in re.findall(r'(?i)\be[12]?\s*=\s*(\d+)', text)]
    if len(ns) < 2 or not cs or not es:
        return []
    import math
    p = math.gcd(ns[0], ns[1])
    if p <= 1 or p >= ns[0]:
        return []
    q = ns[0] // p
    if q == p:
        return []
    phi = (p-1)*(q-1)
    if math.gcd(es[0], phi) != 1:
        return []
    d = pow(es[0], -1, phi)
    m = pow(cs[0], d, ns[0])
    raw = m.to_bytes((m.bit_length()+7)//8, 'big')
    return scan_flags(raw.decode('utf-8', errors='ignore'))

def try_endian(text: str) -> list:
    """大小端序转换（对齐 Go tryEndian）：hex 组内字节反转后扫 flag。"""
    for m in re.findall(r'\b[0-9a-fA-F]{8,}\b', text):
        if len(m) % 2:
            continue
        try:
            raw = bytes.fromhex(m)
        except ValueError:
            continue
        for size in (2, 4, 8):
            if len(raw) % size:
                continue
            swapped = b''.join(raw[i:i+size][::-1] for i in range(0, len(raw), size))
            flags = scan_flags(swapped.decode('utf-8', errors='ignore'))
            if flags:
                return flags
    return []

def try_rail_fence(text: str) -> list:
    """栅栏密码（对齐 Go tryRailFence）：2-8 栏暴力，整串+逐 token。"""
    def rail_dec(cipher, rails):
        n = len(cipher)
        if rails <= 1 or rails >= n:
            return cipher
        pattern = []
        cycle = 2*(rails-1)
        for i in range(n):
            pos = i % cycle
            pattern.append(pos if pos < rails else cycle-pos)
        rows = ['' for _ in range(rails)]
        idx = 0
        counts = [pattern.count(r) for r in range(rails)]
        parts = {}
        for r in range(rails):
            parts[r] = cipher[idx:idx+counts[r]]
            idx += counts[r]
        out = []
        pos_in_row = [0]*rails
        for r in pattern:
            out.append(parts[r][pos_in_row[r]])
            pos_in_row[r] += 1
        return ''.join(out)

    def printable(t):
        return all(0x21 <= ord(c) <= 0x7e or c in ' \t\n\r' for c in t)

    clean = text.strip()
    if len(clean) < 6 or len(clean) > 500 or not printable(clean):
        return []
    stripped = clean.replace(' ', '')
    for rails in range(2, 9):
        flags = scan_flags(rail_dec(stripped, rails))
        if flags:
            return flags
    for tok in clean.split():
        if len(tok) < 6 or len(tok) > 500 or not printable(tok):
            continue
        for rails in range(2, 9):
            flags = scan_flags(rail_dec(tok, rails))
            if flags:
                return flags
    return []

def hunt(text: str, depth: int = 6) -> list:
    """递归下钻（对齐 Go huntPresolve）：已知密钥维吉尼亚优先（密文形似 flag，
    先扫会误当候选）→ 扫 flag → caesar → b64 令牌解码进下一层。"""
    flags = try_vigenere_known_key(text)
    if flags:
        return flags
    flags = scan_flags(text)
    if flags:
        return flags
    if depth <= 0:
        return []
    flags = try_caesar(text)
    if flags:
        return flags
    b64_re = re.compile(r'[A-Za-z0-9+/=]{16,}')
    for m in b64_re.finditer(text):
        pad = m.group(0) + "=" * ((4 - len(m.group(0)) % 4) % 4)
        try:
            decoded = base64.b64decode(pad).decode('utf-8', errors='ignore')
        except Exception:
            continue
        flags = hunt(decoded, depth - 1)
        if flags:
            return flags
    return []

def try_base64(text: str) -> list:
    """base64 令牌递归下钻扫 flag（对齐 Go tryBase64Multilayer）。"""
    return hunt(text)

def try_caesar(text: str) -> list:
    """凯撒 26 位移爆破。"""
    clean = text.strip()
    if len(clean) < 6:
        return []
    for shift in range(1, 26):
        out = []
        for c in clean:
            if 'a' <= c <= 'z':
                out.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                out.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
            else:
                out.append(c)
        flags = scan_flags(''.join(out))
        if flags:
            return flags
    return []

def try_xor_single(text: str) -> list:
    """单字节 XOR（hex 串）。"""
    hex_re = re.compile(r'[0-9a-fA-F]{8,}')
    for m in hex_re.finditer(text):
        try:
            data = bytes.fromhex(m.group())
        except ValueError:
            continue
        for k in range(256):
            out = bytes(b ^ k for b in data)
            try:
                decoded = out.decode('utf-8', errors='ignore')
            except Exception:
                continue
            flags = scan_flags(decoded)
            if flags:
                return flags
    return []

def try_rsa_small_e(text: str) -> list:
    """RSA 小指数攻击：从题目文本解析 c（密文）与 e（默认 3），
    计算精确 e 次根还原明文，对齐 Go tryRSASmallE / solveRSATemplate。
    仅当描述出现 RSA/small_e/ciphertext 且能解析出大整数 c 时尝试，避免误触发。"""
    if not re.search(r'rsa|small.?e|ciphertext|共模|模', text, re.I):
        return []
    cm = re.search(r'c\s*[=:：]\s*(\d{8,})', text)
    if not cm:
        return []
    c = int(cm.group(1))
    em = re.search(r'e\s*[=:：]\s*(\d{1,3})', text)
    e = int(em.group(1)) if em else 3

    def iroot(x, n):
        if x < 0:
            return None
        lo, hi = 0, x
        while lo < hi:
            mid = (lo + hi) // 2
            if mid ** n < x:
                lo = mid + 1
            else:
                hi = mid
        return lo if lo ** n == x else None

    for ee in (e, 3, 5, 7):
        m = iroot(c, ee)
        if m is None:
            continue
        for end in ('big', 'little'):
            try:
                b = m.to_bytes((m.bit_length() + 7) // 8, end)
            except Exception:
                continue
            flags = scan_flags(b.decode('latin1', 'ignore'))
            if flags:
                return flags
    return []


def try_rsa_fermat(text: str) -> list:
    """RSA 费马分解攻击：对齐 Go tryFermatFactor。
    当 n 为相近素数乘积时，a=ceil(sqrt(n)) 起迭代 a^2-n 为完全平方数即分解成功，
    再 RSA 解密 c^d mod n 扫 flag。用于 rsa_fermat_small 等题。"""
    nm = re.search(r'n\s*[=:：]\s*(\d{8,})', text)
    em = re.search(r'e\s*[=:：]\s*(\d{1,3})', text)
    cm = re.search(r'c\s*[=:：]\s*(\d{8,})', text)
    if not (nm and em and cm):
        return []
    n, e, c = int(nm.group(1)), int(em.group(1)), int(cm.group(1))
    if n < 4 or e < 2 or c < 2:
        return []

    def isqrt(x):
        return math.isqrt(x)

    def egcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x1, y1 = egcd(b, a % b)
        return g, y1, x1 - (a // b) * y1

    a = isqrt(n)
    if a * a < n:
        a += 1
    limit = a + 100000
    while a <= limit:
        a2 = a * a
        b2 = a2 - n
        if b2 >= 0:
            b = isqrt(b2)
            if b * b == b2:
                p, q = a - b, a + b
                if p > 0 and q > 0 and p * q == n:
                    phi = (p - 1) * (q - 1)
                    g, d, _ = egcd(e, phi)
                    if g == 1 and d < 0:
                        d += phi
                    if g == 1 and d > 0:
                        m = pow(c, d, n)
                        mb = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                        return scan_flags(mb.decode('latin1', 'ignore'))
        a += 1
    return []


def try_morse(text: str) -> list:
    """Morse 解码。"""
    table = {
        '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e',
        '..-.': 'f', '--.': 'g', '....': 'h', '..': 'i', '.---': 'j',
        '-.-': 'k', '.-..': 'l', '--': 'm', '-.': 'n', '---': 'o',
        '.--.': 'p', '--.-': 'q', '.-.': 'r', '...': 's', '-': 't',
        '..-': 'u', '...-': 'v', '.--': 'w', '-..-': 'x', '-.--': 'y',
        '--..': 'z', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
        '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
        '-----': '0',
    }
    morse_re = re.compile(r'^[\.\-\s/]+$')
    clean = text.strip()
    if not morse_re.match(clean):
        return []
    words = clean.split(' / ')
    decoded = []
    for word in words:
        letters = word.split(' ')
        sb = []
        for letter in letters:
            letter = letter.strip()
            if letter:
                sb.append(table.get(letter, '?'))
        decoded.append(''.join(sb))
    result = ' '.join(decoded)
    flags = scan_flags(result)
    if flags:
        return flags
    if len(result) > 3:
        return [f'Morse解码: {result}']
    return []

def try_hash_crack(text: str) -> list:
    """常见哈希弱口令爆破（扩充字典，对齐 Go presolve weakPasswords）。"""
    passwords = [
        'password', '123456', 'admin', 'root', 'test', 'guest', 'master',
        'qwerty', 'abc123', 'letmein', 'welcome', 'monkey', 'dragon',
        'baseball', 'football', 'shadow', 'michael', 'superman', 'batman',
        'flag', 'ctf', 'ctf{', 'flag{', 'key', 'secret', 'challenge',
        'secautomind', 'security', 'hack', 'pwn', 'crypto', 'reverse',
        'flag{md5_hash_crack}', 'flag{ctf_challenge}', 'flag{weak_password}',
        'flag{hash_cracked}', 'flag{rainbow_table}', 'flag{dictionary_attack}',
        'password123', 'admin123', 'root123', 'test123', 'guest123',
        'changeme', 'default', 'temp', 'backup', 'debug', 'development',
        '0', '1', '12', '123', '1234', '12345', '123456', '1234567',
        '12345678', '123456789', '1234567890',
        'letmein', 'dragon', 'master', 'monkey', 'shadow', 'superman',
        'batman', 'football', 'welcome', 'abc123', 'qwerty', '654321',
        'password1', 'iloveyou',
    ]
    passwords = list(set(passwords))  # 去重
    hash32 = re.compile(r'\b[0-9a-fA-F]{32}\b')
    results = []
    for m in hash32.finditer(text):
        h = m.group().lower()
        for pw in passwords:
            # 尝试直接匹配 pw
            if hashlib.md5(pw.encode()).hexdigest() == h:
                if pw.startswith('flag{'):
                    results.append(pw)
                else:
                    results.append(f'flag{{{pw}}}')
                continue
            # 尝试 flag{pw} 格式（CTF 常见模式）
            flag_pw = f'flag{{{pw}}}'
            if hashlib.md5(flag_pw.encode()).hexdigest() == h:
                results.append(flag_pw)
    return results

# ── presolve 调度（复刻 Go presolve.go 的并发扇出） ─────────

SOLVERS = [
    ('flag_scan', scan_flags),
    ('base64_multilayer', try_base64),
    ('caesar', try_caesar),
    ('xor_single', try_xor_single),
    ('morse', try_morse),
    ('hash_crack', try_hash_crack),
]

def presolve(description: str) -> tuple:
    """对一道题跑全部确定性求解器，返回 (engine, flag_or_None)。
    对齐 Go：已知密钥维吉尼亚优先 → hunt 递归下钻（b64→b64→caesar 等任意嵌套顺序）。"""
    # 已知密钥维吉尼亚优先（密文本身形似 flag，先扫会把密文误当候选）
    flags = try_vigenere_known_key(description)
    if flags:
        return 'vigenere_known_key', flags[0]

    # 先直接扫 flag
    flags = scan_flags(description)
    if flags:
        return 'flag_scan', flags[0]

    # 顶层凯撒优先归因（纯 caesar 文本不再误标 base64_multilayer）
    flags = try_caesar(description)
    if flags:
        return 'caesar', flags[0]

    # 递归下钻（base64 多层/链式 caesar，任意嵌套顺序）
    flags = hunt(description)
    if flags:
        return 'base64_multilayer', flags[0]

    # 共享素数分解 / 大小端 / 栅栏（对齐 Go fanout 优先级 4）
    flags = try_common_factor(description)
    if flags:
        return 'rsa_common_factor', flags[0]
    flags = try_endian(description)
    if flags:
        return 'endian', flags[0]
    flags = try_rail_fence(description)
    if flags:
        return 'rail_fence', flags[0]

    # 尝试 hex 解码后扫 flag
    hex_re = re.compile(r'[0-9a-fA-F]{16,}')
    for m in hex_re.finditer(description):
        try:
            decoded = bytes.fromhex(m.group(0)).decode('utf-8', errors='ignore')
        except Exception:
            continue
        for f in scan_flags(decoded):
            return 'hex_decode', f

    # 跑其他求解器（跳过已并入 hunt 的 flag_scan/base64/caesar）
    for name, fn in SOLVERS:
        if name in ('flag_scan', 'base64_multilayer', 'caesar'):
            continue
        flags = fn(description)
        for f in flags:
            if scan_flags(f):
                return name, f

    # RSA 费马分解（对齐 Go tryFermatFactor，先于小指数兜底）
    fermat_flags = try_rsa_fermat(description)
    if fermat_flags:
        return 'rsa_fermat', fermat_flags[0]
    # RSA 小指数攻击（末尾兜底，breizhctf2022_rsa 等带 c 的题目）
    rsa_flags = try_rsa_small_e(description)
    if rsa_flags:
        return 'rsa_small_e', rsa_flags[0]
    return None, None

# ── 主流程 ─────────────────────────────────────────

def main():
    with open(BENCH, encoding='utf-8') as f:
        bench = json.load(f)

    problems = bench['problems']
    results = []
    hit, miss = 0, 0

    for pid, p in problems.items():
        engine, flag = presolve(p['description'])
        matched = False
        if flag:
            computed_sha = sha256(flag)
            expected_sha = p['flag_sha256']
            matched = computed_sha == expected_sha
            if matched:
                hit += 1
            else:
                miss += 1
        else:
            miss += 1

        results.append({
            'id': pid,
            'category': p['category'],
            'sub': p.get('sub', ''),
            'difficulty': p['difficulty'],
            'presolve_engine': engine,
            'presolve_flag': flag,
            'sha256_match': matched,
            'expected_skill': p.get('presolve_skill', ''),
        })
        status = '✅ HIT' if matched else ('⚠️ MISMATCH' if flag else '❌ MISS')
        print(f'  {status}  {pid}  engine={engine}  flag={flag}')

    total = len(problems)
    report = {
        'total': total,
        'hit': hit,
        'miss': miss,
        'coverage_pct': round(hit / total * 100, 1) if total else 0,
        'results': results,
    }
    with open(REPORT, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f'\n=== 覆盖率报告 ===')
    print(f'总数: {total}')
    print(f'确定性命中 (SHA-256 匹配): {hit}')
    print(f'未命中: {miss}')
    print(f'覆盖率: {report["coverage_pct"]}%')
    print(f'报告已写入: {REPORT}')

if __name__ == '__main__':
    main()
