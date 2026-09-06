#!/usr/bin/env python3
"""
CTF Benchmark Judge：对回归集跑 presolve 覆盖率分析。
读 data/ctf_benchmark/benchmark.json → 对每道题跑确定性求解器 → sha256 验证 → 输出覆盖率报告。
"""
import json, hashlib, re, base64, sys

BENCH = "data/ctf_benchmark/benchmark.json"
REPORT = "data/ctf_benchmark/coverage_report.json"

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

# ── 确定性求解器（Go presolve.go 的 Python 镜像） ─────────

def scan_flags(text: str) -> list:
    """正则扫描 flag{...} / ctf{...} / dasctf{...} 等。"""
    p = re.compile(r'(?i)(?:flag|ctf|dasctf|key)\s*[=:：]?\s*\{([^}]{4,})\}')
    return list(set(m.group(0) for m in p.finditer(text)))

def try_base64(text: str) -> list:
    """多层 base64 解码后扫 flag。"""
    b64_re = re.compile(r'[A-Za-z0-9+/=]{16,}')
    for m in b64_re.finditer(text):
        cur = m.group(0)
        for _ in range(5):
            pad = cur + "=" * ((4 - len(cur) % 4) % 4)
            try:
                decoded = base64.b64decode(pad).decode('utf-8', errors='ignore')
            except Exception:
                break
            flags = scan_flags(decoded)
            if flags:
                return flags
            cur = decoded
    return []

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
    """对一道题跑全部确定性求解器，返回 (engine, flag_or_None)。"""
    for name, fn in SOLVERS:
        flags = fn(description)
        for f in flags:
            # 验证是 flag 形式（而非"xx解码: ..."）
            if re.match(r'(?i)(flag|ctf|dasctf)\{', f):
                return name, f
            # 非 flag 形式的中间结果（如 Morse 解码文本）继续扫 flag
            inner = scan_flags(f)
            if inner:
                return name, inner[0]
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
