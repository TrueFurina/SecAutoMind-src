#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_lcg_attachment.py — LCG 附件一致性校验器（batch2 物料坑排除闸门）

题目：ext_gctf2023_least-common-genominator
机制（见 generate.py）：
  1. 以固定 seed 起一个 LCG；前 6 个输出原样写入 dump.txt（无论是否素数）。
  2. 从第 7 个输出起，逐个筛选 isprime 且 bit_length()==512 的值，收集满 8 个。
  3. RSA 模数 n = 这 8 个素数之积；public.pem 导出 (n, e)。

本脚本离线复现该过程，将「按 dump 还原出的 8 素数之积」与 public.pem 中的 n 比对：
  - 一致  → 附件自洽，闸门放开后可离线吃下（free-win 成立）。
  - 不一致 → 物料坑：pem 与 dump/flag 非同一实例，free-win 不成立，必须先修附件。

退出码：0=一致，1=不一致（可作 CI gate），2=异常（参数/解析错误）。

用法：
  python3 scripts/fire/verify_lcg_attachment.py
  python3 scripts/fire/verify_lcg_attachment.py --attachment-dir <dir>
  python3 scripts/fire/verify_lcg_attachment.py --dump <dump.txt> --pem <public.pem> --json
"""

import argparse
import base64
import json
import os
import sys

# 把 crypto_lib 加入 import 路径（ctf_crypto 提供 lcg_recover_params / lcg_next）
_HERE = os.path.dirname(os.path.abspath(__file__))
_CRYPTO_LIB = os.path.join(_HERE, "..", "..", "internal", "runnerl3", "crypto_lib")
sys.path.insert(0, os.path.abspath(_CRYPTO_LIB))

try:
    from sympy import isprime as _sympy_isprime  # 服务器环境优先
    def isprime(n):  # noqa: F811
        return _sympy_isprime(n)
except Exception:  # noqa: BLE001
    # 本地零依赖兜底：Miller-Rabin 概率素性测试
    import random

    def _powmod(a, d, n):
        return pow(a, d, n)

    def _miller_rabin_once(n, a):
        d = n - 1
        r = 0
        while d % 2 == 0:
            d //= 2
            r += 1
        x = _powmod(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                return True
        return False

    _MR_BASES_SMALL = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    def isprime(n):
        if n < 2:
            return False
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % p == 0:
                return n == p
        if n < 1 << 64:
            return all(_miller_rabin_once(n, b) for b in _MR_BASES_SMALL)
        # 大数（512-bit）：概率测试，40 轮足够安全
        return all(_miller_rabin_once(n, random.randrange(2, n - 1)) for _ in range(40))

import ctf_crypto as C  # noqa: E402


# ----------------------------------------------------------------------------
# 极简 DER 解析：从 PKIX SubjectPublicKeyInfo 取 (n, e)
# ----------------------------------------------------------------------------
def _read_tlv(data, i):
    """返回 (tag, value_bytes, next_index)。仅处理 INTEGER/BIT STRING/SEQUENCE。"""
    tag = data[i]
    i += 1
    length = data[i]
    i += 1
    if length & 0x80:
        nb = length & 0x7F
        length = 0
        for _ in range(nb):
            length = (length << 8) | data[i]
            i += 1
    value = data[i : i + length]
    return tag, value, i + length


def parse_rsa_pubkey_pem(pem_text):
    """解析 RSA PublicKey PEM，返回 (n, e)。不依赖 pycryptodome。"""
    lines = [ln for ln in pem_text.strip().splitlines()
             if ln and not ln.startswith("-----")]
    der = base64.b64decode("".join(lines))
    # 顶层 SEQUENCE
    tag, seq, _ = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("顶层不是 SEQUENCE")
    # seq 内：AlgorithmIdentifier(SEQUENCE) + subjectPublicKey(BIT STRING)
    _, _, idx = _read_tlv(seq, 0)          # 跳过 algorithm
    btag, bitstr, _ = _read_tlv(seq, idx)  # BIT STRING
    if btag != 0x03:
        raise ValueError("未找到 BIT STRING")
    # BIT STRING 首字节为 unused-bits，其后才是 RSAPublicKey DER
    inner = bitstr[1:]
    itag, rsa_seq, _ = _read_tlv(inner, 0)
    if itag != 0x30:
        raise ValueError("BIT STRING 内不是 SEQUENCE")
    # RSAPublicKey = SEQUENCE { n INTEGER, e INTEGER }
    ntag, n_val, nxt = _read_tlv(rsa_seq, 0)
    etag, e_val, _ = _read_tlv(rsa_seq, nxt)
    if ntag != 0x02 or etag != 0x02:
        raise ValueError("n/e 不是 INTEGER")
    n = int.from_bytes(n_val, "big")
    e = int.from_bytes(e_val, "big")
    return n, e


# ----------------------------------------------------------------------------
# 核心校验
# ----------------------------------------------------------------------------
def load_dump(path):
    with open(path) as f:
        vals = [int(x) for x in f.read().split() if x.strip()]
    return vals


def recover_and_forward(dump, n_primes=8, bits=512, max_iter=200000):
    """恢复 LCG 参数 → 自洽校验 → 从第 7 个输出续推收集 8 个 512-bit 素数。"""
    res = {"dump_count": len(dump)}
    # 1) 恢复参数
    params = C.lcg_recover_params(dump)
    if params is None:
        res["recover_ok"] = False
        return res, []
    m, a, c = params
    res["recover_ok"] = True
    res["modulus_bits"] = m.bit_length()

    # 2) 自洽：用恢复参数重放前 6 个值，应完全一致
    ok = True
    st = dump[0]
    for expected in dump[1:]:
        st = C.lcg_next(st, a, c, m)
        if st != expected:
            ok = False
            break
    res["self_consistent"] = ok
    if not ok:
        return res, []

    # 3) 从第 6 个输出（dump[-1]）续推，收集 512-bit 素数
    primes = []
    st = dump[-1]
    it = 0
    while len(primes) < n_primes and it < max_iter:
        st = C.lcg_next(st, a, c, m)
        it += 1
        if st.bit_length() != bits:
            continue
        if isprime(st):
            primes.append(st)
    res["iterations"] = it
    res["primes_found"] = len(primes)
    return res, primes


def _long_to_bytes(n):
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def decrypt_flag(primes, pem_n, e_pub, flag_path, sha_anchor=None):
    """用 8 素数分解 n → 算 d → 解密 flag.txt → 校验格式与 sha256 锚。"""
    from math import gcd
    phi = 1
    for p in primes:
        phi *= (p - 1)
    if gcd(e_pub, phi) != 1:
        return {"decrypt_ok": False, "reason": "gcd(e,phi)!=1"}
    d = pow(e_pub, -1, phi)
    ct = open(flag_path, "rb").read()
    c = int.from_bytes(ct, "little")  # generate.py 以 little-endian 写密文
    m = pow(c, d, pem_n)
    flag = _long_to_bytes(m)  # bytes_to_long 是 big-endian，故逆变换亦 big-endian
    info = {
        "decrypt_ok": flag.startswith(b"CTF{") and flag.rstrip(b"\x00").endswith(b"}"),
        "flag_len": len(flag),
        "flag_head": flag[:16].decode("latin1"),
    }
    try:
        import hashlib
        h = hashlib.sha256(flag).hexdigest()
        info["flag_sha256"] = h
        info["flag_sha256_12"] = h[:12]
        if sha_anchor is not None:
            info["sha_anchor_match"] = (h[:12] == sha_anchor)
    except Exception:  # noqa: BLE001
        pass
    return info


def verify(attachment_dir, sha_anchor=None):
    dump_path = os.path.join(attachment_dir, "dump.txt")
    pem_path = os.path.join(attachment_dir, "public.pem")
    if not os.path.isfile(dump_path):
        return {"ok": False, "error": f"缺少 dump.txt: {dump_path}"}
    if not os.path.isfile(pem_path):
        return {"ok": False, "error": f"缺少 public.pem: {pem_path}"}

    dump = load_dump(dump_path)
    res, primes = recover_and_forward(dump)

    report = {"attachment_dir": os.path.abspath(attachment_dir)}
    report.update(res)

    # 解析 PEM
    try:
        n_pub, e_pub = parse_rsa_pubkey_pem(open(pem_path).read())
        report["pem_n_bits"] = n_pub.bit_length()
        report["pem_e"] = e_pub
    except Exception as ex:  # noqa: BLE001
        report["pem_parse_error"] = str(ex)
        report["consistent"] = False
        report["ok"] = False
        return report

    if len(primes) == 8:
        n_calc = 1
        for p in primes:
            n_calc *= p
        report["calc_n_bits"] = n_calc.bit_length()
        report["consistent"] = (n_calc == n_pub)
        report["n_calc_eq_n_pem"] = (n_calc == n_pub)
    else:
        report["calc_n_bits"] = None
        report["consistent"] = False
        report["n_calc_eq_n_pem"] = False
        report["note"] = f"只收集到 {len(primes)} 个素数（期望 8），无法构造 n"

    # 第二段：若 flag.txt 存在，端到端解密验证
    flag_path = os.path.join(attachment_dir, "flag.txt")
    if os.path.isfile(flag_path) and len(primes) == 8 and report["consistent"]:
        try:
            dec = decrypt_flag(primes, n_pub, e_pub, flag_path, sha_anchor)
            report["decrypt"] = dec
            report["free_win"] = bool(dec.get("decrypt_ok") and report["consistent"])
            if sha_anchor is not None and "sha_anchor_match" in dec:
                report["free_win"] = report["free_win"] and dec["sha_anchor_match"]
        except Exception as ex:  # noqa: BLE001
            report["decrypt_error"] = str(ex)

    report["ok"] = bool(report.get("consistent"))
    return report


def main():
    ap = argparse.ArgumentParser(description="LCG 附件一致性校验器")
    ap.add_argument("--attachment-dir", default=None,
                    help="附件目录（含 dump.txt 与 public.pem），默认指向 LCG 题")
    ap.add_argument("--dump", default=None, help="显式指定 dump.txt")
    ap.add_argument("--pem", default=None, help="显式指定 public.pem")
    ap.add_argument("--sha-anchor", default=None,
                    help="flag sha256 前 12 位锚（如 69981daf9abd），用于端到端校验")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args()

    if args.dump and args.pem:
        d = os.path.dirname(os.path.abspath(args.dump))
        # 仅覆盖路径，复用 verify 的文件名约定
        import tempfile
        _tmp = tempfile.mkdtemp()
        import shutil
        shutil.copy(args.dump, os.path.join(_tmp, "dump.txt"))
        shutil.copy(args.pem, os.path.join(_tmp, "public.pem"))
        fp = os.path.join(d, "flag.txt")
        if os.path.isfile(fp):
            shutil.copy(fp, os.path.join(_tmp, "flag.txt"))
        rep = verify(_tmp, sha_anchor=args.sha_anchor)
    else:
        adir = args.attachment_dir or os.path.join(
            _HERE, "..", "..",
            "data", "questions_external_bench", "_attachments",
            "ext_gctf2023_least-common-genominator")
        adir = os.path.abspath(adir)
        rep = verify(adir, sha_anchor=args.sha_anchor)

    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        print("=" * 60)
        print("LCG 附件一致性校验  —  ext_gctf2023_least-common-genominator")
        print("=" * 60)
        print(f"附件目录      : {rep.get('attachment_dir', 'n/a')}")
        print(f"dump 输出数   : {rep.get('dump_count')}")
        print(f"参数恢复      : {'OK' if rep.get('recover_ok') else 'FAIL'}")
        if rep.get('recover_ok'):
            print(f"  恢复模数位数: {rep.get('modulus_bits')}")
            print(f"  自洽重放    : {'OK' if rep.get('self_consistent') else 'FAIL'}")
            print(f"  续推迭代数  : {rep.get('iterations')}")
            print(f"  收集素数    : {rep.get('primes_found')}/8")
        print(f"PEM n 位数    : {rep.get('pem_n_bits')}")
        if rep.get('calc_n_bits') is not None:
            print(f"计算 n 位数   : {rep.get('calc_n_bits')}")
        print(f"一致性判定    : {'PASS ✅' if rep.get('consistent') else 'FAIL ❌'}")
        dec = rep.get("decrypt")
        if dec:
            print(f"端到端解密    : {'OK ✅' if dec.get('decrypt_ok') else 'FAIL ❌'}")
            print(f"  flag 前缀   : {dec.get('flag_head')!r}")
            if dec.get("flag_sha256_12"):
                print(f"  flag sha256_12: {dec.get('flag_sha256_12')}")
                if "sha_anchor_match" in dec:
                    print(f"  锚匹配      : {'YES' if dec['sha_anchor_match'] else 'NO'}")
        if rep.get("free_win") is not None:
            print(f"FREE-WIN 判定 : {'成立 ✅' if rep['free_win'] else '不成立 ❌'}")
        if rep.get('note'):
            print(f"备注          : {rep['note']}")
        print("=" * 60)

    sys.exit(0 if rep.get('ok') else (2 if rep.get('error') or rep.get('pem_parse_error') else 1))


if __name__ == "__main__":
    main()
