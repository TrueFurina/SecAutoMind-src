#!/usr/bin/env python3
"""JWT 认证绕过靶场 —— 复刻真实 CTF / 实战三类 JWT 考点。

三个场景各自独立（路径前缀不同），flag 只有在**真正绕过鉴权**时才返回：
  1. jwt_weak    : HS256 弱密钥（secret123）—— 需爆破出密钥后重签提权
  2. jwt_none    : 服务端信任 alg=none，不校验签名 —— 需伪造无签名 admin token
  3. jwt_rs256   : RS256→HS256 混淆，服务端把 RSA 公钥当 HMAC 密钥 ——
                   需取回 /public.pem 并用公钥字节重签

未带合法 admin token 一律 401（或 403），绝不泄漏 flag。
纯标准库实现，不依赖 PyJWT/cryptography。

用法: python jwt_range.py [port] [--dump-json]
"""

import base64
import hashlib
import hmac
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 18097

# ── 场景定义：(flag, 考点说明) ──
SCENES = {
    "jwt_weak": ("flag{jwt_w3ak_s3cr3t_brut3f0rc3}",
                 "JWT 鉴权绕过：POST /jwt_weak/api/login 用 user=guest 登录拿到 JWT，"
                 "访问 /jwt_weak/api/flag 需要 role=admin。服务端用 HS256 且密钥是常见弱口令。"),
    "jwt_none": ("flag{jwt_alg_n0n3_byp4ss}",
                 "JWT 鉴权绕过：POST /jwt_none/api/login 用 user=guest 登录拿到 JWT，"
                 "访问 /jwt_none/api/flag 需要 role=admin。注意服务端对 alg=none 的处理。"),
    "jwt_rs256": ("flag{jwt_rs256_t0_hs256_c0nfus10n}",
                  "JWT 鉴权绕过：POST /jwt_rs256/api/login 用 user=guest 登录拿到 JWT，"
                  "公钥在 /jwt_rs256/public.pem，访问 /jwt_rs256/api/flag 需要 role=admin。"),
}

# 真实 2048 位 RSA 公钥（由 crypto/rsa 生成），服务端错误地把它当 HMAC 密钥用
PUBKEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzOnznUakkoWkMDUqegsv
+NNI+saugPj9YkIsEmrrx8WuzuPr3RNQi20vJzIMPJ54N7FQzA+TxY8ytPja4r8c
D3eXoHoSsJ1OQ2MeQQQsA7gneYi8KEffJwE3e/uAqJuDoW3fxCcOi21eg2mHFmOI
sfoPuj0L8FCT5xU4sOi3mj/97gOk0yPkIf2XheARGgMCqgIXEERIIzsUrSoNdnQv
pxf1Chprpj03ZuRmmWRfLrwD8VpZIm6R7NovJRhHZO70k0Is6K05rFhUREsstlb6
f+qvdRihJhkQ37s7hCh1EndlHuOf05Jt9HqMNjn6HNi27k0B4Y6Au42n2IacYxqS
6QIDAQAB
-----END PUBLIC KEY-----
"""

WEAK_SECRET = b"secret123"


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hs256(signing_input: str, key: bytes) -> str:
    return b64e(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())


def issue(claims: dict, key: bytes, alg: str = "HS256") -> str:
    h = b64e(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64e(json.dumps(claims, separators=(",", ":")).encode())
    si = h + "." + p
    return si + "." + hs256(si, key)


def unverified_claims(token: str):
    """不校验签名地解析 header/payload（模拟真实服务端先读 alg 的代码路径）。"""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None
    try:
        header = json.loads(b64d(parts[0]))
        payload = json.loads(b64d(parts[1]))
    except Exception:
        return None, None
    return header, payload


class Range(BaseHTTPRequestHandler):
    # 若用 HTTP/1.1 且不设 timeout，服务线程会挂在 readline 上等下一个请求，
    # Go/urllib 的持久连接会把线程耗尽（实测跑两轮后靶场无应答）。
    protocol_version = "HTTP/1.0"
    timeout = 5

    def log_message(self, *a):
        pass

    # ── helpers ──
    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _scene(self):
        """从路径首段取场景名。"""
        seg = self.path.split("?")[0].strip("/").split("/")
        return seg[0] if seg and seg[0] in SCENES else None

    def _token(self):
        """从 Authorization: Bearer 或 Cookie 里取 token。"""
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        cookie = self.headers.get("Cookie") or ""
        for kv in cookie.split(";"):
            k, _, v = kv.partition("=")
            if k.strip().lower() in ("token", "jwt", "access_token"):
                return v.strip()
        return ""

    # ── 路由 ──
    def do_GET(self):
        path = self.path.split("?")[0]
        scene = self._scene()

        if path == "/" or path == "/index.html":
            links = "".join(
                f'<li><a href="/{s}/api/login">{s}</a> — {d}</li>' for s, (_, d) in SCENES.items()
            )
            return self._send(200, f"<html><body><h1>JWT Range</h1><ul>{links}</ul></body></html>")

        if scene is None:
            return self._send(404, "not found")

        # 公钥端点（RS256→HS256 场景）
        if path.endswith("/public.pem"):
            return self._send(200, PUBKEY_PEM, "application/x-pem-file")

        if path.endswith("/jwks.json"):
            return self._json(200, {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "n": ""}]})

        # flag 端点：三个场景各自的校验逻辑
        if path.endswith("/api/flag") or path.endswith("/flag"):
            return self._flag(scene)

        if path.endswith("/api/me"):
            return self._json(200, {"user": "guest"})

        return self._send(404, "not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        scene = self._scene()
        if scene is None or not path.endswith("/api/login"):
            return self._send(404, "not found")

        form = parse_qs(self._body().decode("utf-8", "replace"))
        user = (form.get("user") or form.get("username") or ["guest"])[0]

        if scene == "jwt_weak":
            key = WEAK_SECRET
        elif scene == "jwt_rs256":
            # 漏洞点：把 RSA 公钥字节当 HMAC 密钥（典型 RS256→HS256 混淆）
            key = PUBKEY_PEM
        else:  # jwt_none
            key = WEAK_SECRET

        token = issue({"user": user, "role": "user", "iat": int(time.time())}, key)
        return self._json(200, {"token": token, "user": user})

    # ── 鉴权校验（各场景不同） ──
    def _flag(self, scene):
        token = self._token()
        if not token:
            return self._json(401, {"error": "missing token"})

        header, payload = unverified_claims(token)
        if header is None:
            return self._json(401, {"error": "malformed token"})

        alg = str(header.get("alg", "")).lower()

        ok = False
        if scene == "jwt_none":
            # 漏洞点：alg=none 时完全跳过签名校验，直接信任 claims
            if alg == "none":
                ok = True
            else:
                ok = self._verify_hs256(token, WEAK_SECRET)
        elif scene == "jwt_weak":
            ok = self._verify_hs256(token, WEAK_SECRET)
        elif scene == "jwt_rs256":
            # 漏洞点：HS256 时用公钥字节做 HMAC 密钥
            if alg == "hs256":
                ok = self._verify_hs256(token, PUBKEY_PEM)
            else:
                ok = self._verify_hs256(token, PUBKEY_PEM)

        if not ok:
            return self._json(403, {"error": "invalid signature"})

        role = str((payload or {}).get("role", "")).lower()
        is_admin = role == "admin" or bool((payload or {}).get("admin")) or \
            bool((payload or {}).get("isAdmin")) or str((payload or {}).get("user", "")).lower() == "admin"
        if not is_admin:
            return self._json(403, {"error": "admin only", "user": (payload or {}).get("user")})

        return self._json(200, {"ok": True, "flag": SCENES[scene][0]})

    @staticmethod
    def _verify_hs256(token: str, key: bytes) -> bool:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        si = parts[0] + "." + parts[1]
        # 逐字节比较，防时序侧信道
        return hmac.compare_digest(hs256(si, key), parts[2])


if __name__ == "__main__":
    if "--dump-json" in sys.argv:
        print(json.dumps(
            {"problems": {k: {"flag_sha256": hashlib.sha256(v[0].encode()).hexdigest(),
                              "description": v[1]} for k, v in SCENES.items()}},
            indent=2, ensure_ascii=False))
        sys.exit(0)
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Range)
    srv.serve_forever()
