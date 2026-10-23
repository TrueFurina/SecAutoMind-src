#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecAutoMind CRC64 靶场（CRC64 Range）——复刻「CRC64 线性性伪造 cookie」真题。

真题对照：CyberNova 2026 - Lazarus Phantom DB（crc_forgery_real，static 集 MISS 的能力面）。
攻击本质：CRC64 是 GF(2) 上的**线性**校验（非安全 MAC）——对同长度输入
          crc(A⊕B) = crc(A) ⊕ crc(B)。攻击者只需：
            1) /login 拿到 guest cookie 的 crc；
            2) /oracle 查询翻转模式 Δ = guest ⊕ admin 的 crc（多项式参数未知也可学）；
            3) crc(admin) = crc(guest) ⊕ crc(Δ) → 提交伪造 cookie → 通过完整性校验。
诚实设计：
  - CRC64 用**自定义多项式/初值/xorout**（不暴露、非标准库可算），必须靠 oracle 学；
  - flag 只在「data 精确等于 admin 块 且 crc 校验通过」时返回 —— 无关键词可猜；
  - 仅监听 127.0.0.1。

用法：  python crc64_range.py [port] [--dump-json]
"""
import hashlib
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

SCENES = {
    "crc64_bitflip": "flag{crc64_1s_n0t_4_m4c_b1tfl1p}",
}

PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 18097

# 自定义 CRC64 参数（真题"未知参数"语义；改动后靶场自洽，攻击仍走 oracle）
# 注：INIT/XOROUT 置 0 使 crc 成为 GF(2) 上的严格线性映射（crc(a⊕b)=crc(a)⊕crc(b)），
#     多项式仍为自定义值（非标准库可算）→ 反注水不变，攻击链可解。
POLY = 0x1AD3D94CBCA9B8F1
INIT = 0x0
XOROUT = 0x0

GUEST_BLOCK = b"user=guest\x00\x00\x00\x00\x00\x00"   # 16 字节
ADMIN_BLOCK = b"user=admin\x00\x00\x00\x00\x00\x00"   # 16 字节（同长度可翻转）


def crc64_custom(data: bytes) -> int:
    """逐 bit 长除法实现自定义 CRC64（refin=False, refout=False）。"""
    crc = INIT
    for b in data:
        crc ^= b << 56
        for _ in range(8):
            if crc & (1 << 63):
                crc = ((crc << 1) ^ POLY) & ((1 << 64) - 1)
            else:
                crc = (crc << 1) & ((1 << 64) - 1)
    return crc ^ XOROUT


def b2h(b: bytes) -> str:
    return b.hex()


def h2b(h: str) -> bytes:
    try:
        return bytes.fromhex(h)
    except Exception:
        return b""


def page(title: str, body: str) -> bytes:
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>%s</title></head>"
        "<body><h1>%s</h1>%s<hr><a href='/'>index</a></body></html>"
        % (title, title, body)
    ).encode("utf-8")


class Range(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _q(self, key, default=""):
        return parse_qs(urlparse(self.path).query).get(key, [default])[0]

    def do_GET(self):
        path = urlparse(self.path).path
        route = {
            "/": self.r_index,
            "/login": self.r_login,
            "/oracle": self.r_oracle,
            "/admin": self.r_admin,
        }.get(path)
        if route:
            route()
        else:
            self._send(404, json.dumps({"ok": False, "msg": "not found"}).encode())

    def r_index(self):
        self._send(200, page("CRC64 Range", "<p>cookie integrity service</p>"))

    def r_login(self):
        """发放 guest cookie：data + crc64（自定义参数）。"""
        data = GUEST_BLOCK
        self._send(200, json.dumps({
            "ok": True,
            "data": b2h(data),
            "crc": "%016x" % crc64_custom(data),
            "note": "cookie format: <hex(data)>.<hex(crc64)>",
        }).encode())

    def r_oracle(self):
        """CRC 计算 oracle：任意数据 → 自定义 CRC64（攻击者借线性性学 Δ 贡献）。"""
        h = self._q("data", "")
        raw = h2b(h)
        if not raw:
            self._send(400, json.dumps({"ok": False, "msg": "bad hex"}).encode())
            return
        self._send(200, json.dumps({"ok": True, "crc": "%016x" % crc64_custom(raw)}).encode())

    def r_admin(self):
        """受保护后台：cookie 必须 data==admin 且 crc64(data) 匹配（伪造才能过）。"""
        cookie = self._q("cookie", "")
        if "." not in cookie:
            self._send(403, json.dumps({"ok": False, "msg": "bad cookie format"}).encode())
            return
        data_hex, crc_hex = cookie.split(".", 1)
        data = h2b(data_hex)
        try:
            given_crc = int(crc_hex, 16)
        except Exception:
            self._send(403, json.dumps({"ok": False, "msg": "bad crc"}).encode())
            return
        if data != ADMIN_BLOCK:
            self._send(403, json.dumps({"ok": False, "msg": "not admin"}).encode())
            return
        if given_crc != crc64_custom(data):
            self._send(403, json.dumps({"ok": False, "msg": "integrity check failed"}).encode())
            return
        self._send(200, json.dumps({"ok": True, "flag": SCENES["crc64_bitflip"]}).encode())


def dump_json():
    out = {"problems": {
        k: {"category": "crypto", "flag_sha256": hashlib.sha256(v.encode()).hexdigest()}
        for k, v in SCENES.items()
    }}
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    if "--dump-json" in sys.argv:
        dump_json()
        sys.exit(0)
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Range)
    srv.serve_forever()
