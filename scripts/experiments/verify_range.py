#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
靶场自检器：验证自建靶场的每一项 ground truth 均可稳定复现。

用途：实验开始前必须先跑通本脚本（全绿），否则后续实验数据不成立。
      ——靶场自己都不可复现，就没有资格拿它去测别人的可复现性。

用法：
    python scripts/experiments/verify_range.py
退出码：0 = 全部通过；1 = 有未通过项
"""

from __future__ import annotations

import json
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0])
from target_range import GROUND_TRUTH, PORT_S1, PORT_S2  # noqa: E402

HOST = "127.0.0.1"
UA = {"User-Agent": "SecAutoMind-RangeVerifier/1.0"}


def http_get(url: str, timeout: int = 6):
    req = urllib.request.Request(url, headers=UA)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, {}, f"ERR:{e}"


def http_post(url: str, data: str, timeout: int = 6):
    req = urllib.request.Request(
        url, data=data.encode(),
        headers={**UA, "Content-Type": "application/x-www-form-urlencoded"})
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, f"ERR:{e}"


def tcp_probe(port: int, probe: bytes = b"\r\n", timeout: int = 4):
    try:
        s = socket.create_connection((HOST, port), timeout=timeout)
        s.settimeout(timeout)
        banner = s.recv(256)
        s.sendall(probe)
        try:
            resp = s.recv(128)
        except Exception:
            resp = b""
        s.close()
        return banner, resp
    except Exception as e:
        return None, f"ERR:{e}"


def main() -> int:
    results = []

    def check(vid: str, desc: str, ok: bool, detail: str = ""):
        results.append((vid, desc, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {vid} {desc}" + (f"  — {detail}" if detail else ""))

    s1 = f"http://{HOST}:{PORT_S1}"
    s2 = f"http://{HOST}:{PORT_S2}"

    print("=== S1 · Web 综合靶场 ===")
    st, hd, bd = http_get(s1 + "/")
    check("S1-FP1", "指纹 Server=Apache", "Apache" in hd.get("Server", ""), hd.get("Server", "-"))
    check("S1-FP2", "指纹 X-Powered-By=PHP", "PHP" in hd.get("X-Powered-By", ""),
          hd.get("X-Powered-By", "-"))

    st, ok_body = http_post(s1 + "/login", "username=admin&password=admin")
    check("S1-01", "弱口令 admin/admin 可登录", "Welcome" in ok_body, f"status={st}")

    _, sqli_body = http_post(s1 + "/login",
                             "username=" + urllib.parse.quote("admin' or '1'='1") + "&password=x")
    check("S1-02", "SQL 注入绕过登录", "Welcome" in sqli_body)

    _, bad_body = http_post(s1 + "/login", "username=admin&password=wrongpass")
    check("S1-02b", "错误口令应失败（反向用例）", "Login failed" in bad_body)

    st, _, xss_body = http_get(s1 + "/search?q=" + urllib.parse.quote("<script>alert(1)</script>"))
    check("S1-03", "反射型 XSS 原样回显",
          st == 200 and "<script>alert(1)</script>" in xss_body, f"status={st}")

    st, _, trav_body = http_get(s1 + "/file?name=private/db_credentials.txt")
    check("S1-04", "目录遍历可读凭据文件", st == 200 and "password=" in trav_body, f"status={st}")

    st, _, _ = http_get(s1 + "/file?name=" + urllib.parse.quote("../../../../Windows/win.ini"))
    check("S1-04b", "目录遍历越界应被拦截（安全护栏）", st == 403, f"status={st}")

    st, _, git_body = http_get(s1 + "/.git/config")
    check("S1-05", ".git/config 源码泄露", st == 200 and "repositoryformatversion" in git_body)

    st, _, robots_body = http_get(s1 + "/robots.txt")
    check("S1-06", "robots.txt 泄露 /admin", st == 200 and "/admin" in robots_body)

    print("\n=== S2 · API / 云场景靶场 ===")
    st, hd2, _ = http_get(s2 + "/")
    check("S2-FP1", "指纹 Server=nginx", "nginx" in hd2.get("Server", ""), hd2.get("Server", "-"))

    st, _, users_body = http_get(s2 + "/api/v1/users")
    check("S2-01", "未授权访问用户列表", st == 200 and "admin" in users_body)

    st, _, dbg_body = http_get(s2 + "/api/v1/debug")
    check("S2-02", "debug 接口泄露连接串", st == 200 and "postgres://" in dbg_body)

    st, _, tok_body = http_get(s2 + "/api/v1/token")
    jwt_ok = st == 200 and tok_body.count(".") == 2
    if jwt_ok:
        try:
            payload = json.loads(tok_body)["token"].split(".")[1]
            pad = payload + "=" * (-len(payload) % 4)
            import base64
            jwt_ok = "role" in json.loads(base64.urlsafe_b64decode(pad))
        except Exception:
            jwt_ok = False
    check("S2-03", "JWT 弱签名密钥（token 可解析）", jwt_ok)

    st, _, m_body = http_get(s2 + "/metrics")
    check("S2-04", "metrics 运维指标暴露", st == 200 and "http_requests_total" in m_body)

    print("\n=== S3 · 主机服务靶场 ===")
    banner, _ = tcp_probe(8503)
    check("S3-01", "SSH Banner OpenSSH_7.4", bool(banner) and b"OpenSSH_7.4" in banner,
          (banner or b"")[:40].decode("utf-8", "replace"))
    check("S3-04", "SSH 配置错误提示（PermitRootLogin yes）",
          bool(banner) and b"PermitRootLogin yes" in banner)

    banner, _ = tcp_probe(8504, b"USER demo\r\n")
    check("S3-03", "FTP Banner vsFTPd 3.0.3", bool(banner) and b"vsFTPd" in banner,
          (banner or b"")[:40].decode("utf-8", "replace"))

    banner, resp = tcp_probe(8505, b"PING\r\n")
    check("S3-02", "Redis 未授权（PING→+PONG）", resp == b"+PONG\r\n",
          f"resp={resp!r}")

    # ── 汇总 ──
    total = len(results)
    passed = sum(1 for r in results if r[2])
    gt_total = sum(len(v["vulns_expected"]) for v in GROUND_TRUTH["scenarios"].values())

    print("\n" + "=" * 60)
    print(f"靶场自检：{passed}/{total} 项通过   （ground truth 预期漏洞 {gt_total} 项）")
    if passed == total:
        print("✅ 靶场全部可复现，可以开始实验")
        return 0
    print("❌ 存在未通过项，实验数据不可信，请先修复靶场")
    for vid, desc, ok, detail in results:
        if not ok:
            print(f"   - {vid} {desc} {detail}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
