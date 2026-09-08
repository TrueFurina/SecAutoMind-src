#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反序列化漏洞靶场（真实可利用，非关键词模拟）。

三个场景各自独立校验，**未真正利用成功绝不返回 flag**：
  1. deser_pickle   —— POST /unpickle 直接提交 pickle 字节流，服务端真 pickle.loads
                       （这是真实的 RCE 面：pickle 反序列化即代码执行）
  2. deser_php      —— POST /unserialize 接收 PHP 序列化串，对象注入后
                       FlagReader.__toString 读取 path 属性指向的文件
  3. deser_php_cookie —— GET /profile 从 Cookie: session 取 PHP 序列化串并反序列化，
                       传输方式不同、入口不同，考验引擎的端点/入口发现能力

靶场刻意把服务端工作目录切到含 flag.txt 的临时目录，因此 payload 里的
相对路径 open('flag.txt') 是**真实的文件读取**，不是伪造回显。

用法：
    python deser_range.py [port]        # 启动靶场
    python deser_range.py --dump-json   # 输出基准集（只落 flag 的 SHA-256）
"""
import hashlib
import http.server
import json
import os
import pickle
import socketserver
import sys
import tempfile

FLAG_PICKLE = "flag{d3s3r_p1ckl3_rc3_r34d_fl4g}"
FLAG_PHP = "flag{php_0bj3ct_1nj3ct10n_r34d}"
FLAG_COOKIE = "flag{c00k13_d3s3r_php_1nj3ct10n}"

# 场景元信息：description 里刻意给出端点/参数/类名线索，
# 与真实 CTF 题目描述形态一致（读题取线索即能定向打）。
SCENES = {
    "deser_pickle": (
        FLAG_PICKLE,
        "目标提供 Python pickle 反序列化接口：POST /unpickle，"
        "请求体直接提交 pickle 序列化字节流，服务端 pickle.loads 后把结果回显。"
        "flag 位于服务端当前工作目录的 flag.txt。",
    ),
    "deser_php": (
        FLAG_PHP,
        "目标 PHP 站点 POST /unserialize 接收 data 参数（PHP 序列化字符串），"
        "存在对象注入：FlagReader 类被反序列化时 __toString 会读取 path 属性指向的文件。"
        "flag 文件为 flag.txt。",
    ),
    "deser_php_cookie": (
        FLAG_COOKIE,
        "目标 GET /profile 从 Cookie 的 session 字段读取 PHP 序列化字符串并反序列化，"
        "LogViewer 类反序列化时读取 file 属性指向的文件。flag 文件为 flag.txt。",
    ),
}

# ---------------- PHP 序列化：极简反序列化器（靶场刻意脆弱） ----------------


class PhpObj:
    """反序列化得到的对象。靶场危险点：特定类被字符串化时读取属性指向的文件。"""

    def __init__(self, cls, props):
        self.cls = cls
        self.props = props

    def __str__(self):
        if self.cls in ("FlagReader", "LogViewer", "FileDump", "Template"):
            p = (self.props.get("path") or self.props.get("file")
                 or self.props.get("filename") or self.props.get("log"))
            if p:
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as fh:
                        return fh.read()
                except Exception as e:  # noqa: BLE001
                    return "ERR:%s" % e
        return "<object %s>" % self.cls

    def __repr__(self):
        return self.__str__()


def _php_unescape(raw):
    out = []
    i = 0
    while i < len(raw):
        if raw[i] == "\\" and i + 2 < len(raw):
            try:
                out.append(chr(int(raw[i + 1:i + 3], 16)))
                i += 3
                continue
            except ValueError:
                pass
        out.append(raw[i])
        i += 1
    return "".join(out)


def php_unserialize(s):
    """解析 PHP serialize() 格式（支持 s/S/i/b/d/a/O/N）。

    private/protected 属性名带 \\x00 前缀，解析时统一取最后一段（与 PHP 内部一致）。
    """
    i = 0
    n = len(s)

    def read_len():
        nonlocal i
        j = s.index(":", i)
        v = int(s[i:j])
        i = j + 1
        return v

    def parse():
        nonlocal i
        if i >= n:
            raise ValueError("unexpected end")
        c = s[i]
        if c == "N":
            i += 2
            return None
        if c in "ibd":
            i += 2
            j = s.index(";", i)
            v = s[i:j]
            i = j + 1
            if c == "i":
                return int(v)
            if c == "b":
                return v == "1"
            return float(v)
        if c in "sS":
            i += 2
            ln = read_len()
            if i >= n or s[i] != '"':
                raise ValueError("bad string")
            i += 1
            raw = s[i:i + ln]
            i += ln + 2  # 闭合引号 + ';'
            return _php_unescape(raw) if c == "S" else raw
        if c == "a":
            i += 2
            cnt = read_len()
            if s[i] != "{":
                raise ValueError("bad array")
            i += 1
            out = {}
            for _ in range(cnt):
                k = parse()
                v = parse()
                out[k] = v
            i += 1  # '}'
            return out
        if c == "O":
            i += 2
            ln = read_len()
            if s[i] != '"':
                raise ValueError("bad object")
            i += 1
            cls = s[i:i + ln]
            i += ln + 2
            cnt = read_len()
            if s[i] != "{":
                raise ValueError("bad object body")
            i += 1
            props = {}
            for _ in range(cnt):
                k = parse()
                v = parse()
                if isinstance(k, str):
                    k = k.split("\x00")[-1]  # 去 private/protected 前缀
                props[k] = v
            i += 1  # '}'
            return PhpObj(cls, props)
        raise ValueError("unknown type %r" % c)

    return parse()


def render(obj):
    """把反序列化结果转成回显文本（模拟 PHP 里 echo $obj）。"""
    if obj is None:
        return "null"
    if isinstance(obj, PhpObj):
        return str(obj)
    if isinstance(obj, (dict, list)):
        return json.dumps(obj, ensure_ascii=False, default=str)
    return str(obj)


# ---------------- HTTP 靶场 ----------------


def setup_workdir():
    """建立靶场工作目录（含 flag.txt 等），并 chdir 过去。

    这样 payload 里的相对路径是**真实文件读取**。
    每个场景单独起进程（测试/复刻脚本按场景设 DESER_RANGE_FLAG），
    等价于「每题一台独立靶机」。
    """
    flag = os.environ.get("DESER_RANGE_FLAG", FLAG_PICKLE)
    d = tempfile.mkdtemp(prefix="deser_range_")
    with open(os.path.join(d, "flag.txt"), "w", encoding="utf-8") as fh:
        fh.write(flag)
    with open(os.path.join(d, "flag"), "w", encoding="utf-8") as fh:
        fh.write(os.environ.get("DESER_RANGE_FLAG", FLAG_PICKLE))
    with open(os.path.join(d, "secret.txt"), "w", encoding="utf-8") as fh:
        fh.write(os.environ.get("DESER_RANGE_FLAG", FLAG_PICKLE))
    with open(os.path.join(d, "app.log"), "w", encoding="utf-8") as fh:
        fh.write("2026-09-08 INFO service started (no flag here)\n")
    os.chdir(d)
    return d


class Range(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "DeserRange/1.0"
    workdir = None

    def log_message(self, *a):
        pass

    # --- 工具 ---
    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self):
        ln = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(ln) if ln > 0 else b""

    def _path(self):
        return self.path.split("?", 1)[0]

    def _query(self):
        from urllib.parse import parse_qs, urlparse
        return parse_qs(urlparse(self.path).query)

    # --- 场景 1：pickle 反序列化 ---
    def _pickle(self, raw):
        if not raw:
            # 也接受 base64 文本提交（很多题目把 pickle 塞在表单里）
            self._send(400, "empty body")
            return
        try:
            obj = pickle.loads(raw)  # noqa: S301 —— 靶场刻意脆弱点
        except Exception as e:  # noqa: BLE001
            self._send(500, "pickle error: %s" % e)
            return
        try:
            if hasattr(obj, "read"):
                out = obj.read()
            else:
                out = str(obj)
        except Exception as e:  # noqa: BLE001
            out = "ERR:%s" % e
        if not isinstance(out, str):
            out = str(out)
        self._send(200, "deserialized: %s" % out)

    # --- 场景 2/3：PHP 对象注入 ---
    def _php(self, payload):
        if not payload:
            self._send(401, "unauthenticated: no session object")
            return
        try:
            obj = php_unserialize(payload)
        except Exception as e:  # noqa: BLE001
            self._send(500, "unserialize error: %s" % e)
            return
        self._send(200, "welcome back. profile=%s" % render(obj))

    def do_GET(self):
        p = self._path()
        if p == "/":
            self._send(200, "deser range ready\ntry /unpickle (POST) or /unserialize (POST) or /profile (GET)")
            return
        if p == "/unpickle":
            self._send(405, "use POST for /unpickle")
            return
        if p == "/unserialize":
            self._send(405, "use POST for /unserialize")
            return
        if p == "/profile":
            cookie = self.headers.get("Cookie") or ""
            payload = ""
            for part in cookie.split(";"):
                part = part.strip()
                if part.startswith("session="):
                    from urllib.parse import unquote
                    payload = unquote(part[len("session="):])
            self._php(payload)
            return
        if p == "/hint":
            self._send(200, json.dumps({"files": ["flag.txt", "flag", "secret.txt"]}))
            return
        self._send(404, "not found")

    def do_POST(self):
        raw = self._body()  # 必须先读空请求体：否则 keep-alive 连接上残留的 body
        # 会被当成下一个请求的请求行（表现为 Bad request syntax）
        p = self._path()
        if p == "/unpickle":
            self._pickle(raw)
            return
        if p == "/unserialize":
            ct = (self.headers.get("Content-Type") or "").lower()
            payload = ""
            if "application/x-www-form-urlencoded" in ct:
                from urllib.parse import unquote
                q = unquote(raw.decode("utf-8", "replace"))
                for part in q.split("&"):
                    if part.startswith("data="):
                        payload = part[len("data="):]
            else:
                payload = raw.decode("utf-8", "replace")
            self._php(payload)
            return
        self._send(404, "not found")


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    if "--dump-json" in sys.argv:
        print(json.dumps({
            "problems": {
                k: {"flag_sha256": hashlib.sha256(v[0].encode()).hexdigest(),
                    "description": v[1]}
                for k, v in SCENES.items()
            }
        }, indent=2, ensure_ascii=False))
        sys.exit(0)

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18110
    # 场景隔离：传场景名则该靶机只承载这一题的 flag（等价「每题一台靶机」）；
    # 不传则用环境变量 DESER_RANGE_FLAG（默认 pickle 场景）做通用调试靶机。
    scene = sys.argv[2] if len(sys.argv) > 2 else None
    if scene:
        if scene not in SCENES:
            print("unknown scene: %s" % scene, file=sys.stderr)
            sys.exit(2)
        os.environ["DESER_RANGE_FLAG"] = SCENES[scene][0]
    setup_workdir()
    srv = ThreadedHTTPServer(("127.0.0.1", port), Range)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
