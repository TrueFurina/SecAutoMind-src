#!/usr/bin/env python3
"""SQL 注入深度靶场 —— 真 sqlite3 库，三类真实注入考点。

flag 只在注入真正成功时经查询结果回显：
  1. sqli_union : GET /sqli_union/news?id= 数字拼接注入。
                  需 UNION SELECT 探列数 → sqlite_master 拿表名 → 提取 secret.flag。
  2. sqli_error : GET /sqli_error/search?q= 引号拼接注入。
                  需引号闭合 + 字符串拼接子查询把 flag 拼进结果。
  3. sqli_blind : GET /sqli_blind/check?user= 布尔盲注（仅返回 exists / no such user）。
                  需 length 探测 + 逐字符二分提取 secret.flag。

纯标准库实现。
用法: python sqli_range.py [port] [--dump-json]
"""

import hashlib
import json
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote

PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 18121

SCENES = {
    "sqli_union": ("flag{sqli_uni0n_s3lect_3xtract}",
                   "SQL 注入：GET /sqli_union/news?id=1 的 id 参数直接拼入 SQL。"
                   "flag 存在 secret 表的 flag 字段（先 UNION 探列数，再查 sqlite_master 或直接取）。"),
    "sqli_error": ("flag{sqli_c0ncat_subsquery_l3ak}",
                   "SQL 注入：GET /sqli_error/search?q=web 的 q 参数单引号拼接。"
                   "flag 存在 secret 表。可闭合引号后用 || 拼接子查询回显。"),
    "sqli_blind": ("flag{sqli_b00l_bl1nd_b1n4ry}",
                   "SQL 注入：GET /sqli_blind/check?user=admin 的 user 参数拼接，"
                   "页面仅返回 user exists / no such user（布尔盲注）。flag 在 secret 表。"),
}

DB_PATH = ":memory:"


def build_into(conn):
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE news (id INTEGER PRIMARY KEY, title TEXT, body TEXT);
        CREATE TABLE users (id INTEGER PRIMARY KEY, user TEXT, pass TEXT, role TEXT);
        CREATE TABLE secret (flag TEXT);
    """)
    c.executemany("INSERT INTO news VALUES (?,?,?)", [
        (1, "Welcome", "Welcome to the news portal."),
        (2, "Security", "We patched everything. Trust us."),
        (3, "Status", "All systems operational."),
    ])
    c.executemany("INSERT INTO users VALUES (?,?,?,?)", [
        (1, "admin", "s3cure_p4ss", "admin"),
        (2, "guest", "guest", "user"),
        (3, "alice", "wonderland", "user"),
    ])
    for tbl, scene in (("union_flag", "sqli_union"), ("error_flag", "sqli_error"),
                       ("blind_flag", "sqli_blind")):
        c.execute("CREATE TABLE %s (flag TEXT)" % tbl)
        c.execute("INSERT INTO %s VALUES (?)" % tbl, (SCENES[scene][0],))
    c.execute("INSERT INTO secret VALUES (?)", ("flag{master_enumeration_wins}",))
    conn.commit()


# 进程级单库：sqlite3 连接须声明 check_same_thread=False（ThreadingHTTPServer 多线程）
DB = sqlite3.connect(DB_PATH, check_same_thread=False)
build_into(DB)


def q(sql):
    """执行拼接 SQL（漏洞点本身），返回 (rows, err)。"""
    cur = DB.cursor()
    try:
        cur.execute(sql)
        return cur.fetchall(), None
    except sqlite3.Error as e:
        return None, str(e)


class Range(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    timeout = 10

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _param(self):
        _, _, qs = self.path.partition("?")
        vals = parse_qs(qs)
        for k in ("id", "q", "user"):
            if k in vals:
                return k, vals[k][0]
        return None, ""

    def do_GET(self):
        path = unquote(self.path.split("?")[0])
        scene = path.strip("/").split("/")[0] if path.strip("/") else ""

        if path == "/" or path == "/index.html":
            links = "".join(f'<li><a href="/{s}/x">{s}</a> — {d}</li>'
                            for s, (_, d) in SCENES.items())
            return self._send(200, f"<html><body><h1>SQLi Range</h1><ul>{links}</ul></body></html>")

        # ── 场景 1：UNION（数字拼接） ──
        if scene == "sqli_union" and path.startswith("/sqli_union/news"):
            _, v = self._param()
            # 漏洞点：id 直接拼接
            rows, err = q("SELECT id,title,body FROM news WHERE id=%s" % (v or "1"))
            if err:
                return self._send(500, "<pre>%s</pre>" % err)
            html = "".join("<div>%s | %s | %s</div>" % (r[0], r[1], r[2]) for r in rows)
            return self._send(200, "<html><body>%s</body></html>" % html)

        # ── 场景 2：引号闭合 + 字符串拼接子查询回显（搜索词同时被拼进输出日志列） ──
        if scene == "sqli_error" and path.startswith("/sqli_error/search"):
            _, v = self._param()
            # 漏洞点：搜索词被拼进 SELECT 输出字面量（"查询日志"回显）与 LIKE 两处
            rows, err = q("SELECT 'Query log: ' || '%s' || ' >>', title, body "
                          "FROM news WHERE body LIKE '%%%s%%'" % (v or "web", "welcome"))
            if err:
                return self._send(200, "<html><body><pre>SQL error: %s</pre></body></html>" % err)
            html = "".join("<div>%s | %s | %s</div>" % (r[0], r[1], r[2]) for r in rows)
            return self._send(200, "<html><body>%s</body></html>" % (html or "<i>no result</i>"))

        # ── 场景 3：布尔盲注 ──
        if scene == "sqli_blind" and path.startswith("/sqli_blind/check"):
            _, v = self._param()
            rows, err = q("SELECT role FROM users WHERE user='%s'" % (v or "admin"))
            if err:
                return self._send(200, "no such user")
            if rows:
                return self._send(200, "user exists")
            return self._send(200, "no such user")

        return self._send(404, "not found")


def main():
    if "--dump-json" in sys.argv:
        print(json.dumps(
            {"problems": {k: {"flag_sha256": hashlib.sha256(v[0].encode()).hexdigest(),
                              "description": v[1]} for k, v in SCENES.items()}},
            indent=2, ensure_ascii=False))
        sys.exit(0)
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Range)
    srv.serve_forever()


if __name__ == "__main__":
    main()
