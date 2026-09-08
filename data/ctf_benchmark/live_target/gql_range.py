#!/usr/bin/env python3
"""GraphQL 漏洞靶场（纯标准库）——第 10 基准集。

三个场景，各自独立校验，flag 只在**真实利用成功**时返回：

- gql_introspection  内省开启：__schema 泄露未公开的查询字段 secretFlag →
  query { secretFlag } 直接取 flag。
- gql_idor           user(id:"1") 是普通用户；id:"2" 是管理员，notes 字段即 flag。
- gql_mutation       内省泄露 mutation.execCmd(cmd) ——服务端按命令**真实读取**靶机
  文件（cat flag.txt → open('flag.txt')），构成隐藏调试入口 RCE。

手写 mini GraphQL 执行器（正则抽取固定形态，复刻常见实现的行为面），
每场景独立起进程 = 每题一台靶机。
"""
import hashlib
import json
import os
import re
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG_INTROSPECTION = "flag{gr4phql_1ntr0sp3ct10n_l34k}"
FLAG_IDOR = "flag{gr4phql_1d0r_4dm1n_n0t3s}"
FLAG_MUTATION = "flag{gr4phql_h1dd3n_mut4t10n_rc3}"

SCENES = {
    "gql_introspection": FLAG_INTROSPECTION,
    "gql_idor": FLAG_IDOR,
    "gql_mutation": FLAG_MUTATION,
}

DESCRIPTIONS = {
    "gql_introspection":
        "站点在 /graphql 提供 GraphQL 接口（POST JSON {query}）。内省未关闭。"
        "文档只写了 user(id) 查询，但 schema 里还藏着别的字段。flag 即隐藏字段的返回值。",
    "gql_idor":
        "站点在 /graphql 提供 GraphQL 接口（POST JSON {query}）。user(id:\"1\") { name role notes } "
        "返回当前用户；管理员账号 id 是 2。flag 在管理员的 notes 字段里。",
    "gql_mutation":
        "站点在 /graphql 提供 GraphQL 接口（POST JSON {query}）。官方文档只有查询，"
        "但生产环境忘了下线调试 mutation（可以对靶机文件执行 cat）。flag 在靶机工作目录 flag.txt。",
}

USERS = {
    "1": {"name": "guest", "role": "user",
          "notes": "welcome! administrators manage things under id 2."},
    "2": {"name": "root", "role": "admin", "notes": "FLAG_PLACEHOLDER_IDOR"},
}

RE_INTRO_FIELDS = re.compile(r"__schema\s*\{[^}]*?queryType\s*\{[^}]*?fields\s*\{([^}]*)", re.I | re.S)
RE_INTRO_MUT = re.compile(r"__schema\s*\{[^}]*?mutationType\s*\{[^}]*?fields\s*\{([^}]*)", re.I | re.S)
RE_USER = re.compile(r'user\s*\(\s*id\s*:\s*"([^"]*)"\s*\)\s*\{([^}]*)', re.I | re.S)
RE_SECRETFIELD = re.compile(r"\bsecretFlag\b")
RE_EXECCMD = re.compile(r'execCmd\s*\(\s*cmd\s*:\s*"([^"]*)"', re.I | re.S)


class Range(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # noqa: N802
        pass

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, code: int, body: bytes, ctype: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---------- mini GraphQL 执行 ----------
    def _execute(self, query: str, scene: str) -> dict:
        data = {"data": {}}
        out = data["data"]

        # 内省：queryType 字段名列表（隐藏字段也会列出——漏洞所在）
        m = RE_INTRO_FIELDS.search(query)
        if m and scene == "gql_introspection":
            names = re.findall(r"\bname\b", m.group(1))
            if names:
                # 服务端真实 schema（含未公开字段）
                out["__schema"] = {"queryType": {"fields": [
                    {"name": "user"}, {"name": "secretFlag"}]}}
        m = RE_INTRO_MUT.search(query)
        if m and scene == "gql_mutation":
            if re.findall(r"\bname\b", m.group(1)):
                out["__schema"] = {"mutationType": {"fields": [
                    {"name": "execCmd"}]}}

        # 隐藏查询字段
        if scene == "gql_introspection" and RE_SECRETFIELD.search(query):
            out["secretFlag"] = SCENES[scene]

        # IDOR
        m = RE_USER.search(query)
        if m and scene == "gql_idor":
            uid = m.group(1)
            rec = USERS.get(uid)
            if rec is None:
                data["errors"] = [{"message": "user not found: %s" % uid}]
            else:
                fields = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", m.group(2))
                sel = {f: rec[f] for f in fields if f in rec}
                out["user"] = sel or rec

        # 隐藏 mutation：按命令真实读取靶机文件
        m = RE_EXECCMD.search(query)
        if m and scene == "gql_mutation":
            cmd = m.group(1)
            fn = cmd.replace("cat ", "").replace("type ", "").strip().strip("'\"")
            fp = os.path.join(os.getcwd(), os.path.basename(fn) or fn)
            if os.path.isfile(fp):
                with open(fp, "r", encoding="utf-8") as fh:
                    out["execCmd"] = fh.read()
            else:
                data["errors"] = [{"message": "execCmd: no such file: %s" % fn}]
        return data

    def do_GET(self):  # noqa: N802
        p = self.path.split("?", 1)[0]
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if p in ("/graphql", "/api/graphql"):
            self._send(405, json.dumps({"errors": [{"message": "POST only"}]}).encode())
            return
        self._send(404, b"not found")

    def do_POST(self):  # noqa: N802
        p = self.path.split("?", 1)[0]
        raw = self._body()
        if p not in ("/graphql", "/api/graphql"):
            self._send(404, b"not found")
            return
        try:
            req = json.loads(raw.decode("utf-8", "replace"))
            query = str(req.get("query") or "")
        except Exception:
            self._send(400, json.dumps({"errors": [{"message": "bad json"}]}).encode())
            return
        scene = os.environ.get("GQL_RANGE_SCENE", "gql_introspection")
        result = self._execute(query, scene)
        self._send(200, json.dumps(result).encode())


def main():
    if "--dump-json" in sys.argv:
        print(json.dumps({
            "benchmark": "graphql",
            "version": 1,
            "problems": {
                sid: {
                    "flag_sha256": hashlib.sha256(flag.encode()).hexdigest(),
                    "category": "web/graphql",
                    "description": DESCRIPTIONS[sid],
                } for sid, flag in SCENES.items()
            },
        }, indent=2, ensure_ascii=False))
        return

    scene = sys.argv[2] if len(sys.argv) > 2 else "gql_introspection"
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18201
    os.environ["GQL_RANGE_SCENE"] = scene

    d = tempfile.mkdtemp(prefix="gql_range_")
    os.chdir(d)
    with open("flag.txt", "w", encoding="utf-8") as fh:
        fh.write(SCENES.get(scene, FLAG_MUTATION))
    USERS["2"]["notes"] = SCENES.get(scene, FLAG_IDOR)

    ThreadingHTTPServer(("127.0.0.1", port), Range).serve_forever()


if __name__ == "__main__":
    main()
