#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XXE 漏洞靶场（自建「有漏洞的 XML 解析器」，复刻真实解析器的危险行为）。

背景：Python 标准库 xml 默认**禁止**解析外部实体（这是安全默认值），
真实世界的漏洞来自会解析实体的解析器（libxml2/老版本 lxml 等）。
本靶场实现一个极简 XML 解析器，**故意保留**以下危险行为：
  1. DTD 内部子集的实体声明与展开（&xxe; → 读本地文件）
  2. XInclude（<xi:include href="..." parse="text"/> → 读本地文件）
  3. 参数实体 + 外部实体（%oob; → 解析器主动发 HTTP 请求 = Blind XXE 外带）

三个场景各自独立校验，**未真正利用成功绝不返回 flag**：
  xxe_reflected : POST /parse     —— 解析结果回显（经典 XXE 文件读）
  xxe_xinclude  : POST /api/xml   —— XInclude 文件读（无需 DOCTYPE 的变体）
  xxe_oob       : POST /import    —— 参数实体外带，flag 经 /oob?d=... 记录，
                                    从 /oob-log 读取（响应里没有 flag，考验外带通道）

用法：
    python xxe_range.py [port] [scene]
    python xxe_range.py --dump-json
"""
import hashlib
import http.server
import json
import os
import re
import socketserver
import sys
import tempfile
import urllib.request

FLAG_REFLECTED = "flag{xxe_3nt1ty_f1l3_r34d}"
FLAG_XINCLUDE = "flag{x1nclud3_t3xt_p4rs3_r34d}"
FLAG_OOB = "flag{bl1nd_xxe_o0b_p4r4m_3nt1ty}"

SCENES = {
    "xxe_reflected": (
        FLAG_REFLECTED,
        "目标提供 XML 解析接口：POST /parse，请求体为 XML 文档，服务端解析后回显文本内容。"
        "解析器支持 DTD 实体声明。flag 文件为 flag.txt。",
    ),
    "xxe_xinclude": (
        FLAG_XINCLUDE,
        "目标提供 XML 导入接口：POST /api/xml，请求体为 XML 文档。"
        "解析器支持 XInclude（xi:include href= parse=text）。flag 文件为 flag.txt。",
    ),
    "xxe_oob": (
        FLAG_OOB,
        "目标提供 XML 批量导入接口：POST /import，请求体为 XML 文档，响应只有 ok 不回显内容。"
        "解析器支持 DTD 参数实体与外部实体引用（会主动请求 SYSTEM 指向的 URL）。"
        "靶机自身提供 /oob 探针端点与 /oob-log 查询端点。flag 文件为 flag.txt。",
    ),
}


# ---------------- 极简「有漏洞」XML 解析器 ----------------

class VulnerableXMLParser:
    """刻意保留危险行为的 XML 解析器：实体展开 / XInclude / 参数实体外部请求。"""

    max_depth = 8

    def __init__(self):
        self.gen_entities = {}     # 一般实体: name -> (kind, value) kind in local/net
        self.param_entities = {}   # 参数实体: name -> (kind, value)
        self.fetched = []          # 记录解析器主动发起的请求（OOB 证据）

    # --- DTD 解析 ---
    def _parse_dtd(self, dtd):
        # 反复提取 <!ENTITY ...> 声明（一般/参数、内部/外部）
        ent_re = re.compile(r'<!ENTITY\s+(%?)\s*([A-Za-z0-9_\-]+)\s+(SYSTEM\s+"([^"]*)"|"((?:[^"\\]|\\.)*)")\s*>')
        changed = True
        while changed:
            changed = False
            m = ent_re.search(dtd)
            if not m:
                break
            is_param, name, external, uri, internal = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
            changed = True
            dtd = dtd[:m.start()] + dtd[m.end():]
            if external:
                self.param_entities[name] = ("ext", uri) if is_param else ("ext", uri)
                self.gen_entities[name] = ("ext", uri)
            else:
                val = internal
                # 内部子集里参数实体引用立即展开（真实解析器行为）
                if is_param:
                    val = self._expand(val, self.param_entities, kind="param")
                    self.param_entities[name] = ("int", val)
                else:
                    val = self._expand(val, self.gen_entities, kind="gen")
                    self.gen_entities[name] = ("int", val)
        # 使用参数实体（%name; 在 DTD 中出现 = 外部实体被「用」了 → 发请求）
        for m in re.finditer(r"%([A-Za-z0-9_\-]+);", dtd):
            name = m.group(1)
            if name in self.param_entities:
                kind, val = self.param_entities[name]
                if kind == "ext":
                    self._resolve_external(val)

    # --- 展开与解析 ---
    def _resolve_external(self, uri):
        """解析外部实体：本地文件读 / 网络请求（Blind XXE 外带的落点）。

        外部实体的 URI 里若含参数实体引用（如 http://host/oob?d=%file;），
        取回前先展开——这是经典 OOB payload 依赖的解析器行为。
        """
        if "%" in uri:
            expanded = self._expand(uri, self.param_entities, "param")
            if expanded != uri:
                uri = expanded
        self.fetched.append(uri)
        if re.match(r"^https?://", uri):
            try:
                with urllib.request.urlopen(uri, timeout=3) as resp:
                    return resp.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                return ""
        for cand in (uri.lstrip("/"), uri):
            try:
                with open(cand, "r", encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            except Exception:  # noqa: BLE001
                continue
        return ""

    def _expand(self, text, table, kind, depth=0):
        if depth > self.max_depth:
            return text
        pat = r"%([A-Za-z0-9_\-]+);" if kind == "param" else r"&([A-Za-z0-9_\-]+);"
        return re.sub(pat, lambda m: self._entity_value(m.group(1), table, kind, depth), text)

    def _entity_value(self, name, table, kind, depth):
        if name not in table:
            return ""
        kind2, val = table[name]
        if kind2 == "ext":
            val = self._resolve_external(val)
        else:
            val = self._expand(val, table, kind, depth + 1)
        return val

    def _xinclude(self, text):
        inc_re = re.compile(r'<xi:include\s+href="([^"]*)"(?:\s+parse="text")?\s*/>')
        return inc_re.sub(lambda m: self._resolve_external(m.group(1)), text)

    def parse(self, doc):
        # 1) 提取并处理 DOCTYPE 内部子集
        m = re.search(r"<!DOCTYPE[^[]*\[(.*?)\]>", doc, re.S)
        if m:
            self._parse_dtd(m.group(1))
            doc = doc[:m.start()] + doc[m.end():]
        # 2) 展开一般实体
        doc = self._expand(doc, self.gen_entities, "gen")
        # 3) XInclude
        doc = self._xinclude(doc)
        # 4) 取文本内容（极简：去掉所有标签）
        text = re.sub(r"<[^>]*>", " ", doc)
        return " ".join(text.split())


# ---------------- HTTP 靶场 ----------------

def setup_workdir(flag):
    d = tempfile.mkdtemp(prefix="xxe_range_")
    with open(os.path.join(d, "flag.txt"), "w", encoding="utf-8") as fh:
        fh.write(flag)
    with open(os.path.join(d, "flag"), "w", encoding="utf-8") as fh:
        fh.write(flag)
    os.chdir(d)
    return d


class Range(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "XXERange/1.0"
    oob_hits = []

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self):
        ln = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(ln) if ln > 0 else b""

    def _path(self):
        return self.path.split("?", 1)[0]

    def do_GET(self):
        p = self._path()
        if p == "/":
            self._send(200, "xxe range ready")
        elif p == "/oob":
            self.oob_hits.append(self.path)
            self._send(200, "ok")
        elif p == "/oob-log":
            self._send(200, "\n".join(self.oob_hits) if self.oob_hits else "no oob yet")
        elif p in ("/parse", "/api/xml", "/import"):
            self._send(405, "use POST")
        else:
            self._send(404, "not found")

    def do_POST(self):
        raw = self._body()
        p = self._path()
        if p == "/parse":
            self._scene(raw, echo=True)
        elif p == "/api/xml":
            self._scene(raw, echo=True)
        elif p == "/import":
            self._scene(raw, echo=False)
        else:
            self._send(404, "not found")

    def _scene(self, raw, echo):
        try:
            doc = raw.decode("utf-8", "replace")
            parser = VulnerableXMLParser()
            text = parser.parse(doc)
        except Exception as e:  # noqa: BLE001
            self._send(500, "parse error: %s" % e)
            return
        if echo:
            self._send(200, "parsed: %s" % text)
        else:
            self._send(200, "import ok")


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

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18160
    scene = sys.argv[2] if len(sys.argv) > 2 else None
    flag = SCENES[scene][0] if scene in SCENES else os.environ.get("XXE_RANGE_FLAG", FLAG_REFLECTED)
    setup_workdir(flag)
    srv = ThreadedHTTPServer(("127.0.0.1", port), Range)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
