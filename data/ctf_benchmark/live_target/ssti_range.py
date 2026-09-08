#!/usr/bin/env python3
"""SSTI 深度靶场 —— 三类真实模板注入考点（自建 mini 求值引擎，真 Python eval 环境）。

flag 只在模板求值真正逃逸时回显：
  1. ssti_expr    : GET /ssti_expr/hello?name={{...}} —— Jinja 风格 {{ }} 定界，
                    求值环境 globals 含真实 os 模块。flag 在环境变量 SSTI_EXPR_FLAG。
  2. ssti_format  : GET /ssti_format/greet?who={...} —— Python str.format 注入，
                    用户输入是格式串本身。flag 经 g=globals() 可达（SECRET 常量）。
  3. ssti_filtered: GET /ssti_filtered/hello?name=... —— 黑名单过滤 "{{" 与 "}}"，
                    但求值引擎同时支持 Twig 风格 {% %} 定界（黑名单绕过）。
                    flag 在环境变量 SSTI_FILT_FLAG。

反作弊：flag 不在任何响应里直接出现；{{flag()}} 之类不存在的名字会抛 NameError。
纯标准库实现。
用法: python ssti_range.py [port] [--dump-json]
"""

import hashlib
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote

PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 18122

FLAG_EXPR = "flag{ssti_jinja_3nv_3scap3}"
FLAG_FORMAT = "flag{ssti_f0rmat_string_gl0b}"
FLAG_FILT = "flag{ssti_bl4cklist_twig_bypass}"

SCENES = {
    "ssti_expr": (FLAG_EXPR,
                  "SSTI：GET /ssti_expr/hello?name=World 会把 name 当 Jinja 模板渲染（{{ }} 定界）。"
                  "flag 存在环境变量 SSTI_EXPR_FLAG。"),
    "ssti_format": (FLAG_FORMAT,
                    "SSTI：GET /ssti_format/greet?who=World 的 who 是 str.format 的格式串本身。"
                    "flag 是靶机源码里的 SECRET 常量，可经 globals() 可达。"),
    "ssti_filtered": (FLAG_FILT,
                      "SSTI：GET /ssti_filtered/hello?name=... 是模板注入点，但黑名单过滤了 "
                      "{{ 和 }}。引擎另支持 Twig 风格 {% %} 定界。flag 存在环境变量 SSTI_FILT_FLAG。"),
}

os.environ["SSTI_EXPR_FLAG"] = FLAG_EXPR
os.environ["SSTI_FILT_FLAG"] = FLAG_FILT
SECRET = FLAG_FORMAT

# 求值环境：真实 os 可达（真实 Jinja 沙箱逃逸的典型形态），flag 名不在环境里
EVAL_GLOBALS = {"os": os, "len": len, "str": str, "int": int, "open": open}


class TemplateError(Exception):
    pass


def eval_expr(expr):
    """真 Python eval —— 模板引擎求值内核（漏洞点本身）。"""
    try:
        return str(eval(expr, dict(EVAL_GLOBALS)))  # noqa: S307 靶场漏洞本体
    except Exception as e:
        raise TemplateError(str(e))


def render(text, start, end):
    """把 text 里所有 start...end 片段求值后替换。"""
    out, i = [], 0
    while True:
        j = text.find(start, i)
        if j < 0:
            out.append(text[i:])
            break
        k = text.find(end, j + len(start))
        if k < 0:
            out.append(text[i:])
            break
        out.append(text[i:j])
        out.append(eval_expr(text[j + len(start):k].strip()))
        i = k + len(end)
    return "".join(out)


def ssti_render(text):
    """Jinja 风格：{{ expr }}。"""
    return render(text, "{{", "}}")


def twig_render(text):
    """Twig 风格：{% expr %}（黑名单没覆盖这个定界）。"""
    return render(text, "{%", "%}")


def format_render(who):
    """str.format 注入（漏洞点本身）：用户输入是格式串。"""
    try:
        return "Hello, " + who.format(g=globals())
    except Exception as e:
        return "Hello, <format error: %s>" % e


def blacklist(name):
    """黑名单：剥掉 {{ 与 }}（模拟错误的安全过滤）。"""
    return name.replace("{{", "").replace("}}", "")


class Range(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    timeout = 8

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
        for k in ("name", "who"):
            if k in vals:
                return k, vals[k][0]
        return None, ""

    def do_GET(self):
        path = unquote(self.path.split("?")[0])
        scene = path.strip("/").split("/")[0] if path.strip("/") else ""

        if path == "/" or path == "/index.html":
            links = "".join(f'<li><a href="/{s}/hello?name=x">{s}</a> — {d}</li>'
                            for s, (_, d) in SCENES.items())
            return self._send(200, f"<html><body><h1>SSTI Range</h1><ul>{links}</ul></body></html>")

        key, val = self._param()

        # ── 场景 1：Jinja {{ }} 求值逃逸 ──
        if scene == "ssti_expr" and path.startswith("/ssti_expr/hello"):
            try:
                return self._send(200, "<h2>Hello, %s!</h2>" % ssti_render(val or "World"))
            except TemplateError as e:
                return self._send(200, "<h2>Hello, <b>template error</b>: %s</h2>" % e)

        # ── 场景 2：str.format 注入 ──
        if scene == "ssti_format" and path.startswith("/ssti_format/greet"):
            return self._send(200, "<h2>%s</h2>" % format_render(val or "World"))

        # ── 场景 3：黑名单绕过（{{ 被剥掉，{% 仍在） ──
        if scene == "ssti_filtered" and path.startswith("/ssti_filtered/hello"):
            cleaned = blacklist(val or "World")
            try:
                return self._send(200, "<h2>Hello, %s!</h2>" % twig_render(cleaned))
            except TemplateError as e:
                return self._send(200, "<h2>Hello, <b>template error</b>: %s</h2>" % e)

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
