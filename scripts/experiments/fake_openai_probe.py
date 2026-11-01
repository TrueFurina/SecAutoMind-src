#!/usr/bin/env python3
"""假 OpenAI 端点（零 token 集成验证用，2026-11-01）。

用途：验证两件此前**只被单测覆盖**、但真实链路上没验过的事：
  1. `localArtifactHint()` 是否真把 cwd 里的工件清单写进了**线上请求体**
     （上一轮的错就在这里：harness 准备好了 ≠ 模型收到了）；
  2. `python_session` 路径围栏在**真 Linux** 上是否挡住越界绝对路径
     （单测跑在 Windows，路径语义不同，不能替代）。

做法：按次序返回脚本化的 assistant 轮次，并把每个请求体落盘。

两种剧本（`--scenario`）：

- `leak`（默认）：第 1 轮 → 让模型读 /home/user/.bashrc（应被围栏拒）；
  第 2 轮 → 列当前目录（应放行）；第 3 轮 → 输出一个假 flag 收口。
- `inbox`（2026-11-01 新增）：第 1 轮 → `read_attachment` 下载本探针自己
  `/att/<name>` 上的附件；第 2 轮 → **从上一轮工具回执里解析出真实落盘路径**，
  用 `python_session` 打开它；第 3 轮 → 收口。
  验的是「工具给的路径能不能被自己的围栏打开」——这两段代码口径不一致时，
  附件题会变成不可解，而跑批只会显示"模型不会用工具"，看不出真因。

零依赖、零外网、零 token。跑完看 /tmp/fake_llm/req_*.json 即可。

⚠️ 坑（2026-11-01 自己踩到）：轮次计数器 `N["i"]` 是**进程级全局**，
脚本化轮次用完后再来一发会被判成"第 4 轮"直接回 flag 收口 ——
表现为跑批日志里**一条工具执行都没有**、看起来像"模型没调工具"。
每次跑批前必须重启探针（`fuser -k <port>/tcp` 再起），不要复用进程。
"""
import argparse
import json
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

OUT = "/tmp/fake_llm"
N = {"i": 0}
STEP1 = {"code": ""}
SCEN = {"name": "leak", "port": 18999, "att": "att.bin"}

# 探针自己提供的"附件"内容：MZ 开头，便于断言模型真读到了字节而不是拿到一段报错文本。
ATT_BYTES = b"MZfake-attachment-from-probe\x00\x01\x02"


def tool_call(code):
    return {
        "id": "call_%d" % N["i"],
        "type": "function",
        "function": {"name": "python_session", "arguments": json.dumps({"code": code})},
    }


def named_tool_call(name, args):
    return {
        "id": "call_%d" % N["i"],
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


def first_user_text(body):
    for m in body.get("messages") or []:
        if m.get("role") == "user":
            return m.get("content") or ""
    return ""


def last_tool_text(body):
    """取最近一条 tool 消息的内容（= 上一轮工具回执）。"""
    for m in reversed(body.get("messages") or []):
        if m.get("role") == "tool":
            c = m.get("content")
            if isinstance(c, str):
                return c
    return ""


def scripted_leak(i, body):
    """按轮次返回脚本化动作；第 3 步的路径**从 prompt 里解析**，
    这样同时也验证了"提示里的绝对路径是机器可直接用的"。"""
    if i == 1:
        return tool_call(STEP1["code"])
    if i == 2:
        return tool_call("import os; print(os.getcwd(), sorted(os.listdir('.')))")
    if i == 3:
        txt = first_user_text(body)
        m = re.search(r"(/[^\s()（）]+VVMM\.exe)", txt)
        if not m:
            return tool_call("print('NO_ABS_PATH_IN_PROMPT')")
        p = m.group(1)
        return tool_call("print(open(%r,'rb').read(2))" % p)
    return None


def scripted_inbox(i, body):
    if i == 1:
        return named_tool_call(
            "read_attachment",
            {"attachment_url": "http://127.0.0.1:%d/att/%s" % (SCEN["port"], SCEN["att"])},
        )
    if i == 2:
        txt = last_tool_text(body)
        m = re.search(r"路径:\s*(\S+)", txt)
        if not m:
            # 连路径都没回执 ⇒ 直接暴露，别让后面的断言"因为没执行而假绿"
            return tool_call("print('NO_PATH_IN_TOOL_RESULT: %s')" % txt[:120].replace("'", '"'))
        p = m.group(1)
        return tool_call("print(open(%r,'rb').read(4))" % p)
    if i == 3:
        return None
    return None


def scripted(i, body):
    if SCEN["name"] == "inbox":
        return scripted_inbox(i, body)
    return scripted_leak(i, body)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/att/%s" % SCEN["att"]:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(ATT_BYTES)))
            self.end_headers()
            self.wfile.write(ATT_BYTES)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        ln = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(ln)
        N["i"] += 1
        i = N["i"]
        try:
            body = json.loads(raw)
        except Exception:
            body = {"_raw": raw.decode("utf-8", "replace")}
        os.makedirs(OUT, exist_ok=True)
        with open(os.path.join(OUT, "req_%03d.json" % i), "w", encoding="utf-8") as f:
            json.dump(body, f, ensure_ascii=False, indent=1)

        tc = scripted(i, body)
        if tc is not None:
            msg = {"role": "assistant", "content": None, "tool_calls": [tc]}
            finish = "tool_calls"
        else:
            msg = {"role": "assistant", "content": "flag{fake_probe_0001}"}
            finish = "stop"

        resp = {
            "id": "chatcmpl-fake-%d" % i,
            "object": "chat.completion",
            "created": 0,
            "model": "fake-probe",
            "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
        data = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18999)
    ap.add_argument("--scenario", default="leak", choices=["leak", "inbox"],
                    help="leak=越界路径探针；inbox=附件收件箱闭环探针")
    ap.add_argument("--att", default="att.bin", help="inbox 剧本里探针自己提供的附件名")
    ap.add_argument("--step1", default="print(open('/home/user/.bashrc').read()[:40])",
                    help="第 1 轮的 python 代码（探针用，可换成读仓库答案文件等）")
    a = ap.parse_args()
    STEP1["code"] = a.step1
    SCEN["name"] = a.scenario
    SCEN["port"] = a.port
    SCEN["att"] = a.att
    os.makedirs(OUT, exist_ok=True)
    HTTPServer(("127.0.0.1", a.port), H).serve_forever()
