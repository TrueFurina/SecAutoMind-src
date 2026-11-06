#!/usr/bin/env python3
"""DashScope 模型可用性探针（只读、不落盘、不打印密钥）。

为什么需要：2026-11-07 用 `qwen3.8-max-0902` 跑 40 题，29 题拿到 `HTTP 403`，
旧口径把它算成「未解」，读出来是一张假的 0 分表。**跑一整轮之前必须先确认
这个模型名在当前 key 下真的能调通**，否则 40 题 × 180s 全是接口失败。

探针只做一件事：发一个 4 token 的最小请求，打印
  model | HTTP/异常类型 | 是否返回内容
绝不打印 key、不打印 header、不打印响应体全文（只取前 80 字符）。

用法（必须在 ctfsbx 上下文里跑，env 里有 DASHSCOPE_API_KEY）：
  /home/user/sam_runs/run.sh scripts/probe_dashscope_models.py model1 model2 ...
"""
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("DASHSCOPE_BASE_URL",
                      "https://dashscope.aliyuncs.com/compatible-mode/v1").rstrip("/")


TOOLS = [{
    "type": "function",
    "function": {
        "name": "run_python",
        "description": "run python code",
        "parameters": {"type": "object", "properties": {"code": {"type": "string"}},
                       "required": ["code"]},
    },
}]


def probe(model, key, with_tools=False, max_tokens=None):
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "say ok"}],
        "max_tokens": 4,
    }
    if with_tools:
        # 2026-11-07: kimi-k3 在**带 tools 的请求**上八题全 400，但同一个模型
        # 不带 tools 的探测是 200。所以要能把这两种请求分开探。
        payload["tools"] = TOOLS
        payload["tool_choice"] = "auto"
        payload["max_tokens"] = 32
    if max_tokens:
        payload["max_tokens"] = int(max_tokens)
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        BASE + "/chat/completions",
        data=body,
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            payload = json.loads(r.read().decode("utf-8", "replace"))
        msg = (payload.get("choices") or [{}])[0].get("message") or {}
        txt = (msg.get("content") or "").strip()
        return "200 OK", True, txt[:40].replace("\n", " ")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:160].replace("\n", " ")
        except Exception:
            pass
        # 只回错误类型与截断后的正文，不回 header（header 里有 key）
        return "HTTP %d" % e.code, False, detail
    except Exception as e:  # noqa: BLE001
        # 🔴 只打印异常类型，绝不打印 str(e)：请求头非法时 str(e) 会回显整个
        # "Bearer <key>"，2026-11-07 已经因此泄露过一次 STEP_API_KEY。
        return "EXC %s" % type(e).__name__, False, ""


def main(argv):
    key = os.environ.get("DASHSCOPE_API_KEY") or ""
    if not key:
        print("DASHSCOPE_API_KEY 未设置", file=sys.stderr)
        return 2
    if key != key.strip() or "\r" in key or "\n" in key:
        # 换行/回车混入会让 header 非法，而且异常里会把 key 整个吐出来
        print("DASHSCOPE_API_KEY 含空白字符（拒绝继续）", file=sys.stderr)
        return 2
    skip = set()
    for i, a in enumerate(argv):
        if a == "--maxtok" and i + 1 < len(argv):
            skip.add(argv[i + 1])
    models = [a for a in argv[1:] if not a.startswith("--") and a not in skip]
    with_tools = "--tools" in argv
    maxtok = None
    for i, a in enumerate(argv):
        if a == "--maxtok" and i + 1 < len(argv):
            maxtok = argv[i + 1]
    if not models:
        models = ["qwen3.8-flash"]
    bad = 0
    for m in models:
        status, ok, note = probe(m, key, with_tools, maxtok)
        bad += 0 if ok else 1
        print("%-26s %-14s %s %s" % (m, status, "OK" if ok else "FAIL", note))
    print("--- %d/%d 可用 ---" % (len(models) - bad, len(models)))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
