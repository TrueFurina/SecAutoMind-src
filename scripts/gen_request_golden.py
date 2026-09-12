#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""生成「DasCTF 协议请求侧」双语言一致性 golden 文件。

与 gen_protocol_golden.py（解析侧）互补：那一侧验证「怎么解读平台返回」，
这一侧验证「怎么向平台发请求」——端点路径、查询参数、鉴权头、请求体键名与类型。

真值来源（单一真值源 / single source of truth）：
    西湖论剑真源 ctf_agent/ctfplatform/dasctf.py 的 DasCTFPlatform 客户端
    真实发出的 HTTP 请求（不是读源码猜，而是让真源客户端打一个记录型 mock server，
    把线上实际会发出的报文录下来）。

Go 侧 internal/ctfplatform 由 request_golden_test.go 断言与 golden 逐项一致。

用法：
    python scripts/gen_request_golden.py [--source <ctf_agent 目录>] [--check]

--check：只比对不写入（供 CI 使用），golden 过期则返回非 0。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

REPO = Path(__file__).resolve().parent.parent
GOLDEN = REPO / "internal" / "ctfplatform" / "testdata" / "request_golden.json"

DEFAULT_SOURCE = Path(r"E:/Program/西湖论剑/ctf_agent")

# 参与一致性断言的请求头（User-Agent 在内：Go 默认 UA 是典型 WAF 拦截特征）
COMPARED_HEADERS = ("x-agent-accesskey", "content-type", "user-agent")

# 假 token（合成值，非真实凭证）
SYNTHETIC_TOKEN = "SYNTHETIC-TOKEN-FOR-PARITY-ONLY"

# mock server 按路径返回的最小可用响应（只需让两侧客户端走完同一条流程）
RESPONSES = {
    "/slab-match/api/v1/agent/ctf/exercise-list": {
        "code": "00000",
        "data": [{"id": 1, "name": "分类容器", "corpus": [{"id": 1001, "name": "web-01"}]}],
    },
    "/slab-match/api/v1/agent/ctf/exercise": {
        "code": "00000",
        "data": {"id": 1001, "name": "web-01", "endpoints": []},
    },
    "/slab-match/api/v1/agent/ctf/build-exercise-env": {
        "code": "00000",
        "data": {"instance_id": "inst-1", "status": "running"},
    },
    "/slab-match/api/v1/agent/answer-panel/answer": {
        "code": "00000",
        "data": {"isCorrect": True, "message": "ok"},
    },
    "/slab-match/api/v1/agent/ctf/recover-exercise-env": {"code": "00000", "data": {}},
}
DEFAULT_RESPONSE = {"code": "00000", "data": {}}

RECORDED: list = []


class RecorderHandler(BaseHTTPRequestHandler):
    """记录请求并回最小响应。"""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # 静音，避免污染 golden 生成输出
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        u = urlparse(self.path)
        headers = {k.lower(): v for k, v in self.headers.items()}
        try:
            body_json = json.loads(raw.decode("utf-8")) if raw else None
        except Exception:
            body_json = raw.decode("utf-8", "replace") if raw else None
        RECORDED.append(
            {
                "method": self.command,
                "path": u.path,
                "query": {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()},
                "headers": {h: headers.get(h) for h in COMPARED_HEADERS if headers.get(h)},
                "json": body_json,
            }
        )
        payload = json.dumps(RESPONSES.get(u.path, DEFAULT_RESPONSE)).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()


def load_truth(source: Path):
    source = Path(source)
    if not source.is_dir():
        raise SystemExit(f"真源目录不存在: {source}")
    sys.path.insert(0, str(source))
    try:
        from ctfplatform.dasctf import DEFAULT_ENDPOINTS, DasCTFPlatform  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise SystemExit(f"导入真源失败（Python 环境/依赖问题）: {exc}") from exc
    return DEFAULT_ENDPOINTS, DasCTFPlatform


async def drive(platform) -> None:
    """驱动真源客户端走一遍完整答题流程（含数值型与非数值型 id 两个分支）。"""
    platform._list_cache_ttl = 0.0  # 关掉列表 TTL 缓存，确保请求真实发出
    await platform.list_challenges()
    platform._detail_cache = {}  # 关掉详情缓存（真源默认 300s）
    await platform.get_challenge("1001")
    await platform.create_instance("1001")
    await platform.submit_flag("1001", "flag{abc_123}")
    await platform.submit_flag("nonnumeric-id", "flag{xyz_789}")
    await platform.reset_instance("1001")
    try:
        await platform.aclose()
    except Exception:
        pass


def build_golden(source: Path) -> dict:
    endpoints, cls = load_truth(source)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), RecorderHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        platform = cls(base_url=f"http://127.0.0.1:{port}", token=SYNTHETIC_TOKEN)
        asyncio.run(drive(platform))
    finally:
        srv.shutdown()
        srv.server_close()

    return {
        "_source": "西湖论剑真源 ctfplatform/dasctf.py 客户端实发请求（记录型 mock server）",
        "_disclaimer": "golden 由真源生成，禁止手改；改动解析/请求逻辑后重新生成并复核差异",
        "endpoints": dict(endpoints),
        "requests": RECORDED,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=str(DEFAULT_SOURCE))
    ap.add_argument("--check", action="store_true", help="只比对不写入，过期返回非 0")
    args = ap.parse_args()

    golden = build_golden(Path(args.source))
    text = json.dumps(golden, ensure_ascii=False, indent=2, sort_keys=False)

    if args.check:
        current = GOLDEN.read_text(encoding="utf-8") if GOLDEN.exists() else ""
        if current.strip() == text.strip():
            print(f"OK golden 未过期: {GOLDEN}")
            return 0
        print(f"STALE golden 需重新生成: {GOLDEN}")
        return 1

    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(text + "\n", encoding="utf-8")
    print(f"已写入 {GOLDEN}（{len(golden['requests'])} 条请求，{len(golden['endpoints'])} 个端点）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
