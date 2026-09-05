#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecAutoMind 平台 API 客户端（实验驱动用）

封装：登录鉴权 / SSE 流式推演 / 事件解析 / 结构化结果采集。

设计要点：
  - 只依赖标准库，任何人可一键复现实验
  - 采集的字段直接对应赛题评分维度需要的证据：
      tool_calls   → 维度④ 工具协同与扩展能力（跨工具链编排）
      events       → 维度③ 决策逻辑与可解释性（决策链可追溯）
      finalized    → 维度① 任务理解与执行（闭环是否完成）
      duration_ms  → 各维度的效率证据

用法：
    python scripts/experiments/sam_client.py --smoke   # 链路冒烟测试
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

DEFAULT_BASE = "http://127.0.0.1:18086"
DEFAULT_USER = "admin"


class SamClient:
    def __init__(self, base: str = DEFAULT_BASE, user: str = DEFAULT_USER,
                 password: str | None = None, timeout: int = 30):
        self.base = base.rstrip("/")
        self.user = user
        self.password = password or self._read_initial_password()
        self.token: str | None = None
        self.timeout = timeout

    @staticmethod
    def _read_initial_password() -> str:
        """从 data/admin_initial_password.txt 读取首次启动生成的初始密码。"""
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(os.path.dirname(here))  # .../scripts/experiments -> 仓库根
        path = os.path.join(root, "data", "admin_initial_password.txt")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("密码") or line.strip().startswith("Password"):
                        return line.split(":", 1)[1].strip()
        raise RuntimeError(
            "未找到初始密码，请先启动 secautomind-ai.exe 生成 "
            "data/admin_initial_password.txt，或显式传入 password")

    # ── 鉴权 ──
    def login(self) -> str:
        req = urllib.request.Request(
            f"{self.base}/api/auth/login",
            data=json.dumps({"username": self.user, "password": self.password}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
        self.token = data.get("token")
        if not self.token:
            raise RuntimeError(f"登录未返回 token: {str(data)[:200]}")
        return self.token

    def _headers(self) -> dict:
        if not self.token:
            self.login()
        return {"Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "text/event-stream"}

    # ── 推演（SSE 流式）──
    def run_agent(self, message: str, orchestration: str = "deep",
                  conversation_id: str | None = None, role: str | None = None,
                  overall_timeout: int = 600, verbose: bool = False) -> dict:
        """下发一次推演任务并消费 SSE 流，返回结构化结果。

        Args:
            message: 自然语言任务
            orchestration: deep | plan_execute | supervisor
            overall_timeout: 整体墙钟上限（秒）
        """
        body: dict = {"message": message, "orchestration": orchestration}
        if conversation_id:
            body["conversationId"] = conversation_id
        if role:
            body["role"] = role

        req = urllib.request.Request(
            f"{self.base}/api/multi-agent/stream",
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers=self._headers(), method="POST")

        t0 = time.time()
        events: list[dict] = []
        tool_calls: list[dict] = []
        hitl_decisions: list[dict] = []
        usage: dict = {}
        final_text = ""
        finalized = False
        error = None
        status = None
        completion_reason = None
        evidence_verified = None
        conversation_id_out = conversation_id

        try:
            with urllib.request.urlopen(req, timeout=overall_timeout) as resp:
                buf = b""
                while True:
                    if time.time() - t0 > overall_timeout:
                        error = f"overall_timeout>{overall_timeout}s"
                        break
                    chunk = resp.read1(8192)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n\n" in buf:
                        raw_event, buf = buf.split(b"\n\n", 1)
                        ev = self._parse_sse(raw_event)
                        if not ev:
                            continue
                        events.append(ev)
                        if verbose:
                            print(f"  <{ev.get('type')}> {str(ev.get('message'))[:100]}", flush=True)

                        et = ev.get("type")
                        data = ev.get("data") or {}

                        if et == "tool_call":
                            tool_calls.append({
                                "seq": len(tool_calls) + 1,
                                "tool": data.get("toolName"),
                                "args": str(data.get("arguments"))[:500],
                                "agent": data.get("einoAgent"),
                                "role": data.get("einoRole"),
                                "t_ms": int((time.time() - t0) * 1000),
                            })
                        elif et == "tool_result":
                            # 回填工具执行成败（维度④：工具链实际生效情况）
                            tn = data.get("toolName")
                            for tc in reversed(tool_calls):
                                if tc.get("tool") == tn and "success" not in tc:
                                    tc["success"] = data.get("success")
                                    tc["is_error"] = data.get("isError")
                                    tc["preview"] = str(data.get("resultPreview"))[:200]
                                    break
                        elif et in ("hitl_audit_agent", "hitl_decision", "hitl_resumed"):
                            # 人机协同裁决：决策可解释性的核心证据（谁批的、依据什么、批准还是拒绝）
                            hitl_decisions.append({
                                "event": et,
                                "tool": data.get("toolName"),
                                "decision": data.get("decision"),
                                "decided_by": data.get("decidedBy") or data.get("reviewer"),
                                "mode": data.get("mode"),
                                "status": data.get("status"),
                                "comment": str(data.get("comment"))[:600],
                                "t_ms": int((time.time() - t0) * 1000),
                            })
                        elif et == "eino_usage_summary":
                            usage = data if isinstance(data, dict) else {}
                        elif et == "error":
                            error = str(data)[:300]
                        elif et == "response":
                            # 只有 finalized=true 才是成功最终回复。
                            # 注意：正文在事件外层 message 上（SSE 三层结构），内层 data 只有元数据。
                            body_text = ev.get("message") or data.get("message") or data.get("content") or ""
                            if data.get("finalized") is True:
                                finalized = True
                                final_text = body_text
                                status = data.get("status")
                                completion_reason = data.get("completionReason")
                                evidence_verified = data.get("evidenceVerified")
                            elif data.get("finalized") is False:
                                final_text = body_text
                        elif et == "done":
                            break

                        if isinstance(data, dict) and data.get("conversationId"):
                            conversation_id_out = data["conversationId"]
        except urllib.error.HTTPError as e:
            error = f"HTTP {e.code}: {e.read()[:300].decode('utf-8', 'replace')}"
        except Exception as e:
            error = f"{type(e).__name__}: {e}"

        hits = [h for h in hitl_decisions if h.get("decision")]
        return {
            "message": message,
            "orchestration": orchestration,
            "conversation_id": conversation_id_out,
            "duration_ms": int((time.time() - t0) * 1000),
            "finalized": finalized,
            "status": status,
            "completion_reason": completion_reason,
            "evidence_verified": evidence_verified,
            "tool_calls": tool_calls,
            "tool_call_count": len(tool_calls),
            "tool_names": [t["tool"] for t in tool_calls if t.get("tool")],
            "tool_success_count": sum(1 for t in tool_calls if t.get("success") is True),
            "tool_error_count": sum(1 for t in tool_calls if t.get("is_error") is True),
            "hitl_decisions": hitl_decisions,
            "hitl_count": len(hits),
            "hitl_approve": sum(1 for h in hits if h.get("decision") == "approve"),
            "hitl_reject": sum(1 for h in hits if h.get("decision") in ("reject", "deny")),
            "hitl_sample_reasons": [h.get("comment", "")[:300] for h in hits[:3]],
            "usage": usage,
            "event_count": len(events),
            "event_types": sorted({e.get("type") for e in events if e.get("type")}),
            "final_text": final_text[:6000],
            "error": error,
        }

    @staticmethod
    def _parse_sse(raw: bytes) -> dict | None:
        """解析一个 SSE 事件块。

        平台 SSE 为三层结构：{type, message, data:{...真实字段...}}
        ——真实字段（toolName / finalized / decision 等）在嵌套的 data 里，
        少剥一层会导致所有字段取不到（曾在此踩坑）。
        """
        try:
            text = raw.decode("utf-8", "replace").strip()
        except Exception:
            return None
        if not text or text.startswith(":"):
            return None
        typ, data_str = None, None
        for line in text.splitlines():
            if line.startswith("event:"):
                typ = line[6:].strip()
            elif line.startswith("data:"):
                data_str = line[5:].strip()
        if data_str is None:
            return None
        try:
            payload = json.loads(data_str)
        except Exception:
            return {"type": typ, "data": {"_raw": data_str}, "message": None}

        if not isinstance(payload, dict):
            return {"type": typ, "data": {"_raw": payload}, "message": None}

        # 三层结构：外层 type 可能为空（用 SSE event: 行或 payload.type 兜底）
        ev_type = typ or payload.get("type")
        inner = payload.get("data")
        if not isinstance(inner, dict):
            inner = {} if inner is None else {"_value": inner}
        # 若没有嵌套 data（少数事件为扁平结构），退化为 payload 自身
        if "data" not in payload:
            inner = {k: v for k, v in payload.items() if k not in ("type", "message")}
        return {"type": ev_type, "data": inner, "message": payload.get("message")}


def smoke_test() -> int:
    """链路冒烟：登录 + 一次超短推演，验证 SSE 事件可解析。"""
    c = SamClient()
    print(f"登录 {c.base} ...")
    c.login()
    print(f"  token 获取成功: {c.token[:8]}...")

    print("下发冒烟任务（对自建靶场 S1 做一次轻量探测）...")
    r = c.run_agent(
        "对 127.0.0.1:8501 的授权演示靶场做一次 Web 安全检测："
        "先识别服务与指纹，再探测常见漏洞（目录枚举、SQL 注入、XSS 等），最后输出结论。",
        orchestration="deep", overall_timeout=420, verbose=True)

    print("\n=== 冒烟结果 ===")
    for k in ("duration_ms", "finalized", "status", "tool_call_count",
              "event_count", "event_types", "completion_reason", "error"):
        print(f"  {k}: {r[k]}")
    print(f"  tool_names: {r['tool_names']}")
    print(f"  final_text(前300): {r['final_text'][:300]}")
    ok = r["error"] is None and r["event_count"] > 0
    print("\n" + ("✅ 链路打通" if ok else "❌ 链路异常"))
    return 0 if ok else 1


if __name__ == "__main__":
    if "--smoke" in sys.argv:
        sys.exit(smoke_test())
    print(__doc__)
