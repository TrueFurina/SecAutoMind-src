"""StepFun `json_object` 协议 A/B —— 复跑入口。

预注册（口径、判据、阈值、已知混杂）见：
    docs/evidence/stepfun_jsonmode_AB_预注册_20261104.md

产物：
    docs/evidence/stepfun_jsonmode_AB_20261104/raw.jsonl
    docs/evidence/stepfun_jsonmode_AB_20261104/summary.json

用法：
    python -X utf8 scripts/exp_stepfun_jsonmode_ab.py
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
import time
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[1]
OUT_DIR = REPO / "docs" / "evidence" / "stepfun_jsonmode_AB_20261104"
ENDPOINT = os.getenv("STEP_BASE_URL", "https://api.stepfun.com/v1").rstrip("/") + "/chat/completions"
MODEL = "step-3.5-flash"
MAX_TOKENS = 2000          # 引擎默认，见 ctf_agent/llm/client.py:345
REPS = 2
TIMEOUT = 300.0

# 逐字取自 ctf_agent/core/phases.py:112-133（真实 plan 阶段 system 提示）
SYSTEM = (
    "\n你是资深 CTF 选手。根据题目信息与已执行步骤，决定下一步行动。"
    "优先选择能获得真实证据的动作："
    "tool=调用工具（file_analyze 读附件/http_request 发包/python 跑脚本/deterministic_decode 确定性解码）; "
    "script=执行 Python 脚本（计算/解密/爆破）; reason=纯推理分析; "
    '输出 JSON: {"action": "reason|tool|script|flag", "detail": "...", '
    '"stage": "recon|exploit|flag_extract", "done": false}。'
    '若已能确定 flag，输出 {"action": "flag", "done": true, "flag": "..."}。'
    "禁止猜测或凭直觉输出 flag。flag 必须来自：①工具/脚本的实际输出，"
    "②附件内容的直接提取，③数学计算的确定性结果；"
    "任何未经验证的 flag 一律视为未解出，继续取证（赛后复盘修复：misc-008/pwn-005 伪成功）。"
    "【web 题】若题目提供靶机地址（host/port/url），第一步必须用 tool:http_request "
    "访问目标并分析响应（含源码/robots/备份文件探测）；"
    "若未提供靶机且无附件（本地评测环境），明确当前无靶机，直接走 web_toolkit "
    "模板判断题型并输出可复现 payload，禁止纯推理空转（复盘修复：本地 web 0/6 空转）。"
    "若常规推理/工具均失败、连续 stuck_loop 或附件编码不明，必须调用 tool:deterministic_decode "
    "自动尝试多策略解码（base64/hex/morse/ROT13/zip链/DNS隧道/RAID0）；"
    "【持久工作区】你可输出 {\"action\": \"command\", \"command\": \"<shell 命令>\", "
    "\"detail\": \"...\", \"stage\": \"exploit\", \"done\": false} 在持久工作区执行 shell 命令"
    "（file/strings/gdb/管道交互/多命令组合等），工作目录跨步保留、产物自动索引；"
    "严禁用 command 执行 echo/print 直接打印 flag 字面量冒充答案（此类输出会被 sha256 闸拒绝）。"
    "【重要】只输出一个 JSON 对象，禁止输出 JSON 以外的任何文字、"
    "前言、解释、代码围栏或 Markdown 标记，严格以 { 开头以 } 结尾。"
)

PROMPTS = [
    ("crypto_b64", "题目分类：crypto。题干：附件给出字符串 Y3J5cHRMXtrMzNfYjY0X2FscGhhfQ==。已完成步骤：无。"),
    ("pwn_libc", "题目分类：pwn。题干：附件 challenge（ELF 64 位，NX 开，无 canary）与 libc.so.6。已完成步骤：checksec 完成。"),
    ("web_nosrc", "题目分类：web。题干：目标 http://10.0.0.5:8080/ ，无源码无附件。已完成步骤：无。"),
    ("misc_morse", "题目分类：misc。题干：附件内容为一串由 . 和 - 与空格组成的文本。已完成步骤：无。"),
    ("rev_obf", "题目分类：rev。题干：附件 crackme，字符串被混淆。已完成步骤：strings 输出稀疏。"),
    ("forensics_pcap", "题目分类：forensics。题干：附件 traffic.pcap，疑似 DNS 隧道。已完成步骤：无。"),
    ("script_brute", "题目分类：crypto。题干：4 位数字 PIN 的 MD5 为 5f4dcc3b5aa765d61d8327deb882cf99。已完成步骤：无。"),
    ("flag_check", "题目分类：misc。题干：脚本输出中出现疑似 flag 片段 flag{base64_is_easy}。已完成步骤：脚本已执行成功。"),
]


def _engine_helpers():
    """优先用引擎原函数；导入失败则回落到本地等价实现，并在汇总里标注。"""
    sys.path.insert(0, str(REPO / "CTF-Agent_融合"))
    try:
        from ctf_agent.llm.client import _extract_content, _extract_json_object  # noqa: PLC0415
        return _extract_content, _extract_json_object, "engine"
    except Exception as exc:  # noqa: BLE001
        def _extract_content(data):
            try:
                msg = data["choices"][0]["message"]
            except (KeyError, IndexError, TypeError):
                return None
            content = msg.get("content")
            if not isinstance(content, str) or not content.strip():
                content = msg.get("reasoning_content")
            return content.strip() or None if isinstance(content, str) else None

        def _extract_json_object(text):
            if not isinstance(text, str):
                return None
            s = text.strip()
            if s.startswith("```"):
                s = s.strip("`")
                if s.startswith("json"):
                    s = s[4:]
            i, j = s.find("{"), s.rfind("}")
            if i < 0 or j <= i:
                return None
            try:
                obj = json.loads(s[i:j + 1])
            except Exception:  # noqa: BLE001
                return None
            return obj if isinstance(obj, dict) else None

        print(f"[warn] 引擎导入失败({type(exc).__name__}: {exc})，使用本地等价实现")
        return _extract_content, _extract_json_object, "fallback"


def main() -> int:
    key = os.getenv("STEP_API_KEY", "").strip()
    if not key:
        print("REFUSED: STEP_API_KEY 为空")
        return 3
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    extract_content, extract_json, helper_src = _engine_helpers()

    arms = [("A_off", None), ("B_on", {"type": "json_object"})]
    raw_path = OUT_DIR / "raw.jsonl"
    records = []
    with raw_path.open("w", encoding="utf-8") as fh:
        for arm, rf in arms:
            for pid, ptext in PROMPTS:
                for rep in range(1, REPS + 1):
                    payload = {
                        "model": MODEL,
                        "messages": [
                            {"role": "system", "content": SYSTEM},
                            {"role": "user", "content": ptext},
                        ],
                        "max_tokens": MAX_TOKENS,
                    }
                    if rf:
                        payload["response_format"] = rf
                    t0 = time.time()
                    status = None
                    body = None
                    err = None
                    try:
                        r = httpx.post(
                            ENDPOINT,
                            json=payload,
                            headers={"Authorization": f"Bearer {key}"},
                            timeout=TIMEOUT,
                            trust_env=False,
                        )
                        status = r.status_code
                        body = r.json() if r.status_code == 200 else r.text[:400]
                    except Exception as exc:  # noqa: BLE001
                        err = f"{type(exc).__name__}: {exc}"
                    latency = round((time.time() - t0) * 1000)

                    rec = {
                        "ts": _dt.datetime.now().isoformat(timespec="seconds"),
                        "arm": arm, "prompt_id": pid, "rep": rep,
                        "model": MODEL, "json_mode": bool(rf),
                        "http": status, "error": err, "latency_ms": latency,
                    }
                    if isinstance(body, dict):
                        msg = ((body.get("choices") or [{}])[0] or {}).get("message") or {}
                        c = msg.get("content")
                        rc = msg.get("reasoning_content")
                        rs = msg.get("reasoning")
                        rec.update({
                            "content_len": len(c) if isinstance(c, str) else 0,
                            "reasoning_content_len": len(rc) if isinstance(rc, str) else 0,
                            "reasoning_len": len(rs) if isinstance(rs, str) else 0,
                            "usage": body.get("usage"),
                        })
                        engine_out = extract_content(body)
                        obj = extract_json(engine_out) if engine_out else None
                        if engine_out is None:
                            bucket = "empty_reply"
                        elif obj is None:
                            bucket = "protocol_fail"
                        else:
                            bucket = "ok"
                        rec["bucket"] = bucket
                        rec["content_head"] = (engine_out or "")[:120]
                    else:
                        rec["bucket"] = "http_error"
                        rec["content_head"] = str(body)[:120] if body else (err or "")
                    records.append(rec)
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    fh.flush()
                    print(f"{arm} {pid} r{rep} -> {rec['bucket']} ({latency}ms, http={status})")

    def rate(arm, b):
        sel = [r for r in records if r["arm"] == arm and r["bucket"] in ("ok", "protocol_fail", "empty_reply")]
        n = len(sel)
        k = sum(1 for r in sel if r["bucket"] == b)
        return k, n, round(100.0 * k / n, 1) if n else None

    summary = {
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "endpoint": ENDPOINT, "model": MODEL, "max_tokens": MAX_TOKENS, "reps": REPS,
        "prompts": len(PROMPTS), "helper_source": helper_src,
        "arms": {},
    }
    for arm, _ in arms:
        ok_k, ok_n, ok_r = rate(arm, "ok")
        pf_k, pf_n, pf_r = rate(arm, "protocol_fail")
        er_k, er_n, er_r = rate(arm, "empty_reply")
        http_err = sum(1 for r in records if r["arm"] == arm and r["bucket"] == "http_error")
        summary["arms"][arm] = {
            "denominator": ok_n, "ok": ok_k, "protocol_fail": pf_k, "empty_reply": er_k,
            "ok_rate_pct": ok_r, "protocol_fail_rate_pct": pf_r, "empty_reply_rate_pct": er_r,
            "http_error_calls": http_err,
        }
    a_ok = summary["arms"]["A_off"]["ok_rate_pct"]
    b_ok = summary["arms"]["B_on"]["ok_rate_pct"]
    delta = None if (a_ok is None or b_ok is None) else round(b_ok - a_ok, 1)
    summary["delta_ok_rate_pp"] = delta
    summary["verdict"] = (
        None if delta is None else ("json_object 有效（≥20pp）" if delta >= 20 else "未证有效（<20pp）")
    )
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
