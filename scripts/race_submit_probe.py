#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""race_submit_probe.py —— 提交通道探针（赛前必跑，**不发任何 flag**）。

## 为什么存在（2026-10-24 羊城杯 0 分复盘，四条待办里最致命的一条）
那天我解出 GraphNexus 之后才发现：**没有提交通道**。解法对了，分还是 0。
更早的 10-22 还踩过一次变体：25 次提交全失败，原因不是答案错，
而是**格式/通道**（带壳 vs 去壳、字段名 `exerciseId` vs `exercise_id`）。

结论：**「能提交」必须是一个被实测过的前置条件，不能靠假设。**

## 安全设计（这是本脚本的第一约束）
请求体是模块常量 `PROBE_BODY = "{}"`，**不含 flag、不含 confirmation**：
- CTF² 需要 `confirmation=true` 才会真的交，`{}` 只会被判参数缺失；
- DASCTF 需要 `exerciseId` + `flag`，`{}` 同样只会被判参数不全。
所以探针**不可能消耗答题次数**，也**不可能误交**。模块加载时会断言这一点。

## 判读（只看平台业务码，不看 HTTP 状态）
| 响应 | 含义 | 结论 |
|---|---|---|
| `40001` 参数不全 / HTTP 400 | 端点存在、鉴权已通过 | ✅ 通道通 |
| `40403` 无权操作 / HTTP 401 | 令牌无效/过期/无该赛事权限 | ❌ 令牌坏 |
| HTTP 404 | 路径错（平台/赛事/题号不对） | ❌ 路径错 |
| HTTP 429 | 限流（说明端点在） | ⚠️ 通道在但被限流 |
| 2xx | **不该发生**（说明真的交了什么） | 🚨 立即人工核查 |

## 用法
    # 只看将要发什么，不联网（CI 用这个）
    python scripts/race_submit_probe.py --platform ctf2 --dry-run

    # 实探（需要环境变量里的令牌；不会回显令牌）
    python scripts/race_submit_probe.py --platform ctf2 \
        --competition <uuid> --stage <uuid> --challenge <uuid>
    python scripts/race_submit_probe.py --platform dasctf --base-url https://ycb-bk.dasctf.com

退出码：0=通道通 / 1=通道不通 / 2=用法或环境错误。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

# ── 安全不变量：探针体必须是空 JSON，绝不含 flag / confirmation ──────────────
PROBE_BODY = "{}"
assert "flag" not in PROBE_BODY and "confirmation" not in PROBE_BODY, \
    "探针体里不许出现 flag/confirmation —— 否则可能真的提交"

CTF2_AGENT_BASE = "/api/open/v1/user/agent"
DASCTF_SUBMIT_PATH = "/slab-match/api/v1/agent/answer-panel/answer"

# 业务码 → 判定
_CODE_OK = ("40001",)          # 参数不全 ⇒ 鉴权已过
_CODE_DENY = ("40403", "401")  # 无权 / 未认证


def build_url(platform: str, *, base_url: str = "", competition: str = "",
              stage: str = "", challenge: str = "") -> str:
    """构造提交端点 URL。缺参数就抛 ValueError（不许拼出半截地址去试）。"""
    if platform == "ctf2":
        if not (base_url and competition and stage and challenge):
            raise ValueError("ctf2 需要 --base-url / --competition / --stage / --challenge")
        return (base_url.rstrip("/") + CTF2_AGENT_BASE
                + "/competitions/" + competition + "/stages/" + stage
                + "/challenges/" + challenge + "/submit/")
    if platform == "dasctf":
        if not base_url:
            raise ValueError("dasctf 需要 --base-url")
        return base_url.rstrip("/") + DASCTF_SUBMIT_PATH
    raise ValueError("未知平台：%s（支持 ctf2 / dasctf）" % platform)


def build_headers(platform: str, token: str) -> dict:
    if platform == "ctf2":
        return {"Authorization": "Bearer " + token, "Content-Type": "application/json",
                "User-Agent": "SecAutoMind-submit-probe/1.0"}
    return {"X-Agent-AccessKey": token, "Content-Type": "application/json",
            "User-Agent": "SecAutoMind-submit-probe/1.0"}


def classify(http_status: int | None, body: str) -> tuple[str, str]:
    """纯函数：把响应分类成 (verdict, detail)。verdict ∈ ok/deny/path_wrong/rate_limited/unexpected/unknown。

    只看平台业务码，不看 HTTP 状态——DASCTF 家族用 200 + code 表达业务错误。
    """
    b = (body or "").replace(" ", "")
    for c in _CODE_DENY:
        if c in b:
            return "deny", "%s 鉴权失败（令牌无效/过期/无该赛事权限）" % c
    # HTTP 401 时响应体通常是空的，业务码里找不到 —— 必须按状态码兜住，
    # 否则「令牌坏」会被判成 unknown（测试 T3b 抓到的就是这个）。
    if http_status == 401:
        return "deny", "HTTP 401 未认证（令牌无效/过期）"
    for c in _CODE_OK:
        if c in b:
            return "ok", "%s 参数不全（端点存在、鉴权已通过）" % c
    if http_status == 404:
        return "path_wrong", "HTTP 404 路径错（平台/赛事/题号不对）"
    if http_status == 429:
        return "rate_limited", "HTTP 429 限流（端点存在）"
    if http_status == 400:
        return "ok", "HTTP 400 参数不全（端点存在、鉴权已通过）"
    if http_status is not None and 200 <= http_status < 300:
        return "unexpected", "HTTP %s 意外成功——探针不该提交成功，立即人工核查" % http_status
    return "unknown", "HTTP %s 无法判定：%s" % (http_status, (body or "")[:120])


def probe(url: str, headers: dict, timeout: float = 15.0) -> tuple[int | None, str]:
    """发一次空体 POST。网络异常归 None，绝不谎报红绿。"""
    req = urllib.request.Request(url, data=PROBE_BODY.encode("utf-8"),
                                 headers=headers, method="POST")
    # 显式绕代理：只连平台，别被 HTTP_PROXY 劫持（2026-10-24 实锤过的坑）
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(2048).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read(2048).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return exc.code, ""
    except Exception as exc:  # noqa: BLE001
        return None, "网络异常：%s" % exc


def token_for(platform: str, env: dict | None = None) -> str:
    env = os.environ if env is None else env
    if platform == "ctf2":
        return (env.get("CTF2_AGENT_TOKEN") or "").strip()
    return (env.get("CTF_AGENT_PLATFORM_TOKEN") or env.get("DASCTF_TOKEN") or "").strip()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="提交通道探针（不发任何 flag）")
    ap.add_argument("--platform", choices=("ctf2", "dasctf"), required=True)
    ap.add_argument("--base-url", default="")
    ap.add_argument("--competition", default="")
    ap.add_argument("--stage", default="")
    ap.add_argument("--challenge", default="")
    ap.add_argument("--dry-run", action="store_true", help="只打印将要发的请求，不联网")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        url = build_url(args.platform, base_url=args.base_url,
                        competition=args.competition, stage=args.stage,
                        challenge=args.challenge)
    except ValueError as exc:
        print("[FAIL] %s" % exc, file=sys.stderr)
        return 2

    token = token_for(args.platform)
    if not token:
        print("[FAIL] 缺少令牌（ctf2 用 CTF2_AGENT_TOKEN；dasctf 用 "
              "CTF_AGENT_PLATFORM_TOKEN 或 DASCTF_TOKEN）", file=sys.stderr)
        return 2

    if args.dry_run:
        out = {"platform": args.platform, "url": url, "method": "POST",
               "body": PROBE_BODY, "token": "已设置（不显示）",
               "note": "dry-run：未联网；探针体为空 JSON，不可能提交成功"}
        print(json.dumps(out, ensure_ascii=False, indent=2) if args.json
              else "[dry-run] POST %s\n          体=%s  令牌=已设置" % (url, PROBE_BODY))
        return 0

    status, body = probe(url, build_headers(args.platform, token))
    verdict, detail = classify(status, body)

    if args.json:
        print(json.dumps({"platform": args.platform, "url": url, "http": status,
                          "verdict": verdict, "detail": detail}, ensure_ascii=False, indent=2))
    else:
        icon = {"ok": "✅", "deny": "❌", "path_wrong": "❌",
                "rate_limited": "⚠️", "unexpected": "🚨", "unknown": "⚠️"}[verdict]
        print("%s 提交通道 %s —— %s" % (icon, verdict, detail))

    return 0 if verdict == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
