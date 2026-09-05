#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI 通道可用性与余额实测探针（零第三方依赖，仅用 urllib）。

用途：实验因某通道 402 欠费中断时，快速定位「哪些通道此刻真能调通」，
避免把不同能力档模型的实验数据混在同一口径下统计（数字必须同质）。

用法：
    python scripts/experiments/probe_channels.py
    python scripts/experiments/probe_channels.py --json docs/evidence/channel-probe-<date>.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CONFIG = os.path.join(ROOT, "config.yaml")
DEFAULT_OUT = os.path.join(ROOT, "docs", "evidence")

PROBE_MSG = [{"role": "user", "content": "只回复两个字：OK"}]


def expand_env(s: str) -> str:
    """展开 ${VAR} / ${VAR:-default}，与平台 internal/config/envexpand.go 语义一致。

    config.yaml 的 api_key 已零明文化为环境变量引用，探测前必须先展开。
    """
    if not s or "${" not in s:
        return s
    out = []
    i = 0
    while i < len(s):
        idx = s.find("${", i)
        if idx < 0:
            out.append(s[i:])
            break
        out.append(s[i:idx])
        end = s.find("}", idx + 2)
        if end < 0:
            out.append(s[idx:])
            break
        expr = s[idx + 2:end]
        i = end + 1
        var, sep, default = expr.partition(":-")
        val = os.getenv(var, "")
        if val == "" and sep:
            val = default
        out.append(val)
    return "".join(out)


def load_channels(path: str) -> dict:
    """极简 YAML 读取：只抽 ai.channels.<id> 下的 name/base_url/api_key/model。"""
    chans: dict[str, dict] = {}
    cur = None
    in_channels = False
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if re.match(r"^ai:\s*$", line):
                continue
            # 注意：channels 在 ai: 之下，带两空格缩进，正则必须允许缩进
            if re.match(r"^\s*channels:\s*$", line):
                in_channels = True
                cur = None
                continue
            if not in_channels:
                continue
            # 通道 id：4 空格缩进的 `key:`
            m = re.match(r"^    ([A-Za-z0-9_.\-]+):\s*$", line)
            if m:
                cur = m.group(1)
                chans[cur] = {}
                continue
            # 通道字段：6 空格缩进
            m = re.match(r"^      ([A-Za-z0-9_]+):\s*(.*)$", line)
            if m and cur is not None:
                chans[cur][m.group(1)] = m.group(2).strip().strip('"').strip("'")
                continue
            # 遇到退回 4 空格以下的块（如注释段/新顶层键）则退出
            if re.match(r"^\S", line) or re.match(r"^  [A-Za-z0-9_#]", line):
                if cur is not None and not line.startswith("      "):
                    in_channels = False
    return chans


def probe(chan_id: str, cfg: dict, timeout: int = 25) -> dict:
    base = (cfg.get("base_url") or "").rstrip("/")
    key = expand_env(cfg.get("api_key") or "")
    model = cfg.get("model") or ""
    name = cfg.get("name") or chan_id
    res = {
        "id": chan_id,
        "name": name,
        "model": model,
        "base_url": base,
        "ok": False,
        "http": None,
        "latency_ms": None,
        "reply": None,
        "error": None,
    }
    if not (base and key and model):
        res["error"] = "配置缺失(base_url/api_key/model)"
        return res
    url = base + "/chat/completions"
    body = json.dumps({
        "model": model,
        "messages": PROBE_MSG,
        "max_tokens": 16,
        "temperature": 0,
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {key}"},
        method="POST",
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            res["http"] = resp.status
            payload = json.loads(resp.read().decode("utf-8", "replace"))
            res["reply"] = (payload.get("choices") or [{}])[0].get(
                "message", {}).get("content", "")
            res["ok"] = True
    except urllib.error.HTTPError as e:
        res["http"] = e.code
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        res["error"] = f"HTTP {e.code}: {detail}"
    except Exception as e:  # noqa: BLE001
        res["error"] = f"{type(e).__name__}: {e}"
    finally:
        res["latency_ms"] = int((time.time() - t0) * 1000)
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=CONFIG)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--timeout", type=int, default=25)
    args = ap.parse_args()

    chans = load_channels(args.config)
    if not chans:
        print("未解析到任何通道，检查 config.yaml 缩进", file=sys.stderr)
        return 2

    results = []
    print(f"探测 {len(chans)} 个通道 ...", flush=True)
    for cid, cfg in chans.items():
        r = probe(cid, cfg, args.timeout)
        results.append(r)
        flag = "OK " if r["ok"] else "FAIL"
        err = "" if r["ok"] else f"  <- {r['error']}"
        print(f"  [{flag}] {cid:12s} {r['model']:28s} "
              f"{r['latency_ms']:>6}ms{err}", flush=True)

    ok = [r for r in results if r["ok"]]
    os.makedirs(args.out, exist_ok=True)
    day = datetime.now().strftime("%Y%m%d")
    payload = {
        "probed_at": datetime.now().isoformat(timespec="seconds"),
        "config": os.path.relpath(args.config, ROOT),
        "channels_total": len(results),
        "channels_ok": len(ok),
        "note": ("通道能力档不同质——跨通道的实验数据必须分层标注，"
                 "禁止合并统计同一指标。"),
        "results": results,
    }
    jpath = os.path.join(args.out, f"channel-probe-{day}.json")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"\n可用 {len(ok)}/{len(results)} → {jpath}")
    if ok:
        print("可用通道：" + ", ".join(f"{r['id']}({r['model']})" for r in ok))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
