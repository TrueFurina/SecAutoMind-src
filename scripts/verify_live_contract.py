#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DASCTF 官方仿真平台「成功契约」一键验证（拿到有效 Agent Key 后运行）。

为什么存在：
  2026-10-05 只读探测（见 docs/zh-CN/competition-2026/真机联调记录_20261005.md）已证明
  网络可达 / 端点路径正确 / 鉴权方式正确 / Token 被平台识别身份 四项成立，但当时 Token
  无权限（40403），成功响应的**真实结构无法验证**。代码侧（internal/ctfplatform/dasctf.go）
  对成功契约的判据目前只靠「真源 golden + httptest 仿真」两条证据支撑，真机仍未验。

  本脚本把「成功契约」固化成可机验清单，凭证到位后一键跑，逐项 PASS / FAIL / SKIP。
  退出码：0 = 全部通过；1 = 有 FAIL 或缺凭证；2 = 全部 SKIP（说明还是 40403，权限仍未开通）；
          3 = 冻结期（2027-03-01 前，Agent Key 决赛现场才发放，见 FREEZE_UNTIL）。

安全：
  - 凭证只从环境变量 DASCTF_BASE_URL / DASCTF_TOKEN 读，命令历史与输出均不落明文；
  - 默认只跑**只读**接口（overview / 题目列表 / 题目详情），零副作用；
  - 写入接口（起靶机 / 提交 flag / 回收靶机）必须显式 `--full` 才跑。

用法：
  python scripts/verify_live_contract.py            # 只读契约
  python scripts/verify_live_contract.py --full     # 含写入契约（起靶机+提交+回收）
"""
import argparse
import datetime
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "Chrome/126.0 Safari/537.36")
BASE = os.environ.get("DASCTF_BASE_URL", "").rstrip("/")
TOKEN = os.environ.get("DASCTF_TOKEN") or os.environ.get("CTF_AGENT_PLATFORM_TOKEN")
PREFIX = "/slab-match/api/v1/agent"

# 时间锁（用户 2026-10-18 拍板）：Agent Key 仅决赛现场发放，此前本脚本冻结不可跑，
# 防止提前拿到临时凭证时误触发真机请求、也防止此事项被反复催办。到期自动解封。
FREEZE_UNTIL = datetime.date(2027, 3, 1)

ENDPOINTS = {
    "overview": "/answer-panel/overview",
    "challenges": "/ctf/exercise-list",
    "challenge_detail": "/ctf/exercise",
    "build_env": "/ctf/build-exercise-env",
    "submit": "/answer-panel/answer",
    "recover_env": "/ctf/recover-exercise-env",
}

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print("  [%s] %s%s" % (mark, name, (" — " + detail) if detail else ""))


def call(method, endpoint_key, body=None, params=None):
    """走与 dasctf.go 完全一致的请求头，返回 (http_status, business_code, raw_dict)。"""
    path = PREFIX + ENDPOINTS[endpoint_key]
    if params:
        path += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(
        BASE + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "X-Agent-AccessKey": TOKEN,
            "Content-Type": "application/json",
            "User-Agent": UA,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, None, json.loads(raw)
    except urllib.error.HTTPError as e:
        return e.code, None, None
    except Exception as e:  # 网络/超时
        return None, None, {"__error__": str(e)}


def code_of(d):
    if not isinstance(d, dict):
        return None
    return str(d.get("code", ""))


def main():
    ap = argparse.ArgumentParser(description="DASCTF 成功契约真机验证")
    ap.add_argument("--full", action="store_true",
                    help="含写入契约（起靶机→提交 flag→回收），有真实副作用")
    args = ap.parse_args()

    # 时间锁：2027-03-01 前冻结（Agent Key 决赛现场才有）。rc=3 = 冻结期，不是故障。
    if datetime.date.today() < FREEZE_UNTIL:
        print("FROZEN: 真机联调验证冻结至 %s（Agent Key 仅决赛现场发放，用户 2026-10-18 拍板）。"
              % FREEZE_UNTIL.isoformat())
        print("  到期后运行：export DASCTF_BASE_URL=https://pro.dasctf.com")
        print("             export DASCTF_TOKEN=<现场 Agent Key>")
        print("             python scripts/verify_live_contract.py [--full]")
        return 3

    if not BASE or not TOKEN:
        print("FATAL: 缺少 DASCTF_BASE_URL / DASCTF_TOKEN 环境变量。")
        print("  先 export DASCTF_BASE_URL=https://pro.dasctf.com")
        print("  export DASCTF_TOKEN=<Agent Key>   # 只从环境变量读，不落盘")
        return 1

    print("平台: %s  Token: %s…（脱敏）" % (BASE, TOKEN[:4] + "…"))
    print("-" * 60)

    # ── 只读契约（零副作用）───────────────────────────────────────────
    print("一、只读契约（零副作用）")

    # 1. overview：验证 code=="00000"
    st, _, d = call("GET", "overview")
    if st == 200 and code_of(d) == "00000":
        record("overview 成功（code==00000）", True,
               "data 键：%s" % sorted(d.get("data", {}).keys()) if isinstance(d.get("data"), dict) else "")
    elif st == 200 and code_of(d) == "40403":
        record("overview 成功（code==00000）", False, "仍 40403 无权操作 —— Agent Key 未开通")
    else:
        record("overview 成功（code==00000）", False, "HTTP=%s code=%s" % (st, code_of(d)))

    # 2. 题目列表：验证 code=="00000" + 嵌套展平结构（flattenChallenges 契约）
    st, _, d = call("GET", "challenges")
    data = d.get("data") if isinstance(d, dict) else None
    if st == 200 and code_of(d) == "00000":
        if isinstance(data, list):
            record("题目列表展平（data 是平铺 list）", True, "%d 题" % len(data))
        elif isinstance(data, dict):
            # 真源 golden 显示平台可能用 {"corpus":[...]} 嵌套 —— flattenChallenges 要能展开
            record("题目列表展平（data 是平铺 list）", False,
                   "data 是 dict，键 %s —— 若含 corpus 嵌套需复核 flattenChallenges" % sorted(data.keys()))
        else:
            record("题目列表展平（data 是平铺 list）", False, "data 类型 %s" % type(data).__name__)
    elif st == 200 and code_of(d) == "40403":
        record("题目列表展平（data 是平铺 list）", False, "仍 40403 —— 权限未开通")
    else:
        record("题目列表展平（data 是平铺 list）", False, "HTTP=%s code=%s" % (st, code_of(d)))

    # 3. 题目详情：验证 exerciseId 数值型 + 附件字段名（extractAttachmentURLs 契约）
    first_id = None
    if isinstance(data, list) and data:
        first = data[0]
        first_id = first.get("id") or first.get("exerciseId") or first.get("code")
    if first_id is not None:
        st, _, dd = call("GET", "challenge_detail", params={"exerciseId": first_id})
        if st == 200 and code_of(dd) == "00000":
            dd_data = dd.get("data") if isinstance(dd, dict) else None
            att_keys = [k for k in ("attachment", "attachments", "file", "url",
                                    "downloadUrl", "src", "file_url") if dd_data and k in dd_data]
            record("题目详情成功 + 附件字段名", True,
                   "题 %s；附件字段命中：%s" % (first_id, att_keys or "无（该题可能无附件）"))
        elif st == 200 and code_of(dd) == "40403":
            record("题目详情成功 + 附件字段名", False, "仍 40403")
        else:
            record("题目详情成功 + 附件字段名", False, "HTTP=%s code=%s" % (st, code_of(dd)))
    else:
        record("题目详情成功 + 附件字段名", False, "列表无题目，无法取 exerciseId（可能真的没题，也可能列表展平失败）")

    # ── 写入契约（--full 才跑，有真实副作用）──────────────────────────
    if args.full and first_id is not None:
        print("\n二、写入契约（--full，有真实副作用）")

        # 4. 起靶机：验证 endpoints[].exposeIps[0] 靶机地址格式
        st, _, dd = call("POST", "build_env", body={"exerciseId": int(first_id) if str(first_id).isdigit() else first_id})
        if st == 200 and code_of(dd) == "00000":
            ddata = dd.get("data") if isinstance(dd, dict) else {}
            eps = ddata.get("endpoints") or []
            ip = None
            for e in eps:
                ips = e.get("exposeIps") or []
                if ips:
                    ip = ips[0]
                    break
            record("起靶机 + 靶机地址 exposeIps[0]", ip is not None,
                   "地址=%s" % ip if ip else "endpoints 为空或 exposeIps 缺失 —— extractAccess 契约需复核")
        elif st == 200 and code_of(dd) == "40403":
            record("起靶机 + 靶机地址 exposeIps[0]", False, "仍 40403")
        else:
            record("起靶机 + 靶机地址 exposeIps[0]", False, "HTTP=%s code=%s" % (st, code_of(dd)))

        # 5. 提交 flag：验证 code=="00000" + data.isCorrect==true
        #    注意：真实 flag 未知，这里只验证「错误 flag 的失败契约」——提交一个必错的占位符，
        #    期望 code=="00000" 且 isCorrect==false（证明判分通路打通，而非误报满分）。
        st, _, sd = call("POST", "submit", body={"exerciseId": int(first_id) if str(first_id).isdigit() else first_id,
                                                 "flag": "verification_placeholder_not_a_real_flag"})
        if st == 200 and code_of(sd) == "00000":
            sdata = sd.get("data") if isinstance(sd, dict) else {}
            record("提交判分通路（错误 flag 应 isCorrect=false）",
                   sdata.get("isCorrect") is False,
                   "isCorrect=%s" % sdata.get("isCorrect"))
        elif st == 200 and code_of(sd) == "40403":
            record("提交判分通路（错误 flag 应 isCorrect=false）", False, "仍 40403")
        else:
            record("提交判分通路（错误 flag 应 isCorrect=false）", False, "HTTP=%s code=%s" % (st, code_of(sd)))

        # 6. 回收靶机
        st, _, rd = call("POST", "recover_env", body={"exerciseId": int(first_id) if str(first_id).isdigit() else first_id})
        if st == 200 and code_of(rd) == "00000":
            record("回收靶机（code==00000）", True, "")
        else:
            record("回收靶机（code==00000）", False, "HTTP=%s code=%s" % (st, code_of(rd)))

    print("-" * 60)
    fails = [(n, d) for n, ok, d in RESULTS if not ok]
    all_40403 = bool(fails) and all("40403" in d for _, d in fails)
    # 全部 FAIL 且都因 40403 → 权限仍未开通，与「代码契约错」区分
    if all_40403:
        print("结论：%d 项全部未通过，且均因 40403 —— 极可能是 Agent Key 仍未开通。" % len(fails))
        print("  这是**外部动作**：先确认 Key 是否开通 / 是否属本队本场次，再重跑本脚本。")
        return 2
    if fails:
        print("结论：%d/%d 项未通过 —— 代码契约与真机响应不一致，按输出逐项修 dasctf.go。" %
              (len(fails), len(RESULTS)))
        for n, d in fails:
            print("  · %s：%s" % (n, d))
        return 1
    print("结论：%d/%d 项全部通过 —— 成功契约在真机确认，自动化链可参赛。" % (len(RESULTS), len(RESULTS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
