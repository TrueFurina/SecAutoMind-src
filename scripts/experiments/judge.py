#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实验判分器：把一次推演的产出，对照 ground truth 计算客观指标。

⚠️ 诚实口径声明（重要，勿删）：
  本判分器采用**关键词匹配**判定"是否发现某漏洞/是否识别某指纹"，属于**保守判据**：
  - 命中 = 文本中出现了对应关键词（可能漏判：结论正确但措辞不同 → 记为未命中，低估）
  - 未命中 ≠ 平台没发现，只代表"文本里没出现这个词"
  因此本判分器得出的准确率是**保守下界**。
  所有原始 final_text 均完整落盘，供人工逐条复核（见 evidence JSON）。

用法（自检判分逻辑）：
    python scripts/experiments/judge.py --selftest
"""

from __future__ import annotations

import json
import re
from typing import Any

# ── 环境类型判据（命中任一关键词即算识别为该类型）──
ENV_PATTERNS = {
    "Web 应用": [r"web\s*应用", r"web\s*服务", r"web\s*站点", r"http", r"网站"],
    "API 服务": [r"api\s*服务", r"api\s*接口", r"rest\s*api", r"api\s*server"],
    "Linux 主机": [r"linux", r"ubuntu", r"centos", r"debian"],
    "Windows 主机": [r"windows", r"win\s*server"],
}

# ── 指纹判据 ──
FINGERPRINT_PATTERNS = {
    "Apache": [r"apache"],
    "PHP": [r"php"],
    "nginx": [r"nginx"],
    "OpenSSH": [r"openssh"],
    "vsFTPd": [r"vsftpd"],
    "Redis": [r"redis"],
}

# ── 漏洞判据（每条漏洞对应一组"出现在结论里即可认定发现"的关键词）──
VULN_PATTERNS = {
    # S1
    "S1-01": [r"弱口令", r"weak\s*password", r"admin[/ ]?admin", r"默认口令", r"默认密码"],
    "S1-02": [r"sql\s*注入", r"sqli", r"sql\s*injection", r"' or '1'='1", r"注入点"],
    "S1-03": [r"xss", r"跨站脚本", r"反射型", r"script>alert"],
    "S1-04": [r"目录遍历", r"路径遍历", r"path\s*traversal", r"directory\s*traversal", r"\.\./"],
    "S1-05": [r"\.git", r"git\s*泄露", r"源码泄露", r"source\s*(code\s*)?disclosure", r"git\s*config"],
    "S1-06": [r"robots\.txt", r"robots"],
    # S2
    "S2-01": [r"未授权", r"unauthorized", r"无需认证", r"未鉴权", r"越权访问"],
    "S2-02": [r"postgres://", r"连接串", r"debug", r"信息泄露", r"information\s*disclosure"],
    "S2-03": [r"jwt", r"弱密钥", r"weak\s*(signing\s*)?key", r"签名密钥"],
    "S2-04": [r"metrics", r"prometheus", r"监控指标", r"运维指标"],
    # S3
    "S3-01": [r"openssh[_\s]*7\.4", r"ssh.*banner", r"ssh\s*版本", r"banner.*泄露"],
    "S3-02": [r"redis.*未授权", r"未授权.*redis", r"redis", r"\+pong"],
    "S3-03": [r"vsftpd[_\s]*3", r"ftp.*banner", r"ftp\s*版本"],
    "S3-04": [r"permitrootlogin", r"root\s*登录", r"root\s*login", r"配置错误", r"misconfig"],
}


def _match_any(text: str, patterns: list[str]) -> bool:
    t = text.lower()
    for p in patterns:
        if re.search(p, t, re.IGNORECASE):
            return True
    return False


def judge_run(result: dict, scenario: dict) -> dict:
    """对单次推演结果判分。

    Args:
        result: sam_client.run_agent() 的返回
        scenario: GROUND_TRUTH["scenarios"][sid]

    Returns:
        判分明细（含逐条命中情况，可人工复核）
    """
    # 判分文本 = 最终结论 + 工具结果预览 + HITL 裁决理由（裁决理由里常含工具真实输出）
    parts = [result.get("final_text") or ""]
    for tc in result.get("tool_calls", []):
        if tc.get("preview"):
            parts.append(str(tc["preview"]))
    for h in result.get("hitl_decisions", []):
        if h.get("comment"):
            parts.append(str(h["comment"]))
    text = "\n".join(parts)

    # 1) 环境类型识别
    exp_env = scenario.get("env_type_expected", "")
    env_ok = None
    if exp_env:
        # 期望值可能含 "/"（如 "Web 应用 / API 服务"），命中主类型即算对
        primary = exp_env.split("/")[0].strip()
        pats = ENV_PATTERNS.get(primary) or [re.escape(primary)]
        env_ok = _match_any(text, pats)

    # 2) 指纹识别
    fp_expected = scenario.get("fingerprints_expected", [])
    fp_hit = [fp for fp in fp_expected if _match_any(text, FINGERPRINT_PATTERNS.get(fp, [re.escape(fp)]))]
    fp_miss = [fp for fp in fp_expected if fp not in fp_hit]

    # 3) 漏洞发现（逐条判据，保留明细供复核）
    vulns = scenario.get("vulns_expected", [])
    vuln_detail = []
    for v in vulns:
        vid = v["id"]
        pats = VULN_PATTERNS.get(vid, [re.escape(v["name"])])
        hit = _match_any(text, pats)
        vuln_detail.append({
            "id": vid, "name": v["name"], "type": v["type"], "hit": hit,
        })
    v_hit = [d for d in vuln_detail if d["hit"]]

    total_v = len(vulns)
    total_fp = len(fp_expected)

    return {
        "env_type_expected": exp_env,
        "env_type_hit": env_ok,
        "fingerprint_expected": total_fp,
        "fingerprint_hit": len(fp_hit),
        "fingerprint_hit_list": fp_hit,
        "fingerprint_miss_list": fp_miss,
        "fingerprint_accuracy": round(len(fp_hit) / total_fp, 4) if total_fp else None,
        "vuln_expected": total_v,
        "vuln_found": len(v_hit),
        "vuln_recall": round(len(v_hit) / total_v, 4) if total_v else None,
        "vuln_detail": vuln_detail,
        "closed_loop": bool(result.get("finalized")),
        "tool_call_count": result.get("tool_call_count", 0),
        "tool_names": result.get("tool_names", []),
        "duration_ms": result.get("duration_ms", 0),
        "hitl_count": result.get("hitl_count", 0),
        "error": result.get("error"),
        "_judged_text_len": len(text),
    }


# ── 判分逻辑自检：用构造样本验证判据不会明显错判 ──
def selftest() -> int:
    sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0])
    from target_range import GROUND_TRUTH

    cases = [
        ("标准正向样本",
         {"final_text": "目标为 Web 应用，服务器 Apache/2.4.41，后端 PHP/7.4.33。"
                        "发现 SQL 注入（' or '1'='1 可绕过登录）、反射型 XSS、"
                        "目录遍历 ../private/db_credentials.txt、.git 源码泄露、robots.txt 泄露 /admin、"
                        "登录弱口令 admin/admin。",
          "tool_calls": [], "hitl_decisions": []},
         "S1"),
        ("空输出（应全不命中）",
         {"final_text": "", "tool_calls": [], "hitl_decisions": []},
         "S1"),
        ("S3 主机场景",
         {"final_text": "Linux 主机，发现 OpenSSH_7.4 banner 泄露版本，vsFTPd 3.0.3，"
                        "Redis 未授权访问（PING 返回 +PONG），且 PermitRootLogin yes 配置错误。",
          "tool_calls": [], "hitl_decisions": []},
         "S3"),
    ]

    ok = True
    for name, result, sid in cases:
        sc = GROUND_TRUTH["scenarios"][sid]
        j = judge_run(result, sc)
        print(f"\n--- {name} [{sid}] ---")
        print(f"  环境识别命中: {j['env_type_hit']}  指纹 {j['fingerprint_hit']}/{j['fingerprint_expected']}"
              f"  漏洞 {j['vuln_found']}/{j['vuln_expected']}  recall={j['vuln_recall']}")
        if name.startswith("空输出") and (j["vuln_found"] != 0 or j["fingerprint_hit"] != 0):
            print("  ❌ 空输出不应命中任何项"); ok = False
        if name.startswith("标准正向") and j["vuln_found"] < 5:
            print(f"  ❌ 标准样本应命中多数漏洞，实际仅 {j['vuln_found']}"); ok = False
        if name.startswith("S3") and j["vuln_found"] < 3:
            print(f"  ❌ S3 样本应命中多数漏洞，实际仅 {j['vuln_found']}"); ok = False

    print("\n" + ("✅ 判分逻辑自检通过" if ok else "❌ 判分逻辑存在缺陷"))
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    print(__doc__)
