#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""secret_guard 自身回归测试 —— 防止密钥门禁悄悄退化。

背景（2026-09-08 实锤）：
    旧的打包前门禁是 `grep -E "sk-[A-Za-z0-9]{16,}"`，匹配不到 `sk-ws-H.xxx`
    （第 4 位是连字符即断匹配），一把真实存活的千问 key 正是从这个洞漏过去，
    而门禁却一直输出 CLEAN。**失效的门禁比没有门禁更危险** —— 它给的是虚假安全感。

本测试锁定两类样本：
    - MUST_CATCH：必须判为真实凭证（漏检 = 门禁失效 = FAIL）
    - MUST_IGNORE：必须判为占位符/示例（误报 = 噪声淹没真实告警 = FAIL）

用法：
    python scripts/secret_guard_test.py
退出码：0 = 门禁健康；1 = 门禁已退化，必须修 scripts/secret_guard.py
"""
import os
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secret_guard  # noqa: E402


MUST_CATCH = [
    ("千问 ws 通道 key（旧正则漏检的元凶）",
     "api_key: sk-ws-H.PMPEYIE.i3jt.MEUCIQDcErArlfDsw3bWAXRKuvfcyiQf308"),
    ("标准 OpenAI 式 key", "api_key: sk-abcdefghijklmnopqrstuvwxyz123456"),
    ("AWS Access Key", "aws_key: AKIAIOSFODNN7REALKEY12"),
    ("GitHub Personal Token", "token: ghp_abcdefghijklmnopqrstuvwxyz012345"),
    ("飞书 app_secret", 'app_secret: 6jRyD35HaAbY8hen5zfeHHG8rUb6pTra'),
    ("PEM 私钥", "key: -----BEGIN RSA PRIVATE KEY-----"),
    ("Slack Bot Token", "slack: xoxb-1234567890-abcdefghijklmnop"),
]

MUST_IGNORE = [
    ("占位符 xxxxxxx", "app_secret: sk-xxxxxxx"),
    ("下划线占位", "api_key: ${OPENAI_API_KEY}"),
    ("显式示例", "api_key: sk-EXAMPLE-KEY-REPLACE-ME"),
    ("AWS 官方示例值", "aws: AKIAIOSFODNN7EXAMPLE"),
    ("CTF 真题 flag（形似凭证）", 'flag: "picoCTF{@sk_th3_1nt3rn_81e716ff}"'),
    ("中文占位提示", "api_key: 请填写你的密钥"),
    ("fake 标记测试值", "key: sk-fake-key-for-unit-test-only"),
]


def classify(content):
    """直接走「模式匹配 → 分类」逻辑，不经过 scan_dir / SELF_EXEMPT。

    原因：本测试文件内嵌了形似真凭证的样本，若用 scan_dir 全盘扫描，门禁会把它自己
    写成的数据报成 BLOCK（自指死锁），因此门禁侧对 `scripts/secret_guard_test.py`
    做了精确豁免；而测试本身要验证的正是「分类逻辑是否还灵」，必须绕过该豁免，
    直接对 PATTERNS + 判占位逻辑做单元级断言。
    """
    line_is_flag = bool(secret_guard.FLAG_LIKE.search(content))
    real = []
    for label, pat in secret_guard.PATTERNS:
        for m in pat.finditer(content):
            raw = m.group(1) if pat.groups and m.group(1) else m.group(0)
            if not (secret_guard.is_placeholder(raw) or line_is_flag):
                real.append((label, raw))
    return real


def main():
    failures = []

    print("=" * 62)
    print("secret_guard 门禁回归测试")
    print("=" * 62)

    print("\n[1/2] 必须检出（漏检 = 门禁失效）")
    for label, content in MUST_CATCH:
        real = classify(content)
        ok = len(real) > 0
        print("  %s %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            failures.append("未能检出真实凭证: %s" % label)

    print("\n[2/2] 必须豁免（误报 = 噪声淹没告警）")
    for label, content in MUST_IGNORE:
        real = classify(content)
        ok = len(real) == 0
        print("  %s %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            failures.append("误报为真实凭证: %s -> %s" % (label, real[0]["masked"]))

    print("\n" + "=" * 62)
    if failures:
        print("[FAIL] 密钥门禁已退化，必须修 scripts/secret_guard.py：")
        for f in failures:
            print("  - %s" % f)
        print("=" * 62)
        return 1
    print("[PASS] 密钥门禁健康：%d 类真实凭证全部可检出，%d 类占位符全部正确豁免。"
          % (len(MUST_CATCH), len(MUST_IGNORE)))
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
