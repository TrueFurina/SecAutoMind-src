#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""secret_guard 自身回归测试 —— 防止密钥门禁悄悄退化。

背景（2026-09-08 实锤）：
    旧的打包前门禁是 `grep -E "sk-[A-Za-z0-9]{16,}"`，匹配不到 `sk-ws-H.xxx`
    （第 4 位是连字符即断匹配），一把真实存活的千问 key 正是从这个洞漏过去，
    而门禁却一直输出 CLEAN。**失效的门禁比没有门禁更危险** —— 它给的是虚假安全感。

背景（2026-09-13 第二次实锤，更严重）：
    修好正则后，门禁仍有第二层洞：`is_placeholder` 把 `...` 当作**无条件**占位特征。
    于是人工打码后的真 key 片段（`sk-ws-<真前缀>...`）被文档作者当成"已脱敏"写进
    `docs/`，门禁判其为占位符放行 —— 真 key 前 29 字符随交付包发给了评委。
    同时 `SELF_EXEMPT` 整体豁免 `secret_guard_test.py`，而该文件里恰好被写进了**两枚真凭证**。
    教训：① 打码串是"真 key 曾被写进文件"的证据，必须报警而非豁免；
          ② 豁免会腐化，被豁免的文件没人再看；
          ③ 门禁必须加"真 key 指纹反查"（见 secret_guard.load_real_fingerprints），
             直接比对是否含本项目在用的凭证片段，不依赖正则形态。

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
     "api_key: sk-ws-AB12CD34.EF56GH78.IJ90KL12MN34OP56QR78"),
    ("标准 OpenAI 式 key", "api_key: sk-abcdefghijklmnopqrstuvwxyz123456"),
    ("AWS Access Key", "aws_key: AKIAIOSFODNN7REALKEY12"),
    ("GitHub Personal Token", "token: ghp_abcdefghijklmnopqrstuvwxyz012345"),
    ("飞书 app_secret", 'app_secret: Zq12Wx34Er56Ty78Ui90Op12As34Df56'),
    ("PEM 私钥", "key: -----BEGIN RSA PRIVATE KEY-----"),
    ("Slack Bot Token", "slack: xoxb-1234567890-abcdefghijklmnop"),
    # ⚠️ 2026-09-13 新增：交付包里真 key 以「打码截断」形态泄露，旧版因 `...` 无条件豁免而漏检。
    #    样本一律用构造值（与真 key 零公共前缀），避免门禁测试自己成为泄露源。
    ("打码截断的凭证片段（省略号不得再豁免）",
     "doc: 真实存活的 key：`sk-ws-AB12CD34.EF56GH78.IJ90K...`"),
    ("app_secret 短打码片段（8 字符 + 省略号，旧版盲区）",
     "doc: 真实 app_secret: Zq12Wx34..."),
]

MUST_IGNORE = [
    ("占位符 xxxxxxx", "app_secret: sk-xxxxxxx"),
    ("下划线占位", "api_key: ${OPENAI_API_KEY}"),
    ("显式示例", "api_key: sk-EXAMPLE-KEY-REPLACE-ME"),
    ("AWS 官方示例值", "aws: AKIAIOSFODNN7EXAMPLE"),
    ("CTF 真题 flag（形似凭证）", 'flag: "picoCTF{@sk_th3_1nt3rn_81e716ff}"'),
    ("中文占位提示", "api_key: 请填写你的密钥"),
    ("fake 标记测试值", "key: sk-fake-key-for-unit-test-only"),
    # 2026-09-13：app_secret 正则放宽到 8 字符后，纯数字与普通省略号不得误报
    ("纯数字 app_secret（非凭证）", "app_secret: 12345678"),
    ("普通省略号（不像凭证）", "note: 配置见 config 后续 ... 小节"),
    # 2026-09-13：放宽后必须仍排除 JS 取值写法（settings.js 曾因此被误报为 BLOCK）
    ("JS 取值写法（非凭证）",
     "app_secret: document.getElementById('robot-lark-app-secret')?.value.trim() || ''"),
]


def classify(content):
    """直接走「模式匹配 → 分类」逻辑，不经过 scan_dir。

    原因：本测试文件内嵌了形似真凭证的**构造样本**（必须如此才能验证检出能力），
    若用 scan_dir 全盘扫描，门禁会把它自己写成的数据报成 BLOCK（自指死锁），
    因此门禁侧对该文件做了精确豁免；而测试本身要验证的正是「分类逻辑是否还灵」，
    必须绕过该豁免，直接对 PATTERNS + 判占位逻辑做单元级断言。

    ⚠️ 2026-09-13：样本**必须**是构造值。历史上这里曾内嵌两枚真凭证
    （千问 key 前 56 字符、飞书 app_secret 完整 32 字符），因为"反正是公开测试向量"
    的错觉 —— 结果它们进了 git 历史与公开仓库。绝不再犯。
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
            failures.append("误报为真实凭证: %s -> %s" % (label, secret_guard.mask(real[0][1])))

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
