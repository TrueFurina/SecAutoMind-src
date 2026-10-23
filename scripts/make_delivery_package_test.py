#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_delivery_package.py 的排除面回归 + 变异验证（不依赖 pytest，纯 stdlib）。

为什么需要这份测试（2026-10-24 实锤）
--------------------------------------
交付包的排除表此前只写了 `.workbuddy/`，而 AI 协作会话的记忆目录叫 `.workbuddy-ai/`。
`EXCLUDE_PATH_SUBSTR` 里的 `.workbuddy/` 是**带斜杠的子串**，匹配不到 `.workbuddy-ai/`；
`EXCLUDE_DIRS` 里也没有它 → `--list-only` 预览显示 `.workbuddy-ai` 与 `deliverables`
会被纳入交付包（2155 个文件）。

而 `.workbuddy-ai/memory/2026-10-22.md` 里明文记着赛事门户的手机号与密码
（为向用户解释「门户账号 ≠ Agent API 令牌」而写下的原值）。也就是说：
**下一次重打包就会把会话记忆连同凭证一起发给评委**，而 secret_guard 只按密钥形态匹配，
不会把中文语境里的"密码：xxx"判成密钥。这类洞只有"排除面测试"能锁。

覆盖用例
--------
    T1  `.workbuddy-ai` 及其子目录被排除（本次修复的核心）
    T2  `.workbuddy` 仍被排除（旧行为不能被改坏）
    T3  `internal/**` 不被排除（不能误杀源码）
    T4  `data/ctf_benchmark/**` 不被排除（测试资产例外，不能被 data/ 整棵剪掉）
    T5  `data/conversations.db` 被排除（运行数据）
    T6  `config.yaml` 被排除、`.env.example` 不被排除（例外表生效）
    T7  旧版本 Setup 被排除、当前版本 Setup 被纳入（版本同源规则）
    T8  **变异验证**：把 `.workbuddy-ai` 从 EXCLUDE_DIRS 摘掉 → T1 的判据必须转红
        （证明 T1 是被这条排除规则决定的，而不是恰好为真）

用法：
    python scripts/make_delivery_package_test.py
    echo $?     # 0 = 全部通过
"""
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import make_delivery_package as mdp  # noqa: E402

_results = []


def case(name, fn):
    try:
        ok, detail = fn()
    except Exception as exc:                      # 异常一律算失败，不许静默通过
        ok, detail = False, "异常：%r" % (exc,)
    _results.append((name, ok, detail))
    print("  [%s] %-58s %s" % ("PASS" if ok else "FAIL", name, detail))


def _expect(rel, want_excluded, checker=None):
    fn = checker or mdp.is_excluded_dir
    got = fn(rel)
    if got == want_excluded:
        return True, "excluded=%s（符合预期）" % got
    return False, "excluded=%s，期望 %s" % (got, want_excluded)


def t1_agent_state():
    """核心用例：agent 记忆目录必须被排除（含子目录）。"""
    for rel in (".workbuddy-ai", ".workbuddy-ai/memory", ".workbuddy-ai/memory/automations"):
        ok, detail = _expect(rel, True)
        if not ok:
            return False, "%s → %s" % (rel, detail)
    # 直接断言排除表里真的有这一条：删掉它时这条用例必须红，且信息可定位
    if ".workbuddy-ai" not in mdp.EXCLUDE_DIRS:
        return False, "EXCLUDE_DIRS 缺少 '.workbuddy-ai' 条目"
    return True, "3 个路径被排除 + 排除表含该条目"


def t2_old_workbuddy():
    return _expect(".workbuddy/memory/x.md", True)


def t3_source_kept():
    return _expect("internal/vision/preprocess.go", False)


def t4_benchmark_kept():
    """data/ 被整棵剪掉，测试资产靠 INCLUDE_PATH_EXCEPTIONS 单独补进包。

    注意不能直接拿 is_excluded_dir 判 data/ctf_benchmark —— 它命中的正是 `data`
    这条目录规则（返回 True），真正让基准集进包的是例外表 + build_staging 的第二段 walk。
    故这里断言的是「例外表含该路径」且「该目录真实存在」（否则例外是空的、等于没纳入）。
    """
    if "data/ctf_benchmark" not in mdp.INCLUDE_PATH_EXCEPTIONS:
        return False, "INCLUDE_PATH_EXCEPTIONS 缺少 data/ctf_benchmark"
    exc_abs = os.path.join(mdp.ROOT, "data", "ctf_benchmark")
    if not os.path.isdir(exc_abs):
        return False, "例外目录不存在（例外表形同虚设）：%s" % exc_abs
    if not mdp.is_excluded_dir("data/ctf_benchmark"):
        return False, "data/ 未被整棵剪掉 → 运行数据会顺带进包"
    return True, "例外表含该路径 + 目录存在 + data/ 仍被剪掉"


def t5_runtime_data():
    return _expect("data/conversations.db", True)


def t6_config_rules():
    ok1, d1 = _expect("config.yaml", True, mdp.is_excluded_file)
    ok2, d2 = _expect(".env.example", False, mdp.is_excluded_file)
    return (ok1 and ok2), "config.yaml:%s / .env.example:%s" % (d1, d2)


def t7_setup_versions():
    ver = mdp._current_ver_bare()
    cur = "installer/SecAutoMind-Setup-%s-x64.exe" % ver
    old = "installer/SecAutoMind-Setup-0.0.1-x64.exe"
    ok1, d1 = _expect(cur, False, mdp.is_excluded_file)
    ok2, d2 = _expect(old, True, mdp.is_excluded_file)
    return (ok1 and ok2), "当前版纳入 / 旧版排除（ver=%s）" % ver


def t8_mutation():
    """变异验证：摘掉排除条目后，T1 的判据必须转红。"""
    saved = set(mdp.EXCLUDE_DIRS)
    try:
        mdp.EXCLUDE_DIRS.discard(".workbuddy-ai")
        leaked = not mdp.is_excluded_dir(".workbuddy-ai/memory")
    finally:
        mdp.EXCLUDE_DIRS.clear()
        mdp.EXCLUDE_DIRS.update(saved)
    if not leaked:
        return False, "摘掉条目后仍被判排除 → 说明 T1 不是被该规则决定的（空洞绿）"
    # 恢复后必须重新为真
    if not mdp.is_excluded_dir(".workbuddy-ai/memory"):
        return False, "恢复排除表后仍未被排除"
    return True, "摘掉→泄漏可复现；恢复→重新被排除"


def main():
    print("=" * 70)
    print("make_delivery_package 排除面回归 + 变异验证")
    print("=" * 70)
    case("T1 agent 记忆目录 .workbuddy-ai 被排除", t1_agent_state)
    case("T2 .workbuddy 仍被排除", t2_old_workbuddy)
    case("T3 源码 internal/** 不被排除", t3_source_kept)
    case("T4 测试资产 data/ctf_benchmark 不被排除", t4_benchmark_kept)
    case("T5 运行数据 data/*.db 被排除", t5_runtime_data)
    case("T6 config.yaml 排除 / .env.example 例外", t6_config_rules)
    case("T7 Setup 版本同源规则", t7_setup_versions)
    case("T8 变异：摘掉条目后必须泄漏", t8_mutation)

    failed = [n for n, ok, _ in _results if not ok]
    print("-" * 70)
    print("  合计 %d 用例，通过 %d，失败 %d"
          % (len(_results), len(_results) - len(failed), len(failed)))
    if failed:
        for n in failed:
            print("  [FAIL] %s" % n)
        return 1
    print("  [PASS] 排除面回归 + 变异验证全过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
