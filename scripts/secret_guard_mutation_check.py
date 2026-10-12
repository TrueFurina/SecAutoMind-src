#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""密钥门禁的「变异验证」——证明 secret_guard_test.py 真的能杀死退化。

背景（2026-09-13 实锤）：
    门禁曾两次失效，两次都是「测试全绿但门禁已死」：
      · 2026-09-08：正则 `sk-[A-Za-z0-9]{16,}` 匹配不到 `sk-ws-H...`；
      · 2026-09-13：`is_placeholder` 把 `...` 当无条件占位特征，
                    于是真 key 的打码片段被放行、随交付包外发。
    教训：**"测试全绿"不等于"测试有效"**。必须主动把门禁改回错误行为，
    确认回归测试会红 —— 杀不死变异体的测试是摆设。

做法：
    1. 基线：跑 secret_guard_test.py，必须 rc=0；
    2. 注入变异：把 is_placeholder 的省略号分支改回「无条件放行」；
    3. 跑测试，必须 rc≠0（说明变异被捕获）；
    4. 无论成败，finally 恢复原文件；
    5. 恢复后再跑一次，必须 rc=0。

退出码：0 = 变异验证通过；1 = 测试无效或恢复失败。

用法：
    python scripts/secret_guard_mutation_check.py
"""
import os
import pathlib
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = pathlib.Path(__file__).resolve().parent.parent
SG = ROOT / "scripts" / "secret_guard.py"
TEST = ROOT / "scripts" / "secret_guard_test.py"
PY = sys.executable

GOOD = (
    '    if ELLIPSIS.search(value):\n'
    '        core = value.rstrip(".")\n'
    '        if CRED_PREFIX.match(core) and len(core) >= 12:\n'
    '            return False\n'
    '        return True'
)
MUTANT = (
    '    if ELLIPSIS.search(value):\n'
    '        return True'
)

# 变异 2（2026-09-13 深度复检新增）：最强防线缺席时的 fail-closed 被改回"静默放行"。
# 探针文本必须与 secret_guard.py 逐字一致；改结构时同步更新，否则本脚本会显式报 FAIL。
GOOD2 = '    fingerprint_block = fingerprint_degraded and not allow_no_fp'
MUTANT2 = '    fingerprint_block = False'

MUTATIONS = (
    ("省略号 -> 无条件豁免（复现 2026-09-13 泄露事故旧行为）", GOOD, MUTANT),
    ("指纹库为空 -> 静默放行（复现 09-13 复检发现的『防线缺席=通过』）", GOOD2, MUTANT2),
)


def run_test():
    r = subprocess.run([PY, str(TEST)], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", cwd=str(ROOT))
    return r.returncode, r.stdout or ""


def main():
    print("=" * 62)
    print("密钥门禁 · 变异验证（证明回归测试真的能杀死退化）")
    print("=" * 62)

    # 用二进制读入：文本模式 read_text 会做 universal-newlines 转换（CRLF→LF），
    # 若随后用 write_text 写回，Windows 下会把 LF 再转回 CRLF，等于静默改写换行符。
    # 而自检同样用 read_text 比较，三重对称转换会让「换行被改」永远检测不出来
    # （内容逐字相同，只有行尾变了 → line-endings-gate 才发现）。故全程走 bytes。
    orig_b = SG.read_bytes()
    orig = orig_b.decode("utf-8")
    missing = [name for name, good, _ in MUTATIONS if good not in orig]
    if missing:
        print("[FAIL] 未在 secret_guard.py 中找到探针原文：")
        for name in missing:
            print("       - %s" % name)
        print("       门禁结构已变，请同步更新本脚本的探针常量。")
        return 1

    ok = True

    print("\n[1/%d] 基线：回归测试应 PASS" % (len(MUTATIONS) + 2))
    rc, _ = run_test()
    print("  RC=%d  %s" % (rc, "PASS" if rc == 0 else "FAIL"))
    if rc != 0:
        ok = False

    idx = 2
    for name, good, mutant in MUTATIONS:
        step = "[%d/%d]" % (idx, len(MUTATIONS) + 2)
        idx += 1
        try:
            print("\n%s 注入变异：%s" % (step, name))
            SG.write_bytes(orig.replace(good, mutant).encode("utf-8"))
            rc_m, out_m = run_test()
            caught = rc_m != 0
            print("  RC=%d  %s" % (rc_m, "FAIL(✅ 变异被捕获)" if caught else "PASS(❌ 变异未被捕获 = 测试无效)"))
            if not caught:
                ok = False
                print("  测试输出尾部：")
                print("\n".join(out_m.splitlines()[-8:]))
        finally:
            print("  恢复原文件（finally 保证）")
            SG.write_bytes(orig_b)

    print("\n[%d/%d] 恢复后：回归测试应重新 PASS" % (len(MUTATIONS) + 2, len(MUTATIONS) + 2))
    rc_r, _ = run_test()
    print("  RC=%d  %s" % (rc_r, "PASS" if rc_r == 0 else "FAIL"))
    if rc_r != 0:
        ok = False

    # 完整性自检：文件内容必须与原文逐字节一致
    if SG.read_bytes() != orig_b:
        print("[FAIL] secret_guard.py 未恢复到原始内容！")
        ok = False

    print("\n" + "=" * 62)
    if ok:
        print("[PASS] 变异验证有效：基线绿 → 注入 %d 类旧行为均变红 → 恢复后复绿。" % len(MUTATIONS))
        print("=" * 62)
        return 0
    print("[FAIL] 密钥门禁的回归测试无效或恢复失败，必须修 scripts/secret_guard.py。")
    print("=" * 62)
    return 1


if __name__ == "__main__":
    sys.exit(main())
