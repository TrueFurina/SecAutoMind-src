#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_golden_freeze 门禁回归测试 —— 防止「golden 冻结校验」空转报绿。

背景（2026-10-14 门禁 fail-closed 审计实锤）：
    冻结文件 `golden_freeze.json` 若被清空（或不含任何受保护文件），原实现的
    比对循环一次都不进 → `problems` 为空 → 打印「PASS：golden 与冻结值一致」并 rc=0。
    **一条都没校验却报"一致"**，与 `_audit_llm_pool.py` 当年「池文件缺失 → 全绿」
    是同一个失效形态：把"防线缺席"当成"防线通过"。

    真实风险场景：有人误提交空冻结文件 / 合并冲突把内容冲掉 / `--update` 在
    testdata 全缺时写出 `{}` —— 此后任何人手改 golden，CI 全绿放行。

本测试锁死三条：
    A. 冻结清单为空 → rc=1（fail-closed，不得静默放行）；
    B. 冻结值正确 → rc=0（不得修成恒红）；
    C. golden 被篡改且冻结值存在 → rc=1（篡改检测必须仍然有效）。

用法：
    python scripts/check_golden_freeze_test.py
退出码：0 = 门禁健康；1 = 门禁已退化，必须修 scripts/check_golden_freeze.py
"""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "check_golden_freeze.py")
FILES = ("protocol_fixtures.json", "protocol_golden.json", "request_golden.json")


def sha256_lf(data: bytes) -> str:
    """与门禁同口径：按规范化行尾（CRLF→LF）计算。"""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def run_case(frozen: dict, contents: dict):
    """在临时仓库里跑门禁，返回 (rc, 输出)。

    frozen   —— 写入 golden_freeze.json 的内容
    contents —— {文件名: 字节内容}，写入 testdata/
    """
    tmp = tempfile.mkdtemp(prefix="golden_gate_")
    try:
        root = pathlib.Path(tmp) / "repo"
        (root / "scripts").mkdir(parents=True)
        td = root / "internal" / "ctfplatform" / "testdata"
        td.mkdir(parents=True)
        shutil.copyfile(GATE, root / "scripts" / "check_golden_freeze.py")
        for name in FILES:
            if name in contents:
                (td / name).write_bytes(contents[name])
        (td / "golden_freeze.json").write_text(
            json.dumps(frozen, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8", newline="\n")
        p = subprocess.run([sys.executable, str(root / "scripts" / "check_golden_freeze.py")],
                           cwd=str(root), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    failures = []
    good = {FILES[0]: b'{"a": 1}\n'}
    good_hash = sha256_lf(good[FILES[0]])

    print("=" * 62)
    print("check_golden_freeze 门禁回归测试（冻结空转防线）")
    print("=" * 62)

    # A. 冻结清单为空 → 必须 rc=1
    print("\n[1/3] 冻结清单为空必须 fail-closed")
    rc, out = run_case({}, good)
    ok = (rc == 1)
    print("  %s A 冻结文件为 {} 且 golden 存在（期望 rc=1，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("冻结清单为空却报绿（rc=%d）——门禁空转\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # A2. 冻结清单存在但键名全不匹配 → 同样零覆盖 → 必须 rc=1
    rc, out = run_case({"totally_unrelated.json": "deadbeef"}, good)
    ok = (rc == 1)
    print("  %s A2 冻结键名与受保护文件零交集（期望 rc=1，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("冻结清单零覆盖却报绿（rc=%d）\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # B. 冻结值正确 → 必须 rc=0
    print("\n[2/3] 正常场景不得被修成恒红")
    rc, out = run_case({FILES[0]: good_hash}, good)
    ok = (rc == 0) and ("已校验 1/3" in out)
    print("  %s B 冻结值一致（期望 rc=0 且报已校验 1/3，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("一致场景未通过或覆盖数虚报（rc=%d）\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # C. 篡改检测必须仍然有效
    print("\n[3/3] 篡改检测必须仍有效")
    rc, out = run_case({FILES[0]: "0" * 64}, good)
    ok = (rc == 1)
    print("  %s C golden 与冻结值不符（期望 rc=1，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("篡改未被检出（rc=%d）——门禁已失效\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    print("\n" + "=" * 62)
    if failures:
        print("[FAIL] golden 冻结门禁已退化，必须修 scripts/check_golden_freeze.py：")
        for f in failures:
            print("  - %s" % f)
        print("=" * 62)
        return 1
    print("[PASS] golden 冻结门禁健康：空清单/零覆盖 fail-closed，"
          "一致场景放行且覆盖数真实，篡改仍检出。")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
