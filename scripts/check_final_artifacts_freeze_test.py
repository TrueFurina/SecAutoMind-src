#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_final_artifacts_freeze 门禁回归测试 —— 防止「交付物冻结」靠空清单静默放行。

背景（2026-10-14 门禁 fail-closed 审计实锤）：
    受保护对象（PPT / 交付压缩包 / 演示视频）不随 git 分发，CI 检出里一个都没有，
    因此门禁有一条**有意设计**的 SKIP 分支：`got` 为空 → 打印跳过并 rc=0。

    这条分支本身没错（否则 CI 恒红，噪音门禁比没门禁更糟），但它同时开了一个洞：
    **把冻结清单 `artifacts` 清空，CI 依然走 SKIP 报绿**。此时门禁的"上锁"语义
    被彻底架空——清单锁了 0 项，"任何改动即 BLOCK"就成了一句空话。

    与 `_audit_llm_pool.py` 当年「池文件缺失 → 全绿」同构：输入缺失本身必须算红。
    本测试把"清单锁了 0 项"与"实物不在本检出"两种空区分开：
      · 清单为空        → rc=1（未上锁 = fail-closed）
      · 清单非空、实物缺 → rc=0（CI 场景，保持原设计）
      · 清单非空、实物在但 sha256 变了 → rc=1（篡改检测必须仍有效）

用法：
    python scripts/check_final_artifacts_freeze_test.py
退出码：0 = 门禁健康；1 = 门禁已退化，必须修 scripts/check_final_artifacts_freeze.py
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "check_final_artifacts_freeze.py")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_case(manifest_artifacts: dict, files: dict, omit_artifacts_key: bool = False):
    """在临时仓库里跑门禁，返回 (rc, 输出)。

    manifest_artifacts    —— 写入 docs/final-artifacts.freeze.json 的 artifacts 段
    files                 —— {相对路径: 字节内容}，写入仓库（用于构造"实物存在"的场景）
    omit_artifacts_key    —— True 时整个 artifacts 键都不写（等同未上锁）
    """
    tmp = tempfile.mkdtemp(prefix="finalart_gate_")
    try:
        root = os.path.join(tmp, "repo")
        os.makedirs(os.path.join(root, "scripts"))
        os.makedirs(os.path.join(root, "docs"))
        shutil.copyfile(GATE, os.path.join(root, "scripts",
                                           "check_final_artifacts_freeze.py"))
        for rel, data in files.items():
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(data)
        manifest = {"schema": 1, "note": "test"}
        if not omit_artifacts_key:
            manifest["artifacts"] = manifest_artifacts
        with open(os.path.join(root, "docs", "final-artifacts.freeze.json"),
                  "w", encoding="utf-8", newline="\n") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        p = subprocess.run(
            [sys.executable, os.path.join(root, "scripts",
                                          "check_final_artifacts_freeze.py")],
            cwd=root, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=120)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    failures = []
    # 逻辑名必须与门禁 collect() 的命名一致（"ppt/" + 文件名），否则测到的是
    # "缺锁/多锁"而不是"内容被改"。
    name = "ppt/x.pptx"

    print("=" * 62)
    print("check_final_artifacts_freeze 门禁回归测试（空清单防线）")
    print("=" * 62)

    # A. 清空单 = 未上锁 → 必须 rc=1（本轮修复的核心）
    print("\n[1/3] 冻结清单未上锁任何交付物必须 fail-closed")
    rc, out = run_case({}, {})
    ok = (rc == 1)
    print("  %s A artifacts 为空（期望 rc=1，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("空冻结清单却报绿（rc=%d）——上锁语义被架空\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # A2. artifacts 键整个缺失（等同未上锁）→ 必须 rc=1
    rc, out = run_case({}, {}, omit_artifacts_key=True)
    ok = (rc == 1)
    print("  %s A2 artifacts 键缺失（期望 rc=1，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("artifacts 键缺失却报绿（rc=%d）\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # B. 清单非空 + CI 无实物 → 必须 rc=0（保持原有 SKIP 设计，不得修成恒红）
    print("\n[2/3] CI 无实物的正常场景不得被修成恒红")
    locked = {name: {"path": "SecAutoMind_PPT/x.pptx",
                     "sha256": "0" * 64, "size": 10}}
    rc, out = run_case(locked, {})
    ok = (rc == 0) and ("清单已锁 1 项" in out)
    print("  %s B 清单已锁 1 项、本检出无实物（期望 rc=0 且报已锁 1 项，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("CI 场景（清单非空/实物缺失）未跳过（rc=%d）\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # C. 实物存在但 sha256 不符 → 篡改检测必须仍有效
    print("\n[3/3] 篡改检测必须仍有效")
    rc, out = run_case(locked, {"SecAutoMind_PPT/x.pptx": b"REAL-CONTENT"})
    ok = (rc == 1)
    print("  %s C 实物与冻结 sha256 不符（期望 rc=1，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("交付物被改动却未 BLOCK（rc=%d）——门禁已失效\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    print("\n" + "=" * 62)
    if failures:
        print("[FAIL] 交付物冻结门禁已退化，必须修 scripts/check_final_artifacts_freeze.py：")
        for f in failures:
            print("  - %s" % f)
        print("=" * 62)
        return 1
    print("[PASS] 交付物冻结门禁健康：空清单 fail-closed，"
          "CI 无实物仍按设计跳过，实物篡改仍 BLOCK。")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
