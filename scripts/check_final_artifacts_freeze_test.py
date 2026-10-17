#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_final_artifacts_freeze 门禁回归测试（13 项）—— 防止「交付物冻结」靠空清单静默放行，
并把「生成器↔产物契约」（2026-10-18 新增）钉死。

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

2026-10-17 追加 schema 2「退役留痕」用例（D/E/F/G）：
    受保护对象全是 .gitignore 的本地二进制，不在版本控制内。若 `--update` 直接重写
    artifacts，磁盘上缺失的项会被**连同历史哈希一起静默抹掉**——保护面缩小却无记录。
    实测踩到：ppt/演示模板版.pptx 与 package/*.tar.gz 本机不存在（跨盘 + git 历史双查无果）。
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


def run_case(manifest_artifacts: dict, files: dict, omit_artifacts_key: bool = False,
             manifest_retired: dict = None, run_update: bool = False, with_gate_deps: bool = False):
    """在临时仓库里跑门禁，返回 (rc, 输出[, 更新后的清单 dict])。

    manifest_artifacts    —— 写入 docs/final-artifacts.freeze.json 的 artifacts 段
    files                 —— {相对路径: 字节内容}，写入仓库（用于构造"实物存在"的场景）
    omit_artifacts_key    —— True 时整个 artifacts 键都不写（等同未上锁）
    manifest_retired      —— schema 2 的 retired 段（退役留痕）
    run_update            —— True 时改跑 `--update`，并回读更新后的清单
    with_gate_deps        —— True 时把「生成器↔产物契约」依赖的两个门禁脚本一并复制进
                             临时仓库（生成器哈希判据要 import check_artifact_numbers）
    """
    tmp = tempfile.mkdtemp(prefix="finalart_gate_")
    try:
        root = os.path.join(tmp, "repo")
        os.makedirs(os.path.join(root, "scripts"))
        os.makedirs(os.path.join(root, "docs"))
        shutil.copyfile(GATE, os.path.join(root, "scripts",
                                           "check_final_artifacts_freeze.py"))
        if with_gate_deps:
            for dep in ("check_artifact_numbers.py", "check_material_numbers.py"):
                shutil.copyfile(os.path.join(HERE, dep), os.path.join(root, "scripts", dep))
        for rel, data in files.items():
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(data)
        manifest = {"schema": 2, "note": "test"}
        if not omit_artifacts_key:
            manifest["artifacts"] = manifest_artifacts
        if manifest_retired is not None:
            manifest["retired"] = manifest_retired
        with open(os.path.join(root, "docs", "final-artifacts.freeze.json"),
                  "w", encoding="utf-8", newline="\n") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        argv = [sys.executable, os.path.join(root, "scripts",
                                             "check_final_artifacts_freeze.py")]
        if run_update:
            argv.append("--update")
        p = subprocess.run(argv, cwd=root, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
        out = (p.stdout or "") + (p.stderr or "")
        if run_update:
            with open(os.path.join(root, "docs", "final-artifacts.freeze.json"),
                      encoding="utf-8") as fh:
                return p.returncode, out, json.load(fh)
        return p.returncode, out
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
    print("\n[1/13] 冻结清单未上锁任何交付物必须 fail-closed")
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
    print("\n[2/13] CI 无实物的正常场景不得被修成恒红")
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
    print("\n[3/13] 篡改检测必须仍有效")
    rc, out = run_case(locked, {"SecAutoMind_PPT/x.pptx": b"REAL-CONTENT"})
    ok = (rc == 1)
    print("  %s C 实物与冻结 sha256 不符（期望 rc=1，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("交付物被改动却未 BLOCK（rc=%d）——门禁已失效\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    print("\n" + "=" * 62)

    # ── schema 2：退役留痕 ────────────────────────────────────────────────
    gone = "ppt/演示模板版.pptx"
    gone_entry = {"path": "SecAutoMind_PPT/演示模板版.pptx",
                  "sha256": "a" * 64, "size": 54091138}
    real_reason = "本机产物缺失且未入 git，跨盘检索与 git 历史双查无果；需重建后才纳入冻结"

    # D. --update 时磁盘缺失项必须迁入 retired，不得静默消失
    print("\n[4/13] --update 时磁盘缺失项必须迁入 retired（不得静默缩小保护面）")
    rc, out, newman = run_case({gone: gone_entry}, {}, run_update=True)
    ok = (rc == 0 and newman.get("retired", {}).get(gone, {}).get("sha256") == "a" * 64
          and gone not in newman.get("artifacts", {}))
    print("  %s D 缺失项迁入 retired 且保留原哈希（期望 rc=0 且 retired 含该项，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("--update 把磁盘缺失项静默删除了（retired=%s）\n    %s"
                        % (json.dumps(newman.get("retired"), ensure_ascii=False),
                           out.strip().replace("\n", "\n    ")[:400]))

    # E. 退役项重新出现在磁盘 → 必须报红（复活必须显式）
    # ⚠️ artifacts 必须非空，否则门禁先在"清单未上锁"处 BLOCK 返回，走不到复活判据
    # （那测到的是空清单防线，不是复活判据）。
    print("\n[5/13] 退役项复活必须报红（退役 ≠ 可悄悄回来）")
    rc, out = run_case({name: {"path": "SecAutoMind_PPT/x.pptx",
                               "sha256": "0" * 64, "size": 10}},
                       {"SecAutoMind_PPT/x.pptx": b"REAL-CONTENT",
                        "SecAutoMind_PPT/演示模板版.pptx": b"BACK-AGAIN"},
                       manifest_retired={gone: dict(gone_entry, retired_at="2026-10-17T09:00:00",
                                                    reason=real_reason)})
    ok = (rc == 1 and "退役项重新出现在磁盘" in out)
    print("  %s E 退役项回到磁盘（期望 rc=1 且报复活，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("退役项复活未报红（rc=%d）——退役段成了绕过上锁的通道\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # F. retired 原因仍是自动占位文本 → 必须报红（防止"退役"沦为洗白）
    print("\n[6/13] retired 原因仍为占位文本必须报红（留痕不许空转）")
    rc, out = run_case({name: {"path": "SecAutoMind_PPT/x.pptx",
                               "sha256": "0" * 64, "size": 10}},
                       {"SecAutoMind_PPT/x.pptx": b"REAL-CONTENT"},
                       manifest_retired={gone: dict(
                           gone_entry, retired_at="2026-10-17T09:00:00",
                           reason="磁盘上已不存在（被删/未生成/改名？）——由 --update 自动迁移留痕，"
                                  "**需人工复核并改写为真实原因**")})
    ok = (rc == 1 and "占位文本" in out)
    print("  %s F retired 原因未人工填写（期望 rc=1 且报占位，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("retired 占位原因未报红（rc=%d）——留痕会空转\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # G. 退役项不在磁盘 + 原因已人工填写 → 不得误报（反向对照，防恒红）
    print("\n[7/13] 已登记原因的退役项不得误报（反向对照，防修成恒红）")
    rc, out = run_case({name: {"path": "SecAutoMind_PPT/x.pptx",
                               "sha256": "0" * 64, "size": 10}},
                       {"SecAutoMind_PPT/x.pptx": b"REAL-CONTENT"},
                       manifest_retired={gone: dict(gone_entry,
                                                    retired_at="2026-10-17T09:00:00",
                                                    reason=real_reason)})
    ok = (rc == 1 and "退役" not in out.split("[BLOCK]")[-1])
    print("  %s G 退役项已登记且不在磁盘（期望 rc=1 仅因 sha256 不符、不涉退役，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("已登记的退役项被误报（rc=%d）\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # H. 退役项实物回来 + 显式 --update → 必须从 retired 摘出、重新上锁，且**保留退役历史**
    #    （2026-10-18 实测缺陷：旧实现只做单向迁移，复活后 --update 摘不掉 retired 条目，
    #      --check 的「复活必报」从此永久红，没有任何合法出路。）
    print("\n[8/13] 退役项复活 + --update 必须收口：重新上锁且保留退役历史")
    rc, out, newman = run_case({}, {"SecAutoMind_PPT/演示模板版.pptx": b"BACK-AGAIN"},
                              manifest_retired={gone: dict(gone_entry,
                                                           retired_at="2026-10-17T09:00:00",
                                                           reason=real_reason)},
                              run_update=True)
    hist = (newman.get("artifacts", {}).get(gone) or {}).get("previous_retirement") or {}
    ok = (rc == 0 and gone in newman.get("artifacts", {})
          and gone not in newman.get("retired", {})
          and hist.get("sha256") == "a" * 64)
    print("  %s H 复活项重新上锁、retired 摘出、previous_retirement 留史（实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("--update 无法收口退役项复活（artifacts=%s, retired=%s, hist=%s）"
                        % (json.dumps(newman.get("artifacts"), ensure_ascii=False)[:300],
                           json.dumps(newman.get("retired"), ensure_ascii=False)[:300],
                           json.dumps(hist, ensure_ascii=False)[:300]))

    # H2. 收口后复跑 --check 必须 PASS（证明"永久红"已被消除，而不是只是换了报错）
    print("\n[9/13] 复活收口后 --check 必须放行（不得留成永久报红）")
    rc2, out2 = run_case(newman.get("artifacts", {}),
                         {"SecAutoMind_PPT/演示模板版.pptx": b"BACK-AGAIN"},
                         manifest_retired=newman.get("retired", {}))
    ok2 = (rc2 == 0)
    print("  %s H2 收口后 --check 放行（期望 rc=0，实际 rc=%d）" % ("PASS" if ok2 else "FAIL", rc2))
    if not ok2:
        failures.append("复活收口后 --check 仍红（rc=%d）\n    %s"
                        % (rc2, out2.strip().replace("\n", "\n    ")[:400]))

    # ── 生成器 ↔ 产物 契约（2026-10-18 实锤）───────────────────────────────
    # 背景：三份答辩 PPT 的冻结产物与生成器**内容不一致**（生成器已改「91 个 YAML」，
    # 产物还写「100+ YAML」；安装包 33.6 MB vs 实物 20 MB）。产物不在 git 里，
    # 只锁产物 sha 查不出"产物是旧生成器的输出" → 必须同时钉生成器哈希。
    gen_rel = "SecAutoMind_PPT/make_x.py"
    gen_body = b"from pathlib import Path\nOUT = Path(__file__).resolve().parent / 'x.pptx'\n"
    gen_files = {"SecAutoMind_PPT/x.pptx": b"REAL-CONTENT", gen_rel: gen_body}

    # I1. 有生成器但清单未记其哈希 → 必须报（否则"产物是否陈旧"永远无人问）
    print("\n[10/13] 有生成器却未记录其哈希必须报红")
    rc, out = run_case(locked, gen_files, with_gate_deps=True)
    ok = (rc == 1 and "未记录其哈希" in out)
    print("  %s I1 清单缺 generator 字段（期望 rc=1，实际 rc=%d）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("清单缺生成器哈希却报绿（rc=%d）——产物陈旧无从发现\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # I2. --update 必须把生成器路径 + 哈希写进清单
    print("\n[11/13] --update 必须记录生成器路径与哈希")
    rc, out, nm = run_case({}, gen_files, run_update=True, with_gate_deps=True)
    genrec = ((nm.get("artifacts") or {}).get(name) or {}).get("generator") or {}
    ok = (rc == 0 and genrec.get("path") == gen_rel
          and genrec.get("sha256") == sha256(gen_body))
    print("  %s I2 generator 字段写入（期望 rc=0 且 path/sha 正确，实际 rc=%d, rec=%s）"
          % ("PASS" if ok else "FAIL", rc, json.dumps(genrec, ensure_ascii=False)[:120]))
    if not ok:
        failures.append("--update 未记录生成器哈希（rec=%s）"
                        % json.dumps(genrec, ensure_ascii=False)[:200])

    # I3. 生成器改了、产物没重跑 → 必须报红（本轮要防的正是这件事）
    print("\n[12/13] 生成器改动而产物未重新上锁必须报红")
    touched = dict(gen_files)
    touched[gen_rel] = gen_body + "# 2026-10-18 changed a number\n".encode("utf-8")
    rc, out = run_case(nm.get("artifacts", {}), touched, with_gate_deps=True)
    ok = (rc == 1 and "生成器" in out and "已改动" in out)
    print("  %s I3 生成器已改（期望 rc=1 且报生成器改动，实际 rc=%d）"
          % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("生成器已改却未报红（rc=%d）——产物陈旧静默通过\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    # I4. 反向钉：生成器未改 + 产物未改 → 必须放行（证明 I1~I3 不是恒红）
    print("\n[13/13] 生成器与产物都没动时必须放行（证明 I1~I3 非恒红）")
    rc, out = run_case(nm.get("artifacts", {}), gen_files, with_gate_deps=True)
    ok = (rc == 0)
    print("  %s I4 全一致（期望 rc=0，实际 rc=%d）" % ("PASS" if ok else "FAIL", rc))
    if not ok:
        failures.append("生成器与产物均未改却报红（rc=%d）\n    %s"
                        % (rc, out.strip().replace("\n", "\n    ")[:400]))

    if failures:
        print("[FAIL] 交付物冻结门禁已退化，必须修 scripts/check_final_artifacts_freeze.py：")
        for f in failures:
            print("  - %s" % f)
        print("=" * 62)
        return 1
    print("[PASS] 交付物冻结门禁健康：空清单 fail-closed，"
          "CI 无实物仍按设计跳过，实物篡改仍 BLOCK，"
          "退役留痕不丢/复活必报/占位原因必报/已登记退役不误报，"
          "生成器哈希缺失必报/生成器改动必报/两者未动则放行。")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
