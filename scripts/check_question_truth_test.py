#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`check_question_truth.py` 状态判定回归测试。

背景（2026-10-26 实锤）：
  该脚本原先把 `real_reverse_js` 判成 `NO_MATCH` 并计入 `broken`（=真值矛盾）。
  实算证明真值 `flag{cslhahldlnst0day}` 的 sha256 **完全正确**，
  真正原因是声明的 `index.html` 已丢失（现存仅 31 字节空壳），答案随原件消失。
  幸存附件 `coso.js` 的 `delog()` 是诱导项，**本来就推不出真值** → 属题设，不是矛盾。

  修复：新增 `partial_attachments` 状态。文件「存在但内容近乎空壳」与「文件不存在」
  同等视为缺失——只看存在性会把空壳当有效附件。

本测试锁住三件事（含**反向变异**，防止把真问题一并放过）：
  ① 附件齐全 + 明文 flag 不匹配 → 仍必须 NO_MATCH（不能因本次修改而放过真矛盾）
  ② 附件确有缺失 + 幸存附件不匹配 → partial_attachments（不计入 broken）
  ③ 附件存在但是空壳 + 幸存附件不匹配 → partial_attachments
  ④ 明文 flag 与 sha256 不符 → 仍必须 MISMATCH

用法：python scripts/check_question_truth_test.py
退出码：0 = 全部通过；1 = 有用例失败。
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_question_truth.py"
CTF = ROOT / "CTF-Agent_融合" / "ctf_agent"


def _load_module():
    spec = importlib.util.spec_from_file_location("cqt", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def main() -> int:
    mod = _load_module()
    real_sha = hashlib.sha256(b"flag{the_real_one}").hexdigest()

    # 🔴 2026-10-26 修正：原先在**真实题库目录**下建临时用例
    #    （`data/questions_real/_attachments/_cqt_test`），有两个问题：
    #    ① 污染真实数据目录；② 并发/重跑时 `mkdir` 撞 `FileExistsError`
    #    ——实测 30 次里失败 2 次（间歇性假红）。
    #    `check_one` 按传入 fp 的位置解析相对附件，故把题库整体放到 tempdir 即可。
    tmp_root = Path(tempfile.mkdtemp(prefix="cqt_test_"))
    abs_base = tmp_root / "attachments"
    abs_base.mkdir(parents=True)

    results: list[tuple[str, bool, str]] = []

    def case(qid: str, files: dict[str, str], declared: list[str], expect: str) -> None:
        d = abs_base / qid
        d.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            (d / name).write_text(content, encoding="utf-8")
        # 用**绝对路径**声明附件：`_resolve_attachment` 只把相对路径绑在仓库根/ctf_agent 根，
        # 绝对路径原样返回，因此测试可完全脱离真实数据目录。
        atts = [str(abs_base / qid / n) for n in declared]
        qf = d / f"{qid}.json"
        qf.write_text(
            json.dumps(
                {"id": qid, "flag": real_sha, "flag_sha256": real_sha, "attachments": atts},
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        r = mod.check_one(qf)
        ok = r["status"] == expect
        results.append((qid, ok, f"expect={expect} got={r['status']}"))

    wrong = 'var x = "flag{wrong_answer_here}";'

    # ① 附件齐全（无缺失/无空壳）→ 真矛盾必须仍然报出来
    case("mut_no_match", {"src.js": wrong}, ["src.js"], "NO_MATCH")

    # ② 附件确有缺失
    case("mut_partial", {"src.js": wrong}, ["src.js", "missing.html"], "partial_attachments")

    # ③ 附件存在但是空壳（31 字节级）
    case(
        "mut_hollow",
        {"src.js": wrong, "index.html": "<!DOCTYPE html><title></title>"},
        ["src.js", "index.html"],
        "partial_attachments",
    )

    # ④ 明文 flag 与 sha256 不符
    d = abs_base / "mut_mismatch"
    d.mkdir(parents=True, exist_ok=True)
    qf = d / "mut_mismatch.json"
    qf.write_text(
        json.dumps(
            {"id": "mut_mismatch", "flag": "flag{plaintext}", "flag_sha256": real_sha,
             "attachments": []},
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    r = mod.check_one(qf)
    results.append(("mut_mismatch", r["status"] == "MISMATCH",
                    f"expect=MISMATCH got={r['status']}"))

    # ⑤ 真实数据：real_reverse_js 必须是 partial_attachments，且不再计入 broken
    #    ⚠️ 该文件**已入 git**（`data/questions_real/reverse/real_reverse_js.json` 被跟踪），
    #    故 CI 上可读。但仍加 fail-loud：若哪天它被移出 git，必须**报错**而不是静默少跑一条。
    real_q = CTF / "data/questions_real/reverse/real_reverse_js.json"
    if real_q.is_file():
        r = mod.check_one(real_q)
        results.append(("real_reverse_js", r["status"] == "partial_attachments",
                        f"expect=partial_attachments got={r['status']}"))
    else:
        results.append(("real_reverse_js", False,
                        f"题面 JSON 不存在（CI 应能看到，缺失即数据丢失）: {real_q}"))

    # 清理失败不得影响判定（同 `_audit_corpus_integrity_test`：某些沙箱的审计钩子
    # 会在 rmtree 上抛 PermissionError，ignore_errors=True 拦不住）
    try:
        shutil.rmtree(tmp_root, ignore_errors=True)
    except Exception:  # noqa: BLE001
        pass

    failed = [x for x in results if not x[1]]
    for qid, ok, msg in results:
        print(f"{'PASS' if ok else 'FAIL'}  {qid:18} {msg}")
    print(f"\n{len(results) - len(failed)}/{len(results)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
