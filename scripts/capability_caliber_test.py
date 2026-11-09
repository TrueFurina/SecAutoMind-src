#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""CI 自测入口：判据链 + 私有锚点 + verdict 一致性 + 证据面接线 + 恢复率口径。

项目约定：CI job 的自测入口用 `*_test.py`（门禁地图据此标注「有变异/自测」）。
前两段是合成数据（不产出可引用分数）；第三段校验真实 verdict 与生产判据
重算一致；第四段把 14 条「写了没锁」的断言入口统一接进 CI，并交叉校验全部
证据文件（第 13 条是「真实 orchestrator → 本地桩模型 → 判分」端到端契约，
零额度零外网）；第五段守「调用失败不许并进空答」这条口径。不新增判据，只做转发。

  python scripts/capability_caliber_test.py
退出码：五段全绿 = 0；任一失败 = 1。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import analyze_retry_recoverability  # noqa: E402
import audit_private_proof  # noqa: E402
import run_capability_eval  # noqa: E402
import verify_verdict_chain  # noqa: E402
import verify_capability_evidence  # noqa: E402


def main() -> int:
    print("=== 1/5 私有性外部锚点契约（含洗白攻击变异）===")
    rc1 = audit_private_proof.selftest()
    print("=== 2/5 能力率判据链路（判据/入口/作用域/假阴性）===")
    rc2 = run_capability_eval.pipeline_selftest()
    print("=== 3/5 已入库 verdict 一致性（含事后篡改变异）===")
    rc3 = verify_verdict_chain.selftest()
    rc4 = verify_verdict_chain.check()
    print("=== 4/5 证据面统一接线（14 条断言入口 + 交叉一致性）===")
    rc5 = verify_capability_evidence.selftest()
    rc6 = verify_capability_evidence.check()
    print("=== 5/5 空答恢复率：调用失败不得并进空答（含变异）===")
    rc7 = analyze_retry_recoverability.selftest()
    ok = all(rc == 0 for rc in (rc1, rc2, rc3, rc4, rc5, rc6, rc7))
    print("能力率口径门禁自测：%s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
