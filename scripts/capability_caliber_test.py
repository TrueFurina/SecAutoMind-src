#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""CI 自测入口：能力率判据链 + 私有性外部锚点契约 + verdict 一致性。

项目约定：CI job 的自测入口用 `*_test.py`（门禁地图据此标注「有变异/自测」）。
前两段是合成数据（不产出可引用分数）；第三段还校验**真实已入库 verdict**
与生产判据重算一致，并用变异攻击证明事后篡改会被拦下。不新增判据，只做转发。

  python scripts/capability_caliber_test.py
退出码：三段全绿 = 0；任一失败 = 1。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import audit_private_proof  # noqa: E402
import run_capability_eval  # noqa: E402
import verify_verdict_chain  # noqa: E402


def main() -> int:
    print("=== 1/3 私有性外部锚点契约（含洗白攻击变异）===")
    rc1 = audit_private_proof.selftest()
    print("=== 2/3 能力率判据链路（判据/入口/作用域/假阴性）===")
    rc2 = run_capability_eval.pipeline_selftest()
    print("=== 3/3 已入库 verdict 一致性（含事后篡改变异）===")
    rc3 = verify_verdict_chain.selftest()
    rc4 = verify_verdict_chain.check()
    ok = (rc1 == 0 and rc2 == 0 and rc3 == 0 and rc4 == 0)
    print("能力率口径门禁自测：%s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
