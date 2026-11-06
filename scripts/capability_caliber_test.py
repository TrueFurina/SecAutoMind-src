#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""CI 自测入口：判据链 + 私有锚点 + verdict 一致性 + 证据面接线。

项目约定：CI job 的自测入口用 `*_test.py`（门禁地图据此标注「有变异/自测」）。
前两段是合成数据（不产出可引用分数）；第三段校验真实 verdict 与生产判据
重算一致；第四段把 11 条「写了没锁」的断言入口统一接进 CI，并交叉校验全部
证据文件。不新增判据，只做转发。

  python scripts/capability_caliber_test.py
退出码：四段全绿 = 0；任一失败 = 1。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import audit_private_proof  # noqa: E402
import run_capability_eval  # noqa: E402
import verify_verdict_chain  # noqa: E402
import verify_capability_evidence  # noqa: E402


def main() -> int:
    print("=== 1/4 私有性外部锚点契约（含洗白攻击变异）===")
    rc1 = audit_private_proof.selftest()
    print("=== 2/4 能力率判据链路（判据/入口/作用域/假阴性）===")
    rc2 = run_capability_eval.pipeline_selftest()
    print("=== 3/4 已入库 verdict 一致性（含事后篡改变异）===")
    rc3 = verify_verdict_chain.selftest()
    rc4 = verify_verdict_chain.check()
    print("=== 4/4 证据面统一接线（11 条断言入口 + 交叉一致性）===")
    rc5 = verify_capability_evidence.selftest()
    rc6 = verify_capability_evidence.check()
    ok = all(rc == 0 for rc in (rc1, rc2, rc3, rc4, rc5, rc6))
    print("能力率口径门禁自测：%s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
